"""Exact-version image building, bounded subprocesses, and active attestation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from typing import Mapping, Sequence

from .contract import Contract, IntegrityError, target_for
from .core import canonical_items, canonical_json_bytes


MAX_CONTROL_OUTPUT_BYTES = 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^(?:[^\s@]+@)?sha256:[0-9a-f]{64}$")
_NODE_VERSION_RE = re.compile(
    r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9._-]+)?$"
)
_CODEX_WRAPPER_PATH = "/usr/local/lib/node_modules/@openai/codex/bin/codex.js"
_CODEX_NATIVE_PATH = (
    "/usr/local/lib/node_modules/@openai/codex-linux-arm64/"
    "vendor/aarch64-unknown-linux-musl/bin/codex"
)


@dataclass(frozen=True, slots=True)
class ImageBuildPlan:
    target_name: str
    image_tag: str
    base_image_digest: str
    dockerfile: bytes
    recipe_sha256: str
    build_args: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ImageAttestation:
    target_name: str
    contract_sha256: str
    image_reference: str
    image_digest: str
    image_id: str
    base_image_digest: str
    recipe_sha256: str
    target_version: str
    package_integrity: str
    node_version: str
    os: str
    arch: str
    image_family: str
    attestation_sha256: str
    platform_package_integrity: str | None = None
    wrapper_sha256: str | None = None
    platform_binary_sha256: str | None = None


def _write_bytes(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        process.terminate()
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        process.kill()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        raise IntegrityError("control-plane process resisted SIGKILL") from exc


def bounded_run(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 30,
    max_output_bytes: int = MAX_CONTROL_OUTPUT_BYTES,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Run fixed argv with a wall deadline and bounded combined output."""

    if (
        not argv
        or not all(isinstance(item, str) and item and "\x00" not in item for item in argv)
        or timeout <= 0
        or max_output_bytes <= 0
    ):
        raise IntegrityError("invalid bounded control-plane command")
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise IntegrityError(f"cannot start control-plane command: {exc}") from exc

    exceeded = threading.Event()
    lock = threading.Lock()
    total = 0
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()

    def drain(pipe, destination: bytearray) -> None:
        nonlocal total
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    break
                with lock:
                    previous = total
                    total += len(chunk)
                    remaining = max(0, max_output_bytes - previous)
                    if remaining:
                        destination.extend(chunk[:remaining])
                    if total > max_output_bytes:
                        exceeded.set()
        finally:
            pipe.close()

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=drain, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_buffer), daemon=True),
    )
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if exceeded.is_set():
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        exceeded.wait(min(0.05, remaining))
    if timed_out or exceeded.is_set():
        _terminate_process_group(process)
    for reader in readers:
        reader.join(timeout=2)
    if any(reader.is_alive() for reader in readers):
        _terminate_process_group(process)
        raise IntegrityError("control-plane command left output pipes open")
    if timed_out:
        raise IntegrityError("control-plane command exceeded wall deadline")
    if exceeded.is_set():
        raise IntegrityError("control-plane command exceeded output budget")
    stdout_bytes = bytes(stdout_buffer)
    stderr_bytes = bytes(stderr_buffer)
    return subprocess.CompletedProcess(
        list(argv),
        int(process.returncode),
        stdout_bytes.decode("utf-8", errors="replace") if text else stdout_bytes,
        stderr_bytes.decode("utf-8", errors="replace") if text else stderr_bytes,
    )


_LABEL_PREFIX = "io.canary-matrix."
_LABEL_FIELDS = {
    "base_image_digest": "base-image-digest",
    "recipe_sha256": "recipe-sha256",
    "target_version": "target-version",
    "package_integrity": "package-integrity",
    "platform_package_integrity": "platform-package-integrity",
    "wrapper_sha256": "wrapper-sha256",
    "platform_binary_sha256": "platform-binary-sha256",
    "node_version": "node-version",
    "os": "os-release",
    "arch": "architecture",
    "image_family": "image-family",
    "contract_sha256": "contract-sha256",
}


def _label(field: str) -> str:
    return _LABEL_PREFIX + _LABEL_FIELDS[field]


def render_image_build_plan(
    contract: Contract,
    target_name: str,
    *,
    base_image_digest: str,
) -> ImageBuildPlan:
    target = target_for(contract, target_name)
    if (
        "@sha256:" not in base_image_digest
        or not _IMAGE_DIGEST_RE.fullmatch(base_image_digest)
    ):
        raise IntegrityError("base image must be a registry reference pinned by SHA-256")
    if contract.probe_kind == "codex_trust_enter_39487":
        if target.platform_npm_integrity is None:
            raise IntegrityError("Codex image target has no platform package SRI")
        dockerfile = f'''FROM {base_image_digest}

ARG CANARY_TARGET_VERSION
ARG CANARY_NPM_INTEGRITY
ARG CANARY_PLATFORM_NPM_INTEGRITY
ARG CANARY_WRAPPER_SHA256
ARG CANARY_PLATFORM_BINARY_SHA256
ARG CANARY_NODE_VERSION
ARG CANARY_OS_RELEASE
ARG CANARY_ARCH
ARG CANARY_IMAGE_FAMILY
ARG CANARY_CONTRACT_SHA256
ARG CANARY_RECIPE_SHA256

RUN set -eu; command -v node; command -v npm; command -v tar; command -v ln
RUN set -eu; \
    mkdir -p /tmp/canary-top /tmp/canary-platform; \
    cd /tmp/canary-top; \
    npm pack --json "@openai/codex@${{CANARY_TARGET_VERSION}}" > pack.json; \
    cd /tmp/canary-platform; \
    npm pack --json "@openai/codex@${{CANARY_TARGET_VERSION}}-linux-arm64" > pack.json; \
    top_tarball="/tmp/canary-top/$(node -p 'require("/tmp/canary-top/pack.json")[0].filename')"; \
    platform_tarball="/tmp/canary-platform/$(node -p 'require("/tmp/canary-platform/pack.json")[0].filename')"; \
    node -e 'const fs=require("fs"),c=require("crypto"),[p,w]=process.argv.slice(1),g="sha512-"+c.createHash("sha512").update(fs.readFileSync(p)).digest("base64");if(g!==w){{console.error("top-level npm SRI mismatch");process.exit(72)}}' "${{top_tarball}}" "${{CANARY_NPM_INTEGRITY}}"; \
    node -e 'const fs=require("fs"),c=require("crypto"),[p,w]=process.argv.slice(1),g="sha512-"+c.createHash("sha512").update(fs.readFileSync(p)).digest("base64");if(g!==w){{console.error("platform npm SRI mismatch");process.exit(73)}}' "${{platform_tarball}}" "${{CANARY_PLATFORM_NPM_INTEGRITY}}"; \
    mkdir -p /usr/local/lib/node_modules/@openai/codex /usr/local/lib/node_modules/@openai/codex-linux-arm64; \
    tar -xzf "${{top_tarball}}" -C /usr/local/lib/node_modules/@openai/codex --strip-components=1 --no-same-owner --no-same-permissions; \
    tar -xzf "${{platform_tarball}}" -C /usr/local/lib/node_modules/@openai/codex-linux-arm64 --strip-components=1 --no-same-owner --no-same-permissions; \
    node -e 'const fs=require("fs"),[v]=process.argv.slice(1),t=JSON.parse(fs.readFileSync("/usr/local/lib/node_modules/@openai/codex/package.json")),p=JSON.parse(fs.readFileSync("/usr/local/lib/node_modules/@openai/codex-linux-arm64/package.json"));if(t.name!=="@openai/codex"||t.version!==v||p.name!=="@openai/codex"||p.version!==v+"-linux-arm64")process.exit(74)' "${{CANARY_TARGET_VERSION}}"; \
    test -f /usr/local/lib/node_modules/@openai/codex/bin/codex.js; \
    test ! -L /usr/local/lib/node_modules/@openai/codex/bin/codex.js; \
    test -f /usr/local/lib/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex; \
    test ! -L /usr/local/lib/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex; \
    test -x /usr/local/lib/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex; \
    node -e 'const fs=require("fs"),c=require("crypto"),[p,w]=process.argv.slice(1),g=c.createHash("sha256").update(fs.readFileSync(p)).digest("hex");if(g!==w){{console.error("wrapper SHA-256 mismatch");process.exit(75)}}' /usr/local/lib/node_modules/@openai/codex/bin/codex.js "${{CANARY_WRAPPER_SHA256}}"; \
    node -e 'const fs=require("fs"),c=require("crypto"),[p,w]=process.argv.slice(1),g=c.createHash("sha256").update(fs.readFileSync(p)).digest("hex");if(g!==w){{console.error("platform binary SHA-256 mismatch");process.exit(76)}}' /usr/local/lib/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex "${{CANARY_PLATFORM_BINARY_SHA256}}"; \
    ln -s /usr/local/lib/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex; \
    rm -rf /tmp/canary-top /tmp/canary-platform
RUN set -eu; \
    node -e 'const fs=require("fs"),v={{package:"@openai/codex",platform_alias:"@openai/codex-linux-arm64",version:process.env.CANARY_TARGET_VERSION}};fs.writeFileSync("/etc/canary-matrix-target.json",JSON.stringify(v)+"\\n")'; \
    codex --version; node --version

LABEL {_label("base_image_digest")}="{base_image_digest}" \
      {_label("recipe_sha256")}="${{CANARY_RECIPE_SHA256}}" \
      {_label("target_version")}="${{CANARY_TARGET_VERSION}}" \
      {_label("package_integrity")}="${{CANARY_NPM_INTEGRITY}}" \
      {_label("platform_package_integrity")}="${{CANARY_PLATFORM_NPM_INTEGRITY}}" \
      {_label("wrapper_sha256")}="${{CANARY_WRAPPER_SHA256}}" \
      {_label("platform_binary_sha256")}="${{CANARY_PLATFORM_BINARY_SHA256}}" \
      {_label("node_version")}="${{CANARY_NODE_VERSION}}" \
      {_label("os")}="${{CANARY_OS_RELEASE}}" \
      {_label("arch")}="${{CANARY_ARCH}}" \
      {_label("image_family")}="${{CANARY_IMAGE_FAMILY}}" \
      {_label("contract_sha256")}="${{CANARY_CONTRACT_SHA256}}"

ENTRYPOINT []
CMD []
'''.encode("utf-8")
    else:
        dockerfile = f'''FROM {base_image_digest}

ARG CANARY_TARGET_VERSION
ARG CANARY_NPM_INTEGRITY
ARG CANARY_NODE_VERSION
ARG CANARY_OS_RELEASE
ARG CANARY_ARCH
ARG CANARY_IMAGE_FAMILY
ARG CANARY_CONTRACT_SHA256
ARG CANARY_RECIPE_SHA256

RUN set -eu; command -v node; command -v npm; command -v cat
RUN set -eu; \\
    npm pack --json "@google/gemini-cli@${{CANARY_TARGET_VERSION}}" > /tmp/canary-pack.json; \\
    node -e 'const fs=require("fs"),c=require("crypto"),p=require("/tmp/canary-pack.json")[0].filename,w=process.env.CANARY_NPM_INTEGRITY,g="sha512-"+c.createHash("sha512").update(fs.readFileSync(p)).digest("base64");if(g!==w){{console.error("npm SRI mismatch");process.exit(72)}}'; \\
    tarball="$(node -p 'require("/tmp/canary-pack.json")[0].filename')"; \\
    npm install --global "./${{tarball}}"; \\
    rm -f "${{tarball}}" /tmp/canary-pack.json
RUN set -eu; \\
    node -e 'const fs=require("fs"),v={{package:"@google/gemini-cli",version:process.env.CANARY_TARGET_VERSION}};fs.writeFileSync("/etc/canary-matrix-target.json",JSON.stringify(v)+"\\n")'; \\
    gemini --version; node --version

LABEL {_label("base_image_digest")}="{base_image_digest}" \\
      {_label("recipe_sha256")}="${{CANARY_RECIPE_SHA256}}" \\
      {_label("target_version")}="${{CANARY_TARGET_VERSION}}" \\
      {_label("package_integrity")}="${{CANARY_NPM_INTEGRITY}}" \\
      {_label("node_version")}="${{CANARY_NODE_VERSION}}" \\
      {_label("os")}="${{CANARY_OS_RELEASE}}" \\
      {_label("arch")}="${{CANARY_ARCH}}" \\
      {_label("image_family")}="${{CANARY_IMAGE_FAMILY}}" \\
      {_label("contract_sha256")}="${{CANARY_CONTRACT_SHA256}}"

ENTRYPOINT []
CMD ["gemini", "--version"]
'''.encode("utf-8")
    recipe_sha256 = hashlib.sha256(dockerfile).hexdigest()
    build_args = canonical_items(
        {
            "CANARY_TARGET_VERSION": target.version,
            "CANARY_NPM_INTEGRITY": target.npm_integrity,
            "CANARY_NODE_VERSION": target.node_version,
            "CANARY_OS_RELEASE": target.os,
            "CANARY_ARCH": target.arch,
            "CANARY_IMAGE_FAMILY": target.image_family,
            "CANARY_CONTRACT_SHA256": contract.raw_sha256,
            "CANARY_RECIPE_SHA256": recipe_sha256,
        }
    )
    if target.platform_npm_integrity is not None:
        build_args = canonical_items(
            {
                **dict(build_args),
                "CANARY_PLATFORM_NPM_INTEGRITY": target.platform_npm_integrity,
                "CANARY_WRAPPER_SHA256": target.wrapper_sha256,
                "CANARY_PLATFORM_BINARY_SHA256": target.platform_binary_sha256,
            }
        )
    return ImageBuildPlan(
        target_name=target_name,
        image_tag=target.image_tag,
        base_image_digest=base_image_digest,
        dockerfile=dockerfile,
        recipe_sha256=recipe_sha256,
        build_args=build_args,
    )


def build_target_image(
    plan: ImageBuildPlan,
    *,
    runner=bounded_run,
) -> subprocess.CompletedProcess[str]:
    if hashlib.sha256(plan.dockerfile).hexdigest() != plan.recipe_sha256:
        raise IntegrityError("image build plan Dockerfile digest mismatch")
    build_args = dict(plan.build_args)
    if build_args.get("CANARY_RECIPE_SHA256") != plan.recipe_sha256:
        raise IntegrityError("image build plan recipe argument mismatch")
    arch = build_args.get("CANARY_ARCH")
    if arch not in {"amd64", "arm64"}:
        raise IntegrityError("image build plan architecture is unsupported")
    with tempfile.TemporaryDirectory(prefix="canary_image_context_") as context:
        root = Path(context)
        dockerfile = root / "Dockerfile"
        _write_bytes(dockerfile, plan.dockerfile, 0o444)
        argv = [
            "docker",
            "build",
            "--pull=false",
            "--no-cache",
            "--rm=true",
            "--force-rm",
            "--platform",
            f"linux/{arch}",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--cpu-period",
            "100000",
            "--cpu-quota",
            "100000",
            "--file",
            str(dockerfile),
            "--tag",
            plan.image_tag,
        ]
        for key, value in plan.build_args:
            argv.extend(["--build-arg", f"{key}={value}"])
        argv.append(str(root))
        rendered = " ".join(argv).lower()
        if any(token in rendered for token in ("--secret", "--ssh", "docker.sock", "type=bind")):
            raise IntegrityError("image build command exposes a forbidden surface")
        completed = runner(argv, timeout=900, max_output_bytes=8 * 1024 * 1024)
        if completed.returncode != 0:
            detail = (str(completed.stdout) + str(completed.stderr))[-4000:]
            raise IntegrityError("target image build failed: " + detail)
        return completed


def _secure_probe_argv(
    image_digest: str,
    executable: str,
    *arguments: str,
    extra_environment: Sequence[str] = (),
) -> list[str]:
    if not _IMAGE_DIGEST_RE.fullmatch(image_digest):
        raise IntegrityError("image probe requires an immutable image digest")
    if executable not in {"gemini", "codex", "node", "cat", _CODEX_NATIVE_PATH}:
        raise IntegrityError("image probe executable is not trusted")
    if any(item not in {"CODEX_HOME=/tmp/codex-home"} for item in extra_environment):
        raise IntegrityError("image probe environment is not trusted")
    return [
        "docker",
        "run",
        "--rm",
        "--cpus",
        "1",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "64",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--env",
        "HOME=/tmp",
        *[item for value in extra_environment for item in ("--env", value)],
        "--entrypoint",
        executable,
        image_digest,
        *arguments,
    ]


def _parse_os_release(text: str) -> str:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    distro = values.get("ID", "")
    version = values.get("VERSION_ID", "")
    if not re.fullmatch(r"[a-z0-9._-]{1,40}", distro) or not re.fullmatch(
        r"[A-Za-z0-9._-]{1,40}", version
    ):
        raise IntegrityError("image /etc/os-release is incomplete or unsafe")
    return f"{distro}-{version}"


def _attestation_payload(attestation: ImageAttestation) -> dict[str, str]:
    payload = {
        "target_name": attestation.target_name,
        "contract_sha256": attestation.contract_sha256,
        "image_reference": attestation.image_reference,
        "image_digest": attestation.image_digest,
        "image_id": attestation.image_id,
        "base_image_digest": attestation.base_image_digest,
        "recipe_sha256": attestation.recipe_sha256,
        "target_version": attestation.target_version,
        "package_integrity": attestation.package_integrity,
        "node_version": attestation.node_version,
        "os": attestation.os,
        "arch": attestation.arch,
        "image_family": attestation.image_family,
    }
    if attestation.platform_package_integrity is not None:
        payload["platform_package_integrity"] = (
            attestation.platform_package_integrity
        )
    if attestation.wrapper_sha256 is not None:
        payload["wrapper_sha256"] = attestation.wrapper_sha256
    if attestation.platform_binary_sha256 is not None:
        payload["platform_binary_sha256"] = attestation.platform_binary_sha256
    return payload


def verify_image_attestation(
    contract: Contract, target_name: str, attestation: ImageAttestation
) -> None:
    target = target_for(contract, target_name)
    expected = {
        "target_name": target_name,
        "contract_sha256": contract.raw_sha256,
        "image_reference": target.image_tag,
        "target_version": target.version,
        "package_integrity": target.npm_integrity,
        "os": target.os,
        "arch": target.arch,
        "image_family": target.image_family,
    }
    if target.platform_npm_integrity is not None:
        expected["platform_package_integrity"] = target.platform_npm_integrity
        expected["wrapper_sha256"] = target.wrapper_sha256
        expected["platform_binary_sha256"] = target.platform_binary_sha256
    elif attestation.platform_package_integrity is not None:
        raise IntegrityError(
            "image attestation has an unexpected platform package integrity"
        )
    elif (
        attestation.wrapper_sha256 is not None
        or attestation.platform_binary_sha256 is not None
    ):
        raise IntegrityError("image attestation has unexpected execution-path hashes")
    payload = _attestation_payload(attestation)
    mismatched = sorted(key for key, value in expected.items() if payload.get(key) != value)
    if mismatched:
        raise IntegrityError(
            "image attestation conflicts with contract: " + ", ".join(mismatched)
        )
    if not _IMAGE_DIGEST_RE.fullmatch(attestation.image_digest):
        raise IntegrityError("image attestation digest is malformed")
    if not _IMAGE_DIGEST_RE.fullmatch(attestation.image_id):
        raise IntegrityError("image attestation ID is malformed")
    if not _IMAGE_DIGEST_RE.fullmatch(attestation.base_image_digest):
        raise IntegrityError("image attestation base digest is malformed")
    if not _SHA256_RE.fullmatch(attestation.recipe_sha256):
        raise IntegrityError("image attestation recipe digest is malformed")
    actual_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    if actual_sha256 != attestation.attestation_sha256:
        raise IntegrityError("image attestation SHA-256 mismatch")
    node_match = _NODE_VERSION_RE.fullmatch(attestation.node_version)
    if not node_match:
        raise IntegrityError("image attestation Node version is malformed")
    expected_node = target.node_version.removeprefix("v")
    if "." in expected_node:
        if attestation.node_version.removeprefix("v") != expected_node:
            raise IntegrityError("image attestation Node version mismatch")
    elif node_match.group(1) != expected_node:
        raise IntegrityError("image attestation Node major mismatch")


def attest_image(
    contract: Contract,
    target_name: str,
    plan: ImageBuildPlan,
    *,
    runner=bounded_run,
) -> ImageAttestation:
    target = target_for(contract, target_name)
    if plan.target_name != target_name or plan.image_tag != target.image_tag:
        raise IntegrityError("image build plan targets the wrong arm")
    if plan != render_image_build_plan(
        contract, target_name, base_image_digest=plan.base_image_digest
    ):
        raise IntegrityError("image build plan is not the canonical trusted recipe")
    inspect = runner(
        ["docker", "image", "inspect", target.image_tag],
        timeout=20,
        max_output_bytes=256 * 1024,
    )
    if inspect.returncode != 0:
        raise IntegrityError("cannot inspect target image")
    try:
        records = json.loads(inspect.stdout)
    except json.JSONDecodeError as exc:
        raise IntegrityError("Docker image inspection returned invalid JSON") from exc
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise IntegrityError("Docker image inspection must return exactly one object")
    record = records[0]
    image_id = record.get("Id")
    if not isinstance(image_id, str) or not _IMAGE_DIGEST_RE.fullmatch(image_id):
        raise IntegrityError("Docker image inspection has no immutable image ID")
    if record.get("Os") != "linux" or record.get("Architecture") != target.arch:
        raise IntegrityError("Docker image platform does not match the contract")
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
    ):
        raise IntegrityError("Docker image has no string label map")
    expected_labels = {
        _label("base_image_digest"): plan.base_image_digest,
        _label("recipe_sha256"): plan.recipe_sha256,
        _label("target_version"): target.version,
        _label("package_integrity"): target.npm_integrity,
        _label("node_version"): target.node_version,
        _label("os"): target.os,
        _label("arch"): target.arch,
        _label("image_family"): target.image_family,
        _label("contract_sha256"): contract.raw_sha256,
    }
    if target.platform_npm_integrity is not None:
        expected_labels[_label("platform_package_integrity")] = (
            target.platform_npm_integrity
        )
        expected_labels[_label("wrapper_sha256")] = str(target.wrapper_sha256)
        expected_labels[_label("platform_binary_sha256")] = str(
            target.platform_binary_sha256
        )
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise IntegrityError("Docker image labels do not match the trusted build plan")

    executable = str(contract.probe["version_argv"][0])
    version_arguments = tuple(
        str(item) for item in contract.probe["version_argv"][1:]
    )
    codex_environment = (
        ("CODEX_HOME=/tmp/codex-home",)
        if contract.probe_kind == "codex_trust_enter_39487"
        else ()
    )
    version_probe = runner(
        _secure_probe_argv(
            image_id,
            executable,
            *version_arguments,
            extra_environment=codex_environment,
        ),
        timeout=15,
        max_output_bytes=64 * 1024,
    )
    version_text = (version_probe.stdout + "\n" + version_probe.stderr).strip()
    if version_probe.returncode != 0 or not re.search(
        rf"(?<![0-9]){re.escape(target.version)}(?![0-9])", version_text
    ):
        raise IntegrityError("image CLI version does not match the target")
    if contract.probe_kind == "codex_trust_enter_39487":
        origin_script = (
            'const fs=require("fs"),c=require("crypto"),top="/usr/local/lib/node_modules/@openai/'
            'codex/bin/codex.js",root="/usr/local/lib/node_modules/@openai/'
            'codex",alias="/usr/local/lib/node_modules/@openai/codex-linux-arm64/'
            'package.json",bin="/usr/local/lib/node_modules/@openai/'
            'codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex";'
            'const [expectedTop,expectedBin]=process.argv.slice(1);'
            'const resolved=require.resolve("@openai/codex-linux-arm64/package.json",'
            '{paths:[root]});const st=fs.statSync(bin),hash=p=>c.createHash("sha256").update(fs.readFileSync(p)).digest("hex"),topHash=hash(top),binHash=hash(bin);if(fs.realpathSync("/usr/local/'
            'bin/codex")!==top||fs.realpathSync(resolved)!==alias||!st.isFile()||'
            '(st.mode&0o111)===0||topHash!==expectedTop||binHash!==expectedBin)process.exit(77);process.stdout.write(JSON.stringify({wrapper_sha256:topHash,platform_binary_sha256:binHash})+"\\n")'
        )
        origin_probe = runner(
            _secure_probe_argv(
                image_id,
                "node",
                "-e",
                origin_script,
                str(target.wrapper_sha256),
                str(target.platform_binary_sha256),
            ),
            timeout=15,
            max_output_bytes=64 * 1024,
        )
        try:
            origin_value = json.loads(origin_probe.stdout)
        except json.JSONDecodeError as exc:
            raise IntegrityError("image Codex platform origin probe failed") from exc
        if origin_probe.returncode != 0 or origin_value != {
            "wrapper_sha256": target.wrapper_sha256,
            "platform_binary_sha256": target.platform_binary_sha256,
        }:
            raise IntegrityError("image Codex platform origin probe failed")
        native_version_probe = runner(
            _secure_probe_argv(image_id, _CODEX_NATIVE_PATH, "--version"),
            timeout=15,
            max_output_bytes=64 * 1024,
        )
        native_version_text = (
            native_version_probe.stdout + "\n" + native_version_probe.stderr
        ).strip()
        if native_version_probe.returncode != 0 or not re.search(
            rf"(?<![0-9]){re.escape(target.version)}(?![0-9])",
            native_version_text,
        ):
            raise IntegrityError("image native Codex version does not match the target")
    node_probe = runner(
        _secure_probe_argv(image_id, "node", "--version"),
        timeout=15,
        max_output_bytes=64 * 1024,
    )
    node_version = node_probe.stdout.strip()
    node_match = _NODE_VERSION_RE.fullmatch(node_version)
    if node_probe.returncode != 0 or not node_match:
        raise IntegrityError("image Node version probe failed")
    expected_node = target.node_version.removeprefix("v")
    if (
        ("." in expected_node and node_version.removeprefix("v") != expected_node)
        or ("." not in expected_node and node_match.group(1) != expected_node)
    ):
        raise IntegrityError("image Node version does not match the target")
    os_probe = runner(
        _secure_probe_argv(image_id, "cat", "/etc/os-release"),
        timeout=15,
        max_output_bytes=64 * 1024,
    )
    if os_probe.returncode != 0:
        raise IntegrityError("image OS release probe failed")
    os_release = _parse_os_release(os_probe.stdout)
    if os_release != target.os:
        raise IntegrityError("image OS release does not match the target")

    provisional = ImageAttestation(
        target_name=target_name,
        contract_sha256=contract.raw_sha256,
        image_reference=target.image_tag,
        image_digest=image_id,
        image_id=image_id,
        base_image_digest=plan.base_image_digest,
        recipe_sha256=plan.recipe_sha256,
        target_version=target.version,
        package_integrity=target.npm_integrity,
        node_version=node_version,
        os=os_release,
        arch=str(record["Architecture"]),
        image_family=target.image_family,
        attestation_sha256="",
        platform_package_integrity=target.platform_npm_integrity,
        wrapper_sha256=target.wrapper_sha256,
        platform_binary_sha256=target.platform_binary_sha256,
    )
    attestation = ImageAttestation(
        **_attestation_payload(provisional),
        attestation_sha256=hashlib.sha256(
            canonical_json_bytes(_attestation_payload(provisional))
        ).hexdigest(),
    )
    verify_image_attestation(contract, target_name, attestation)
    return attestation
