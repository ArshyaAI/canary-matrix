"""Minimal fail-closed standalone runner for credential-free CLI contracts.

The target receives no host bind, Docker socket, credential, or network. A
trusted control plane stages inert fixture bytes into a bounded run-scoped
tmpfs volume, starts one exact digest-addressed target container, verifies the
workspace, and proves container/volume removal before Canary Core classifies
the observation.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable, Mapping, Sequence
import uuid

from .core import (
    AssertionObservation,
    CapabilityStatus,
    PairPolicy,
    PairResult,
    RunObservation,
    RunResult,
    SCHEMA_VERSION,
    canonical_items,
    canonical_json_bytes,
    classify_run,
    compare_pair,
    pair_result_to_dict,
    run_result_to_dict,
)
from .openbench_bridge import (
    Contract,
    ImageAttestation,
    IntegrityError,
    assert_public_safe,
    bounded_run,
    target_for,
    verify_image_attestation,
)


RUN_RECORD_SCHEMA_VERSION = "canary-standalone-run/v0.1"
PUBLIC_BUNDLE_SCHEMA_VERSION = "canary-standalone-public/v0.1"
EVIDENCE_BUNDLE_SCHEMA_VERSION = "canary-evidence-bundle/v0.1"
MAX_DOCKER_CONTROL_OUTPUT_BYTES = 1024 * 1024
MAX_TARGET_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TARGET_LINE_BYTES = 64 * 1024
MAX_PUBLIC_SAMPLE_BYTES = 16 * 1024
MAX_FIXTURE_ENVELOPE_BYTES = 64 * 1024
WORK_VOLUME_BYTES = 32 * 1024 * 1024

_RUN_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,80}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^(?:[^\s@]+@)?sha256:[0-9a-f]{64}$")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")

_STANDALONE_POLICY = {
    "cpus": "1",
    "memory": "768m",
    "memory_swap": "768m",
    "network": "none",
    "pids_limit": "128",
    "nofile": "1024:1024",
    "read_only_root": True,
    "cap_drop": "ALL",
    "no_new_privileges": True,
    "home": "tmpfs",
    "work_mount": "run_scoped_tmpfs_volume",
    "writable_host_bind": False,
    "docker_socket": False,
    "pull_policy": "never",
}
STANDALONE_POLICY_SHA256 = hashlib.sha256(
    canonical_json_bytes(_STANDALONE_POLICY)
).hexdigest()


_FIXTURE_STAGE_JS = r'''
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const raw = Buffer.from(process.env.CANARY_FIXTURE_B64 || "", "base64");
const envelope = JSON.parse(raw.toString("utf8"));
if (!envelope || !Array.isArray(envelope.files)) process.exit(61);
const component = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
for (const item of envelope.files) {
  if (!item || typeof item.path !== "string" || typeof item.content_base64 !== "string") process.exit(62);
  const parts = item.path.split("/");
  if (!parts.length || parts.some((part) => !component.test(part))) process.exit(63);
  const content = Buffer.from(item.content_base64, "base64");
  const digest = crypto.createHash("sha256").update(content).digest("hex");
  if (digest !== item.sha256 || content.length !== item.size) process.exit(64);
  const destination = path.join("/work", ...parts);
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o755});
  const fd = fs.openSync(destination, "wx", 0o444);
  try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.chmodSync(destination, 0o444);
}
process.stdout.write("CANARY_STAGE_OK\n");
'''.strip()


_FIXTURE_SCAN_JS = r'''
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const files = {};
function walk(root, prefix) {
  const entries = fs.readdirSync(root, {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const relative = prefix ? prefix + "/" + entry.name : entry.name;
    const absolute = path.join(root, entry.name);
    if (entry.isSymbolicLink()) process.exit(71);
    if (entry.isDirectory()) { walk(absolute, relative); continue; }
    if (!entry.isFile()) process.exit(72);
    const stat = fs.lstatSync(absolute);
    if (stat.nlink !== 1) process.exit(73);
    const content = fs.readFileSync(absolute);
    files[relative] = {sha256: crypto.createHash("sha256").update(content).digest("hex"), size: content.length};
  }
}
walk("/work", "");
const ordered = {};
for (const key of Object.keys(files).sort()) ordered[key] = files[key];
process.stdout.write(JSON.stringify({files: ordered}) + "\n");
'''.strip()

FIXTURE_BRIDGE_SHA256 = hashlib.sha256(
    (_FIXTURE_STAGE_JS + "\n---\n" + _FIXTURE_SCAN_JS).encode("utf-8")
).hexdigest()


CommandRunner = Callable[..., subprocess.CompletedProcess]


class StandaloneRunnerError(IntegrityError):
    """Stable internal runner failure; raw subprocess text is never public."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class StreamEvidence:
    total_bytes: int
    sha256: str
    sample: str
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "total_bytes": self.total_bytes,
            "sha256": self.sha256,
            "sample": self.sample,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class VerifiedStandaloneRun:
    target_name: str
    record_sha256: str
    record: Mapping[str, object]
    image_digest: str
    image_attestation_sha256: str
    run_result: RunResult
    public_evidence: tuple[tuple[str, str], ...]


def _call(
    runner: CommandRunner,
    argv: Sequence[str],
    *,
    timeout: float = 30,
    max_output_bytes: int = MAX_DOCKER_CONTROL_OUTPUT_BYTES,
    text: bool = True,
) -> subprocess.CompletedProcess:
    return runner(
        list(argv),
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        text=text,
    )


def _checked_text(
    runner: CommandRunner,
    argv: Sequence[str],
    *,
    code: str,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    result = _call(runner, argv, timeout=timeout)
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise StandaloneRunnerError(code)
    return result


def _pair_present(argv: Sequence[str], flag: str, value: str) -> bool:
    return any(
        argv[index] == flag and index + 1 < len(argv) and argv[index + 1] == value
        for index in range(len(argv))
    )


def validate_target_create_argv(
    argv: Sequence[str], contract: Contract, image_digest: str, volume_name: str
) -> tuple[str, ...]:
    """Verify the exact effective target policy before Docker receives it."""

    errors: list[str] = []
    if not argv or argv[:2] != ["docker", "create"]:
        return ("docker_prefix",)
    if not all(isinstance(item, str) and item and "\x00" not in item for item in argv):
        return ("docker_argv_invalid",)
    rendered = " ".join(argv)
    banned_exact = {
        "--privileged",
        "--device",
        "--cap-add",
        "--env-file",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--userns=host",
        "--cgroupns=host",
        "--network=host",
        "--volumes-from",
        "--publish",
        "--publish-all",
        "--expose",
        "-p",
        "-P",
    }
    banned_prefixes = (
        "--privileged=",
        "--device=",
        "--cap-add=",
        "--env-file=",
        "--pid=",
        "--ipc=",
        "--uts=",
        "--userns=",
        "--cgroupns=",
        "--network=",
        "--volumes-from=",
        "--volume=",
        "--publish=",
        "--expose=",
    )
    if any(item in banned_exact or item.startswith(banned_prefixes) for item in argv):
        errors.append("docker_escape_flag")
    if "docker.sock" in rendered:
        errors.append("docker_socket")
    if (
        "-v" in argv
        or "--volume" in argv
        or any(item.startswith("-v=") or item.startswith("--volume=") for item in argv)
        or "type=bind" in rendered
    ):
        errors.append("docker_host_bind")
    for flag, value, code in (
        ("--cpus", "1", "cpus"),
        ("--memory", "768m", "memory"),
        ("--memory-swap", "768m", "memory_swap"),
        ("--pids-limit", "128", "pids"),
        ("--ulimit", "nofile=1024:1024", "nofile"),
        ("--network", "none", "network"),
        ("--cap-drop", "ALL", "cap_drop"),
        ("--security-opt", "no-new-privileges", "security"),
        ("--pull", "never", "pull"),
        ("--env", "HOME=/tmp/home", "environment"),
        ("--entrypoint", str(contract.probe["argv"][0]), "entrypoint"),
    ):
        if not _pair_present(argv, flag, value):
            errors.append(f"docker_policy_{code}")
    for required in ("--read-only", "--init"):
        if required not in argv:
            errors.append("docker_policy_" + required.removeprefix("--").replace("-", "_"))
    tmpfs = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--tmpfs"]
    if tmpfs != ["/tmp:rw,noexec,nosuid,nodev,size=32m"]:
        errors.append("docker_policy_tmpfs")
    mounts = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--mount"]
    expected_mount = (
        f"type=volume,src={volume_name},dst=/work,volume-nocopy"
    )
    if mounts != [expected_mount]:
        errors.append("docker_work_volume")
    networks = [
        argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--network"
    ]
    if networks != ["none"]:
        errors.append("docker_network_surface")
    environments = [
        argv[index + 1]
        for index, item in enumerate(argv[:-1])
        if item in {"--env", "-e"}
    ]
    if environments != ["HOME=/tmp/home"]:
        errors.append("docker_environment_surface")
    security_options = [
        argv[index + 1]
        for index, item in enumerate(argv[:-1])
        if item == "--security-opt"
    ]
    if security_options != ["no-new-privileges"]:
        errors.append("docker_security_surface")
    expected_tail = [image_digest, *contract.probe["argv"][1:]]
    if list(argv[-len(expected_tail) :]) != expected_tail:
        errors.append("docker_stimulus")
    return tuple(sorted(set(errors)))


def build_target_create_argv(
    contract: Contract,
    target_name: str,
    attestation: ImageAttestation,
    *,
    run_id: str,
    container_name: str,
    volume_name: str,
) -> list[str]:
    verify_image_attestation(contract, target_name, attestation)
    if not _RUN_TOKEN_RE.fullmatch(run_id):
        raise IntegrityError("invalid standalone run identifier")
    if not _RUN_TOKEN_RE.fullmatch(container_name) or not _RUN_TOKEN_RE.fullmatch(volume_name):
        raise IntegrityError("invalid standalone resource name")
    argv = [
        "docker",
        "create",
        "--name",
        container_name,
        "--label",
        f"io.canary-matrix.run_id={run_id}",
        "--pull",
        "never",
        "--cpus",
        "1",
        "--memory",
        "768m",
        "--memory-swap",
        "768m",
        "--pids-limit",
        "128",
        "--ulimit",
        "nofile=1024:1024",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--init",
        "--stop-timeout",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "--mount",
        f"type=volume,src={volume_name},dst=/work,volume-nocopy",
        "--workdir",
        "/work",
        "--env",
        "HOME=/tmp/home",
        "--entrypoint",
        str(contract.probe["argv"][0]),
        attestation.image_digest,
        *contract.probe["argv"][1:],
    ]
    errors = validate_target_create_argv(
        argv, contract, attestation.image_digest, volume_name
    )
    if errors:
        raise IntegrityError("invalid target Docker policy: " + ",".join(errors))
    return argv


def _fixture_envelope(contract: Contract) -> tuple[str, dict[str, object]]:
    files = []
    expected: dict[str, object] = {"files": {}}
    for item in sorted(contract.fixture_files, key=lambda value: value.path):
        digest = hashlib.sha256(item.content).hexdigest()
        files.append(
            {
                "path": item.path,
                "content_base64": base64.b64encode(item.content).decode("ascii"),
                "sha256": digest,
                "size": len(item.content),
            }
        )
        expected["files"][item.path] = {"sha256": digest, "size": len(item.content)}
    payload = canonical_json_bytes({"files": files})
    encoded = base64.b64encode(payload).decode("ascii")
    if len(encoded) > MAX_FIXTURE_ENVELOPE_BYTES:
        raise IntegrityError("fixture envelope exceeds standalone budget")
    return encoded, expected


def _helper_argv(
    *,
    name: str,
    run_id: str,
    image_digest: str,
    volume_name: str,
    mode: str,
    fixture_b64: str | None = None,
) -> list[str]:
    if mode not in {"stage", "scan"}:
        raise IntegrityError("unknown fixture helper mode")
    mount = f"type=volume,src={volume_name},dst=/work,volume-nocopy"
    if mode == "scan":
        mount += ",readonly"
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        f"io.canary-matrix.run_id={run_id}",
        "--pull",
        "never",
        "--cpus",
        "0.5",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "32",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=8m",
        "--mount",
        mount,
        "--workdir",
        "/work",
    ]
    if mode == "stage":
        if fixture_b64 is None:
            raise IntegrityError("stage helper requires a fixture envelope")
        argv.extend(["--env", f"CANARY_FIXTURE_B64={fixture_b64}"])
    argv.extend(
        [
            "--entrypoint",
            "node",
            image_digest,
            "-e",
            _FIXTURE_STAGE_JS if mode == "stage" else _FIXTURE_SCAN_JS,
        ]
    )
    rendered = " ".join(argv)
    if (
        "type=bind" in rendered
        or "docker.sock" in rendered
        or "--privileged" in argv
        or not _pair_present(argv, "--network", "none")
        or "-v" in argv
    ):
        raise IntegrityError("fixture helper violates containment policy")
    return argv


def _keeper_argv(
    *,
    name: str,
    run_id: str,
    image_digest: str,
    volume_name: str,
) -> list[str]:
    """Keep the local-driver tmpfs mounted across sequential helper containers."""

    argv = [
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        f"io.canary-matrix.run_id={run_id}",
        "--pull",
        "never",
        "--cpus",
        "0.1",
        "--memory",
        "96m",
        "--memory-swap",
        "96m",
        "--pids-limit",
        "16",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--stop-timeout",
        "1",
        "--mount",
        f"type=volume,src={volume_name},dst=/work,volume-nocopy",
        "--entrypoint",
        "node",
        image_digest,
        "-e",
        "setInterval(() => {}, 2147483647)",
    ]
    rendered = " ".join(argv)
    if (
        "type=bind" in rendered
        or "docker.sock" in rendered
        or "--privileged" in argv
        or not _pair_present(argv, "--network", "none")
        or "-v" in argv
    ):
        raise IntegrityError("fixture keeper violates containment policy")
    return argv


def _parse_json_object(text: str, code: str) -> dict[str, object]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StandaloneRunnerError(code) from exc
    if not isinstance(value, dict):
        raise StandaloneRunnerError(code)
    return value


def _verify_volume_inspect(text: str, volume_name: str, run_id: str) -> None:
    try:
        records = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StandaloneRunnerError("volume_inspect_invalid") from exc
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise StandaloneRunnerError("volume_inspect_invalid")
    record = records[0]
    expected_options = {
        "type": "tmpfs",
        "device": "tmpfs",
        "o": f"size={WORK_VOLUME_BYTES},nosuid,nodev,noexec",
    }
    labels = record.get("Labels")
    if (
        record.get("Name") != volume_name
        or record.get("Driver") != "local"
        or record.get("Options") != expected_options
        or not isinstance(labels, dict)
        or labels.get("io.canary-matrix.run_id") != run_id
    ):
        raise StandaloneRunnerError("volume_policy_mismatch")


def _scan_workspace(
    runner: CommandRunner,
    *,
    name: str,
    run_id: str,
    image_digest: str,
    volume_name: str,
) -> dict[str, object]:
    result = _checked_text(
        runner,
        _helper_argv(
            name=name,
            run_id=run_id,
            image_digest=image_digest,
            volume_name=volume_name,
            mode="scan",
        ),
        code="workspace_scan_failed",
        timeout=20,
    )
    return _parse_json_object(result.stdout, "workspace_manifest_invalid")


def _stream_evidence(payload: bytes) -> StreamEvidence:
    head_size = MAX_PUBLIC_SAMPLE_BYTES // 2
    tail_size = MAX_PUBLIC_SAMPLE_BYTES - head_size
    truncated = len(payload) > MAX_PUBLIC_SAMPLE_BYTES
    sample_bytes = (
        payload
        if not truncated
        else payload[:head_size]
        + b"\n[... bounded sample omitted bytes ...]\n"
        + payload[-tail_size:]
    )
    return StreamEvidence(
        total_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        sample=sample_bytes.decode("utf-8", errors="replace"),
        truncated=truncated,
    )


def _has_oversized_line(payload: bytes) -> bool:
    current = 0
    for byte in payload:
        if byte == 10:
            current = 0
        else:
            current += 1
            if current > MAX_TARGET_LINE_BYTES:
                return True
    return False


def _normalize_hooks_diagnostic(
    stdout: bytes, stderr: bytes, *, exit_code: int | None, timed_out: bool
) -> str:
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace").lower()
    if timed_out:
        return "timeout"
    if (
        "gemini hooks <command>" in text
        or "manage gemini cli hooks" in text
        or ("commands:" in text and "hooks migrate" in text)
    ):
        return "hooks_help"
    if "unknown argument" in text or "usage: gemini" in text:
        return "hooks_command_absent"
    if exit_code == 0:
        return "other_success"
    return "other_error"


def _container_state(text: str) -> dict[str, object]:
    try:
        records = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StandaloneRunnerError("container_state_invalid") from exc
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise StandaloneRunnerError("container_state_invalid")
    state = records[0].get("State")
    if not isinstance(state, dict):
        raise StandaloneRunnerError("container_state_invalid")
    return state


def _cleanup_resources(
    runner: CommandRunner, *, container_names: Sequence[str], volume_name: str
) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name in container_names:
        try:
            _call(runner, ["docker", "rm", "--force", "--volumes", name], timeout=15)
            probe = _call(runner, ["docker", "container", "inspect", name], timeout=10)
            result[f"container:{name}"] = probe.returncode != 0
        except IntegrityError:
            result[f"container:{name}"] = False
    try:
        _call(runner, ["docker", "volume", "rm", "--force", volume_name], timeout=15)
        probe = _call(runner, ["docker", "volume", "inspect", volume_name], timeout=10)
        result[f"volume:{volume_name}"] = probe.returncode != 0
    except IntegrityError:
        result[f"volume:{volume_name}"] = False
    return result


def _stable_failure_code(exc: BaseException) -> str:
    if isinstance(exc, StandaloneRunnerError):
        return exc.code
    text = str(exc)
    if "wall deadline" in text:
        return "target_timeout"
    if "output budget" in text:
        return "output_budget_exceeded"
    return "control_plane_error"


def execute_target(
    contract: Contract,
    target_name: str,
    attestation: ImageAttestation,
    *,
    runner: CommandRunner = bounded_run,
    run_nonce: str | None = None,
) -> VerifiedStandaloneRun:
    """Execute one target arm and return a digest-bound classified record."""

    if contract.probe_kind != "gemini_hooks_command_16049":
        raise IntegrityError("standalone v0.1 only supports the hooks command probe")
    verify_image_attestation(contract, target_name, attestation)
    target = target_for(contract, target_name)
    nonce = run_nonce or uuid.uuid4().hex[:12]
    if not re.fullmatch(r"[a-z0-9]{8,20}", nonce):
        raise IntegrityError("invalid standalone run nonce")
    run_id = f"cm-{target_name}-{nonce}"
    container_name = f"cm-target-{target_name}-{nonce}"
    stage_name = f"cm-stage-{target_name}-{nonce}"
    before_name = f"cm-before-{target_name}-{nonce}"
    after_name = f"cm-after-{target_name}-{nonce}"
    keeper_name = f"cm-keeper-{target_name}-{nonce}"
    volume_name = f"cm-work-{target_name}-{nonce}"
    resource_names = (
        container_name,
        stage_name,
        before_name,
        after_name,
        keeper_name,
    )
    fixture_b64, expected_manifest = _fixture_envelope(contract)
    create_argv = build_target_create_argv(
        contract,
        target_name,
        attestation,
        run_id=run_id,
        container_name=container_name,
        volume_name=volume_name,
    )

    integrity_errors: list[str] = []
    stdout = b""
    stderr = b""
    exit_code: int | None = None
    signal_number: int | None = None
    timed_out = False
    oom_killed = False
    before_manifest: dict[str, object] | None = None
    after_manifest: dict[str, object] | None = None

    try:
        volume = _checked_text(
            runner,
            [
                "docker",
                "volume",
                "create",
                "--driver",
                "local",
                "--opt",
                "type=tmpfs",
                "--opt",
                "device=tmpfs",
                "--opt",
                f"o=size={WORK_VOLUME_BYTES},nosuid,nodev,noexec",
                "--label",
                f"io.canary-matrix.run_id={run_id}",
                volume_name,
            ],
            code="volume_create_failed",
        )
        if volume.stdout.strip() != volume_name:
            raise StandaloneRunnerError("volume_identity_mismatch")
        inspected_volume = _checked_text(
            runner,
            ["docker", "volume", "inspect", volume_name],
            code="volume_inspect_failed",
        )
        _verify_volume_inspect(inspected_volume.stdout, volume_name, run_id)

        keeper = _checked_text(
            runner,
            _keeper_argv(
                name=keeper_name,
                run_id=run_id,
                image_digest=attestation.image_digest,
                volume_name=volume_name,
            ),
            code="fixture_keeper_start_failed",
            timeout=20,
        )
        if not _CONTAINER_ID_RE.fullmatch(keeper.stdout.strip()):
            raise StandaloneRunnerError("fixture_keeper_id_invalid")
        keeper_inspect = _checked_text(
            runner,
            ["docker", "container", "inspect", keeper_name],
            code="fixture_keeper_state_unavailable",
        )
        if _container_state(keeper_inspect.stdout).get("Running") is not True:
            raise StandaloneRunnerError("fixture_keeper_not_running")

        staged = _checked_text(
            runner,
            _helper_argv(
                name=stage_name,
                run_id=run_id,
                image_digest=attestation.image_digest,
                volume_name=volume_name,
                mode="stage",
                fixture_b64=fixture_b64,
            ),
            code="fixture_stage_failed",
            timeout=20,
        )
        if staged.stdout != "CANARY_STAGE_OK\n":
            raise StandaloneRunnerError("fixture_stage_evidence_missing")
        before_manifest = _scan_workspace(
            runner,
            name=before_name,
            run_id=run_id,
            image_digest=attestation.image_digest,
            volume_name=volume_name,
        )
        if before_manifest != expected_manifest:
            raise StandaloneRunnerError("fixture_stage_mismatch")

        created = _checked_text(
            runner, create_argv, code="target_create_failed", timeout=30
        )
        if not _CONTAINER_ID_RE.fullmatch(created.stdout.strip()):
            raise StandaloneRunnerError("target_container_id_invalid")
        try:
            started = _call(
                runner,
                ["docker", "start", "--attach", container_name],
                timeout=contract.timeout_s + 5,
                max_output_bytes=MAX_TARGET_OUTPUT_BYTES,
                text=False,
            )
            if not isinstance(started.stdout, bytes) or not isinstance(started.stderr, bytes):
                raise StandaloneRunnerError("target_stream_type_invalid")
            stdout = started.stdout
            stderr = started.stderr
            if _has_oversized_line(stdout) or _has_oversized_line(stderr):
                integrity_errors.append("output_line_limit_exceeded")
        except IntegrityError as exc:
            code = _stable_failure_code(exc)
            if code == "target_timeout":
                timed_out = True
            else:
                integrity_errors.append(code)

        if not timed_out:
            inspected = _checked_text(
                runner,
                ["docker", "container", "inspect", container_name],
                code="container_state_unavailable",
            )
            state = _container_state(inspected.stdout)
            if state.get("Running") is not False:
                integrity_errors.append("container_not_stopped")
            raw_exit = state.get("ExitCode")
            if isinstance(raw_exit, int) and not isinstance(raw_exit, bool):
                exit_code = raw_exit
            else:
                integrity_errors.append("target_exit_unavailable")
            oom_killed = state.get("OOMKilled") is True
            if oom_killed:
                integrity_errors.append("target_oom")
            if isinstance(state.get("Error"), str) and state["Error"]:
                integrity_errors.append("container_runtime_error")
            after_manifest = _scan_workspace(
                runner,
                name=after_name,
                run_id=run_id,
                image_digest=attestation.image_digest,
                volume_name=volume_name,
            )
            if after_manifest != before_manifest:
                integrity_errors.append("workspace_changed")
        else:
            integrity_errors.append("workspace_postcheck_missing")
    except (IntegrityError, OSError, ValueError) as exc:
        integrity_errors.append(_stable_failure_code(exc))
    finally:
        cleanup = _cleanup_resources(
            runner, container_names=resource_names, volume_name=volume_name
        )
        failed_cleanup = sorted(name for name, verified in cleanup.items() if not verified)
        integrity_errors.extend(f"cleanup_failed:{name}" for name in failed_cleanup)

    stdout_evidence = _stream_evidence(stdout)
    stderr_evidence = _stream_evidence(stderr)
    diagnostic = _normalize_hooks_diagnostic(
        stdout, stderr, exit_code=exit_code, timed_out=timed_out
    )
    accepted = set(contract.probe["accepted_diagnostics"])
    evidence_complete = diagnostic in accepted
    capability = (
        CapabilityStatus.UNSUPPORTED
        if diagnostic == "hooks_command_absent"
        else CapabilityStatus.SUPPORTED
        if diagnostic == "hooks_help"
        else CapabilityStatus.UNKNOWN
    )
    assertions = tuple(
        AssertionObservation(
            assertion_id=item.assertion_id,
            required=item.required,
            supported=capability is CapabilityStatus.SUPPORTED,
            passed=True if diagnostic == "hooks_help" else None,
            evidence_complete=evidence_complete,
            oracle_valid=evidence_complete,
        )
        for item in contract.assertions
    )
    controls = canonical_items(
        {
            "target.version": attestation.target_version,
            "image.digest": attestation.image_digest,
            "image.base_digest": attestation.base_image_digest,
            "image.family": attestation.image_family,
            "image.recipe_sha256": attestation.recipe_sha256,
            "package.integrity": attestation.package_integrity,
            "runtime.node": attestation.node_version,
            "os": attestation.os,
            "arch": attestation.arch,
            "credential.mode": contract.credential_mode,
            "execution.policy": STANDALONE_POLICY_SHA256,
        }
    )
    normalized = canonical_items(
        {
            "diagnostic": diagnostic,
            "exit_code": "none" if exit_code is None else exit_code,
            "signal": "none" if signal_number is None else signal_number,
            "timed_out": str(timed_out).lower(),
        }
    )
    observation = RunObservation(
        schema_version=SCHEMA_VERSION,
        run_id=run_id,
        contract_digest=contract.raw_sha256,
        execution_lane=contract.execution_lane,
        target_identity=f"gemini-cli@{target.version}",
        controls=controls,
        normalized_observations=normalized,
        assertions=assertions,
        integrity_errors=tuple(sorted(set(integrity_errors))),
        capability_status=capability,
        capability_probe_deterministic=True,
        evidence_complete=evidence_complete,
        evidence_contradictory=False,
        nondeterminism_within_policy=True,
        oracle_valid=evidence_complete,
    )
    result = classify_run(observation)
    record = {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "run_id": run_id,
        "contract_sha256": contract.raw_sha256,
        "target_name": target_name,
        "target": {
            "version": target.version,
            "image_digest": attestation.image_digest,
            "image_attestation_sha256": attestation.attestation_sha256,
            "package_integrity": attestation.package_integrity,
            "node_version": attestation.node_version,
        },
        "runner": {
            "kind": "standalone",
            "policy_sha256": STANDALONE_POLICY_SHA256,
            "fixture_bridge_sha256": FIXTURE_BRIDGE_SHA256,
        },
        "stimulus": {"argv": list(contract.probe["argv"])},
        "outcome": {
            "exit_code": exit_code,
            "signal": signal_number,
            "timed_out": timed_out,
            "oom_killed": oom_killed,
            "diagnostic": diagnostic,
            "stdout": stdout_evidence.to_dict(),
            "stderr": stderr_evidence.to_dict(),
        },
        "workspace": {
            "before": before_manifest,
            "after": after_manifest,
            "expected": expected_manifest,
        },
        "cleanup": cleanup,
        "integrity_errors": sorted(set(integrity_errors)),
        "result": run_result_to_dict(result),
    }
    record_bytes = canonical_json_bytes(record)
    if len(record_bytes) > 4 * 1024 * 1024:
        raise IntegrityError("standalone protected record exceeds 4 MiB")
    record_sha256 = hashlib.sha256(record_bytes).hexdigest()
    public_values = {
        "target.version": attestation.target_version,
        "target.exit_code": "none" if exit_code is None else str(exit_code),
        "target.signal": "none" if signal_number is None else str(signal_number),
        "target.diagnostic": diagnostic,
        "image.digest": attestation.image_digest,
        "image.attestation_sha256": attestation.attestation_sha256,
        "package.integrity": attestation.package_integrity,
        "runtime.node": attestation.node_version,
        "export.sha256": record_sha256,
    }
    public_evidence = canonical_items(
        {key: public_values[key] for key in contract.evidence_allowlist}
    )
    return VerifiedStandaloneRun(
        target_name=target_name,
        record_sha256=record_sha256,
        record=record,
        image_digest=attestation.image_digest,
        image_attestation_sha256=attestation.attestation_sha256,
        run_result=result,
        public_evidence=public_evidence,
    )


def compare_standalone_runs(
    contract: Contract,
    baseline: VerifiedStandaloneRun,
    candidate: VerifiedStandaloneRun,
) -> PairResult:
    verify_standalone_run(contract, baseline, expected_target_name="baseline")
    verify_standalone_run(contract, candidate, expected_target_name="candidate")
    if baseline.target_name != "baseline" or candidate.target_name != "candidate":
        raise IntegrityError("standalone runs are not ordered baseline/candidate")
    return compare_pair(
        baseline.run_result,
        candidate.run_result,
        PairPolicy(
            matched_control_keys=contract.matched_controls,
            intended_changed_control_keys=contract.intended_changed_controls,
            deterministic_cli_oracle=True,
        ),
    )


def verify_standalone_run(
    contract: Contract,
    verified: VerifiedStandaloneRun,
    *,
    expected_target_name: str | None = None,
) -> None:
    """Recompute every derived binding before comparison, rendering, or writing."""

    if expected_target_name is not None and verified.target_name != expected_target_name:
        raise IntegrityError("standalone target arm mismatch")
    if not _SHA256_RE.fullmatch(verified.record_sha256):
        raise IntegrityError("standalone record digest is malformed")
    record = verified.record
    if record.get("schema_version") != RUN_RECORD_SCHEMA_VERSION:
        raise IntegrityError("standalone record schema mismatch")
    if record.get("target_name") != verified.target_name:
        raise IntegrityError("standalone record target mismatch")
    if record.get("contract_sha256") != contract.raw_sha256:
        raise IntegrityError("standalone record contract mismatch")
    payload = canonical_json_bytes(record)
    if hashlib.sha256(payload).hexdigest() != verified.record_sha256:
        raise IntegrityError("standalone record SHA-256 mismatch")
    target = record.get("target")
    outcome = record.get("outcome")
    if not isinstance(target, dict) or not isinstance(outcome, dict):
        raise IntegrityError("standalone record target/outcome is malformed")
    if target.get("image_digest") != verified.image_digest:
        raise IntegrityError("standalone image digest binding mismatch")
    if target.get("image_attestation_sha256") != verified.image_attestation_sha256:
        raise IntegrityError("standalone attestation binding mismatch")
    if record.get("result") != run_result_to_dict(verified.run_result):
        raise IntegrityError("standalone record/result mismatch")
    public_values = {
        "target.version": str(target.get("version")),
        "target.exit_code": (
            "none" if outcome.get("exit_code") is None else str(outcome.get("exit_code"))
        ),
        "target.signal": (
            "none" if outcome.get("signal") is None else str(outcome.get("signal"))
        ),
        "target.diagnostic": str(outcome.get("diagnostic")),
        "image.digest": str(target.get("image_digest")),
        "image.attestation_sha256": str(target.get("image_attestation_sha256")),
        "package.integrity": str(target.get("package_integrity")),
        "runtime.node": str(target.get("node_version")),
        "export.sha256": verified.record_sha256,
    }
    expected_public = canonical_items(
        {key: public_values[key] for key in contract.evidence_allowlist}
    )
    if verified.public_evidence != expected_public:
        raise IntegrityError("standalone public evidence binding mismatch")


def render_public_bundle(
    contract: Contract,
    baseline: VerifiedStandaloneRun,
    candidate: VerifiedStandaloneRun,
    pair: PairResult,
) -> tuple[bytes, bytes]:
    verify_standalone_run(contract, baseline, expected_target_name="baseline")
    verify_standalone_run(contract, candidate, expected_target_name="candidate")
    payload = {
        "schema_version": PUBLIC_BUNDLE_SCHEMA_VERSION,
        "contract": {
            "id": contract.contract_id,
            "title": contract.title,
            "digest": contract.raw_sha256,
            "capture_date": contract.capture_date,
            "fix_state": contract.fix_state,
            "source_urls": list(contract.source_urls),
            "source_verified": contract.source_verified,
        },
        "runner": {
            "kind": "standalone",
            "policy_sha256": STANDALONE_POLICY_SHA256,
            "fixture_bridge_sha256": FIXTURE_BRIDGE_SHA256,
        },
        "runs": {
            "baseline": {
                "record_sha256": baseline.record_sha256,
                "result": run_result_to_dict(baseline.run_result),
                "evidence": dict(baseline.public_evidence),
            },
            "candidate": {
                "record_sha256": candidate.record_sha256,
                "result": run_result_to_dict(candidate.run_result),
                "evidence": dict(candidate.public_evidence),
            },
        },
        "pair": pair_result_to_dict(pair),
    }
    json_bytes = canonical_json_bytes(payload)
    lines = [
        f"# {contract.title}",
        "",
        f"Contract: `{contract.contract_id}` (`{contract.raw_sha256}`)",
        f"Runner: `standalone` (`{STANDALONE_POLICY_SHA256}`)",
        f"Execution lane: `{contract.execution_lane.value}`",
        "",
        "| Arm | Target | State | Diagnostic | Exit | Image |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for verified in (baseline, candidate):
        evidence = dict(verified.public_evidence)
        lines.append(
            "| {arm} | {target} | {state} | {diagnostic} | {exit_code} | `{image}` |".format(
                arm=verified.target_name,
                target=evidence.get("target.version", "unknown"),
                state=verified.run_result.state.value,
                diagnostic=evidence.get("target.diagnostic", "unknown"),
                exit_code=evidence.get("target.exit_code", "unknown"),
                image=verified.image_digest,
            )
        )
    lines.extend(
        [
            "",
            f"Pair: **{pair.state.value}** (`{pair.reason_code.value}`; "
            f"claim tier `{pair.claim_tier.value}`).",
            "",
            "Sources:",
            *[f"- {url}" for url in contract.source_urls],
            "",
            "Raw output samples, credentials, host paths, and unallowlisted fields "
            "are intentionally excluded.",
            "",
        ]
    )
    markdown_bytes = "\n".join(lines).encode("utf-8")
    assert_public_safe(json_bytes, contract)
    assert_public_safe(markdown_bytes, contract)
    return json_bytes, markdown_bytes


def write_immutable_record(
    verified: VerifiedStandaloneRun, destination: str | os.PathLike[str]
) -> None:
    # The contract binding is verified by execute_target and every public sink;
    # this local writer still rechecks the immutable record digest before IO.
    if hashlib.sha256(canonical_json_bytes(verified.record)).hexdigest() != verified.record_sha256:
        raise IntegrityError("immutable record digest mismatch before write")
    path = os.fspath(destination)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    payload = canonical_json_bytes(verified.record)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    if hashlib.sha256(payload).hexdigest() != verified.record_sha256:
        raise IntegrityError("immutable record digest mismatch after write")


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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


def write_evidence_bundle(
    contract: Contract,
    baseline_attestation: ImageAttestation,
    candidate_attestation: ImageAttestation,
    baseline: VerifiedStandaloneRun,
    candidate: VerifiedStandaloneRun,
    pair: PairResult,
    destination: str | os.PathLike[str],
) -> Path:
    """Write protected evidence and an allowlisted public view atomically by file."""

    verify_image_attestation(contract, "baseline", baseline_attestation)
    verify_image_attestation(contract, "candidate", candidate_attestation)
    verify_standalone_run(contract, baseline, expected_target_name="baseline")
    verify_standalone_run(contract, candidate, expected_target_name="candidate")
    expected_pair = compare_standalone_runs(contract, baseline, candidate)
    if pair != expected_pair:
        raise IntegrityError("evidence bundle pair result mismatch")
    root = Path(destination)
    if root.exists():
        raise IntegrityError("evidence bundle destination must be absent")
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    protected = root / "protected"
    public = root / "public"
    protected.mkdir(mode=0o700)
    public.mkdir(mode=0o700)

    baseline_record = canonical_json_bytes(baseline.record)
    candidate_record = canonical_json_bytes(candidate.record)
    attestations = canonical_json_bytes(
        {
            "baseline": asdict(baseline_attestation),
            "candidate": asdict(candidate_attestation),
        }
    )
    public_json, public_markdown = render_public_bundle(
        contract, baseline, candidate, pair
    )
    file_payloads = {
        "protected/baseline-record.json": baseline_record,
        "protected/candidate-record.json": candidate_record,
        "protected/image-attestations.json": attestations,
        "public/result.json": public_json,
        "public/README.md": public_markdown,
    }
    for relative, payload in file_payloads.items():
        mode = 0o600 if relative.startswith("protected/") else 0o444
        _write_exclusive(root / relative, payload, mode)
    manifest = {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "contract_id": contract.contract_id,
        "contract_sha256": contract.raw_sha256,
        "pair": pair_result_to_dict(pair),
        "files": {
            relative: hashlib.sha256(payload).hexdigest()
            for relative, payload in sorted(file_payloads.items())
        },
    }
    _write_exclusive(root / "manifest.json", canonical_json_bytes(manifest), 0o600)
    for relative, expected in manifest["files"].items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
            raise IntegrityError("evidence bundle file digest mismatch: " + relative)
    return root
