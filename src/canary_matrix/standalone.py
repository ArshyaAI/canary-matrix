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
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time
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
from .contract import Contract, IntegrityError, assert_public_safe, target_for
from .images import ImageAttestation, bounded_run, verify_image_attestation


RUN_RECORD_SCHEMA_VERSION = "canary-standalone-run/v0.1"
PUBLIC_BUNDLE_SCHEMA_VERSION = "canary-standalone-public/v0.1"
EVIDENCE_BUNDLE_SCHEMA_VERSION = "canary-evidence-bundle/v0.1"
MAX_DOCKER_CONTROL_OUTPUT_BYTES = 1024 * 1024
MAX_TARGET_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TARGET_LINE_BYTES = 64 * 1024
MAX_PUBLIC_SAMPLE_BYTES = 16 * 1024
MAX_FIXTURE_ENVELOPE_BYTES = 64 * 1024
WORK_VOLUME_BYTES = 32 * 1024 * 1024
TERMINAL_NORMALIZER_VERSION = "canary-vt80x30/v1"
MAX_PTY_MARKER_SCAN_BYTES = 512 * 1024
MAX_PTY_MARKER_CANDIDATES = 128

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

_PTY_POLICY = {
    **_STANDALONE_POLICY,
    "transport": "pty",
    "terminal_columns": 80,
    "terminal_rows": 30,
    "clean_home": "/tmp",
    "codex_home_override": False,
    "marker_trigger": "first_proven_visible_rendered_marker",
    "input_delay_ms": 0,
    "input_bytes": "0d",
    "post_marker_window_ms": 1000,
    "output_budget_bytes": MAX_TARGET_OUTPUT_BYTES,
    "marker_scan_bytes": MAX_PTY_MARKER_SCAN_BYTES,
    "marker_candidate_limit": MAX_PTY_MARKER_CANDIDATES,
    "winsize_source": "host_pty_ioctl",
    "terminal_normalizer": TERMINAL_NORMALIZER_VERSION,
    "attach_process_group": True,
    "deliberate_post_observation_termination": True,
}
PTY_POLICY_SHA256 = hashlib.sha256(canonical_json_bytes(_PTY_POLICY)).hexdigest()


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
class PtyProbeResult:
    output: bytes
    marker_seen: bool
    marker_offset: int | None
    input_sent: bool
    input_delay_ms: int | None
    process_exited: bool
    deliberate_attach_termination: bool
    raw_marker_seen: bool = False
    marker_visibility_ambiguous: bool = False


PtyRunner = Callable[..., PtyProbeResult]


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


def _is_codex_pty(contract: Contract) -> bool:
    return contract.probe_kind == "codex_trust_enter_39487"


def _policy_sha256(contract: Contract) -> str:
    return PTY_POLICY_SHA256 if _is_codex_pty(contract) else STANDALONE_POLICY_SHA256


def _runner_kind(contract: Contract) -> str:
    return "standalone_pty" if _is_codex_pty(contract) else "standalone"


def _runner_record(contract: Contract) -> dict[str, object]:
    return {
        "kind": _runner_kind(contract),
        "policy_sha256": _policy_sha256(contract),
        "fixture_bridge_sha256": FIXTURE_BRIDGE_SHA256,
        **(
            {"terminal_normalizer": TERMINAL_NORMALIZER_VERSION}
            if _is_codex_pty(contract)
            else {}
        ),
    }


def _stimulus_record(contract: Contract) -> dict[str, object]:
    return {
        "argv": list(contract.probe["argv"]),
        **(
            {
                "terminal": {
                    "columns": contract.probe["terminal_columns"],
                    "rows": contract.probe["terminal_rows"],
                },
                "marker_sha256": hashlib.sha256(
                    contract.probe["marker"]
                ).hexdigest(),
                "input_sha256": hashlib.sha256(
                    contract.probe["input"]
                ).hexdigest(),
                "input_delay_ms": contract.probe["input_delay_ms"],
                "post_marker_window_ms": contract.probe["post_marker_window_ms"],
            }
            if _is_codex_pty(contract)
            else {}
        ),
    }


def _canonical_target_create_argv(
    contract: Contract,
    *,
    image_digest: str,
    run_id: str,
    container_name: str,
    volume_name: str,
) -> list[str]:
    is_pty = _is_codex_pty(contract)
    return [
        "docker",
        "create",
        "--name",
        container_name,
        "--label",
        f"io.canary-matrix.run_id={run_id}",
        *(["--interactive", "--tty"] if is_pty else []),
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
        f"type=volume,src={volume_name},dst=/work,volume-nocopy"
        + (",readonly" if is_pty else ""),
        "--workdir",
        "/work",
        "--env",
        "HOME=/tmp",
        *(
            [
                "--env",
                "TERM=xterm-256color",
            ]
            if is_pty
            else []
        ),
        "--entrypoint",
        str(contract.probe["argv"][0]),
        image_digest,
        *contract.probe["argv"][1:],
    ]


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
    is_pty = _is_codex_pty(contract)
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
        (
            "--env",
            "HOME=/tmp",
            "environment",
        ),
        ("--entrypoint", str(contract.probe["argv"][0]), "entrypoint"),
    ):
        if not _pair_present(argv, flag, value):
            errors.append(f"docker_policy_{code}")
    for required in ("--read-only", "--init"):
        if required not in argv:
            errors.append("docker_policy_" + required.removeprefix("--").replace("-", "_"))
    for flag in ("--interactive", "--tty"):
        if is_pty and flag not in argv:
            errors.append("docker_policy_" + flag.removeprefix("--"))
        if not is_pty and flag in argv:
            errors.append("docker_unexpected_pty")
    tmpfs = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--tmpfs"]
    if tmpfs != ["/tmp:rw,noexec,nosuid,nodev,size=32m"]:
        errors.append("docker_policy_tmpfs")
    mounts = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--mount"]
    expected_mount = f"type=volume,src={volume_name},dst=/work,volume-nocopy"
    if is_pty:
        expected_mount += ",readonly"
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
    expected_environments = (
        [
            "HOME=/tmp",
            "TERM=xterm-256color",
        ]
        if is_pty
        else ["HOME=/tmp"]
    )
    if environments != expected_environments:
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
    if (
        len(argv) < 6
        or argv[2] != "--name"
        or argv[4] != "--label"
        or not _RUN_TOKEN_RE.fullmatch(argv[3])
        or not argv[5].startswith("io.canary-matrix.run_id=")
    ):
        errors.append("docker_argv_not_canonical")
    else:
        run_id = argv[5].split("=", 1)[1]
        if not _RUN_TOKEN_RE.fullmatch(run_id) or list(argv) != (
            _canonical_target_create_argv(
                contract,
                image_digest=image_digest,
                run_id=run_id,
                container_name=argv[3],
                volume_name=volume_name,
            )
        ):
            errors.append("docker_argv_not_canonical")
    return tuple(sorted(set(errors)))


def build_target_start_argv(contract: Contract, container_name: str) -> list[str]:
    """Return the one trusted Docker start form for the contract transport."""

    if not _RUN_TOKEN_RE.fullmatch(container_name):
        raise IntegrityError("invalid standalone target container name")
    argv = ["docker", "start", "--attach"]
    if _is_codex_pty(contract):
        argv.append("--interactive")
    argv.append(container_name)
    errors = validate_target_start_argv(argv, contract, container_name)
    if errors:
        raise IntegrityError("invalid target start policy: " + ",".join(errors))
    return argv


def validate_target_start_argv(
    argv: Sequence[str], contract: Contract, container_name: str
) -> tuple[str, ...]:
    expected = ["docker", "start", "--attach"]
    if _is_codex_pty(contract):
        expected.append("--interactive")
    expected.append(container_name)
    if list(argv) != expected:
        return ("docker_start_stimulus",)
    if not _RUN_TOKEN_RE.fullmatch(container_name):
        return ("docker_start_container",)
    return ()


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
    argv = _canonical_target_create_argv(
        contract,
        image_digest=attestation.image_digest,
        run_id=run_id,
        container_name=container_name,
        volume_name=volume_name,
    )
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


def _terminate_pty_process_group(process: subprocess.Popen[bytes]) -> None:
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
        raise IntegrityError("PTY control-plane process resisted SIGKILL") from exc


class _TerminalMarkerPrefilter:
    """Find plausible visible marker completions in one bounded VT byte pass.

    Printable bytes participate in a KMP match. SGR may be interleaved without
    breaking the match. OSC/DCS/APC/PM payload is ignored across feed calls,
    while cursor-affecting and unknown controls reset the visible-text match.
    Every returned boundary is still verified by the full terminal normalizer.
    """

    def __init__(self, marker: bytes):
        self.marker = marker
        self.failure = self._failure_table(marker)
        self.match_size = 0
        self.offset = 0
        self.state = "normal"
        self.string_state: str | None = None
        self.csi_bytes = 0
        self.candidate_count = 0

    @staticmethod
    def _failure_table(pattern: bytes) -> tuple[int, ...]:
        failure = [0] * len(pattern)
        matched = 0
        for index in range(1, len(pattern)):
            while matched and pattern[index] != pattern[matched]:
                matched = failure[matched - 1]
            if pattern[index] == pattern[matched]:
                matched += 1
                failure[index] = matched
        return tuple(failure)

    def _reset_match(self) -> None:
        self.match_size = 0

    def _printable(self, byte: int) -> int | None:
        while self.match_size and byte != self.marker[self.match_size]:
            self.match_size = self.failure[self.match_size - 1]
        if byte == self.marker[self.match_size]:
            self.match_size += 1
        if self.match_size != len(self.marker):
            return None
        boundary = self.offset
        self.match_size = self.failure[self.match_size - 1]
        self.candidate_count += 1
        if self.candidate_count > MAX_PTY_MARKER_CANDIDATES:
            raise IntegrityError("PTY rendered-marker detection exceeded budget")
        return boundary

    def feed(self, chunk: bytes) -> tuple[int, ...]:
        boundaries: list[int] = []
        for byte in chunk:
            self.offset += 1
            if self.offset > MAX_PTY_MARKER_SCAN_BYTES:
                self._reset_match()
                continue

            if self.state == "osc":
                if self.string_state == "escape":
                    if byte == ord("\\"):
                        self.state = "normal"
                        self.string_state = None
                    else:
                        self.string_state = None
                    continue
                if byte == 0x07:
                    self.state = "normal"
                elif byte == 0x1B:
                    self.string_state = "escape"
                continue

            if self.state == "string":
                if self.string_state == "escape":
                    if byte == ord("\\"):
                        self.state = "normal"
                        self.string_state = None
                    else:
                        self.string_state = None
                    continue
                if byte == 0x1B:
                    self.string_state = "escape"
                continue

            if self.state == "escape":
                if byte == ord("["):
                    self.state = "csi"
                    self.csi_bytes = 0
                elif byte == ord("]"):
                    self.state = "osc"
                    self.string_state = None
                elif byte in {ord("P"), ord("_"), ord("^")}:
                    self.state = "string"
                    self.string_state = None
                elif byte in {
                    ord("("),
                    ord(")"),
                    ord("*"),
                    ord("+"),
                    ord("-"),
                    ord("."),
                    ord("/"),
                }:
                    self.state = "charset"
                    self._reset_match()
                else:
                    self.state = "normal"
                    self._reset_match()
                continue

            if self.state == "charset":
                self.state = "normal"
                self._reset_match()
                continue

            if self.state == "csi":
                self.csi_bytes += 1
                if 0x40 <= byte <= 0x7E:
                    self.state = "normal"
                    if byte != ord("m") or self.csi_bytes > 129:
                        self._reset_match()
                continue

            if byte == 0x1B:
                self.state = "escape"
                continue
            if 0x20 <= byte <= 0x7E:
                boundary = self._printable(byte)
                if boundary is not None:
                    boundaries.append(boundary)
            else:
                self._reset_match()
        return tuple(boundaries)


def run_target_pty(
    argv: Sequence[str],
    *,
    marker: bytes,
    input_bytes: bytes,
    input_delay_ms: int,
    post_marker_window_ms: int,
    columns: int,
    rows: int,
    timeout: float,
    max_output_bytes: int,
) -> PtyProbeResult:
    """Run one exact Docker attach argv through a bounded 80x30 host PTY."""

    if (
        list(argv[:4]) != ["docker", "start", "--attach", "--interactive"]
        or len(argv) != 5
        or not _RUN_TOKEN_RE.fullmatch(str(argv[-1]))
        or marker != b"Press enter to continue"
        or input_bytes != b"\r"
        or input_delay_ms != 0
        or post_marker_window_ms != 1000
        or (columns, rows) != (80, 30)
        or timeout <= 0
        or max_output_bytes <= 0
    ):
        raise IntegrityError("invalid trusted PTY probe policy")

    master_fd, slave_fd = pty.openpty()
    os.set_blocking(master_fd, False)
    process: subprocess.Popen[bytes] | None = None
    output = bytearray()
    marker_offset: int | None = None
    input_sent = False
    raw_marker_seen = False
    marker_visibility_ambiguous = False
    marker_prefilter = _TerminalMarkerPrefilter(marker)
    raw_marker_tail = b""
    deliberate_attach_termination = False
    process_exited = False
    try:
        fcntl.ioctl(
            slave_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, columns, 0, 0),
        )
        process = subprocess.Popen(
            list(argv),
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave_fd)
        slave_fd = -1
        overall_deadline = time.monotonic() + timeout
        observation_deadline: float | None = None
        eof = False

        def consume_output(chunk: bytes) -> None:
            nonlocal marker_offset
            nonlocal input_sent
            nonlocal raw_marker_seen
            nonlocal marker_visibility_ambiguous
            nonlocal observation_deadline
            nonlocal raw_marker_tail
            if not chunk:
                return
            output.extend(chunk)
            if len(output) > max_output_bytes:
                _terminate_pty_process_group(process)
                raise IntegrityError("PTY target exceeded output budget")

            raw_window = raw_marker_tail + chunk
            if marker in raw_window:
                raw_marker_seen = True
                marker_visibility_ambiguous = True
            raw_marker_tail = raw_window[-(len(marker) - 1) :]
            if marker_offset is not None:
                return

            # The marker is a visible-screen contract, not a raw-byte contract.
            # A single-pass VT-aware prefilter emits only plausible visible-text
            # completions, including SGR-interleaved text. Full normalization at
            # each bounded candidate proves visibility and ambiguity status.
            marker_text = marker.decode("ascii")
            try:
                boundaries = marker_prefilter.feed(chunk)
            except IntegrityError:
                _terminate_pty_process_group(process)
                raise
            if not boundaries:
                return
            payload = bytes(output)
            for boundary in boundaries:
                rendered = normalize_terminal_tail(
                    payload[:boundary], columns=columns, rows=rows
                )
                visible = marker_text in rendered.tail
                if rendered.ambiguity_codes:
                    if visible or marker in payload[:boundary]:
                        marker_visibility_ambiguous = True
                    continue
                if not visible:
                    if marker in payload[:boundary]:
                        marker_visibility_ambiguous = True
                    continue

                marker_offset = boundary
                marker_visibility_ambiguous = False
                try:
                    written = os.write(master_fd, input_bytes)
                except OSError as exc:
                    _terminate_pty_process_group(process)
                    raise IntegrityError(f"PTY target input failed: {exc}") from exc
                if written != len(input_bytes):
                    _terminate_pty_process_group(process)
                    raise IntegrityError("PTY target input was truncated")
                input_sent = True
                observation_deadline = min(
                    time.monotonic() + post_marker_window_ms / 1000,
                    overall_deadline,
                )
                break

        while True:
            now = time.monotonic()
            if observation_deadline is not None and now >= observation_deadline:
                # Include every byte already queued at the observation boundary,
                # then detach. Bytes caused by the later Docker kill are excluded.
                while select.select([master_fd], [], [], 0)[0]:
                    try:
                        chunk = os.read(master_fd, 64 * 1024)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                            break
                        raise IntegrityError(f"PTY target read failed: {exc}") from exc
                    if not chunk:
                        break
                    consume_output(chunk)
                if input_sent and time.monotonic() < observation_deadline:
                    continue
                if process.poll() is None:
                    deliberate_attach_termination = True
                    _terminate_pty_process_group(process)
                process_exited = process.poll() is not None
                break
            if now >= overall_deadline:
                if not input_sent and marker_visibility_ambiguous:
                    if process.poll() is None:
                        deliberate_attach_termination = True
                        _terminate_pty_process_group(process)
                    process_exited = process.poll() is not None
                    break
                _terminate_pty_process_group(process)
                raise IntegrityError("PTY target exceeded wall deadline")
            if process.poll() is not None and eof:
                process_exited = True
                break

            wake_deadline = min(
                overall_deadline,
                observation_deadline
                if observation_deadline is not None
                else overall_deadline,
            )
            wait_s = max(0.0, min(0.05, wake_deadline - now))
            readable, _, _ = select.select([master_fd], [], [], wait_s)
            if not readable:
                if process.poll() is not None:
                    # One final nonblocking read drains bytes queued before exit.
                    readable = [master_fd]
                else:
                    continue
            try:
                chunk = os.read(master_fd, 64 * 1024)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    eof = True
                    continue
                if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    continue
                raise IntegrityError(f"PTY target read failed: {exc}") from exc
            if not chunk:
                eof = True
                continue
            chunks = [chunk]
            while select.select([master_fd], [], [], 0)[0]:
                try:
                    queued = os.read(master_fd, 64 * 1024)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        eof = True
                        break
                    if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                        break
                    raise IntegrityError(f"PTY target read failed: {exc}") from exc
                if not queued:
                    eof = True
                    break
                chunks.append(queued)
            consume_output(b"".join(chunks))
        if process.poll() is None:
            _terminate_pty_process_group(process)
        process_exited = process.poll() is not None
        return PtyProbeResult(
            output=bytes(output),
            marker_seen=marker_offset is not None,
            marker_offset=marker_offset,
            input_sent=input_sent,
            input_delay_ms=0 if input_sent else None,
            process_exited=process_exited,
            deliberate_attach_termination=deliberate_attach_termination,
            raw_marker_seen=raw_marker_seen,
            marker_visibility_ambiguous=marker_visibility_ambiguous,
        )
    except OSError as exc:
        if process is not None and process.poll() is None:
            _terminate_pty_process_group(process)
        raise IntegrityError(f"cannot run PTY target: {exc}") from exc
    finally:
        if slave_fd >= 0:
            os.close(slave_fd)
        try:
            os.close(master_fd)
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class TerminalNormalization:
    tail: str
    ambiguity_codes: tuple[str, ...]


class _TerminalScreen:
    """Small deterministic VT screen for the fixed Codex 80x30 oracle."""

    def __init__(self, columns: int, rows: int):
        self.columns = columns
        self.rows = rows
        self.grid = [[" "] * columns for _ in range(rows)]
        self.x = 0
        self.y = 0
        self.saved = (0, 0)
        self.scroll_top = 0
        self.scroll_bottom = rows - 1
        self.autowrap = True
        self.wrap_pending = False
        self.normal_buffer: tuple[list[list[str]], int, int] | None = None
        self.ambiguities: set[str] = set()
        self.last_printed = " "

    def _blank_row(self) -> list[str]:
        return [" "] * self.columns

    def _clamp(self) -> None:
        self.x = max(0, min(self.columns - 1, self.x))
        self.y = max(0, min(self.rows - 1, self.y))

    def _scroll_up(self, count: int = 1) -> None:
        for _ in range(max(1, count)):
            del self.grid[self.scroll_top]
            self.grid.insert(self.scroll_bottom, self._blank_row())

    def _scroll_down(self, count: int = 1) -> None:
        for _ in range(max(1, count)):
            del self.grid[self.scroll_bottom]
            self.grid.insert(self.scroll_top, self._blank_row())

    def linefeed(self) -> None:
        self.wrap_pending = False
        if self.y == self.scroll_bottom:
            self._scroll_up()
        else:
            self.y = min(self.rows - 1, self.y + 1)

    def reverse_index(self) -> None:
        self.wrap_pending = False
        if self.y == self.scroll_top:
            self._scroll_down()
        else:
            self.y = max(0, self.y - 1)

    def put(self, char: str) -> None:
        import unicodedata

        if unicodedata.combining(char):
            previous_x = self.x - 1 if self.x > 0 else 0
            self.grid[self.y][previous_x] += char
            return
        if self.wrap_pending:
            if self.autowrap:
                self.x = 0
                self.linefeed()
            self.wrap_pending = False
        width = 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        self.grid[self.y][self.x] = char
        self.last_printed = char
        if width == 2 and self.x + 1 < self.columns:
            self.grid[self.y][self.x + 1] = " "
        if self.x + width >= self.columns:
            self.x = self.columns - 1
            self.wrap_pending = True
        else:
            self.x += width

    @staticmethod
    def _params(raw: str) -> list[int | None]:
        body = raw.lstrip("?<!=>")
        if not body:
            return [None]
        values: list[int | None] = []
        for part in body.split(";"):
            numeric = part.split(":", 1)[0]
            values.append(int(numeric) if numeric.isdigit() else None)
        return values

    @staticmethod
    def _value(values: list[int | None], index: int = 0, default: int = 1) -> int:
        if index >= len(values) or values[index] in {None, 0}:
            return default
        return int(values[index])

    def csi(self, raw: str, final: str) -> None:
        values = self._params(raw)
        amount = self._value(values)
        private = raw.startswith("?")
        self.wrap_pending = False
        if final in {"H", "f"}:
            self.y = self._value(values, 0) - 1
            self.x = self._value(values, 1) - 1
            self._clamp()
        elif final in {"A"}:
            self.y -= amount
            self._clamp()
        elif final in {"B", "e"}:
            self.y += amount
            self._clamp()
        elif final in {"C", "a"}:
            self.x += amount
            self._clamp()
        elif final == "D":
            self.x -= amount
            self._clamp()
        elif final == "E":
            self.y += amount
            self.x = 0
            self._clamp()
        elif final == "F":
            self.y -= amount
            self.x = 0
            self._clamp()
        elif final in {"G", "`"}:
            self.x = amount - 1
            self._clamp()
        elif final == "d":
            self.y = amount - 1
            self._clamp()
        elif final == "J":
            mode = 0 if values[0] is None else int(values[0])
            if mode in {2, 3}:
                self.grid = [self._blank_row() for _ in range(self.rows)]
            elif mode == 0:
                self.grid[self.y][self.x :] = [" "] * (self.columns - self.x)
                for row in range(self.y + 1, self.rows):
                    self.grid[row] = self._blank_row()
            elif mode == 1:
                for row in range(0, self.y):
                    self.grid[row] = self._blank_row()
                self.grid[self.y][: self.x + 1] = [" "] * (self.x + 1)
            else:
                self.ambiguities.add("unsupported_erase_display")
        elif final == "K":
            mode = 0 if values[0] is None else int(values[0])
            if mode == 0:
                self.grid[self.y][self.x :] = [" "] * (self.columns - self.x)
            elif mode == 1:
                self.grid[self.y][: self.x + 1] = [" "] * (self.x + 1)
            elif mode == 2:
                self.grid[self.y] = self._blank_row()
            else:
                self.ambiguities.add("unsupported_erase_line")
        elif final == "@":
            row = self.grid[self.y]
            row[self.x : self.x] = [" "] * amount
            del row[self.columns :]
        elif final == "P":
            row = self.grid[self.y]
            del row[self.x : self.x + amount]
            row.extend([" "] * (self.columns - len(row)))
        elif final == "X":
            end = min(self.columns, self.x + amount)
            self.grid[self.y][self.x : end] = [" "] * (end - self.x)
        elif final == "L":
            if self.scroll_top <= self.y <= self.scroll_bottom:
                for _ in range(amount):
                    self.grid.insert(self.y, self._blank_row())
                    del self.grid[self.scroll_bottom + 1]
        elif final == "M":
            if self.scroll_top <= self.y <= self.scroll_bottom:
                for _ in range(amount):
                    del self.grid[self.y]
                    self.grid.insert(self.scroll_bottom, self._blank_row())
        elif final == "S":
            self._scroll_up(amount)
        elif final == "T":
            self._scroll_down(amount)
        elif final == "r":
            top = self._value(values, 0, 1) - 1
            bottom = self._value(values, 1, self.rows) - 1
            if 0 <= top < bottom < self.rows:
                self.scroll_top, self.scroll_bottom = top, bottom
                self.x = self.y = 0
            else:
                self.ambiguities.add("invalid_scroll_region")
        elif final == "s":
            self.saved = (self.x, self.y)
        elif final == "u" and not raw.startswith((">", "?")):
            self.x, self.y = self.saved
            self._clamp()
        elif final == "b":
            for _ in range(amount):
                self.put(self.last_printed)
        elif final in {"h", "l"}:
            enabled = final == "h"
            modes = {value for value in values if value is not None}
            if private and modes & {47, 1047, 1049}:
                if enabled and self.normal_buffer is None:
                    self.normal_buffer = (
                        [row[:] for row in self.grid],
                        self.x,
                        self.y,
                    )
                    self.grid = [self._blank_row() for _ in range(self.rows)]
                    self.x = self.y = 0
                elif not enabled and self.normal_buffer is not None:
                    self.grid, self.x, self.y = self.normal_buffer
                    self.normal_buffer = None
            if private and 7 in modes:
                self.autowrap = enabled
        elif final in {"m", "q", "c", "g", "n", "t"}:
            pass
        elif final == "u" and raw.startswith((">", "?")):
            # Kitty keyboard protocol controls are non-visual. The probe writes
            # its fixed CR byte directly, independent of terminal key encoding.
            pass
        else:
            self.ambiguities.add("unsupported_csi_" + format(ord(final), "02x"))

    def tail(self) -> str:
        lines = ["".join(row).rstrip() for row in self.grid]
        while lines and not lines[0]:
            lines.pop(0)
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines)[-4096:]


def normalize_terminal_tail(
    payload: bytes, *, columns: int = 80, rows: int = 30
) -> TerminalNormalization:
    """Render a bounded VT stream into a deterministic visible terminal tail."""

    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return TerminalNormalization("", ("invalid_utf8",))
    screen = _TerminalScreen(columns, rows)
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\x1b":
            if index + 1 >= len(text):
                screen.ambiguities.add("truncated_escape")
                break
            kind = text[index + 1]
            if kind == "[":
                end = index + 2
                while end < len(text) and not ("@" <= text[end] <= "~"):
                    end += 1
                if end >= len(text):
                    screen.ambiguities.add("truncated_csi")
                    break
                if end - (index + 2) > 128:
                    screen.ambiguities.add("oversized_csi")
                else:
                    screen.csi(text[index + 2 : end], text[end])
                index = end + 1
                continue
            if kind == "]":
                end = index + 2
                while end < len(text):
                    if text[end] == "\x07":
                        end += 1
                        break
                    if text[end : end + 2] == "\x1b\\":
                        end += 2
                        break
                    end += 1
                else:
                    screen.ambiguities.add("truncated_osc")
                index = end
                continue
            if kind in {"P", "_", "^"}:
                end = text.find("\x1b\\", index + 2)
                if end < 0:
                    screen.ambiguities.add("truncated_control_string")
                    break
                index = end + 2
                continue
            if kind in {"(", ")", "*", "+", "-", ".", "/"}:
                if index + 2 >= len(text):
                    screen.ambiguities.add("truncated_charset")
                    break
                index += 3
                continue
            if kind == "7":
                screen.saved = (screen.x, screen.y)
            elif kind == "8":
                screen.x, screen.y = screen.saved
                screen._clamp()
            elif kind == "D":
                screen.linefeed()
            elif kind == "E":
                screen.x = 0
                screen.linefeed()
            elif kind == "M":
                screen.reverse_index()
            elif kind == "c":
                screen = _TerminalScreen(columns, rows)
            elif kind in {"=", ">", "H"}:
                pass
            else:
                screen.ambiguities.add("unsupported_escape_" + format(ord(kind), "02x"))
            index += 2
            continue
        if char == "\r":
            screen.x = 0
            screen.wrap_pending = False
        elif char in {"\n", "\x0b", "\x0c"}:
            screen.linefeed()
        elif char == "\b":
            screen.x = max(0, screen.x - 1)
            screen.wrap_pending = False
        elif char == "\t":
            screen.x = min(screen.columns - 1, ((screen.x // 8) + 1) * 8)
        elif char in {"\x00", "\x07", "\x7f"}:
            pass
        elif ord(char) < 32:
            screen.ambiguities.add("unsupported_control_" + format(ord(char), "02x"))
        else:
            screen.put(char)
        index += 1
    return TerminalNormalization(screen.tail(), tuple(sorted(screen.ambiguities)))


def _normalize_trust_dialog(
    payload: bytes, *, marker_seen: bool, raw_marker_seen: bool
) -> tuple[str, TerminalNormalization]:
    normalized = normalize_terminal_tail(payload, columns=80, rows=30)
    if not marker_seen:
        return (
            "trust_dialog_ambiguous"
            if raw_marker_seen
            else "trust_dialog_unknown"
        ), normalized
    if normalized.ambiguity_codes:
        return "trust_dialog_ambiguous", normalized
    if "Press enter to continue" in normalized.tail:
        return "trust_dialog_stuck", normalized
    return "trust_dialog_advanced", normalized


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
    pty_runner: PtyRunner = run_target_pty,
    run_nonce: str | None = None,
) -> VerifiedStandaloneRun:
    """Execute one target arm and return a digest-bound classified record."""

    if contract.probe_kind not in {
        "gemini_hooks_command_16049",
        "codex_trust_enter_39487",
    }:
        raise IntegrityError("standalone v0.1 has no trusted probe implementation")
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
    start_argv = build_target_start_argv(contract, container_name)

    integrity_errors: list[str] = []
    stdout = b""
    stderr = b""
    exit_code: int | None = None
    signal_number: int | None = None
    timed_out = False
    oom_killed = False
    before_manifest: dict[str, object] | None = None
    after_manifest: dict[str, object] | None = None
    pty_result: PtyProbeResult | None = None
    normalized_terminal = TerminalNormalization("", ())
    deliberate_target_termination = False

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
            if _is_codex_pty(contract):
                pty_result = pty_runner(
                    start_argv,
                    marker=contract.probe["marker"],
                    input_bytes=contract.probe["input"],
                    input_delay_ms=contract.probe["input_delay_ms"],
                    post_marker_window_ms=contract.probe[
                        "post_marker_window_ms"
                    ],
                    columns=contract.probe["terminal_columns"],
                    rows=contract.probe["terminal_rows"],
                    timeout=contract.timeout_s,
                    max_output_bytes=MAX_TARGET_OUTPUT_BYTES,
                )
                if not isinstance(pty_result, PtyProbeResult):
                    raise StandaloneRunnerError("target_pty_result_invalid")
                if (
                    not isinstance(pty_result.output, bytes)
                    or not isinstance(pty_result.marker_seen, bool)
                    or not isinstance(pty_result.input_sent, bool)
                    or not isinstance(pty_result.process_exited, bool)
                    or not isinstance(
                        pty_result.deliberate_attach_termination, bool
                    )
                    or not isinstance(pty_result.raw_marker_seen, bool)
                    or not isinstance(
                        pty_result.marker_visibility_ambiguous, bool
                    )
                    or not pty_result.process_exited
                ):
                    raise StandaloneRunnerError("target_pty_result_invalid")
                stdout = pty_result.output
                raw_marker_present = contract.probe["marker"] in stdout
                if pty_result.raw_marker_seen != raw_marker_present:
                    integrity_errors.append("pty_marker_binding_invalid")
                if pty_result.marker_seen:
                    boundary = pty_result.marker_offset
                    if (
                        not isinstance(boundary, int)
                        or isinstance(boundary, bool)
                        or boundary <= 0
                        or boundary > len(stdout)
                        or stdout[boundary - 1] != contract.probe["marker"][-1]
                    ):
                        integrity_errors.append("pty_marker_binding_invalid")
                    else:
                        rendered_prefix = normalize_terminal_tail(
                            stdout[:boundary], columns=80, rows=30
                        )
                        if (
                            rendered_prefix.ambiguity_codes
                            or "Press enter to continue"
                            not in rendered_prefix.tail
                        ):
                            integrity_errors.append("pty_marker_visibility_unproven")
                elif pty_result.marker_offset is not None:
                    integrity_errors.append("pty_marker_binding_invalid")
                if (
                    pty_result.marker_seen
                    and (
                        not pty_result.input_sent
                        or pty_result.input_delay_ms != 0
                        or pty_result.marker_offset is None
                    )
                ):
                    integrity_errors.append("pty_immediate_input_unproven")
                if not pty_result.marker_seen and pty_result.input_sent:
                    integrity_errors.append("pty_input_without_marker")
            else:
                started = _call(
                    runner,
                    start_argv,
                    timeout=contract.timeout_s + 5,
                    max_output_bytes=MAX_TARGET_OUTPUT_BYTES,
                    text=False,
                )
                if not isinstance(started.stdout, bytes) or not isinstance(
                    started.stderr, bytes
                ):
                    raise StandaloneRunnerError("target_stream_type_invalid")
                stdout = started.stdout
                stderr = started.stderr
            if not _is_codex_pty(contract) and (
                _has_oversized_line(stdout) or _has_oversized_line(stderr)
            ):
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
            if _is_codex_pty(contract) and state.get("Running") is True:
                killed = _checked_text(
                    runner,
                    ["docker", "kill", "--signal", "KILL", container_name],
                    code="target_deliberate_stop_failed",
                    timeout=10,
                )
                if killed.stdout.strip() != container_name:
                    integrity_errors.append("target_deliberate_stop_identity")
                deliberate_target_termination = True
                inspected = _checked_text(
                    runner,
                    ["docker", "container", "inspect", container_name],
                    code="container_state_unavailable_after_stop",
                )
                state = _container_state(inspected.stdout)
            if state.get("Running") is not False:
                integrity_errors.append("container_not_stopped")
            raw_exit = state.get("ExitCode")
            if isinstance(raw_exit, int) and not isinstance(raw_exit, bool):
                exit_code = raw_exit
            else:
                integrity_errors.append("target_exit_unavailable")
            if deliberate_target_termination:
                signal_number = 9
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
    if _is_codex_pty(contract):
        diagnostic, normalized_terminal = _normalize_trust_dialog(
            stdout,
            marker_seen=bool(pty_result and pty_result.marker_seen),
            raw_marker_seen=bool(pty_result and pty_result.raw_marker_seen),
        )
    else:
        diagnostic = _normalize_hooks_diagnostic(
            stdout, stderr, exit_code=exit_code, timed_out=timed_out
        )
    accepted = set(contract.probe["accepted_diagnostics"])
    evidence_complete = diagnostic in accepted
    if _is_codex_pty(contract):
        capability = (
            CapabilityStatus.SUPPORTED
            if evidence_complete
            else CapabilityStatus.UNKNOWN
        )
        assertions = tuple(
            AssertionObservation(
                assertion_id=item.assertion_id,
                required=item.required,
                supported=True,
                passed=(diagnostic != item.forbidden_normalized)
                if evidence_complete
                else None,
                evidence_complete=evidence_complete,
                oracle_valid=evidence_complete,
            )
            for item in contract.assertions
        )
    else:
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
    control_values: dict[str, object] = {
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
        "execution.policy": _policy_sha256(contract),
    }
    if _is_codex_pty(contract):
        control_values.update(
            {
                "package.platform_integrity": attestation.platform_package_integrity,
                "package.wrapper_sha256": attestation.wrapper_sha256,
                "package.platform_binary_sha256": (
                    attestation.platform_binary_sha256
                ),
                "probe.marker_sha256": hashlib.sha256(
                    contract.probe["marker"]
                ).hexdigest(),
                "probe.input_sha256": hashlib.sha256(
                    contract.probe["input"]
                ).hexdigest(),
                "probe.input_delay_ms": contract.probe["input_delay_ms"],
                "probe.post_marker_window_ms": contract.probe[
                    "post_marker_window_ms"
                ],
                "terminal.columns": contract.probe["terminal_columns"],
                "terminal.rows": contract.probe["terminal_rows"],
            }
        )
    controls = canonical_items(control_values)
    normalized = canonical_items(
        {"diagnostic": diagnostic, "probe_complete": "true"}
        if _is_codex_pty(contract)
        else {
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
        target_identity=(
            f"{contract.probe['target_identity_prefix']}@{target.version}"
            if _is_codex_pty(contract)
            else f"gemini-cli@{target.version}"
        ),
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
            **(
                {
                    "platform_package_integrity": (
                        attestation.platform_package_integrity
                    ),
                    "wrapper_sha256": attestation.wrapper_sha256,
                    "platform_binary_sha256": attestation.platform_binary_sha256,
                }
                if _is_codex_pty(contract)
                else {}
            ),
        },
        "runner": _runner_record(contract),
        "stimulus": _stimulus_record(contract),
        "outcome": {
            "exit_code": exit_code,
            "signal": signal_number,
            "timed_out": timed_out,
            "oom_killed": oom_killed,
            "diagnostic": diagnostic,
            **(
                {
                    "marker_seen": bool(pty_result and pty_result.marker_seen),
                    "raw_marker_seen": bool(
                        pty_result and pty_result.raw_marker_seen
                    ),
                    "marker_visibility_ambiguous": bool(
                        pty_result and pty_result.marker_visibility_ambiguous
                    ),
                    "input_sent": bool(pty_result and pty_result.input_sent),
                    "deliberate_attach_termination": bool(
                        pty_result and pty_result.deliberate_attach_termination
                    ),
                    "deliberate_target_termination": deliberate_target_termination,
                    "terminal_tail": normalized_terminal.tail,
                    "terminal_ambiguity_codes": list(
                        normalized_terminal.ambiguity_codes
                    ),
                }
                if _is_codex_pty(contract)
                else {}
            ),
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
    if _is_codex_pty(contract):
        public_values["package.platform_integrity"] = str(
            attestation.platform_package_integrity
        )
        public_values["package.wrapper_sha256"] = str(attestation.wrapper_sha256)
        public_values["package.platform_binary_sha256"] = str(
            attestation.platform_binary_sha256
        )
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
    target_spec = target_for(contract, verified.target_name)
    expected_target_values = {
        "version": target_spec.version,
        "package_integrity": target_spec.npm_integrity,
        **(
            {"platform_package_integrity": target_spec.platform_npm_integrity}
            if _is_codex_pty(contract)
            else {}
        ),
    }
    if _is_codex_pty(contract):
        expected_target_values.update(
            {
                "wrapper_sha256": target_spec.wrapper_sha256,
                "platform_binary_sha256": target_spec.platform_binary_sha256,
            }
        )
    if any(target.get(key) != value for key, value in expected_target_values.items()):
        raise IntegrityError("standalone record target contract binding mismatch")
    if record.get("runner") != _runner_record(contract):
        raise IntegrityError("standalone runner policy binding mismatch")
    if record.get("stimulus") != _stimulus_record(contract):
        raise IntegrityError("standalone trusted stimulus binding mismatch")
    if target.get("image_digest") != verified.image_digest:
        raise IntegrityError("standalone image digest binding mismatch")
    if target.get("image_attestation_sha256") != verified.image_attestation_sha256:
        raise IntegrityError("standalone attestation binding mismatch")
    if record.get("result") != run_result_to_dict(verified.run_result):
        raise IntegrityError("standalone record/result mismatch")
    expected_identity = (
        f"{contract.probe['target_identity_prefix']}@{target_spec.version}"
        if _is_codex_pty(contract)
        else f"gemini-cli@{target_spec.version}"
    )
    if (
        verified.run_result.run_id != record.get("run_id")
        or verified.run_result.contract_digest != contract.raw_sha256
        or verified.run_result.execution_lane is not contract.execution_lane
        or verified.run_result.target_identity != expected_identity
        or dict(verified.run_result.normalized_observations).get("diagnostic")
        != outcome.get("diagnostic")
    ):
        raise IntegrityError("standalone classified result binding mismatch")
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
    if _is_codex_pty(contract):
        public_values["package.platform_integrity"] = str(
            target.get("platform_package_integrity")
        )
        public_values["package.wrapper_sha256"] = str(target.get("wrapper_sha256"))
        public_values["package.platform_binary_sha256"] = str(
            target.get("platform_binary_sha256")
        )
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
        "runner": _runner_record(contract),
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
        f"Runner: `{_runner_kind(contract)}` (`{_policy_sha256(contract)}`)",
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


def _attestation_record(attestation: ImageAttestation) -> dict[str, object]:
    value = asdict(attestation)
    for optional in (
        "platform_package_integrity",
        "wrapper_sha256",
        "platform_binary_sha256",
    ):
        if value.get(optional) is None:
            value.pop(optional, None)
    return value


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
            "baseline": _attestation_record(baseline_attestation),
            "candidate": _attestation_record(candidate_attestation),
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
