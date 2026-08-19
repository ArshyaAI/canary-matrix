"""Strict OpenBench bridge for the Canary Matrix one-day capability spike.

Contracts are untrusted declarative data. This module owns the executable
probe registry, fixed checker, generated pack, export verification, containment
policy, and public allowlist. OpenBench observations are inputs; ``core`` is the
only authority that emits Canary states.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from types import MappingProxyType
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from .core import (
    AssertionObservation,
    CapabilityStatus,
    ExecutionLane,
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


CONTRACT_SCHEMA_VERSION = "canary-contract/v0.1"
PACK_RECEIPT_SCHEMA_VERSION = "canary-pack/v0.1"
PUBLIC_BUNDLE_SCHEMA_VERSION = "canary-public-bundle/v0.1"
OPENBENCH_COMMIT = "9e26c96a7df012ca9173e9725211c4cc58e11948"
MAX_CONTRACT_BYTES = 256 * 1024
MAX_EXPORT_BYTES = 4 * 1024 * 1024
MAX_PUBLIC_DIAGNOSTIC_CHARS = 16 * 1024
MAX_CONTROL_OUTPUT_BYTES = 1024 * 1024
MAX_GENERATED_FILE_BYTES = 512 * 1024

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^(?:[^\s@]+@)?sha256:[0-9a-f]{64}$")
_NPM_INTEGRITY_RE = re.compile(r"^sha512-[A-Za-z0-9+/]+={0,2}$")
_IMAGE_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{2,200}$")
_SAFE_FIXTURE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NODE_VERSION_RE = re.compile(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9._-]+)?$")
_ALLOWED_FIX_STATES = {
    "reported",
    "proposed_unmerged",
    "merged_unreleased",
    "released",
    "unknown",
}


class ContractError(ValueError):
    """The declarative contract is invalid or attempts to expand authority."""


class IntegrityError(RuntimeError):
    """A generated pack, immutable export, or public artifact failed integrity."""


FIXED_CHECKER_SH = r'''#!/bin/sh
set -eu

# The inherited checker environment is deliberately discarded before the fixed
# verifier runs. TASK_DIR is a runner-owned path, never contract-controlled.
exec /usr/bin/env -i \
  PATH=/usr/bin:/bin \
  LC_ALL=C \
  LANG=C \
  /usr/bin/python3 - "$TASK_DIR/checker_data/initial_manifest.json" <<'PY'
import hashlib
import json
import os
import stat
import sys

expected_path = sys.argv[1]
with open(expected_path, "r", encoding="utf-8") as handle:
    expected = json.load(handle)

observed = {}
for root, dirs, files in os.walk(".", topdown=True, followlinks=False):
    dirs.sort()
    files.sort()
    for name in dirs:
        path = os.path.join(root, name)
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise SystemExit("CANARY_VERIFIER_FAIL symlink")
    for name in files:
        path = os.path.join(root, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("CANARY_VERIFIER_FAIL non_regular")
        relative = os.path.relpath(path, ".").replace(os.sep, "/")
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        observed[relative] = {"sha256": digest.hexdigest(), "size": info.st_size}

if observed != expected.get("files"):
    raise SystemExit("CANARY_VERIFIER_FAIL workspace_manifest")
print("CANARY_VERIFIER_OK")
PY
'''
FIXED_CHECKER_SHA256 = hashlib.sha256(FIXED_CHECKER_SH.encode("utf-8")).hexdigest()


_PROBE_REGISTRY = MappingProxyType(
    {
        "gemini_sandbox_26964": MappingProxyType(
            {
                "argv": ("gemini", "--sandbox"),
                "version_argv": ("gemini", "--version"),
                "instruction": (
                    "Credential-free parser calibration for Gemini CLI issue #26964. "
                    "The candidate manifest invokes the fixed probe argv; no model "
                    "prompt, provider credential, or network access is permitted."
                ),
                "accepted_diagnostics": ("no_error", "unknown_argument_c"),
                "forbidden_diagnostic": "unknown_argument_c",
            }
        ),
        "gemini_hooks_command_16049": MappingProxyType(
            {
                "argv": ("gemini", "hooks", "--help"),
                "version_argv": ("gemini", "--version"),
                "instruction": (
                    "Credential-free command-registration calibration derived from "
                    "Gemini CLI issue #16049. The fixed probe reads hooks help only; "
                    "no model prompt, provider credential, or network is permitted."
                ),
                "accepted_diagnostics": ("hooks_help", "hooks_command_absent"),
                "forbidden_diagnostic": "hooks_command_absent",
            }
        ),
    }
)


_CONTAINMENT_POLICY = {
    "cpus": "2",
    "memory": "2g",
    "memory_swap": "2g",
    "network": "none",
    "pids_limit": "256",
    "nofile": "4096:4096",
    "read_only_root": True,
    "cap_drop": "ALL",
    "no_new_privileges": True,
    "work_mount": "run_scoped_tmpfs_volume",
    "writable_host_bind": False,
}
CONTAINMENT_POLICY_SHA256 = hashlib.sha256(
    canonical_json_bytes(_CONTAINMENT_POLICY)
).hexdigest()


@dataclass(frozen=True, slots=True)
class FixtureFile:
    path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class ContractAssertion:
    assertion_id: str
    kind: str
    required: bool
    forbidden_normalized: str


@dataclass(frozen=True, slots=True)
class TargetSpec:
    name: str
    version: str
    image_tag: str
    image_family: str
    npm_integrity: str
    node_version: str
    os: str
    arch: str


@dataclass(frozen=True, slots=True)
class ImageBuildPlan:
    """Trusted, byte-bound recipe inputs shared by both immutable target arms."""

    target_name: str
    image_tag: str
    base_image_digest: str
    dockerfile: bytes
    recipe_sha256: str
    build_args: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ImageAttestation:
    """Facts independently observed from one locally resolved immutable image."""

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


@dataclass(frozen=True, slots=True)
class Contract:
    path: str
    raw_sha256: str
    contract_id: str
    title: str
    capture_date: str
    fix_state: str
    source_urls: tuple[str, ...]
    source_verified: bool
    capability: str
    systems: tuple[str, ...]
    credential_mode: str
    execution_lane: ExecutionLane
    probe_kind: str
    timeout_s: int
    trials: int
    fixture_files: tuple[FixtureFile, ...]
    assertions: tuple[ContractAssertion, ...]
    matched_controls: tuple[str, ...]
    intended_changed_controls: tuple[str, ...]
    evidence_allowlist: tuple[str, ...]
    redaction_patterns: tuple[str, ...]
    baseline: TargetSpec
    candidate: TargetSpec

    @property
    def probe(self) -> Mapping[str, object]:
        return _PROBE_REGISTRY[self.probe_kind]


@dataclass(frozen=True, slots=True)
class VerifiedExport:
    target_name: str
    export_sha256: str
    row_sha256: str
    image_digest: str
    image_attestation_sha256: str
    run_result: RunResult
    public_evidence: tuple[tuple[str, str], ...]


def _strict_keys(
    value: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        raise ContractError(f"{context}: missing fields: {', '.join(missing)}")
    if unknown:
        raise ContractError(f"{context}: unknown fields: {', '.join(unknown)}")


def _string(value: object, context: str, *, max_chars: int = 400) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise ContractError(f"{context}: expected non-empty string <= {max_chars} chars")
    if any(ord(char) < 32 and char not in "\t" for char in value):
        raise ContractError(f"{context}: control characters are forbidden")
    return value


def _fixture_content(value: object, context: str) -> str:
    if not isinstance(value, str) or len(value) > 64 * 1024:
        raise ContractError(f"{context}: expected UTF-8 text <= 64 KiB")
    if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        raise ContractError(f"{context}: unsafe control character")
    return value


def _string_list(
    value: object, context: str, *, min_items: int = 1, max_items: int = 32
) -> tuple[str, ...]:
    if not isinstance(value, list) or not (min_items <= len(value) <= max_items):
        raise ContractError(
            f"{context}: expected array with {min_items}..{max_items} items"
        )
    items = tuple(_string(item, f"{context}[]") for item in value)
    if len(set(items)) != len(items):
        raise ContractError(f"{context}: duplicate values are forbidden")
    return items


def _safe_relative_path(value: object, context: str) -> str:
    raw = _string(value, context, max_chars=160)
    if "\\" in raw:
        raise ContractError(f"{context}: backslashes are forbidden")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or raw.startswith("./")
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\x00" in raw
    ):
        raise ContractError(f"{context}: path must remain inside the fixture")
    if any(not _SAFE_FIXTURE_COMPONENT_RE.fullmatch(part) for part in path.parts):
        raise ContractError(
            f"{context}: path components must use portable letters, digits, '.', '_', or '-'"
        )
    return path.as_posix()


def _parse_target(name: str, value: object) -> TargetSpec:
    if not isinstance(value, dict):
        raise ContractError(f"targets.{name}: expected table")
    _strict_keys(
        value,
        required={
            "version",
            "image_tag",
            "image_family",
            "npm_integrity",
            "node_version",
            "os",
            "arch",
        },
        context=f"targets.{name}",
    )
    version = _string(value["version"], f"targets.{name}.version", max_chars=80)
    if not _VERSION_RE.fullmatch(version):
        raise ContractError(f"targets.{name}.version: invalid semantic version")
    image_tag = _string(value["image_tag"], f"targets.{name}.image_tag", max_chars=200)
    if not _IMAGE_TAG_RE.fullmatch(image_tag):
        raise ContractError(f"targets.{name}.image_tag: invalid image reference")
    integrity = _string(
        value["npm_integrity"], f"targets.{name}.npm_integrity", max_chars=160
    )
    if not _NPM_INTEGRITY_RE.fullmatch(integrity):
        raise ContractError(f"targets.{name}.npm_integrity: invalid sha512 SRI")
    try:
        sri_digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ContractError(
            f"targets.{name}.npm_integrity: invalid base64 digest"
        ) from exc
    if len(sri_digest) != hashlib.sha512().digest_size:
        raise ContractError(
            f"targets.{name}.npm_integrity: expected a 64-byte SHA-512 digest"
        )
    return TargetSpec(
        name=name,
        version=version,
        image_tag=image_tag,
        image_family=_string(
            value["image_family"], f"targets.{name}.image_family", max_chars=100
        ),
        npm_integrity=integrity,
        node_version=_string(
            value["node_version"], f"targets.{name}.node_version", max_chars=40
        ),
        os=_string(value["os"], f"targets.{name}.os", max_chars=80),
        arch=_string(value["arch"], f"targets.{name}.arch", max_chars=40),
    )


def load_contract(path: str | os.PathLike[str]) -> Contract:
    """Load one strict declarative contract without accepting executable fields."""

    source = Path(path)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ContractError("contract source must be a regular non-symlink file")
    if info.st_size > MAX_CONTRACT_BYTES:
        raise ContractError("contract exceeds the 256 KiB limit")
    raw = source.read_bytes()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ContractError(f"invalid UTF-8 TOML contract: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("contract root must be a table")
    _strict_keys(
        data,
        required={
            "schema_version",
            "id",
            "title",
            "capture_date",
            "fix_state",
            "source_urls",
            "source_verified",
            "capability",
            "systems",
            "credential_mode",
            "execution_lane",
            "probe_kind",
            "timeout_s",
            "trials",
            "matched_controls",
            "intended_changed_controls",
            "evidence_allowlist",
            "redaction_patterns",
            "fixture",
            "assertions",
            "targets",
        },
        context="contract",
    )
    if data["schema_version"] != CONTRACT_SCHEMA_VERSION:
        raise ContractError(
            f"contract.schema_version: expected {CONTRACT_SCHEMA_VERSION!r}"
        )
    contract_id = _string(data["id"], "contract.id", max_chars=81)
    if not _ID_RE.fullmatch(contract_id):
        raise ContractError("contract.id: expected lowercase portable identifier")
    title = _string(data["title"], "contract.title", max_chars=200)
    if any(char in title for char in "<>|"):
        raise ContractError("contract.title: unsafe Markdown presentation character")
    capture_date = _string(data["capture_date"], "contract.capture_date", max_chars=10)
    try:
        parsed_date = date.fromisoformat(capture_date)
    except ValueError as exc:
        raise ContractError("contract.capture_date: expected ISO date") from exc
    if parsed_date > date.today():
        raise ContractError("contract.capture_date: future dates are forbidden")
    fix_state = _string(data["fix_state"], "contract.fix_state", max_chars=40)
    if fix_state not in _ALLOWED_FIX_STATES:
        raise ContractError("contract.fix_state: unknown state")
    source_urls = _string_list(data["source_urls"], "contract.source_urls", max_items=8)
    for url in source_urls:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ContractError(f"contract.source_urls: unsafe URL {url!r}")
    if not isinstance(data["source_verified"], bool):
        raise ContractError("contract.source_verified: expected boolean")
    systems = _string_list(data["systems"], "contract.systems", max_items=8)
    credential_mode = _string(
        data["credential_mode"], "contract.credential_mode", max_chars=40
    )
    if credential_mode != "none":
        raise ContractError("v0.1 spike accepts credential_mode='none' only")
    try:
        lane = ExecutionLane(data["execution_lane"])
    except (TypeError, ValueError) as exc:
        raise ContractError("contract.execution_lane: unknown lane") from exc
    if lane is not ExecutionLane.CONTAINER_NO_HOST_WRITE:
        raise ContractError("v0.1 spike requires container_no_host_write")
    probe_kind = _string(data["probe_kind"], "contract.probe_kind", max_chars=80)
    if probe_kind not in _PROBE_REGISTRY:
        raise ContractError("contract.probe_kind: no trusted probe implementation")
    timeout_s = data["timeout_s"]
    trials = data["trials"]
    if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or not 1 <= timeout_s <= 60:
        raise ContractError("contract.timeout_s: expected integer 1..60")
    if trials != 1:
        raise ContractError("v0.1 deterministic spike requires exactly one trial")

    fixture = data["fixture"]
    if not isinstance(fixture, dict):
        raise ContractError("contract.fixture: expected table")
    _strict_keys(fixture, required={"files"}, context="contract.fixture")
    raw_files = fixture["files"]
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= 16:
        raise ContractError("contract.fixture.files: expected 1..16 file tables")
    fixture_files: list[FixtureFile] = []
    fixture_paths: set[str] = set()
    total_fixture_bytes = 0
    for index, item in enumerate(raw_files):
        context = f"contract.fixture.files[{index}]"
        if not isinstance(item, dict):
            raise ContractError(f"{context}: expected table")
        _strict_keys(item, required={"path", "content"}, context=context)
        relative = _safe_relative_path(item["path"], f"{context}.path")
        if relative in fixture_paths:
            raise ContractError(f"{context}.path: duplicate fixture path")
        fixture_paths.add(relative)
        content = _fixture_content(item["content"], f"{context}.content")
        encoded = content.encode("utf-8")
        total_fixture_bytes += len(encoded)
        if total_fixture_bytes > 128 * 1024:
            raise ContractError("contract.fixture: total content exceeds 128 KiB")
        fixture_files.append(FixtureFile(relative, encoded))

    raw_assertions = data["assertions"]
    if not isinstance(raw_assertions, list) or not 1 <= len(raw_assertions) <= 16:
        raise ContractError("contract.assertions: expected 1..16 assertion tables")
    assertions: list[ContractAssertion] = []
    assertion_ids: set[str] = set()
    for index, item in enumerate(raw_assertions):
        context = f"contract.assertions[{index}]"
        if not isinstance(item, dict):
            raise ContractError(f"{context}: expected table")
        _strict_keys(
            item,
            required={"id", "kind", "required", "forbidden_normalized"},
            context=context,
        )
        assertion_id = _string(item["id"], f"{context}.id", max_chars=80)
        if not _ID_RE.fullmatch(assertion_id) or assertion_id in assertion_ids:
            raise ContractError(f"{context}.id: invalid or duplicate identifier")
        assertion_ids.add(assertion_id)
        if item["kind"] != "forbid_normalized_diagnostic":
            raise ContractError(f"{context}.kind: no trusted implementation")
        if not isinstance(item["required"], bool):
            raise ContractError(f"{context}.required: expected boolean")
        forbidden = _string(
            item["forbidden_normalized"],
            f"{context}.forbidden_normalized",
            max_chars=80,
        )
        if forbidden != _PROBE_REGISTRY[probe_kind]["forbidden_diagnostic"]:
            raise ContractError(
                f"{context}.forbidden_normalized: conflicts with trusted probe"
            )
        assertions.append(
            ContractAssertion(assertion_id, item["kind"], item["required"], forbidden)
        )

    targets = data["targets"]
    if not isinstance(targets, dict):
        raise ContractError("contract.targets: expected table")
    _strict_keys(targets, required={"baseline", "candidate"}, context="contract.targets")
    baseline = _parse_target("baseline", targets["baseline"])
    candidate = _parse_target("candidate", targets["candidate"])
    if baseline.version == candidate.version:
        raise ContractError("contract.targets: baseline and candidate versions must differ")
    if (
        baseline.image_family != candidate.image_family
        or baseline.node_version != candidate.node_version
        or baseline.os != candidate.os
        or baseline.arch != candidate.arch
    ):
        raise ContractError("contract.targets: matched platform controls must be identical")

    matched = _string_list(
        data["matched_controls"], "contract.matched_controls", max_items=32
    )
    intended = _string_list(
        data["intended_changed_controls"],
        "contract.intended_changed_controls",
        max_items=16,
    )
    if set(matched) & set(intended):
        raise ContractError("matched and intended-changed controls must be disjoint")
    required_matched = {
        "os",
        "arch",
        "runtime.node",
        "credential.mode",
        "execution.policy",
        "image.base_digest",
        "image.family",
        "image.recipe_sha256",
    }
    required_changed = {"target.version", "image.digest", "package.integrity"}
    if set(matched) != required_matched or set(intended) != required_changed:
        raise ContractError("v0.1 control policy must match the frozen calibration schema")

    evidence_allowlist = _string_list(
        data["evidence_allowlist"], "contract.evidence_allowlist", max_items=32
    )
    allowed_evidence = {
        "target.version",
        "target.exit_code",
        "target.signal",
        "target.diagnostic",
        "image.digest",
        "package.integrity",
        "runtime.node",
        "image.attestation_sha256",
        "export.sha256",
    }
    if not set(evidence_allowlist) <= allowed_evidence:
        raise ContractError("contract.evidence_allowlist: contains non-public field")
    redaction_patterns = _string_list(
        data["redaction_patterns"],
        "contract.redaction_patterns",
        min_items=0,
        max_items=16,
    )
    if redaction_patterns:
        raise ContractError(
            "v0.1 contracts cannot supply executable redaction regular expressions"
        )

    return Contract(
        path=str(source.resolve()),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        contract_id=contract_id,
        title=title,
        capture_date=capture_date,
        fix_state=fix_state,
        source_urls=source_urls,
        source_verified=data["source_verified"],
        capability=_string(data["capability"], "contract.capability", max_chars=100),
        systems=systems,
        credential_mode=credential_mode,
        execution_lane=lane,
        probe_kind=probe_kind,
        timeout_s=timeout_s,
        trials=trials,
        fixture_files=tuple(fixture_files),
        assertions=tuple(assertions),
        matched_controls=matched,
        intended_changed_controls=intended,
        evidence_allowlist=evidence_allowlist,
        redaction_patterns=redaction_patterns,
        baseline=baseline,
        candidate=candidate,
    )


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


def _fixture_manifest(files: Sequence[FixtureFile]) -> dict[str, object]:
    return {
        "files": {
            item.path: {
                "sha256": hashlib.sha256(item.content).hexdigest(),
                "size": len(item.content),
            }
            for item in sorted(files, key=lambda item: item.path)
        }
    }


def _candidate_manifest(contract: Contract) -> bytes:
    probe = contract.probe
    argv = ", ".join(json.dumps(item) for item in probe["argv"])
    version_argv = ", ".join(json.dumps(item) for item in probe["version_argv"])
    name = f"canary-{contract.contract_id}"
    return (
        "kind = \"manifest\"\n"
        f"name = {json.dumps(name)}\n"
        "isolate_home = true\n"
        "inherit_env = false\n"
        "unmetered = true\n"
        f"command = [{argv}]\n"
        f"version_command = [{version_argv}]\n"
        f"policy_headless_args = [{json.dumps(probe['argv'][-1])}]\n"
        "policy_auto_approve_args = []\n"
        "pass_env = []\n"
        "unset_env = []\n"
    ).encode("utf-8")


def generate_pack(contract: Contract, destination: str | os.PathLike[str]) -> Path:
    """Generate the only OpenBench runtime representation from a contract."""

    root = Path(destination)
    if root.exists() and any(root.iterdir()):
        raise IntegrityError("generated pack destination must be absent or empty")
    root.mkdir(parents=True, exist_ok=True)
    task = root / contract.contract_id
    workspace = task / "workspace"
    checker_data = task / "checker_data"
    workspace.mkdir(parents=True)
    checker_data.mkdir(parents=True)

    generated: dict[str, bytes] = {
        "pack.toml": (
            "org = \"canary-matrix\"\n"
            f"name = {json.dumps(contract.contract_id)}\n"
            "version = \"0.1.0\"\n"
            "kind = \"tasks\"\n"
            f"description = {json.dumps(contract.title)}\n"
            "license = \"MIT\"\n"
            f"tasks = [{json.dumps(contract.contract_id)}]\n"
        ).encode("utf-8"),
        "candidate.toml": _candidate_manifest(contract),
        f"{contract.contract_id}/instruction.md": (
            f"# {contract.title}\n\n{contract.probe['instruction']}\n"
        ).encode("utf-8"),
        f"{contract.contract_id}/checker.sh": FIXED_CHECKER_SH.encode("utf-8"),
        f"{contract.contract_id}/checker_data/initial_manifest.json": (
            canonical_json_bytes(_fixture_manifest(contract.fixture_files))
        ),
    }
    for item in contract.fixture_files:
        generated[f"{contract.contract_id}/workspace/{item.path}"] = item.content

    for relative, payload in sorted(generated.items()):
        mode = 0o555 if relative.endswith("/checker.sh") else 0o444
        _write_bytes(root / relative, payload, mode)

    receipt = {
        "schema_version": PACK_RECEIPT_SCHEMA_VERSION,
        "openbench_commit": OPENBENCH_COMMIT,
        "contract_id": contract.contract_id,
        "contract_sha256": contract.raw_sha256,
        "fixed_checker_sha256": FIXED_CHECKER_SHA256,
        "containment_policy_sha256": CONTAINMENT_POLICY_SHA256,
        "files": {
            relative: hashlib.sha256(payload).hexdigest()
            for relative, payload in sorted(generated.items())
        },
    }
    _write_bytes(root / "canary-pack.json", canonical_json_bytes(receipt), 0o444)
    verify_generated_pack(contract, root)
    return root


def verify_generated_pack(
    contract: Contract, pack_root: str | os.PathLike[str]
) -> Mapping[str, object]:
    root = Path(pack_root)
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise IntegrityError(f"generated-pack root is unavailable: {exc}") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
        raise IntegrityError("generated-pack root must be a real directory")
    receipt_path = root / "canary-pack.json"
    try:
        receipt_info = receipt_path.lstat()
    except OSError as exc:
        raise IntegrityError(f"generated-pack receipt is unavailable: {exc}") from exc
    if receipt_path.is_symlink() or not stat.S_ISREG(receipt_info.st_mode):
        raise IntegrityError("generated-pack receipt must be a regular non-symlink file")
    if receipt_info.st_size > MAX_GENERATED_FILE_BYTES:
        raise IntegrityError("generated-pack receipt exceeds the file budget")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"invalid generated-pack receipt: {exc}") from exc
    if not isinstance(receipt, dict):
        raise IntegrityError("generated-pack receipt must be an object")
    expected_header = {
        "schema_version": PACK_RECEIPT_SCHEMA_VERSION,
        "openbench_commit": OPENBENCH_COMMIT,
        "contract_id": contract.contract_id,
        "contract_sha256": contract.raw_sha256,
        "fixed_checker_sha256": FIXED_CHECKER_SHA256,
        "containment_policy_sha256": CONTAINMENT_POLICY_SHA256,
    }
    for key, expected in expected_header.items():
        if receipt.get(key) != expected:
            raise IntegrityError(f"generated-pack receipt mismatch: {key}")
    files = receipt.get("files")
    if not isinstance(files, dict) or not files:
        raise IntegrityError("generated-pack receipt has no file manifest")
    actual_paths: set[str] = set()
    actual_directories: set[str] = set()
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        filenames.sort()
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise IntegrityError(f"generated-pack tree rejects symlink: {relative}")
            if not stat.S_ISDIR(info.st_mode):
                raise IntegrityError(f"generated-pack tree rejects special entry: {relative}")
            actual_directories.add(relative)
        for name in filenames:
            path = current_path / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise IntegrityError(f"generated-pack tree rejects symlink: {relative}")
            if not stat.S_ISREG(info.st_mode):
                raise IntegrityError(f"generated-pack tree rejects special entry: {relative}")
            if info.st_nlink != 1:
                raise IntegrityError(f"generated-pack tree rejects hard link: {relative}")
            if info.st_size > MAX_GENERATED_FILE_BYTES:
                raise IntegrityError(f"generated-pack file exceeds budget: {relative}")
            actual_paths.add(relative)
    expected_paths = set(files) | {"canary-pack.json"}
    if actual_paths != expected_paths:
        raise IntegrityError("generated-pack file set mismatch")
    expected_directories = {
        parent.as_posix()
        for relative in expected_paths
        for parent in PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    if actual_directories != expected_directories:
        raise IntegrityError("generated-pack directory set mismatch")
    for relative, expected in files.items():
        try:
            safe_relative = (
                _safe_relative_path(relative, "generated-pack receipt path")
                if isinstance(relative, str)
                else None
            )
        except ContractError as exc:
            raise IntegrityError("generated-pack file manifest is malformed") from exc
        if (
            safe_relative != relative
            or not isinstance(expected, str)
            or not _SHA256_RE.fullmatch(expected)
        ):
            raise IntegrityError("generated-pack file manifest is malformed")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"generated-pack file is not regular: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise IntegrityError(f"generated-pack digest mismatch: {relative}")
    checker = root / contract.contract_id / "checker.sh"
    if hashlib.sha256(checker.read_bytes()).hexdigest() != FIXED_CHECKER_SHA256:
        raise IntegrityError("fixed checker digest mismatch")
    return MappingProxyType(receipt)


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Best-effort bounded termination for a trusted control-plane command."""

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
    """Run fixed trusted argv with a wall deadline and bounded combined output."""

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
        (
            stdout_bytes.decode("utf-8", errors="replace")
            if text
            else stdout_bytes
        ),
        (
            stderr_bytes.decode("utf-8", errors="replace")
            if text
            else stderr_bytes
        ),
    )


_IMAGE_LABEL_PREFIX = "io.canary-matrix."
_IMAGE_LABEL_FIELDS = {
    "base_image_digest": "base-image-digest",
    "recipe_sha256": "recipe-sha256",
    "target_version": "target-version",
    "package_integrity": "package-integrity",
    "node_version": "node-version",
    "os": "os-release",
    "arch": "architecture",
    "image_family": "image-family",
    "contract_sha256": "contract-sha256",
}


def _image_label(field: str) -> str:
    return _IMAGE_LABEL_PREFIX + _IMAGE_LABEL_FIELDS[field]


def render_image_build_plan(
    contract: Contract,
    target_name: str,
    *,
    base_image_digest: str,
) -> ImageBuildPlan:
    """Render the fixed SRI-verifying image recipe without contract code execution."""

    target = target_for(contract, target_name)
    if (
        "@sha256:" not in base_image_digest
        or not _IMAGE_DIGEST_RE.fullmatch(base_image_digest)
    ):
        raise IntegrityError("base image must be a registry reference pinned by SHA-256")
    dockerfile = f'''# syntax=docker/dockerfile:1
FROM {base_image_digest}

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

LABEL {_image_label("base_image_digest")}="{base_image_digest}" \\
      {_image_label("recipe_sha256")}="${{CANARY_RECIPE_SHA256}}" \\
      {_image_label("target_version")}="${{CANARY_TARGET_VERSION}}" \\
      {_image_label("package_integrity")}="${{CANARY_NPM_INTEGRITY}}" \\
      {_image_label("node_version")}="${{CANARY_NODE_VERSION}}" \\
      {_image_label("os")}="${{CANARY_OS_RELEASE}}" \\
      {_image_label("arch")}="${{CANARY_ARCH}}" \\
      {_image_label("image_family")}="${{CANARY_IMAGE_FAMILY}}" \\
      {_image_label("contract_sha256")}="${{CANARY_CONTRACT_SHA256}}"

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
    return ImageBuildPlan(
        target_name=target_name,
        image_tag=target.image_tag,
        base_image_digest=base_image_digest,
        dockerfile=dockerfile,
        recipe_sha256=recipe_sha256,
        build_args=build_args,
    )


def _secure_image_probe_argv(
    image_digest: str, executable: str, *arguments: str
) -> list[str]:
    if not _IMAGE_DIGEST_RE.fullmatch(image_digest):
        raise IntegrityError("image probe requires an immutable image digest")
    if executable not in {"gemini", "node", "cat"}:
        raise IntegrityError("image probe executable is not trusted")
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
    return {
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
    """Inspect and actively probe a built image before any OpenBench claim."""

    target = target_for(contract, target_name)
    if plan.target_name != target_name or plan.image_tag != target.image_tag:
        raise IntegrityError("image build plan targets the wrong arm")
    expected_plan = render_image_build_plan(
        contract, target_name, base_image_digest=plan.base_image_digest
    )
    if plan != expected_plan:
        raise IntegrityError("image build plan is not the canonical trusted recipe")
    inspect = runner(
        ["docker", "image", "inspect", target.image_tag],
        timeout=20,
        max_output_bytes=256 * 1024,
    )
    if inspect.returncode != 0:
        raise IntegrityError("cannot inspect target image: " + inspect.stderr[-2000:])
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
    build_args = dict(plan.build_args)
    expected_labels = {
        _image_label("base_image_digest"): plan.base_image_digest,
        _image_label("recipe_sha256"): plan.recipe_sha256,
        _image_label("target_version"): target.version,
        _image_label("package_integrity"): target.npm_integrity,
        _image_label("node_version"): target.node_version,
        _image_label("os"): target.os,
        _image_label("arch"): target.arch,
        _image_label("image_family"): target.image_family,
        _image_label("contract_sha256"): contract.raw_sha256,
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise IntegrityError("Docker image labels do not match the trusted build plan")
    if build_args.get("CANARY_RECIPE_SHA256") != plan.recipe_sha256:
        raise IntegrityError("image build plan recipe argument mismatch")

    version_probe = runner(
        _secure_image_probe_argv(image_id, "gemini", "--version"),
        timeout=15,
        max_output_bytes=64 * 1024,
    )
    version_text = (version_probe.stdout + "\n" + version_probe.stderr).strip()
    if version_probe.returncode != 0 or not re.search(
        rf"(?<![0-9]){re.escape(target.version)}(?![0-9])", version_text
    ):
        raise IntegrityError("image CLI version does not match the target")
    node_probe = runner(
        _secure_image_probe_argv(image_id, "node", "--version"),
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
        _secure_image_probe_argv(image_id, "cat", "/etc/os-release"),
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
    )
    attestation = ImageAttestation(
        **{
            **_attestation_payload(provisional),
            "attestation_sha256": hashlib.sha256(
                canonical_json_bytes(_attestation_payload(provisional))
            ).hexdigest(),
        }
    )
    verify_image_attestation(contract, target_name, attestation)
    return attestation


def validate_secure_docker_argv(argv: object) -> tuple[str, ...]:
    """Verify the exact effective Docker policy recorded by OpenBench."""

    errors: list[str] = []
    if not isinstance(argv, list) or not argv or not all(
        isinstance(item, str) for item in argv
    ):
        return ("docker_argv_invalid",)
    if argv[:3] != ["docker", "run", "--rm"]:
        errors.append("docker_prefix")
    banned = {
        "--privileged",
        "--env-file",
        "--pid=host",
        "--ipc=host",
        "--network=host",
        "--device",
    }
    if any(item in banned for item in argv):
        errors.append("docker_escape_flag")
    if any("docker.sock" in item for item in argv):
        errors.append("docker_socket")

    def pair_present(flag: str, value: str) -> bool:
        return any(
            argv[index] == flag and index + 1 < len(argv) and argv[index + 1] == value
            for index in range(len(argv))
        )

    for flag, value, label in (
        ("--cpus", "2", "cpus"),
        ("--memory", "2g", "memory"),
        ("--memory-swap", "2g", "memory_swap"),
        ("--pids-limit", "256", "pids"),
        ("--ulimit", "nofile=4096:4096", "nofile"),
        ("--network", "none", "network"),
        ("--cap-drop", "ALL", "cap_drop"),
        ("--security-opt", "no-new-privileges", "no_new_privileges"),
    ):
        if not pair_present(flag, value):
            errors.append(f"docker_policy_{label}")
    if "--read-only" not in argv:
        errors.append("docker_policy_read_only")
    required_tmpfs = {
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "/root:rw,noexec,nosuid,nodev,size=64m",
    }
    observed_tmpfs = {
        argv[index + 1]
        for index, item in enumerate(argv[:-1])
        if item == "--tmpfs"
    }
    if observed_tmpfs != required_tmpfs:
        errors.append("docker_policy_tmpfs")

    volume_specs: list[str] = []
    bind_specs: list[str] = []
    env_specs: list[str] = []
    for index, item in enumerate(argv[:-1]):
        if item == "--mount":
            volume_specs.append(argv[index + 1])
        elif item == "-v":
            bind_specs.append(argv[index + 1])
        elif item in {"-e", "--env"}:
            env_specs.append(argv[index + 1])
    work_volumes = [
        item
        for item in volume_specs
        if "type=volume" in item and ("dst=/work" in item or "target=/work" in item)
    ]
    if len(work_volumes) != 1 or "readonly" in work_volumes[0]:
        errors.append("docker_work_volume")
    if any("type=bind" in item for item in volume_specs):
        errors.append("docker_mount_bind")
    if any(not item.endswith(":ro") for item in bind_specs):
        errors.append("docker_writable_host_bind")
    if set(env_specs) != {"BENCH_WORKDIR=/work", "HOME=/root"}:
        errors.append("docker_environment_surface")
    return tuple(sorted(set(errors)))


def build_openbench_argv(
    contract: Contract,
    pack_root: str | os.PathLike[str],
    results_path: str | os.PathLike[str],
    image_digest: str,
) -> list[str]:
    if not _IMAGE_DIGEST_RE.fullmatch(image_digest):
        raise IntegrityError("OpenBench run requires an exact image digest")
    root = Path(pack_root).resolve()
    return [
        sys.executable,
        "-m",
        "obench.run",
        "--task",
        contract.contract_id,
        "--candidate",
        str(root / "candidate.toml"),
        "--model",
        "none",
        "--trials",
        "1",
        "--timeout",
        str(contract.timeout_s),
        "--checker-timeout",
        "20",
        "--tasks-dir",
        str(root),
        "--results-path",
        str(Path(results_path).resolve()),
        "--exec",
        "docker",
        "--docker-image",
        image_digest,
        "--no-docker-fallback",
        "--force",
    ]


def secure_openbench_environment(
    docker_tmpdir: str | os.PathLike[str],
) -> dict[str, str]:
    """Return the minimal trusted control-plane environment for OpenBench."""

    allowed_names = (
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    )
    env = {name: os.environ[name] for name in allowed_names if os.environ.get(name)}
    env["OPENBENCH_SECURE_NO_HOST_WRITE"] = "1"
    env["OPENBENCH_DOCKER_TMPDIR"] = str(Path(docker_tmpdir).resolve())
    env["PYTHONHASHSEED"] = "0"
    return env


def run_openbench_once(
    contract: Contract,
    *,
    pack_root: str | os.PathLike[str],
    results_path: str | os.PathLike[str],
    image_digest: str,
    openbench_root: str | os.PathLike[str],
) -> subprocess.CompletedProcess[str]:
    """Run one immutable target arm; callers run baseline and candidate separately."""

    verify_generated_pack(contract, pack_root)
    results = Path(results_path)
    if results.exists():
        raise IntegrityError("immutable run results path already exists")
    results.parent.mkdir(parents=True, exist_ok=True)
    tmpdir = results.parent / "docker-tmp"
    tmpdir.mkdir(mode=0o700, exist_ok=True)
    argv = build_openbench_argv(contract, pack_root, results, image_digest)
    if "--allow-version-drift" in argv or "--docker-fallback" in argv:
        raise IntegrityError("forbidden OpenBench compatibility flag")
    completed = bounded_run(
        argv,
        cwd=Path(openbench_root).resolve(),
        env=secure_openbench_environment(tmpdir),
        timeout=contract.timeout_s + 120,
        max_output_bytes=MAX_CONTROL_OUTPUT_BYTES,
    )
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr)[-4000:]
        raise IntegrityError(f"OpenBench immutable run failed: {detail}")
    if not results.is_file():
        raise IntegrityError("OpenBench run produced no export")
    return completed


_OPENBENCH_REQUIRED_FIELDS = {
    "run_id",
    "harness",
    "task",
    "trial",
    "completed",
    "error",
    "output_tail",
    "cmd",
    "checker_exit",
    "success",
    "harness_version",
    "harness_version_source",
    "exec_mode",
    "image_digest",
    "candidate_provenance",
    "workspace_changed",
    "checker_stdout",
    "checker_stderr",
    "checker_workspace_files",
    "timeout_s",
    "failure_class",
    "failure_reason",
    "version_drift",
}


def _read_single_jsonl(path: Path, expected_sha256: str) -> tuple[dict[str, object], str]:
    if not _SHA256_RE.fullmatch(expected_sha256):
        raise IntegrityError("expected export SHA-256 is malformed")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise IntegrityError("export must be a regular non-symlink file")
    if info.st_size > MAX_EXPORT_BYTES:
        raise IntegrityError("export exceeds the 4 MiB limit")
    payload = path.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected_sha256:
        raise IntegrityError("immutable export SHA-256 mismatch")
    lines = [line for line in payload.splitlines() if line.strip()]
    if len(lines) != 1:
        raise IntegrityError("immutable run export must contain exactly one row")
    try:
        row = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"invalid OpenBench JSONL row: {exc}") from exc
    if not isinstance(row, dict):
        raise IntegrityError("OpenBench row must be an object")
    return row, hashlib.sha256(lines[0]).hexdigest()


def _normalize_diagnostic(output: str, exit_code: int | None, timed_out: bool) -> str:
    lowered = output.lower()
    if "unknown argument: c" in lowered:
        return "unknown_argument_c"
    if "sandbox image" in lowered and ("missing" in lowered or "pull" in lowered):
        return "sandbox_runtime_unavailable"
    if "cannot connect" in lowered and "docker" in lowered:
        return "sandbox_runtime_unavailable"
    if any(token in lowered for token in ("api key", "authentication required", "login required")):
        return "auth_required"
    if timed_out:
        return "timeout"
    if exit_code == 0:
        return "no_error"
    return "other_error"


def _target_exit(row: Mapping[str, object]) -> tuple[int | None, int | None, bool]:
    completed = row.get("completed")
    error = row.get("error")
    if completed is True and error is None:
        return 0, None, False
    if isinstance(error, str):
        match = re.fullmatch(r"exit (-?[0-9]+)", error.strip())
        if match:
            returncode = int(match.group(1))
            if returncode < 0:
                return None, -returncode, False
            return returncode, None, False
        if error.startswith("timeout after "):
            return None, None, True
    return None, None, False


def target_for(contract: Contract, name: str) -> TargetSpec:
    if name == "baseline":
        return contract.baseline
    if name == "candidate":
        return contract.candidate
    raise IntegrityError("target name must be baseline or candidate")


def verify_export(
    contract: Contract,
    *,
    target_name: str,
    export_path: str | os.PathLike[str],
    expected_export_sha256: str,
    image_attestation: ImageAttestation,
    pack_root: str | os.PathLike[str],
) -> VerifiedExport:
    """Verify, normalize, and classify one immutable OpenBench export."""

    target = target_for(contract, target_name)
    verify_image_attestation(contract, target_name, image_attestation)
    expected_image_digest = image_attestation.image_digest
    receipt = verify_generated_pack(contract, pack_root)
    row, row_sha256 = _read_single_jsonl(
        Path(export_path), expected_export_sha256
    )
    integrity_errors: list[str] = []
    missing = sorted(_OPENBENCH_REQUIRED_FIELDS - set(row))
    integrity_errors.extend(f"missing:{field}" for field in missing)

    if row.get("task") != contract.contract_id:
        integrity_errors.append("task_identity")
    if row.get("harness") != f"canary-{contract.contract_id}":
        integrity_errors.append("harness_identity")
    if row.get("trial") != 1:
        integrity_errors.append("trial")
    if row.get("exec_mode") != "docker":
        integrity_errors.append("exec_mode")
    if row.get("version_drift") is not False:
        integrity_errors.append("version_drift")
    if row.get("image_digest") != expected_image_digest:
        integrity_errors.append("image_digest")
    if row.get("harness_version") != target.version:
        integrity_errors.append("target_version")
    if row.get("harness_version_source") != "container":
        integrity_errors.append("version_source")
    if row.get("timeout_s") != contract.timeout_s:
        integrity_errors.append("timeout_policy")
    if row.get("checker_exit") != 0:
        integrity_errors.append("fixed_checker_exit")
    if "CANARY_VERIFIER_OK" not in str(row.get("checker_stdout") or ""):
        integrity_errors.append("fixed_checker_evidence")
    if row.get("workspace_changed") is not False:
        integrity_errors.append("workspace_changed")

    provenance = row.get("candidate_provenance")
    candidate_digest = receipt["files"].get("candidate.toml")
    if not isinstance(provenance, dict):
        integrity_errors.append("candidate_provenance")
    else:
        if provenance.get("spec_sha256") != candidate_digest:
            integrity_errors.append("candidate_spec_digest")
        if provenance.get("command") != list(contract.probe["argv"]):
            integrity_errors.append("candidate_command")
        if provenance.get("version_command") != list(contract.probe["version_argv"]):
            integrity_errors.append("candidate_version_command")
        if provenance.get("inherit_env") is not False or provenance.get("pass_env") != []:
            integrity_errors.append("candidate_environment")
        if provenance.get("auth_files") != []:
            integrity_errors.append("candidate_auth")

    cmd = row.get("cmd")
    if not isinstance(cmd, dict):
        integrity_errors.append("command_provenance")
        docker_errors = ("docker_argv_missing",)
    else:
        if cmd.get("adapter_cmd") != list(contract.probe["argv"]):
            integrity_errors.append("effective_stimulus")
        docker_errors = validate_secure_docker_argv(cmd.get("docker"))
    integrity_errors.extend(docker_errors)

    output = row.get("output_tail")
    if not isinstance(output, str):
        integrity_errors.append("output_tail")
        output = ""
    elif len(output) > MAX_PUBLIC_DIAGNOSTIC_CHARS or "\x00" in output:
        integrity_errors.append("output_tail_budget")
    exit_code, signal_number, timed_out = _target_exit(row)
    if exit_code is None and signal_number is None and not timed_out:
        integrity_errors.append("target_exit_unavailable")
    diagnostic = _normalize_diagnostic(output, exit_code, timed_out)
    accepted = set(contract.probe["accepted_diagnostics"])
    evidence_complete = diagnostic in accepted
    oracle_valid = evidence_complete
    assertions = tuple(
        AssertionObservation(
            assertion_id=item.assertion_id,
            required=item.required,
            supported=True,
            passed=(diagnostic != item.forbidden_normalized) if evidence_complete else None,
            evidence_complete=evidence_complete,
            oracle_valid=oracle_valid,
        )
        for item in contract.assertions
    )
    controls = canonical_items(
        {
            "target.version": image_attestation.target_version,
            "image.digest": expected_image_digest,
            "image.base_digest": image_attestation.base_image_digest,
            "image.family": image_attestation.image_family,
            "image.recipe_sha256": image_attestation.recipe_sha256,
            "package.integrity": image_attestation.package_integrity,
            "runtime.node": image_attestation.node_version,
            "os": image_attestation.os,
            "arch": image_attestation.arch,
            "credential.mode": contract.credential_mode,
            "execution.policy": CONTAINMENT_POLICY_SHA256,
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
        run_id=str(row.get("run_id") or ""),
        contract_digest=contract.raw_sha256,
        execution_lane=contract.execution_lane,
        target_identity=f"gemini-cli@{target.version}",
        controls=controls,
        normalized_observations=normalized,
        assertions=assertions,
        integrity_errors=tuple(sorted(set(integrity_errors))),
        capability_status=CapabilityStatus.SUPPORTED,
        capability_probe_deterministic=True,
        evidence_complete=evidence_complete,
        evidence_contradictory=False,
        nondeterminism_within_policy=True,
        oracle_valid=oracle_valid,
    )
    result = classify_run(observation)
    public_values = {
        "target.version": image_attestation.target_version,
        "target.exit_code": "none" if exit_code is None else str(exit_code),
        "target.signal": "none" if signal_number is None else str(signal_number),
        "target.diagnostic": diagnostic,
        "image.digest": expected_image_digest,
        "image.attestation_sha256": image_attestation.attestation_sha256,
        "package.integrity": image_attestation.package_integrity,
        "runtime.node": image_attestation.node_version,
        "export.sha256": expected_export_sha256,
    }
    public_evidence = canonical_items(
        {
            key: public_values[key]
            for key in contract.evidence_allowlist
        }
    )
    return VerifiedExport(
        target_name=target_name,
        export_sha256=expected_export_sha256,
        row_sha256=row_sha256,
        image_digest=expected_image_digest,
        image_attestation_sha256=image_attestation.attestation_sha256,
        run_result=result,
        public_evidence=public_evidence,
    )


def compare_verified_exports(
    contract: Contract,
    baseline: VerifiedExport,
    candidate: VerifiedExport,
) -> PairResult:
    if baseline.target_name != "baseline" or candidate.target_name != "candidate":
        raise IntegrityError("verified exports are not ordered baseline/candidate")
    policy = PairPolicy(
        matched_control_keys=contract.matched_controls,
        intended_changed_control_keys=contract.intended_changed_controls,
        deterministic_cli_oracle=True,
    )
    return compare_pair(baseline.run_result, candidate.run_result, policy)


_PUBLIC_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"/Users/[^/\s]+/"),
)


def assert_public_safe(payload: bytes, contract: Contract) -> None:
    text = payload.decode("utf-8")
    patterns = list(_PUBLIC_SECRET_PATTERNS)
    patterns.extend(re.compile(pattern) for pattern in contract.redaction_patterns)
    for pattern in patterns:
        if pattern.search(text):
            raise IntegrityError(f"public artifact hit redaction sink: {pattern.pattern}")


def render_public_bundle(
    contract: Contract,
    baseline: VerifiedExport,
    candidate: VerifiedExport,
    pair: PairResult,
) -> tuple[bytes, bytes]:
    """Render byte-stable public JSON and Markdown from already-classified data."""

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
        "openbench": {
            "commit": OPENBENCH_COMMIT,
            "fixed_checker_sha256": FIXED_CHECKER_SHA256,
            "containment_policy_sha256": CONTAINMENT_POLICY_SHA256,
        },
        "runs": {
            "baseline": {
                "result": run_result_to_dict(baseline.run_result),
                "evidence": dict(baseline.public_evidence),
            },
            "candidate": {
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
        f"OpenBench: `{OPENBENCH_COMMIT}`",
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
            "Raw transcripts, credentials, host paths, and unallowlisted OpenBench fields "
            "are intentionally excluded.",
            "",
        ]
    )
    markdown_bytes = "\n".join(lines).encode("utf-8")
    assert_public_safe(json_bytes, contract)
    assert_public_safe(markdown_bytes, contract)
    return json_bytes, markdown_bytes


def write_public_bundle(
    contract: Contract,
    baseline: VerifiedExport,
    candidate: VerifiedExport,
    pair: PairResult,
    destination: str | os.PathLike[str],
) -> Path:
    root = Path(destination)
    if root.exists() and any(root.iterdir()):
        raise IntegrityError("public bundle destination must be absent or empty")
    root.mkdir(parents=True, exist_ok=True)
    json_bytes, markdown_bytes = render_public_bundle(
        contract, baseline, candidate, pair
    )
    manifest = {
        "schema_version": PUBLIC_BUNDLE_SCHEMA_VERSION,
        "files": {
            "result.json": hashlib.sha256(json_bytes).hexdigest(),
            "README.md": hashlib.sha256(markdown_bytes).hexdigest(),
        },
    }
    _write_bytes(root / "result.json", json_bytes, 0o444)
    _write_bytes(root / "README.md", markdown_bytes, 0o444)
    _write_bytes(root / "manifest.json", canonical_json_bytes(manifest), 0o444)
    return root


def export_sha256(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def isolated_pack(contract: Contract):
    """Convenience context manager used by the spike and tests."""

    class _PackContext:
        def __enter__(self) -> Path:
            self._tmp = tempfile.TemporaryDirectory(prefix="canary_pack_")
            return generate_pack(contract, self._tmp.name)

        def __exit__(self, exc_type, exc, traceback) -> None:
            self._tmp.cleanup()

    return _PackContext()
