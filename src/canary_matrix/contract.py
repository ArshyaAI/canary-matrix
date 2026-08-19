"""Strict declarative contracts and public-output safety for Canary Matrix."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import date
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from .core import ExecutionLane


CONTRACT_SCHEMA_VERSION = "canary-contract/v0.1"
MAX_CONTRACT_BYTES = 256 * 1024

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$")
_IMAGE_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{2,200}$")
_NPM_INTEGRITY_RE = re.compile(r"^sha512-[A-Za-z0-9+/]+={0,2}$")
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PLATFORM_TEXT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")

_ALLOWED_FIX_STATES = {
    "reported",
    "proposed_unmerged",
    "merged_unreleased",
    "released",
    "unknown",
}


class ContractError(ValueError):
    """The declarative contract is malformed or attempts to expand authority."""


class IntegrityError(RuntimeError):
    """A runner, immutable artifact, or public binding failed integrity."""


PROBE_REGISTRY = MappingProxyType(
    {
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
        "codex_trust_enter_39487": MappingProxyType(
            {
                "argv": ("codex",),
                "version_argv": ("codex", "--version"),
                "instruction": (
                    "Credential-free PTY calibration derived from OpenAI Codex CLI "
                    "issue #39487. The fixed 80x30 probe starts bare Codex with fresh "
                    "existing HOME=/tmp and no CODEX_HOME override, waits for the "
                    "first rendered trust-dialog marker, sends carriage return with "
                    "zero intentional delay, and observes one bounded post-marker window."
                ),
                "accepted_diagnostics": (
                    "trust_dialog_advanced",
                    "trust_dialog_stuck",
                ),
                "forbidden_diagnostic": "trust_dialog_stuck",
                "marker": b"Press enter to continue",
                "input": b"\r",
                "input_delay_ms": 0,
                "post_marker_window_ms": 1000,
                "terminal_columns": 80,
                "terminal_rows": 30,
                "package_spec": "@openai/codex",
                "platform_package_spec": "@openai/codex@{version}-linux-arm64",
                "platform_package_alias": "@openai/codex-linux-arm64",
                "platform_binary_relative": (
                    "vendor/aarch64-unknown-linux-musl/bin/codex"
                ),
                "target_identity_prefix": "@openai/codex",
            }
        ),
    }
)


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
    platform_npm_integrity: str | None = None
    wrapper_sha256: str | None = None
    platform_binary_sha256: str | None = None


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
    baseline: TargetSpec
    candidate: TargetSpec

    @property
    def probe(self) -> Mapping[str, object]:
        return PROBE_REGISTRY[self.probe_kind]


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
    if any(ord(char) < 32 for char in value):
        raise ContractError(f"{context}: control characters are forbidden")
    return value


def _string_list(
    value: object,
    context: str,
    *,
    min_items: int = 1,
    max_items: int = 32,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not min_items <= len(value) <= max_items:
        raise ContractError(
            f"{context}: expected array with {min_items}..{max_items} items"
        )
    items = tuple(_string(item, f"{context}[]") for item in value)
    if len(set(items)) != len(items):
        raise ContractError(f"{context}: duplicate values are forbidden")
    return items


def _fixture_content(value: object, context: str) -> bytes:
    if not isinstance(value, str):
        raise ContractError(f"{context}: expected UTF-8 text")
    encoded = value.encode("utf-8")
    if len(encoded) > 64 * 1024:
        raise ContractError(f"{context}: fixture file exceeds 64 KiB")
    if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        raise ContractError(f"{context}: unsafe control character")
    return encoded


def _safe_relative_path(value: object, context: str) -> str:
    raw = _string(value, context, max_chars=160)
    if "\\" in raw:
        raise ContractError(f"{context}: backslashes are forbidden")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or raw.startswith("./")
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(not _SAFE_COMPONENT_RE.fullmatch(part) for part in path.parts)
    ):
        raise ContractError(f"{context}: unsafe fixture-relative path")
    return path.as_posix()


def _parse_npm_integrity(value: object, context: str) -> str:
    integrity = _string(value, context, max_chars=160)
    if not _NPM_INTEGRITY_RE.fullmatch(integrity):
        raise ContractError(f"{context}: invalid sha512 SRI")
    try:
        decoded = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ContractError(f"{context}: invalid base64 digest") from exc
    if len(decoded) != hashlib.sha512().digest_size:
        raise ContractError(f"{context}: expected a 64-byte SHA-512 digest")
    return integrity


def _parse_sha256(value: object, context: str) -> str:
    digest = _string(value, context, max_chars=64)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ContractError(f"{context}: expected lowercase SHA-256")
    return digest


def _parse_target(
    name: str, value: object, *, requires_platform_integrity: bool
) -> TargetSpec:
    context = f"targets.{name}"
    if not isinstance(value, dict):
        raise ContractError(f"{context}: expected table")
    required = {
        "version",
        "image_tag",
        "image_family",
        "npm_integrity",
        "node_version",
        "os",
        "arch",
    }
    if requires_platform_integrity:
        required.update(
            {
                "platform_npm_integrity",
                "wrapper_sha256",
                "platform_binary_sha256",
            }
        )
    _strict_keys(value, required=required, context=context)
    version = _string(value["version"], f"{context}.version", max_chars=80)
    if not _VERSION_RE.fullmatch(version):
        raise ContractError(f"{context}.version: invalid semantic version")
    image_tag = _string(value["image_tag"], f"{context}.image_tag", max_chars=200)
    if not _IMAGE_TAG_RE.fullmatch(image_tag):
        raise ContractError(f"{context}.image_tag: invalid image reference")
    image_family = _string(
        value["image_family"], f"{context}.image_family", max_chars=100
    )
    if not _ID_RE.fullmatch(image_family):
        raise ContractError(f"{context}.image_family: invalid identifier")
    node_version = _string(
        value["node_version"], f"{context}.node_version", max_chars=40
    )
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+\.[0-9]+)?", node_version):
        raise ContractError(f"{context}.node_version: invalid expectation")
    os_name = _string(value["os"], f"{context}.os", max_chars=80)
    if not _PLATFORM_TEXT_RE.fullmatch(os_name):
        raise ContractError(f"{context}.os: invalid platform value")
    arch = _string(value["arch"], f"{context}.arch", max_chars=40)
    if arch not in {"amd64", "arm64"}:
        raise ContractError(f"{context}.arch: unsupported architecture")
    platform_npm_integrity = None
    wrapper_sha256 = None
    platform_binary_sha256 = None
    if requires_platform_integrity:
        if arch != "arm64":
            raise ContractError(
                f"{context}.arch: trusted Codex platform package requires arm64"
            )
        platform_npm_integrity = _parse_npm_integrity(
            value["platform_npm_integrity"],
            f"{context}.platform_npm_integrity",
        )
        wrapper_sha256 = _parse_sha256(
            value["wrapper_sha256"], f"{context}.wrapper_sha256"
        )
        platform_binary_sha256 = _parse_sha256(
            value["platform_binary_sha256"],
            f"{context}.platform_binary_sha256",
        )
    return TargetSpec(
        name=name,
        version=version,
        image_tag=image_tag,
        image_family=image_family,
        npm_integrity=_parse_npm_integrity(
            value["npm_integrity"], f"{context}.npm_integrity"
        ),
        node_version=node_version,
        os=os_name,
        arch=arch,
        platform_npm_integrity=platform_npm_integrity,
        wrapper_sha256=wrapper_sha256,
        platform_binary_sha256=platform_binary_sha256,
    )


def load_contract(path: str | os.PathLike[str]) -> Contract:
    source = Path(path)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ContractError("contract source must be a regular non-symlink file")
    if info.st_size > MAX_CONTRACT_BYTES:
        raise ContractError("contract exceeds 256 KiB")
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
        raise ContractError("contract.id: invalid portable identifier")
    title = _string(data["title"], "contract.title", max_chars=200)
    if any(char in title for char in "<>|"):
        raise ContractError("contract.title: unsafe Markdown presentation character")
    capture_date = _string(data["capture_date"], "contract.capture_date", max_chars=10)
    try:
        parsed_date = date.fromisoformat(capture_date)
    except ValueError as exc:
        raise ContractError("contract.capture_date: expected ISO date") from exc
    if parsed_date > date.today():
        raise ContractError("contract.capture_date: future date")
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
    if any(not _ID_RE.fullmatch(item) for item in systems):
        raise ContractError("contract.systems: invalid identifier")
    credential_mode = _string(
        data["credential_mode"], "contract.credential_mode", max_chars=40
    )
    if credential_mode != "none":
        raise ContractError("v0.1 accepts credential_mode='none' only")
    try:
        lane = ExecutionLane(data["execution_lane"])
    except (TypeError, ValueError) as exc:
        raise ContractError("contract.execution_lane: unknown lane") from exc
    probe_kind = _string(data["probe_kind"], "contract.probe_kind", max_chars=80)
    if probe_kind not in PROBE_REGISTRY:
        raise ContractError("contract.probe_kind: no trusted implementation")
    expected_lane = (
        ExecutionLane.CONTAINER_PTY_NO_HOST_WRITE
        if probe_kind == "codex_trust_enter_39487"
        else ExecutionLane.CONTAINER_NO_HOST_WRITE
    )
    if lane is not expected_lane:
        raise ContractError(
            f"contract.execution_lane: {probe_kind} requires {expected_lane.value}"
        )
    timeout_s = data["timeout_s"]
    if (
        not isinstance(timeout_s, int)
        or isinstance(timeout_s, bool)
        or not 1 <= timeout_s <= 60
    ):
        raise ContractError("contract.timeout_s: expected integer 1..60")
    if data["trials"] != 1:
        raise ContractError("v0.1 deterministic contracts require one trial")

    fixture = data["fixture"]
    if not isinstance(fixture, dict):
        raise ContractError("contract.fixture: expected table")
    _strict_keys(fixture, required={"files"}, context="contract.fixture")
    raw_files = fixture["files"]
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= 16:
        raise ContractError("contract.fixture.files: expected 1..16 file tables")
    fixture_files: list[FixtureFile] = []
    fixture_paths: set[str] = set()
    fixture_total = 0
    for index, item in enumerate(raw_files):
        context = f"contract.fixture.files[{index}]"
        if not isinstance(item, dict):
            raise ContractError(f"{context}: expected table")
        _strict_keys(item, required={"path", "content"}, context=context)
        relative = _safe_relative_path(item["path"], f"{context}.path")
        if relative in fixture_paths:
            raise ContractError(f"{context}.path: duplicate")
        fixture_paths.add(relative)
        content = _fixture_content(item["content"], f"{context}.content")
        fixture_total += len(content)
        if fixture_total > 128 * 1024:
            raise ContractError("contract.fixture: total content exceeds 128 KiB")
        fixture_files.append(FixtureFile(relative, content))

    raw_assertions = data["assertions"]
    if not isinstance(raw_assertions, list) or not 1 <= len(raw_assertions) <= 16:
        raise ContractError("contract.assertions: expected 1..16 tables")
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
            raise ContractError(f"{context}.id: invalid or duplicate")
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
        if forbidden != PROBE_REGISTRY[probe_kind]["forbidden_diagnostic"]:
            raise ContractError(f"{context}.forbidden_normalized: probe conflict")
        assertions.append(
            ContractAssertion(assertion_id, item["kind"], item["required"], forbidden)
        )

    targets = data["targets"]
    if not isinstance(targets, dict):
        raise ContractError("contract.targets: expected table")
    _strict_keys(targets, required={"baseline", "candidate"}, context="contract.targets")
    requires_platform_integrity = probe_kind == "codex_trust_enter_39487"
    baseline = _parse_target(
        "baseline",
        targets["baseline"],
        requires_platform_integrity=requires_platform_integrity,
    )
    candidate = _parse_target(
        "candidate",
        targets["candidate"],
        requires_platform_integrity=requires_platform_integrity,
    )
    if baseline.version == candidate.version:
        raise ContractError("contract.targets: versions must differ")
    if any(
        getattr(baseline, key) != getattr(candidate, key)
        for key in ("image_family", "node_version", "os", "arch")
    ):
        raise ContractError("contract.targets: platform controls must match")

    matched_controls = _string_list(
        data["matched_controls"], "contract.matched_controls", max_items=32
    )
    intended_controls = _string_list(
        data["intended_changed_controls"],
        "contract.intended_changed_controls",
        max_items=16,
    )
    expected_matched = {
        "os",
        "arch",
        "runtime.node",
        "credential.mode",
        "execution.policy",
        "image.base_digest",
        "image.family",
        "image.recipe_sha256",
    }
    expected_changed = {"target.version", "image.digest", "package.integrity"}
    if requires_platform_integrity:
        expected_matched.update(
            {
                "probe.input_delay_ms",
                "probe.input_sha256",
                "probe.marker_sha256",
                "probe.post_marker_window_ms",
                "terminal.columns",
                "terminal.rows",
                "package.wrapper_sha256",
            }
        )
        expected_changed.update(
            {"package.platform_integrity", "package.platform_binary_sha256"}
        )
    if set(matched_controls) != expected_matched or set(intended_controls) != expected_changed:
        raise ContractError("contract control policy conflicts with v0.1")

    evidence_allowlist = _string_list(
        data["evidence_allowlist"], "contract.evidence_allowlist", max_items=32
    )
    allowed_evidence = {
        "target.version",
        "target.exit_code",
        "target.signal",
        "target.diagnostic",
        "image.digest",
        "image.attestation_sha256",
        "package.integrity",
        "package.platform_integrity",
        "package.wrapper_sha256",
        "package.platform_binary_sha256",
        "runtime.node",
        "export.sha256",
    }
    if not set(evidence_allowlist) <= allowed_evidence:
        raise ContractError("contract.evidence_allowlist: non-public field")
    redaction_patterns = data["redaction_patterns"]
    if redaction_patterns != []:
        raise ContractError("v0.1 contracts cannot supply redaction code")

    return Contract(
        path=str(source.resolve()),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        contract_id=contract_id,
        title=title,
        capture_date=capture_date,
        fix_state=fix_state,
        source_urls=source_urls,
        source_verified=data["source_verified"],
        capability=_string(data["capability"], "contract.capability", max_chars=160),
        systems=systems,
        credential_mode=credential_mode,
        execution_lane=lane,
        probe_kind=probe_kind,
        timeout_s=timeout_s,
        trials=1,
        fixture_files=tuple(fixture_files),
        assertions=tuple(assertions),
        matched_controls=matched_controls,
        intended_changed_controls=intended_controls,
        evidence_allowlist=evidence_allowlist,
        baseline=baseline,
        candidate=candidate,
    )


def target_for(contract: Contract, name: str) -> TargetSpec:
    if name == "baseline":
        return contract.baseline
    if name == "candidate":
        return contract.candidate
    raise IntegrityError("target name must be baseline or candidate")


_PUBLIC_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"/Users/[^/\s]+/"),
)


def assert_public_safe(payload: bytes, contract: Contract) -> None:
    del contract  # schema v0.1 intentionally has no contract-authored regex code
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError("public artifact must be UTF-8") from exc
    for pattern in _PUBLIC_SECRET_PATTERNS:
        if pattern.search(text):
            raise IntegrityError(
                f"public artifact hit redaction sink: {pattern.pattern}"
            )
