"""Canonical Canary Matrix state and comparison semantics.

This module is deliberately dependency-free. Execution adapters, verifier
bridges, and renderers may produce observations, but only these pure functions
may produce Canary run or pair verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re
from typing import Iterable, Mapping, Sequence


SCHEMA_VERSION = "canary-matrix/v0.1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CanonicalItems = tuple[tuple[str, str], ...]


class RunState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"
    RUNNER_ERROR = "runner_error"


class PairState(str, Enum):
    NO_OBSERVED_DIFFERENCE = "no_observed_difference"
    OBSERVED_DIFFERENCE = "observed_difference"
    NOT_COMPARABLE = "not_comparable"


class ClaimTier(str, Enum):
    OBSERVATIONAL = "observational"
    DETERMINISTIC_CLI_DELTA = "deterministic_cli_delta"


class CapabilityStatus(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ExecutionLane(str, Enum):
    CONTAINER_NO_HOST_WRITE = "container_no_host_write"
    MONITORED_LOCAL = "monitored_local"


class RunReason(str, Enum):
    INVALID_SCHEMA = "invalid_schema"
    INVALID_OBSERVATION = "invalid_observation"
    INTEGRITY_FAILURE = "integrity_failure"
    CAPABILITY_UNSUPPORTED = "capability_unsupported"
    CAPABILITY_ABSENCE_UNPROVEN = "capability_absence_unproven"
    CAPABILITY_UNKNOWN = "capability_unknown"
    REQUIRED_EVIDENCE_INCOMPLETE = "required_evidence_incomplete"
    EVIDENCE_CONTRADICTORY = "evidence_contradictory"
    NONDETERMINISM_EXCEEDED = "nondeterminism_exceeded"
    INVALID_ORACLE = "invalid_oracle"
    NO_REQUIRED_ASSERTIONS = "no_required_assertions"
    REQUIRED_ASSERTION_UNSUPPORTED = "required_assertion_unsupported"
    REQUIRED_ASSERTION_INCOMPLETE = "required_assertion_incomplete"
    REQUIRED_ASSERTION_INVALID_ORACLE = "required_assertion_invalid_oracle"
    REQUIRED_ASSERTION_FAILED = "required_assertion_failed"
    ALL_REQUIRED_ASSERTIONS_PASSED = "all_required_assertions_passed"


class PairReason(str, Enum):
    SAME_RUN = "same_run"
    INVALID_RUN_RESULT = "invalid_run_result"
    CONTRACT_MISMATCH = "contract_mismatch"
    EXECUTION_LANE_MISMATCH = "execution_lane_mismatch"
    RUN_NOT_COMPARABLE = "run_not_comparable"
    CONTROL_KEY_MISSING = "control_key_missing"
    CONTROL_KEYSET_MISMATCH = "control_keyset_mismatch"
    MATCHED_CONTROL_MISMATCH = "matched_control_mismatch"
    UNEXPECTED_CONTROL_DIFFERENCE = "unexpected_control_difference"
    AMBIGUOUS_UNSUPPORTED_TRANSITION = "ambiguous_unsupported_transition"
    OBSERVATIONS_MATCH = "observations_match"
    OBSERVATIONS_DIFFER = "observations_differ"


@dataclass(frozen=True, slots=True)
class AssertionObservation:
    assertion_id: str
    required: bool = True
    supported: bool = True
    passed: bool | None = None
    evidence_complete: bool = True
    oracle_valid: bool = True


@dataclass(frozen=True, slots=True)
class RunObservation:
    schema_version: str
    run_id: str
    contract_digest: str
    execution_lane: ExecutionLane
    target_identity: str
    controls: CanonicalItems
    normalized_observations: CanonicalItems
    assertions: tuple[AssertionObservation, ...]
    integrity_errors: tuple[str, ...] = ()
    capability_status: CapabilityStatus = CapabilityStatus.SUPPORTED
    capability_probe_deterministic: bool = True
    evidence_complete: bool = True
    evidence_contradictory: bool = False
    nondeterminism_within_policy: bool = True
    oracle_valid: bool = True


@dataclass(frozen=True, slots=True)
class RunResult:
    schema_version: str
    run_id: str
    contract_digest: str
    execution_lane: ExecutionLane
    target_identity: str
    controls: CanonicalItems
    normalized_observations: CanonicalItems
    state: RunState
    reason_code: RunReason
    details: tuple[str, ...]
    capability_status: CapabilityStatus
    capability_probe_deterministic: bool
    oracle_valid: bool


@dataclass(frozen=True, slots=True)
class PairPolicy:
    matched_control_keys: tuple[str, ...]
    intended_changed_control_keys: tuple[str, ...] = ("target.version",)
    deterministic_cli_oracle: bool = False


@dataclass(frozen=True, slots=True)
class PairResult:
    schema_version: str
    baseline_run_id: str
    candidate_run_id: str
    state: PairState
    reason_code: PairReason
    claim_tier: ClaimTier
    changed_control_keys: tuple[str, ...]
    mismatched_control_keys: tuple[str, ...]
    differing_observation_keys: tuple[str, ...]


def canonical_items(values: Mapping[str, object] | Iterable[tuple[str, object]]) -> CanonicalItems:
    """Return sorted string key/value pairs and reject duplicate keys."""

    items = values.items() if isinstance(values, Mapping) else values
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_key, raw_value in items:
        key = str(raw_key)
        if not key or key in seen:
            raise ValueError(f"duplicate or empty canonical key: {key!r}")
        seen.add(key)
        normalized.append((key, str(raw_value)))
    return tuple(sorted(normalized))


def _base_result(
    observation: RunObservation,
    state: RunState,
    reason: RunReason,
    details: Sequence[str] = (),
) -> RunResult:
    lane = observation.execution_lane
    if not isinstance(lane, ExecutionLane):
        lane = ExecutionLane.MONITORED_LOCAL
    capability = observation.capability_status
    if not isinstance(capability, CapabilityStatus):
        capability = CapabilityStatus.UNKNOWN
    return RunResult(
        schema_version=SCHEMA_VERSION,
        run_id=observation.run_id,
        contract_digest=observation.contract_digest,
        execution_lane=lane,
        target_identity=observation.target_identity,
        controls=observation.controls,
        normalized_observations=observation.normalized_observations,
        state=state,
        reason_code=reason,
        details=tuple(details),
        capability_status=capability,
        capability_probe_deterministic=observation.capability_probe_deterministic,
        oracle_valid=observation.oracle_valid,
    )


def _observation_integrity_errors(observation: RunObservation) -> tuple[str, ...]:
    errors = list(observation.integrity_errors)
    if observation.schema_version != SCHEMA_VERSION:
        errors.append("schema_version")
    if not observation.run_id:
        errors.append("run_id")
    if not _SHA256_RE.fullmatch(observation.contract_digest):
        errors.append("contract_digest")
    if not observation.target_identity:
        errors.append("target_identity")
    if not isinstance(observation.execution_lane, ExecutionLane):
        errors.append("execution_lane")
    if not isinstance(observation.capability_status, CapabilityStatus):
        errors.append("capability_status")
    for label, items in (
        ("controls", observation.controls),
        ("normalized_observations", observation.normalized_observations),
    ):
        keys = [item[0] for item in items if isinstance(item, tuple) and len(item) == 2]
        if len(keys) != len(items) or len(keys) != len(set(keys)) or any(not key for key in keys):
            errors.append(label)
    assertion_ids = [item.assertion_id for item in observation.assertions]
    if any(not item for item in assertion_ids) or len(assertion_ids) != len(set(assertion_ids)):
        errors.append("assertions")
    return tuple(sorted(set(errors)))


def classify_run(observation: RunObservation) -> RunResult:
    """Classify one observation using the canonical fail-closed precedence.

    State machine (first matching branch wins):

        integrity -> runner_error
        explicit deterministic absence -> unsupported
        incomplete/contradictory/nondeterministic/invalid oracle -> inconclusive
        required assertion violation -> fail
        every required assertion passes -> pass
    """

    integrity_errors = _observation_integrity_errors(observation)
    if observation.schema_version != SCHEMA_VERSION:
        return _base_result(
            observation,
            RunState.RUNNER_ERROR,
            RunReason.INVALID_SCHEMA,
            integrity_errors,
        )
    if integrity_errors:
        return _base_result(
            observation,
            RunState.RUNNER_ERROR,
            RunReason.INTEGRITY_FAILURE,
            integrity_errors,
        )

    if observation.capability_status is CapabilityStatus.UNSUPPORTED:
        if observation.capability_probe_deterministic:
            return _base_result(
                observation,
                RunState.UNSUPPORTED,
                RunReason.CAPABILITY_UNSUPPORTED,
            )
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.CAPABILITY_ABSENCE_UNPROVEN,
        )
    if observation.capability_status is CapabilityStatus.UNKNOWN:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.CAPABILITY_UNKNOWN,
        )
    if not observation.evidence_complete:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.REQUIRED_EVIDENCE_INCOMPLETE,
        )
    if observation.evidence_contradictory:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.EVIDENCE_CONTRADICTORY,
        )
    if not observation.nondeterminism_within_policy:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.NONDETERMINISM_EXCEEDED,
        )
    if not observation.oracle_valid:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.INVALID_ORACLE,
        )

    required = tuple(item for item in observation.assertions if item.required)
    if not required:
        return _base_result(
            observation,
            RunState.RUNNER_ERROR,
            RunReason.NO_REQUIRED_ASSERTIONS,
        )
    unsupported = tuple(item.assertion_id for item in required if not item.supported)
    if unsupported:
        state = (
            RunState.UNSUPPORTED
            if observation.capability_probe_deterministic
            else RunState.INCONCLUSIVE
        )
        reason = (
            RunReason.REQUIRED_ASSERTION_UNSUPPORTED
            if observation.capability_probe_deterministic
            else RunReason.CAPABILITY_ABSENCE_UNPROVEN
        )
        return _base_result(observation, state, reason, unsupported)
    incomplete = tuple(item.assertion_id for item in required if not item.evidence_complete)
    if incomplete:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.REQUIRED_ASSERTION_INCOMPLETE,
            incomplete,
        )
    invalid_oracles = tuple(item.assertion_id for item in required if not item.oracle_valid)
    if invalid_oracles:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.REQUIRED_ASSERTION_INVALID_ORACLE,
            invalid_oracles,
        )
    unknown = tuple(item.assertion_id for item in required if item.passed is None)
    if unknown:
        return _base_result(
            observation,
            RunState.INCONCLUSIVE,
            RunReason.REQUIRED_ASSERTION_INCOMPLETE,
            unknown,
        )
    failed = tuple(item.assertion_id for item in required if item.passed is False)
    if failed:
        return _base_result(
            observation,
            RunState.FAIL,
            RunReason.REQUIRED_ASSERTION_FAILED,
            failed,
        )
    return _base_result(
        observation,
        RunState.PASS,
        RunReason.ALL_REQUIRED_ASSERTIONS_PASSED,
        tuple(item.assertion_id for item in required),
    )


def _pair_result(
    baseline: RunResult,
    candidate: RunResult,
    state: PairState,
    reason: PairReason,
    *,
    claim_tier: ClaimTier = ClaimTier.OBSERVATIONAL,
    changed: Sequence[str] = (),
    mismatched: Sequence[str] = (),
    differing: Sequence[str] = (),
) -> PairResult:
    return PairResult(
        schema_version=SCHEMA_VERSION,
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        state=state,
        reason_code=reason,
        claim_tier=claim_tier,
        changed_control_keys=tuple(sorted(changed)),
        mismatched_control_keys=tuple(sorted(mismatched)),
        differing_observation_keys=tuple(sorted(differing)),
    )


def compare_pair(
    baseline: RunResult,
    candidate: RunResult,
    policy: PairPolicy,
) -> PairResult:
    """Compare two independently classified immutable-run results."""

    if baseline.run_id == candidate.run_id:
        return _pair_result(
            baseline, candidate, PairState.NOT_COMPARABLE, PairReason.SAME_RUN
        )
    if baseline.schema_version != SCHEMA_VERSION or candidate.schema_version != SCHEMA_VERSION:
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.INVALID_RUN_RESULT,
        )
    if baseline.contract_digest != candidate.contract_digest:
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.CONTRACT_MISMATCH,
        )
    if baseline.execution_lane is not candidate.execution_lane:
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.EXECUTION_LANE_MISMATCH,
        )
    if baseline.state in {RunState.RUNNER_ERROR, RunState.INCONCLUSIVE} or candidate.state in {
        RunState.RUNNER_ERROR,
        RunState.INCONCLUSIVE,
    }:
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.RUN_NOT_COMPARABLE,
        )

    baseline_controls = dict(baseline.controls)
    candidate_controls = dict(candidate.controls)
    if set(baseline_controls) != set(candidate_controls):
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.CONTROL_KEYSET_MISMATCH,
        )
    missing = tuple(
        key
        for key in policy.matched_control_keys + policy.intended_changed_control_keys
        if key not in baseline_controls
    )
    if missing:
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.CONTROL_KEY_MISSING,
            mismatched=missing,
        )
    mismatched = tuple(
        key
        for key in policy.matched_control_keys
        if baseline_controls[key] != candidate_controls[key]
    )
    changed = tuple(
        key
        for key in baseline_controls
        if baseline_controls[key] != candidate_controls[key]
    )
    if mismatched:
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.MATCHED_CONTROL_MISMATCH,
            changed=changed,
            mismatched=mismatched,
        )
    if set(changed) != set(policy.intended_changed_control_keys):
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.UNEXPECTED_CONTROL_DIFFERENCE,
            changed=changed,
        )

    unsupported_count = sum(
        result.state is RunState.UNSUPPORTED for result in (baseline, candidate)
    )
    if unsupported_count and not (
        baseline.capability_probe_deterministic
        and candidate.capability_probe_deterministic
    ):
        return _pair_result(
            baseline,
            candidate,
            PairState.NOT_COMPARABLE,
            PairReason.AMBIGUOUS_UNSUPPORTED_TRANSITION,
            changed=changed,
        )

    baseline_observations = dict(baseline.normalized_observations)
    candidate_observations = dict(candidate.normalized_observations)
    observation_keys = set(baseline_observations) | set(candidate_observations)
    differing = tuple(
        key
        for key in observation_keys
        if baseline_observations.get(key) != candidate_observations.get(key)
    )
    if baseline.state is not candidate.state:
        differing += ("$state",)
    if baseline.capability_status is not candidate.capability_status:
        differing += ("$capability",)

    if not differing:
        return _pair_result(
            baseline,
            candidate,
            PairState.NO_OBSERVED_DIFFERENCE,
            PairReason.OBSERVATIONS_MATCH,
            changed=changed,
        )

    deterministic = (
        policy.deterministic_cli_oracle
        and baseline.oracle_valid
        and candidate.oracle_valid
    )
    return _pair_result(
        baseline,
        candidate,
        PairState.OBSERVED_DIFFERENCE,
        PairReason.OBSERVATIONS_DIFFER,
        claim_tier=(
            ClaimTier.DETERMINISTIC_CLI_DELTA
            if deterministic
            else ClaimTier.OBSERVATIONAL
        ),
        changed=changed,
        differing=differing,
    )


def run_result_to_dict(result: RunResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "run_id": result.run_id,
        "contract_digest": result.contract_digest,
        "execution_lane": result.execution_lane.value,
        "target_identity": result.target_identity,
        "controls": dict(result.controls),
        "normalized_observations": dict(result.normalized_observations),
        "state": result.state.value,
        "reason_code": result.reason_code.value,
        "details": list(result.details),
        "capability_status": result.capability_status.value,
        "capability_probe_deterministic": result.capability_probe_deterministic,
        "oracle_valid": result.oracle_valid,
    }


def pair_result_to_dict(result: PairResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "baseline_run_id": result.baseline_run_id,
        "candidate_run_id": result.candidate_run_id,
        "state": result.state.value,
        "reason_code": result.reason_code.value,
        "claim_tier": result.claim_tier.value,
        "changed_control_keys": list(result.changed_control_keys),
        "mismatched_control_keys": list(result.mismatched_control_keys),
        "differing_observation_keys": list(result.differing_observation_keys),
    }


def canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
