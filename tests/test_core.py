from __future__ import annotations

from dataclasses import replace
import unittest

from canary_matrix.core import (
    AssertionObservation,
    CapabilityStatus,
    ClaimTier,
    ExecutionLane,
    PairPolicy,
    PairReason,
    PairState,
    RunObservation,
    RunReason,
    RunState,
    SCHEMA_VERSION,
    canonical_items,
    canonical_json_bytes,
    classify_run,
    compare_pair,
    pair_result_to_dict,
    run_result_to_dict,
)


DIGEST = "a" * 64
CONTROLS_BASELINE = canonical_items(
    {
        "target.version": "0.24.0-preview.0",
        "os": "debian-12",
        "arch": "arm64",
        "execution.policy": "policy-sha",
        "image.family": "gemini-cli",
    }
)
CONTROLS_CANDIDATE = canonical_items(
    {
        "target.version": "0.42.0",
        "os": "debian-12",
        "arch": "arm64",
        "execution.policy": "policy-sha",
        "image.family": "gemini-cli",
    }
)
PAIR_POLICY = PairPolicy(
    matched_control_keys=("os", "arch", "execution.policy", "image.family"),
    deterministic_cli_oracle=True,
)


def observation(
    *,
    run_id: str = "baseline",
    controls=CONTROLS_BASELINE,
    normalized=None,
    assertions=None,
    **changes,
) -> RunObservation:
    values = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "contract_digest": DIGEST,
        "execution_lane": ExecutionLane.CONTAINER_NO_HOST_WRITE,
        "target_identity": f"gemini-cli@{dict(controls)['target.version']}",
        "controls": controls,
        "normalized_observations": normalized
        or canonical_items({"diagnostic": "accepted", "exit_code": "0"}),
        "assertions": assertions
        or (AssertionObservation("parse_result", passed=True),),
    }
    values.update(changes)
    return RunObservation(**values)


class TestRunClassifier(unittest.TestCase):
    def test_container_pty_lane_is_a_first_class_execution_lane(self):
        lane = ExecutionLane("container_pty_no_host_write")
        self.assertIs(lane, ExecutionLane.CONTAINER_PTY_NO_HOST_WRITE)
        result = classify_run(observation(execution_lane=lane))
        self.assertEqual(result.execution_lane, lane)
        self.assertEqual(result.state, RunState.PASS)

    def test_integrity_failure_wins_over_target_failure(self):
        result = classify_run(
            observation(
                integrity_errors=("cleanup_unverified",),
                assertions=(AssertionObservation("parse_result", passed=False),),
            )
        )
        self.assertEqual(result.state, RunState.RUNNER_ERROR)
        self.assertEqual(result.reason_code, RunReason.INTEGRITY_FAILURE)

    def test_unknown_schema_is_runner_error(self):
        result = classify_run(observation(schema_version="future"))
        self.assertEqual(result.state, RunState.RUNNER_ERROR)
        self.assertEqual(result.reason_code, RunReason.INVALID_SCHEMA)

    def test_deterministic_capability_absence_is_unsupported(self):
        result = classify_run(
            observation(capability_status=CapabilityStatus.UNSUPPORTED)
        )
        self.assertEqual(result.state, RunState.UNSUPPORTED)

    def test_unproven_capability_absence_is_inconclusive(self):
        result = classify_run(
            observation(
                capability_status=CapabilityStatus.UNSUPPORTED,
                capability_probe_deterministic=False,
            )
        )
        self.assertEqual(result.state, RunState.INCONCLUSIVE)
        self.assertEqual(result.reason_code, RunReason.CAPABILITY_ABSENCE_UNPROVEN)

    def test_unknown_capability_is_inconclusive(self):
        result = classify_run(observation(capability_status=CapabilityStatus.UNKNOWN))
        self.assertEqual(result.state, RunState.INCONCLUSIVE)

    def test_incomplete_evidence_is_inconclusive(self):
        result = classify_run(observation(evidence_complete=False))
        self.assertEqual(result.reason_code, RunReason.REQUIRED_EVIDENCE_INCOMPLETE)

    def test_contradictory_evidence_is_inconclusive(self):
        result = classify_run(observation(evidence_contradictory=True))
        self.assertEqual(result.reason_code, RunReason.EVIDENCE_CONTRADICTORY)

    def test_nondeterminism_policy_is_enforced(self):
        result = classify_run(observation(nondeterminism_within_policy=False))
        self.assertEqual(result.reason_code, RunReason.NONDETERMINISM_EXCEEDED)

    def test_invalid_oracle_is_inconclusive(self):
        result = classify_run(observation(oracle_valid=False))
        self.assertEqual(result.reason_code, RunReason.INVALID_ORACLE)

    def test_required_assertion_failure_is_fail(self):
        result = classify_run(
            observation(assertions=(AssertionObservation("required", passed=False),))
        )
        self.assertEqual(result.state, RunState.FAIL)
        self.assertEqual(result.reason_code, RunReason.REQUIRED_ASSERTION_FAILED)

    def test_optional_failure_does_not_fail_run(self):
        result = classify_run(
            observation(
                assertions=(
                    AssertionObservation("required", passed=True),
                    AssertionObservation("optional", required=False, passed=False),
                )
            )
        )
        self.assertEqual(result.state, RunState.PASS)

    def test_no_required_assertions_is_runner_error(self):
        result = classify_run(
            observation(
                assertions=(AssertionObservation("optional", required=False, passed=True),)
            )
        )
        self.assertEqual(result.state, RunState.RUNNER_ERROR)
        self.assertEqual(result.reason_code, RunReason.NO_REQUIRED_ASSERTIONS)

    def test_all_required_assertions_pass(self):
        result = classify_run(observation())
        self.assertEqual(result.state, RunState.PASS)
        self.assertEqual(result.reason_code, RunReason.ALL_REQUIRED_ASSERTIONS_PASSED)


class TestPairComparator(unittest.TestCase):
    def setUp(self):
        self.baseline = classify_run(observation())
        self.candidate = classify_run(
            observation(run_id="candidate", controls=CONTROLS_CANDIDATE)
        )

    def test_matching_observations_have_no_difference(self):
        result = compare_pair(self.baseline, self.candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.NO_OBSERVED_DIFFERENCE)
        self.assertEqual(result.reason_code, PairReason.OBSERVATIONS_MATCH)

    def test_different_observations_are_deterministic_delta(self):
        candidate = classify_run(
            observation(
                run_id="candidate",
                controls=CONTROLS_CANDIDATE,
                normalized=canonical_items(
                    {"diagnostic": "hooks_help", "exit_code": "0"}
                ),
                assertions=(AssertionObservation("parse_result", passed=False),),
            )
        )
        result = compare_pair(self.baseline, candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.OBSERVED_DIFFERENCE)
        self.assertEqual(result.claim_tier, ClaimTier.DETERMINISTIC_CLI_DELTA)
        self.assertIn("$state", result.differing_observation_keys)

    def test_observational_policy_cannot_claim_delta(self):
        candidate = replace(
            self.candidate,
            normalized_observations=canonical_items({"diagnostic": "different"}),
        )
        result = compare_pair(
            self.baseline,
            candidate,
            replace(PAIR_POLICY, deterministic_cli_oracle=False),
        )
        self.assertEqual(result.claim_tier, ClaimTier.OBSERVATIONAL)

    def test_both_proven_unsupported_can_match(self):
        baseline = classify_run(
            observation(capability_status=CapabilityStatus.UNSUPPORTED)
        )
        candidate = classify_run(
            observation(
                run_id="candidate",
                controls=CONTROLS_CANDIDATE,
                capability_status=CapabilityStatus.UNSUPPORTED,
            )
        )
        result = compare_pair(baseline, candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.NO_OBSERVED_DIFFERENCE)

    def test_proven_unsupported_to_supported_is_difference(self):
        baseline = classify_run(
            observation(capability_status=CapabilityStatus.UNSUPPORTED)
        )
        result = compare_pair(baseline, self.candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.OBSERVED_DIFFERENCE)
        self.assertIn("$state", result.differing_observation_keys)

    def test_runner_error_makes_pair_not_comparable(self):
        failed = replace(self.baseline, state=RunState.RUNNER_ERROR)
        result = compare_pair(failed, self.candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.NOT_COMPARABLE)
        self.assertEqual(result.reason_code, PairReason.RUN_NOT_COMPARABLE)

    def test_matched_control_mismatch_is_not_comparable(self):
        mismatched_controls = canonical_items(
            {**dict(CONTROLS_CANDIDATE), "os": "ubuntu-24.04"}
        )
        candidate = replace(self.candidate, controls=mismatched_controls)
        result = compare_pair(self.baseline, candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.NOT_COMPARABLE)
        self.assertEqual(result.reason_code, PairReason.MATCHED_CONTROL_MISMATCH)
        self.assertIn("os", result.mismatched_control_keys)

    def test_unexpected_control_difference_is_not_comparable(self):
        extra_difference = canonical_items(
            {**dict(CONTROLS_CANDIDATE), "runtime.node": "24"}
        )
        baseline_extra = replace(
            self.baseline,
            controls=canonical_items(
                {**dict(CONTROLS_BASELINE), "runtime.node": "22"}
            ),
        )
        candidate_extra = replace(self.candidate, controls=extra_difference)
        result = compare_pair(baseline_extra, candidate_extra, PAIR_POLICY)
        self.assertEqual(result.state, PairState.NOT_COMPARABLE)
        self.assertEqual(result.reason_code, PairReason.UNEXPECTED_CONTROL_DIFFERENCE)

    def test_same_run_is_rejected(self):
        result = compare_pair(self.baseline, self.baseline, PAIR_POLICY)
        self.assertEqual(result.reason_code, PairReason.SAME_RUN)

    def test_serialization_is_byte_stable(self):
        pair = compare_pair(self.baseline, self.candidate, PAIR_POLICY)
        value = {
            "baseline": run_result_to_dict(self.baseline),
            "candidate": run_result_to_dict(self.candidate),
            "pair": pair_result_to_dict(pair),
        }
        self.assertEqual(canonical_json_bytes(value), canonical_json_bytes(value))
        self.assertTrue(canonical_json_bytes(value).endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
