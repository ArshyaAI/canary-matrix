from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
    canonical_items,
    canonical_json_bytes,
    classify_run,
    compare_pair,
    pair_result_to_dict,
    run_result_to_dict,
    SCHEMA_VERSION,
)
from canary_matrix.openbench_bridge import (
    CONTAINMENT_POLICY_SHA256,
    ContractError,
    IntegrityError,
    VerifiedExport,
    bounded_run,
    attest_image,
    build_target_image,
    build_openbench_argv,
    compare_verified_exports,
    export_sha256,
    generate_pack,
    load_contract,
    render_image_build_plan,
    render_public_bundle,
    validate_secure_docker_argv,
    verify_export,
    verify_generated_pack,
)


DIGEST = "a" * 64
CONTROLS_BASELINE = canonical_items(
    {
        "target.version": "0.41.0",
        "os": "ubuntu-24.04",
        "arch": "amd64",
        "execution.policy": "policy-sha",
        "image.family": "gemini-cli",
    }
)
CONTROLS_CANDIDATE = canonical_items(
    {
        "target.version": "0.42.0",
        "os": "ubuntu-24.04",
        "arch": "amd64",
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
                    {"diagnostic": "unknown_argument_c", "exit_code": "1"}
                ),
                assertions=(AssertionObservation("parse_result", passed=False),),
            )
        )
        result = compare_pair(self.baseline, candidate, PAIR_POLICY)
        self.assertEqual(result.state, PairState.OBSERVED_DIFFERENCE)
        self.assertEqual(result.claim_tier, ClaimTier.DETERMINISTIC_CLI_DELTA)
        self.assertIn("$state", result.differing_observation_keys)

    def test_observational_policy_cannot_claim_regression(self):
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
            {**dict(CONTROLS_CANDIDATE), "os": "ubuntu-22.04"}
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


class TestOpenBenchBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.contract_path = cls.repo / "contracts" / "gemini-26964.toml"
        cls.contract = load_contract(cls.contract_path)

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="canary_bridge_test_")
        self.root = Path(self.tempdir.name)
        self.pack = generate_pack(self.contract, self.root / "pack")
        self.receipt = verify_generated_pack(self.contract, self.pack)
        self.base_image_digest = (
            "registry.example/canary-base@sha256:" + "c" * 64
        )
        self.plans = {
            target_name: render_image_build_plan(
                self.contract,
                target_name,
                base_image_digest=self.base_image_digest,
            )
            for target_name in ("baseline", "candidate")
        }
        self.attestations = {
            target_name: attest_image(
                self.contract,
                target_name,
                self.plans[target_name],
                runner=self._fake_image_runner(target_name),
            )
            for target_name in ("baseline", "candidate")
        }

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _image_digest(character: str) -> str:
        return f"sha256:{character * 64}"

    def _fake_image_runner(self, target_name: str, *, label_changes=None):
        target = (
            self.contract.baseline
            if target_name == "baseline"
            else self.contract.candidate
        )
        plan = self.plans[target_name]
        image_id = "sha256:" + ("a" if target_name == "baseline" else "b") * 64
        labels = {
            "io.canary-matrix.base-image-digest": plan.base_image_digest,
            "io.canary-matrix.recipe-sha256": plan.recipe_sha256,
            "io.canary-matrix.target-version": target.version,
            "io.canary-matrix.package-integrity": target.npm_integrity,
            "io.canary-matrix.node-version": target.node_version,
            "io.canary-matrix.os-release": target.os,
            "io.canary-matrix.architecture": target.arch,
            "io.canary-matrix.image-family": target.image_family,
            "io.canary-matrix.contract-sha256": self.contract.raw_sha256,
        }
        labels.update(label_changes or {})

        def runner(argv, *, timeout, max_output_bytes):
            self.assertLessEqual(max_output_bytes, 1024 * 1024)
            if argv[:3] == ["docker", "image", "inspect"]:
                payload = [
                    {
                        "Id": image_id,
                        "Os": "linux",
                        "Architecture": target.arch,
                        "Config": {"Labels": labels},
                    }
                ]
                return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
            self.assertEqual(argv[:3], ["docker", "run", "--rm"])
            self.assertIn("--network", argv)
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertNotIn("docker.sock", " ".join(argv))
            executable = argv[argv.index("--entrypoint") + 1]
            if executable == "gemini":
                return subprocess.CompletedProcess(argv, 0, target.version + "\n", "")
            if executable == "node":
                return subprocess.CompletedProcess(argv, 0, "v22.14.0\n", "")
            if executable == "cat":
                return subprocess.CompletedProcess(
                    argv, 0, 'ID=ubuntu\nVERSION_ID="24.04"\n', ""
                )
            raise AssertionError(f"unexpected image probe: {argv}")

        return runner

    def _secure_docker_argv(self):
        return [
            "docker",
            "run",
            "--rm",
            "--cpus",
            "2",
            "--memory",
            "2g",
            "--memory-swap",
            "2g",
            "--pids-limit",
            "256",
            "--ulimit",
            "nofile=4096:4096",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--tmpfs",
            "/root:rw,noexec,nosuid,nodev,size=64m",
            "--mount",
            "type=volume,src=openbench_canary_test,dst=/work",
            "-v",
            "/trusted/adapters:/bench/adapters:ro",
            "-v",
            "/trusted/instruction:/bench/instruction.txt:ro",
            "-w",
            "/work",
            "-e",
            "BENCH_WORKDIR=/work",
            "-e",
            "HOME=/root",
            self._image_digest("a"),
            "python3",
            "/bench/entry.py",
            f"canary-{self.contract.contract_id}",
            "none",
            str(self.contract.timeout_s),
        ]

    def _row(self, target_name: str, diagnostic: str):
        target = (
            self.contract.baseline
            if target_name == "baseline"
            else self.contract.candidate
        )
        character = "a" if target_name == "baseline" else "b"
        image_digest = self._image_digest(character)
        completed = diagnostic == "no_error"
        output = (
            ""
            if completed
            else "Unknown argument: c\nUsage: gemini [options] [command]\n"
        )
        docker_argv = self._secure_docker_argv()
        docker_argv[docker_argv.index(self._image_digest("a"))] = image_digest
        return {
            "run_id": f"{target_name}-run",
            "harness": f"canary-{self.contract.contract_id}",
            "task": self.contract.contract_id,
            "trial": 1,
            "completed": completed,
            "error": None if completed else "exit 1",
            "output_tail": output,
            "cmd": {
                "docker": docker_argv,
                "adapter_cmd": list(self.contract.probe["argv"]),
            },
            "checker_exit": 0,
            "success": True,
            "harness_version": target.version,
            "harness_version_source": "container",
            "exec_mode": "docker",
            "image_digest": image_digest,
            "candidate_provenance": {
                "spec_sha256": self.receipt["files"]["candidate.toml"],
                "command": list(self.contract.probe["argv"]),
                "version_command": list(self.contract.probe["version_argv"]),
                "inherit_env": False,
                "pass_env": [],
                "auth_files": [],
            },
            "workspace_changed": False,
            "checker_stdout": "CANARY_VERIFIER_OK\n",
            "checker_stderr": "",
            "checker_workspace_files": {},
            "timeout_s": self.contract.timeout_s,
            "failure_class": None if completed else "wrong_answer",
            "failure_reason": None,
            "version_drift": False,
        }

    def _export(self, target_name: str, diagnostic: str):
        path = self.root / f"{target_name}.jsonl"
        payload = (
            json.dumps(
                self._row(target_name, diagnostic),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        path.write_bytes(payload)
        return path, hashlib.sha256(payload).hexdigest()

    def _verified_pair(self):
        baseline_path, baseline_sha = self._export("baseline", "no_error")
        candidate_path, candidate_sha = self._export(
            "candidate", "unknown_argument_c"
        )
        baseline = verify_export(
            self.contract,
            target_name="baseline",
            export_path=baseline_path,
            expected_export_sha256=baseline_sha,
            image_attestation=self.attestations["baseline"],
            pack_root=self.pack,
        )
        candidate = verify_export(
            self.contract,
            target_name="candidate",
            export_path=candidate_path,
            expected_export_sha256=candidate_sha,
            image_attestation=self.attestations["candidate"],
            pack_root=self.pack,
        )
        return baseline, candidate

    def test_contract_freezes_source_and_npm_integrities(self):
        self.assertEqual(self.contract.baseline.version, "0.41.0")
        self.assertEqual(self.contract.candidate.version, "0.42.0")
        self.assertTrue(self.contract.source_verified)
        self.assertEqual(len(self.contract.raw_sha256), 64)
        self.assertTrue(self.contract.baseline.npm_integrity.startswith("sha512-"))

    def test_contract_rejects_executable_or_unknown_fields(self):
        mutated = self.root / "mutated.toml"
        mutated.write_bytes(self.contract_path.read_bytes() + b'\nshell = "curl bad"\n')
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            load_contract(mutated)

    def test_contract_rejects_unsafe_declarative_surfaces(self):
        original = self.contract_path.read_text(encoding="utf-8")
        cases = {
            "fixture path": original.replace(
                'path = "probe.json"', 'path = "not portable.json"'
            ),
            "redaction code": original.replace(
                "redaction_patterns = []", 'redaction_patterns = ["(a+)+$"]'
            ),
            "Markdown": original.replace(
                'title = "Gemini CLI sandbox argument-routing regression (#26964)"',
                'title = "<script>unsafe</script>"',
            ),
            "SHA-512": original.replace(
                self.contract.baseline.npm_integrity, "sha512-YQ==", 1
            ),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                path = self.root / f"unsafe-{label.replace(' ', '-')}.toml"
                path.write_text(payload, encoding="utf-8")
                with self.assertRaises(ContractError):
                    load_contract(path)

    def test_fixed_checker_uses_generated_manifest_and_detects_mutation(self):
        task = self.pack / self.contract.contract_id
        checker = task / "checker.sh"
        workspace = task / "workspace"
        env = dict(os.environ)
        env["TASK_DIR"] = str(task)
        env["SYNTHETIC_SECRET"] = "sk-should-not-be-observed"
        passed = subprocess.run(
            ["bash", str(checker)],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertEqual(passed.stdout, "CANARY_VERIFIER_OK\n")
        os.chmod(workspace / "probe.json", 0o644)
        (workspace / "probe.json").write_text("mutated", encoding="utf-8")
        failed = subprocess.run(
            ["bash", str(checker)],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("workspace_manifest", failed.stderr)

    def test_generated_pack_tampering_is_rejected(self):
        checker = self.pack / self.contract.contract_id / "checker.sh"
        os.chmod(checker, 0o644)
        checker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "digest mismatch"):
            verify_generated_pack(self.contract, self.pack)

    def test_generated_pack_rejects_hidden_symlink_and_hardlink(self):
        symlink = self.pack / "unlisted-symlink"
        symlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(IntegrityError, "rejects symlink"):
            verify_generated_pack(self.contract, self.pack)
        symlink.unlink()
        hardlink = self.pack / "unlisted-hardlink"
        os.link(self.pack / "canary-pack.json", hardlink)
        with self.assertRaisesRegex(IntegrityError, "rejects hard link"):
            verify_generated_pack(self.contract, self.pack)

    def test_image_recipe_is_shared_pinned_and_sri_verifying(self):
        baseline = self.plans["baseline"]
        candidate = self.plans["candidate"]
        self.assertEqual(baseline.dockerfile, candidate.dockerfile)
        self.assertEqual(baseline.recipe_sha256, candidate.recipe_sha256)
        self.assertNotEqual(baseline.build_args, candidate.build_args)
        self.assertIn(self.base_image_digest.encode(), baseline.dockerfile)
        self.assertIn(b"npm SRI mismatch", baseline.dockerfile)
        with self.assertRaisesRegex(IntegrityError, "pinned by SHA-256"):
            render_image_build_plan(
                self.contract, "baseline", base_image_digest="node:22"
            )

    def test_image_builder_uses_generated_only_bounded_context(self):
        observed = []

        def runner(argv, **kwargs):
            observed.append((list(argv), kwargs))
            dockerfile = Path(argv[argv.index("--file") + 1])
            context = Path(argv[-1])
            self.assertEqual(list(context.iterdir()), [dockerfile])
            self.assertEqual(dockerfile.read_bytes(), self.plans["baseline"].dockerfile)
            return subprocess.CompletedProcess(argv, 0, "built\n", "")

        build_target_image(self.plans["baseline"], runner=runner)
        argv, kwargs = observed[0]
        self.assertEqual(argv[:2], ["docker", "build"])
        self.assertIn("--no-cache", argv)
        self.assertIn("--memory", argv)
        self.assertNotIn("--secret", argv)
        self.assertNotIn("--ssh", argv)
        self.assertEqual(kwargs["timeout"], 900)
        with self.assertRaisesRegex(IntegrityError, "Dockerfile digest"):
            build_target_image(
                replace(self.plans["baseline"], dockerfile=b"tampered"),
                runner=runner,
            )

    def test_image_attestation_uses_active_no_network_probes(self):
        baseline = self.attestations["baseline"]
        self.assertEqual(baseline.target_version, "0.41.0")
        self.assertEqual(baseline.node_version, "v22.14.0")
        self.assertEqual(baseline.os, "ubuntu-24.04")
        self.assertEqual(len(baseline.attestation_sha256), 64)
        with self.assertRaisesRegex(IntegrityError, "labels"):
            attest_image(
                self.contract,
                "baseline",
                self.plans["baseline"],
                runner=self._fake_image_runner(
                    "baseline",
                    label_changes={
                        "io.canary-matrix.package-integrity": "sha512-YQ=="
                    },
                ),
            )

    def test_bounded_control_runner_enforces_output_budget(self):
        completed = bounded_run(
            [sys.executable, "-c", "print('ok')"],
            timeout=2,
            max_output_bytes=64,
        )
        self.assertEqual(completed.stdout, "ok\n")
        with self.assertRaisesRegex(IntegrityError, "output budget"):
            bounded_run(
                [sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"],
                timeout=2,
                max_output_bytes=32,
            )

    def test_secure_policy_rejects_writable_bind_and_docker_socket(self):
        argv = self._secure_docker_argv()
        self.assertEqual(validate_secure_docker_argv(argv), ())
        writable = list(argv)
        writable[writable.index("/trusted/adapters:/bench/adapters:ro")] = (
            "/host/work:/work:rw"
        )
        self.assertIn("docker_writable_host_bind", validate_secure_docker_argv(writable))
        socket = list(argv) + ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
        self.assertIn("docker_socket", validate_secure_docker_argv(socket))

    def test_openbench_argv_forbids_drift_and_fallback(self):
        argv = build_openbench_argv(
            self.contract,
            self.pack,
            self.root / "results.jsonl",
            self._image_digest("a"),
        )
        self.assertIn("--no-docker-fallback", argv)
        self.assertNotIn("--docker-fallback", argv)
        self.assertNotIn("--allow-version-drift", argv)

    def test_verified_pair_is_deterministic_delta(self):
        baseline, candidate = self._verified_pair()
        self.assertEqual(baseline.run_result.state, RunState.PASS)
        self.assertEqual(candidate.run_result.state, RunState.FAIL)
        pair = compare_verified_exports(self.contract, baseline, candidate)
        self.assertEqual(pair.state, PairState.OBSERVED_DIFFERENCE)
        self.assertEqual(pair.claim_tier, ClaimTier.DETERMINISTIC_CLI_DELTA)
        self.assertIn("diagnostic", pair.differing_observation_keys)

    def test_export_digest_tampering_is_rejected(self):
        path, digest = self._export("baseline", "no_error")
        with path.open("ab") as handle:
            handle.write(b" \n")
        with self.assertRaisesRegex(IntegrityError, "SHA-256 mismatch"):
            verify_export(
                self.contract,
                target_name="baseline",
                export_path=path,
                expected_export_sha256=digest,
                image_attestation=self.attestations["baseline"],
                pack_root=self.pack,
            )

    def test_export_rejects_tampered_image_attestation(self):
        path, digest = self._export("baseline", "no_error")
        tampered = replace(
            self.attestations["baseline"], node_version="v23.0.0"
        )
        with self.assertRaisesRegex(IntegrityError, "attestation"):
            verify_export(
                self.contract,
                target_name="baseline",
                export_path=path,
                expected_export_sha256=digest,
                image_attestation=tampered,
                pack_root=self.pack,
            )

    def test_policy_bypass_becomes_runner_error(self):
        path, _ = self._export("baseline", "no_error")
        row = json.loads(path.read_text(encoding="utf-8"))
        docker_argv = row["cmd"]["docker"]
        docker_argv[docker_argv.index("none")] = "host"
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        verified = verify_export(
            self.contract,
            target_name="baseline",
            export_path=path,
            expected_export_sha256=export_sha256(path),
            image_attestation=self.attestations["baseline"],
            pack_root=self.pack,
        )
        self.assertEqual(verified.run_result.state, RunState.RUNNER_ERROR)
        self.assertIn("docker_policy_network", verified.run_result.details)

    def test_matched_control_mismatch_is_not_comparable(self):
        baseline, candidate = self._verified_pair()
        changed_controls = canonical_items(
            {**dict(candidate.run_result.controls), "os": "ubuntu-22.04"}
        )
        changed_candidate = replace(
            candidate,
            run_result=replace(candidate.run_result, controls=changed_controls),
        )
        pair = compare_verified_exports(self.contract, baseline, changed_candidate)
        self.assertEqual(pair.state, PairState.NOT_COMPARABLE)
        self.assertEqual(pair.reason_code, PairReason.MATCHED_CONTROL_MISMATCH)

    def test_public_bundle_is_byte_stable_and_drops_raw_secret(self):
        baseline, candidate = self._verified_pair()
        pair = compare_verified_exports(self.contract, baseline, candidate)
        first = render_public_bundle(self.contract, baseline, candidate, pair)
        second = render_public_bundle(self.contract, baseline, candidate, pair)
        self.assertEqual(first, second)
        self.assertNotIn(b"output_tail", first[0])
        self.assertNotIn(b"candidate_provenance", first[0])
        self.assertNotIn(b"sk-should-never-export", first[0])

    def test_public_redaction_sink_fails_closed(self):
        baseline, candidate = self._verified_pair()
        unsafe = replace(
            baseline,
            public_evidence=canonical_items(
                {"target.version": "sk-syntheticsecret12345"}
            ),
        )
        pair = compare_verified_exports(self.contract, baseline, candidate)
        with self.assertRaisesRegex(IntegrityError, "redaction sink"):
            render_public_bundle(self.contract, unsafe, candidate, pair)


if __name__ == "__main__":
    unittest.main()
