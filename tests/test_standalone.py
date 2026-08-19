from __future__ import annotations

from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from canary_matrix.core import ClaimTier, PairState, RunState, canonical_json_bytes
from canary_matrix.contract import IntegrityError, load_contract
from canary_matrix.images import ImageAttestation
from canary_matrix.standalone import (
    STANDALONE_POLICY_SHA256,
    build_target_create_argv,
    compare_standalone_runs,
    execute_target,
    render_public_bundle,
    validate_target_create_argv,
    write_evidence_bundle,
    write_immutable_record,
)


class FakeDockerRunner:
    def __init__(self, contract, target_name: str):
        self.contract = contract
        self.target_name = target_name
        self.target = (
            contract.baseline if target_name == "baseline" else contract.candidate
        )
        self.calls: list[list[str]] = []
        self.volume_exists = False
        self.target_containers: set[str] = set()
        self.keepers: set[str] = set()
        self.expected_manifest = None
        self.workspace_mutated = False
        self.cleanup_volume_fails = False
        self.timeout = False
        self.stdout_override: bytes | None = None

    @staticmethod
    def _completed(argv, returncode=0, stdout="", stderr="", *, text=True):
        if not text:
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def __call__(self, argv, *, timeout, max_output_bytes, text=True):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["docker", "volume", "create"]:
            self.volume_exists = True
            return self._completed(argv, stdout=argv[-1] + "\n", text=text)
        if argv[:3] == ["docker", "volume", "inspect"]:
            if not self.volume_exists:
                return self._completed(argv, returncode=1, stderr="missing", text=text)
            volume_name = argv[-1]
            run_id = self._run_id_for_volume_create()
            payload = [
                {
                    "Name": volume_name,
                    "Driver": "local",
                    "Options": {
                        "type": "tmpfs",
                        "device": "tmpfs",
                        "o": "size=33554432,nosuid,nodev,noexec",
                    },
                    "Labels": {"io.canary-matrix.run_id": run_id},
                }
            ]
            return self._completed(argv, stdout=json.dumps(payload), text=text)
        if argv[:3] == ["docker", "volume", "rm"]:
            if not self.cleanup_volume_fails:
                self.volume_exists = False
            return self._completed(argv, text=text)
        if argv[:2] == ["docker", "run"]:
            if "--detach" in argv:
                name = argv[argv.index("--name") + 1]
                self.keepers.add(name)
                return self._completed(argv, stdout="c" * 64 + "\n", text=text)
            script = argv[-1]
            if "CANARY_STAGE_OK" in script:
                fixture_arg = next(
                    item for item in argv if item.startswith("CANARY_FIXTURE_B64=")
                )
                envelope = json.loads(
                    base64.b64decode(fixture_arg.split("=", 1)[1]).decode()
                )
                files = {}
                for item in envelope["files"]:
                    files[item["path"]] = {
                        "sha256": item["sha256"],
                        "size": item["size"],
                    }
                self.expected_manifest = {"files": files}
                return self._completed(argv, stdout="CANARY_STAGE_OK\n", text=text)
            manifest = json.loads(json.dumps(self.expected_manifest))
            if self.workspace_mutated and "before" not in argv[argv.index("--name") + 1]:
                manifest["files"]["probe.json"]["size"] += 1
            return self._completed(
                argv,
                stdout=json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                + "\n",
                text=text,
            )
        if argv[:2] == ["docker", "create"]:
            name = argv[argv.index("--name") + 1]
            self.target_containers.add(name)
            return self._completed(argv, stdout="a" * 64 + "\n", text=text)
        if argv[:3] == ["docker", "start", "--attach"]:
            if self.timeout:
                raise IntegrityError("control-plane command exceeded wall deadline")
            if self.stdout_override is not None:
                output = self.stdout_override
                code = 0
            elif self.target_name == "baseline":
                output = b"Unknown arguments: hooks\nUsage: gemini [options] [command]\n"
                code = 1
            else:
                output = b"Gemini CLI hooks\nCommands:\n  gemini hooks migrate\n"
                code = 0
            return self._completed(argv, code, output, b"", text=text)
        if argv[:3] == ["docker", "container", "inspect"]:
            name = argv[-1]
            if name in self.keepers:
                payload = [
                    {
                        "State": {
                            "Running": True,
                            "ExitCode": 0,
                            "OOMKilled": False,
                            "Error": "",
                        }
                    }
                ]
                return self._completed(argv, stdout=json.dumps(payload), text=text)
            if name not in self.target_containers:
                return self._completed(argv, 1, stderr="missing", text=text)
            code = 1 if self.target_name == "baseline" else 0
            payload = [
                {
                    "State": {
                        "Running": False,
                        "ExitCode": code,
                        "OOMKilled": False,
                        "Error": "",
                    }
                }
            ]
            return self._completed(argv, stdout=json.dumps(payload), text=text)
        if argv[:3] == ["docker", "rm", "--force"]:
            name = argv[-1]
            self.target_containers.discard(name)
            self.keepers.discard(name)
            return self._completed(argv, text=text)
        raise AssertionError(f"unexpected Docker command: {argv}")

    def _run_id_for_volume_create(self):
        call = next(item for item in self.calls if item[:3] == ["docker", "volume", "create"])
        label = call[call.index("--label") + 1]
        return label.split("=", 1)[1]


class TestStandaloneRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.contract = load_contract(
            cls.repo / "contracts" / "gemini-hooks-command-16049.toml"
        )
        cls.base_digest = "docker.io/library/node@sha256:" + "c" * 64
        cls.recipe_sha256 = "d" * 64

    def _attestation(self, target_name: str):
        target = (
            self.contract.baseline
            if target_name == "baseline"
            else self.contract.candidate
        )
        image_id = "sha256:" + ("a" if target_name == "baseline" else "b") * 64
        values = {
            "target_name": target_name,
            "contract_sha256": self.contract.raw_sha256,
            "image_reference": target.image_tag,
            "image_digest": image_id,
            "image_id": image_id,
            "base_image_digest": self.base_digest,
            "recipe_sha256": self.recipe_sha256,
            "target_version": target.version,
            "package_integrity": target.npm_integrity,
            "node_version": "v22.18.0",
            "os": target.os,
            "arch": target.arch,
            "image_family": target.image_family,
        }
        digest = hashlib.sha256(canonical_json_bytes(values)).hexdigest()
        return ImageAttestation(**values, attestation_sha256=digest)

    def test_contract_is_credential_free_capability_transition(self):
        self.assertEqual(self.contract.probe["argv"], ("gemini", "hooks", "--help"))
        self.assertEqual(self.contract.baseline.version, "0.24.0-preview.0")
        self.assertEqual(self.contract.candidate.version, "0.42.0")
        self.assertEqual(self.contract.credential_mode, "none")

    def test_target_argv_is_fail_closed(self):
        attestation = self._attestation("candidate")
        argv = build_target_create_argv(
            self.contract,
            "candidate",
            attestation,
            run_id="cm-candidate-deadbeef",
            container_name="cm-target-candidate-deadbeef",
            volume_name="cm-work-candidate-deadbeef",
        )
        self.assertEqual(
            validate_target_create_argv(
                argv,
                self.contract,
                attestation.image_digest,
                "cm-work-candidate-deadbeef",
            ),
            (),
        )
        self.assertNotIn("docker.sock", " ".join(argv))
        self.assertNotIn("type=bind", " ".join(argv))
        self.assertNotIn("--privileged", argv)
        escaped = list(argv)
        escaped[escaped.index("none")] = "host"
        self.assertIn(
            "docker_policy_network",
            validate_target_create_argv(
                escaped,
                self.contract,
                attestation.image_digest,
                "cm-work-candidate-deadbeef",
            ),
        )
        extra_env = list(argv)
        extra_env[extra_env.index(attestation.image_digest):extra_env.index(attestation.image_digest)] = [
            "--env",
            "SECRET=value",
        ]
        self.assertIn(
            "docker_environment_surface",
            validate_target_create_argv(
                extra_env,
                self.contract,
                attestation.image_digest,
                "cm-work-candidate-deadbeef",
            ),
        )
        self.assertIn(
            "docker_escape_flag",
            validate_target_create_argv(
                argv[:2] + ["--privileged=true"] + argv[2:],
                self.contract,
                attestation.image_digest,
                "cm-work-candidate-deadbeef",
            ),
        )

    def test_realistic_fake_pair_is_unsupported_to_pass_delta(self):
        baseline_runner = FakeDockerRunner(self.contract, "baseline")
        candidate_runner = FakeDockerRunner(self.contract, "candidate")
        baseline = execute_target(
            self.contract,
            "baseline",
            self._attestation("baseline"),
            runner=baseline_runner,
            run_nonce="deadbeef01",
        )
        candidate = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=candidate_runner,
            run_nonce="deadbeef02",
        )
        self.assertEqual(baseline.run_result.state, RunState.UNSUPPORTED)
        self.assertEqual(candidate.run_result.state, RunState.PASS)
        pair = compare_standalone_runs(self.contract, baseline, candidate)
        self.assertEqual(pair.state, PairState.OBSERVED_DIFFERENCE)
        self.assertEqual(pair.claim_tier, ClaimTier.DETERMINISTIC_CLI_DELTA)
        self.assertTrue(all(baseline.record["cleanup"].values()))
        self.assertTrue(all(candidate.record["cleanup"].values()))
        for call in baseline_runner.calls + candidate_runner.calls:
            self.assertNotIn("docker.sock", " ".join(call))
            self.assertNotIn("type=bind", " ".join(call))

    def test_workspace_mutation_is_runner_error(self):
        runner = FakeDockerRunner(self.contract, "candidate")
        runner.workspace_mutated = True
        verified = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=runner,
            run_nonce="feedface01",
        )
        self.assertEqual(verified.run_result.state, RunState.RUNNER_ERROR)
        self.assertIn("workspace_changed", verified.run_result.details)

    def test_cleanup_failure_is_runner_error(self):
        runner = FakeDockerRunner(self.contract, "candidate")
        runner.cleanup_volume_fails = True
        verified = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=runner,
            run_nonce="feedface02",
        )
        self.assertEqual(verified.run_result.state, RunState.RUNNER_ERROR)
        self.assertTrue(any("cleanup_failed:volume" in item for item in verified.run_result.details))

    def test_output_line_budget_is_runner_error(self):
        runner = FakeDockerRunner(self.contract, "candidate")
        runner.stdout_override = b"x" * (64 * 1024 + 1)
        verified = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=runner,
            run_nonce="feedface03",
        )
        self.assertEqual(verified.run_result.state, RunState.RUNNER_ERROR)
        self.assertIn("output_line_limit_exceeded", verified.run_result.details)

    def test_timeout_fails_closed_and_cleanup_still_runs(self):
        runner = FakeDockerRunner(self.contract, "candidate")
        runner.timeout = True
        verified = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=runner,
            run_nonce="feedface04",
        )
        self.assertEqual(verified.run_result.state, RunState.RUNNER_ERROR)
        self.assertEqual(dict(verified.run_result.normalized_observations)["timed_out"], "true")
        self.assertTrue(all(verified.record["cleanup"].values()))

    def test_public_bundle_is_deterministic_and_excludes_raw_samples(self):
        baseline = execute_target(
            self.contract,
            "baseline",
            self._attestation("baseline"),
            runner=FakeDockerRunner(self.contract, "baseline"),
            run_nonce="cafebabe01",
        )
        candidate = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=FakeDockerRunner(self.contract, "candidate"),
            run_nonce="cafebabe02",
        )
        pair = compare_standalone_runs(self.contract, baseline, candidate)
        first = render_public_bundle(self.contract, baseline, candidate, pair)
        second = render_public_bundle(self.contract, baseline, candidate, pair)
        self.assertEqual(first, second)
        self.assertNotIn(b"sample", first[0])
        self.assertNotIn(b"Unknown arguments", first[0])
        self.assertIn(STANDALONE_POLICY_SHA256.encode(), first[0])

        tampered_record = json.loads(json.dumps(baseline.record))
        tampered_record["outcome"]["diagnostic"] = "forged"
        tampered = replace(baseline, record=tampered_record)
        with self.assertRaisesRegex(IntegrityError, "record SHA-256 mismatch"):
            render_public_bundle(self.contract, tampered, candidate, pair)

        forged_evidence = replace(
            baseline,
            public_evidence=tuple(
                (key, "forged" if key == "target.diagnostic" else value)
                for key, value in baseline.public_evidence
            ),
        )
        with self.assertRaisesRegex(IntegrityError, "public evidence binding"):
            render_public_bundle(self.contract, forged_evidence, candidate, pair)

    def test_immutable_record_is_exclusive_and_digest_bound(self):
        verified = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=FakeDockerRunner(self.contract, "candidate"),
            run_nonce="cafebabe03",
        )
        with tempfile.TemporaryDirectory(prefix="canary_record_test_") as root:
            path = Path(root) / "record.json"
            write_immutable_record(verified, path)
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), verified.record_sha256
            )
            with self.assertRaises(FileExistsError):
                write_immutable_record(verified, path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_evidence_bundle_separates_protected_and_public_files(self):
        baseline_attestation = self._attestation("baseline")
        candidate_attestation = self._attestation("candidate")
        baseline = execute_target(
            self.contract,
            "baseline",
            baseline_attestation,
            runner=FakeDockerRunner(self.contract, "baseline"),
            run_nonce="decafbad01",
        )
        candidate = execute_target(
            self.contract,
            "candidate",
            candidate_attestation,
            runner=FakeDockerRunner(self.contract, "candidate"),
            run_nonce="decafbad02",
        )
        pair = compare_standalone_runs(self.contract, baseline, candidate)
        with tempfile.TemporaryDirectory(prefix="canary_bundle_parent_") as parent:
            destination = Path(parent) / "bundle"
            root = write_evidence_bundle(
                self.contract,
                baseline_attestation,
                candidate_attestation,
                baseline,
                candidate,
                pair,
                destination,
            )
            manifest = json.loads((root / "manifest.json").read_text())
            for relative, expected in manifest["files"].items():
                path = root / relative
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
            self.assertEqual(
                os.stat(root / "protected" / "baseline-record.json").st_mode & 0o777,
                0o600,
            )
            self.assertEqual(
                os.stat(root / "public" / "result.json").st_mode & 0o777,
                0o444,
            )
            public = (root / "public" / "result.json").read_bytes()
            self.assertNotIn(b"sample", public)
            with self.assertRaisesRegex(IntegrityError, "must be absent"):
                write_evidence_bundle(
                    self.contract,
                    baseline_attestation,
                    candidate_attestation,
                    baseline,
                    candidate,
                    pair,
                    destination,
                )


if __name__ == "__main__":
    unittest.main()
