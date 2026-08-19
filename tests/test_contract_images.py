from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from canary_matrix.contract import (
    ContractError,
    IntegrityError,
    assert_public_safe,
    load_contract,
    target_for,
)
from canary_matrix.images import (
    attest_image,
    bounded_run,
    build_target_image,
    render_image_build_plan,
    verify_image_attestation,
)


class TestContractAndImages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.contract_path = cls.repo / "contracts" / "gemini-hooks-command-16049.toml"
        cls.contract = load_contract(cls.contract_path)
        cls.base_digest = "docker.io/library/node@sha256:" + "c" * 64
        cls.plans = {
            name: render_image_build_plan(
                cls.contract, name, base_image_digest=cls.base_digest
            )
            for name in ("baseline", "candidate")
        }

    def _fake_image_runner(self, target_name: str, *, label_changes=None):
        target = target_for(self.contract, target_name)
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

        def runner(argv, *, timeout, max_output_bytes, **kwargs):
            del timeout, kwargs
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
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertNotIn("docker.sock", " ".join(argv))
            executable = argv[argv.index("--entrypoint") + 1]
            if executable == "gemini":
                return subprocess.CompletedProcess(argv, 0, target.version + "\n", "")
            if executable == "node":
                return subprocess.CompletedProcess(argv, 0, "v22.23.2\n", "")
            if executable == "cat":
                return subprocess.CompletedProcess(
                    argv, 0, 'ID=debian\nVERSION_ID="12"\n', ""
                )
            raise AssertionError(f"unexpected image probe: {argv}")

        return runner

    def test_contract_freezes_source_versions_and_integrities(self):
        self.assertEqual(self.contract.contract_id, "gemini-hooks-command-16049")
        self.assertEqual(self.contract.baseline.version, "0.24.0-preview.0")
        self.assertEqual(self.contract.candidate.version, "0.42.0")
        self.assertEqual(
            self.contract.source_urls,
            ("https://github.com/google-gemini/gemini-cli/issues/16049",),
        )
        self.assertTrue(self.contract.source_verified)
        self.assertEqual(len(self.contract.raw_sha256), 64)
        self.assertEqual(self.contract.probe["argv"], ("gemini", "hooks", "--help"))

    def test_contract_rejects_executable_unknown_and_unsafe_fields(self):
        original = self.contract_path.read_text(encoding="utf-8")
        cases = {
            "unknown": original + '\nshell = "curl bad"\n',
            "fixture": original.replace(
                'path = "probe.json"', 'path = "not portable.json"'
            ),
            "redaction": original.replace(
                "redaction_patterns = []", 'redaction_patterns = ["(a+)+$"]'
            ),
            "markdown": original.replace(
                'title = "Gemini CLI hooks command registration transition (#16049)"',
                'title = "<script>unsafe</script>"',
            ),
            "sri": original.replace(
                self.contract.baseline.npm_integrity, "sha512-YQ==", 1
            ),
            "arch": original.replace('arch = "arm64"', 'arch = "mips"', 1),
        }
        with tempfile.TemporaryDirectory(prefix="canary_contract_test_") as root:
            for label, payload in cases.items():
                with self.subTest(label=label):
                    path = Path(root) / f"{label}.toml"
                    path.write_text(payload, encoding="utf-8")
                    with self.assertRaises(ContractError):
                        load_contract(path)

    def test_contract_source_must_be_regular_non_symlink(self):
        with tempfile.TemporaryDirectory(prefix="canary_contract_link_") as root:
            link = Path(root) / "contract.toml"
            link.symlink_to(self.contract_path)
            with self.assertRaisesRegex(ContractError, "non-symlink"):
                load_contract(link)

    def test_target_resolution_fails_closed(self):
        self.assertIs(target_for(self.contract, "baseline"), self.contract.baseline)
        with self.assertRaisesRegex(IntegrityError, "baseline or candidate"):
            target_for(self.contract, "other")

    def test_image_recipe_is_shared_pinned_and_sri_verifying(self):
        baseline = self.plans["baseline"]
        candidate = self.plans["candidate"]
        self.assertEqual(baseline.dockerfile, candidate.dockerfile)
        self.assertEqual(baseline.recipe_sha256, candidate.recipe_sha256)
        self.assertNotEqual(baseline.build_args, candidate.build_args)
        self.assertTrue(baseline.dockerfile.startswith(b"FROM "))
        self.assertNotIn(b"# syntax=", baseline.dockerfile)
        self.assertIn(self.base_digest.encode(), baseline.dockerfile)
        self.assertIn(b"npm SRI mismatch", baseline.dockerfile)
        self.assertNotIn(b"COPY ", baseline.dockerfile)
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
        attestation = attest_image(
            self.contract,
            "baseline",
            self.plans["baseline"],
            runner=self._fake_image_runner("baseline"),
        )
        self.assertEqual(attestation.target_version, "0.24.0-preview.0")
        self.assertEqual(attestation.node_version, "v22.23.2")
        self.assertEqual(attestation.os, "debian-12")
        verify_image_attestation(self.contract, "baseline", attestation)
        with self.assertRaisesRegex(IntegrityError, "labels"):
            attest_image(
                self.contract,
                "baseline",
                self.plans["baseline"],
                runner=self._fake_image_runner(
                    "baseline",
                    label_changes={"io.canary-matrix.package-integrity": "wrong"},
                ),
            )
        with self.assertRaisesRegex(IntegrityError, "SHA-256 mismatch"):
            verify_image_attestation(
                self.contract,
                "baseline",
                replace(attestation, attestation_sha256="0" * 64),
            )

    def test_bounded_control_runner_enforces_timeout_and_output_budget(self):
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
        with self.assertRaisesRegex(IntegrityError, "wall deadline"):
            bounded_run(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                timeout=0.05,
                max_output_bytes=64,
            )

    def test_public_sink_rejects_common_secrets_and_host_paths(self):
        assert_public_safe(b'{"safe":"value"}\n', self.contract)
        for payload in (
            b'{"value":"sk-syntheticsecret12345"}\n',
            b'{"value":"ghp_12345678901234567890"}\n',
            b'{"value":"/Users/private/project"}\n',
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(IntegrityError, "redaction sink"):
                    assert_public_safe(payload, self.contract)


if __name__ == "__main__":
    unittest.main()
