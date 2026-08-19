from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from canary_matrix.cli import main
from canary_matrix.contract import IntegrityError


class _Contract:
    contract_id = "fixture-contract"
    raw_sha256 = "c" * 64


class _Pair:
    pass


class TestCli(unittest.TestCase):
    def invoke(self, argv):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_version(self):
        status, out, err = self.invoke(["version"])
        self.assertEqual(status, 0)
        self.assertEqual(out.strip(), "0.2.0")
        self.assertEqual(err, "")

    def test_invalid_contract_is_error(self):
        with patch("canary_matrix.cli.resolve_contract", side_effect=IntegrityError("bad contract")):
            status, out, err = self.invoke(["run", "missing.toml", "--base-image", "x@sha256:" + "a" * 64, "--output", "/tmp/never-created"])
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertIn("bad contract", err)

    def test_check_preflight_success(self):
        with patch("canary_matrix.cli.resolve_contract", return_value=Path("contract.toml")), \
             patch("canary_matrix.cli.load_contract", return_value=_Contract()), \
             patch("canary_matrix.cli._platform_preflight", return_value={"system": "linux", "machine": "amd64"}), \
             patch("canary_matrix.cli._docker_preflight", return_value="27.0"), \
             patch("canary_matrix.cli._disk_preflight", return_value=10 * 1024**3):
            status, out, err = self.invoke(["check"])
        self.assertEqual(status, 0)
        self.assertIn('"docker_version": "27.0"', out)
        self.assertEqual(err, "")

    def test_run_preserves_sequential_order(self):
        events = []
        contract = _Contract()
        base_plan, candidate_plan = object(), object()
        base_attestation, candidate_attestation = object(), object()
        baseline, candidate, pair = object(), object(), object()

        def load(_path):
            events.append("load")
            return contract

        def render(_contract, target, *, base_image_digest):
            events.append("plan:" + target)
            return base_plan if target == "baseline" else candidate_plan

        def build(plan):
            events.append("build:" + ("baseline" if plan is base_plan else "candidate"))

        def attest(_contract, target, _plan):
            events.append("attest:" + target)
            return base_attestation if target == "baseline" else candidate_attestation

        def execute(_contract, target, _attestation):
            events.append("run:" + target)
            return baseline if target == "baseline" else candidate

        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "bundle")
            with patch("canary_matrix.cli.resolve_contract", return_value=Path("contract.toml")), \
                 patch("canary_matrix.cli.load_contract", side_effect=load), \
                 patch("canary_matrix.cli._platform_preflight", return_value={"system": "linux", "machine": "amd64"}), \
                 patch("canary_matrix.cli._docker_preflight", return_value="27.0"), \
                 patch("canary_matrix.cli._disk_preflight", return_value=10 * 1024**3), \
                 patch("canary_matrix.cli.render_image_build_plan", side_effect=render), \
                 patch("canary_matrix.cli.build_target_image", side_effect=build), \
                 patch("canary_matrix.cli.attest_image", side_effect=attest), \
                 patch("canary_matrix.cli.execute_target", side_effect=execute), \
                 patch("canary_matrix.cli.compare_standalone_runs", side_effect=lambda *args: events.append("compare") or pair), \
                 patch("canary_matrix.cli.write_evidence_bundle", side_effect=lambda *args: events.append("write")), \
                 patch("canary_matrix.cli.pair_result_to_dict", return_value={"state": "pass"}):
                status, out, err = self.invoke(["run", "contract.toml", "--base-image", "x@sha256:" + "a" * 64, "--output", output])
        self.assertEqual(status, 0)
        self.assertEqual(err, "")
        self.assertEqual(events, ["load", "plan:baseline", "plan:candidate", "build:baseline", "attest:baseline", "build:candidate", "attest:candidate", "run:baseline", "run:candidate", "compare", "write"])

    def test_skip_build_does_not_build(self):
        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "bundle")
            with patch("canary_matrix.cli.resolve_contract", return_value=Path("contract.toml")), \
                 patch("canary_matrix.cli.load_contract", return_value=_Contract()), \
                 patch("canary_matrix.cli._platform_preflight", return_value={"system": "linux", "machine": "amd64"}), \
                 patch("canary_matrix.cli._docker_preflight", return_value="27.0"), \
                 patch("canary_matrix.cli._disk_preflight", return_value=10 * 1024**3), \
                 patch("canary_matrix.cli.render_image_build_plan", side_effect=[object(), object()]), \
                 patch("canary_matrix.cli.build_target_image") as build, \
                 patch("canary_matrix.cli.attest_image", side_effect=[object(), object()]), \
                 patch("canary_matrix.cli.execute_target", side_effect=[object(), object()]), \
                 patch("canary_matrix.cli.compare_standalone_runs", return_value=_Pair()), \
                 patch("canary_matrix.cli.write_evidence_bundle"), \
                 patch("canary_matrix.cli.pair_result_to_dict", return_value={"state": "pass"}):
                status, _, err = self.invoke(["run", "contract.toml", "--base-image", "x@sha256:" + "a" * 64, "--output", output, "--skip-build"])
        self.assertEqual(status, 0)
        self.assertFalse(build.called)
        self.assertEqual(err, "")

    def test_run_preflight_failure_happens_before_plan_or_build(self):
        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "bundle")
            with patch("canary_matrix.cli.resolve_contract", return_value=Path("contract.toml")), \
                 patch("canary_matrix.cli.load_contract", return_value=_Contract()), \
                 patch("canary_matrix.cli._platform_preflight", side_effect=IntegrityError("unsupported host")), \
                 patch("canary_matrix.cli.render_image_build_plan") as render:
                status, out, err = self.invoke([
                    "run", "contract.toml", "--base-image", "x@sha256:" + "a" * 64,
                    "--output", output,
                ])
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertIn("unsupported host", err)
        render.assert_not_called()

    def test_disk_preflight_rejects_low_space(self):
        with patch("canary_matrix.cli.shutil.disk_usage") as usage:
            usage.return_value = type("Disk", (), {"free": 1024})()
            from canary_matrix.cli import _disk_preflight

            with self.assertRaisesRegex(IntegrityError, "5 GiB required"):
                _disk_preflight(Path.cwd())

    def test_existing_output_fails_before_work(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("canary_matrix.cli.load_contract") as load:
                status, out, err = self.invoke(["run", "contract.toml", "--base-image", "x@sha256:" + "a" * 64, "--output", temp])
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertIn("output destination must be absent", err)
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
