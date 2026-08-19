from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from canary_matrix.cli import DEFAULT_CONTRACT_NAME
from canary_matrix.contract import ContractError, IntegrityError, load_contract
from canary_matrix.core import ClaimTier, ExecutionLane, PairState, RunState, canonical_json_bytes
from canary_matrix.images import (
    ImageAttestation,
    attest_image,
    render_image_build_plan,
    verify_image_attestation,
)
from canary_matrix.standalone import (
    PTY_POLICY_SHA256,
    PtyProbeResult,
    build_target_create_argv,
    build_target_start_argv,
    compare_standalone_runs,
    execute_target,
    normalize_terminal_tail,
    render_public_bundle,
    run_target_pty,
    validate_target_create_argv,
    validate_target_start_argv,
)


class FakeCodexDockerRunner:
    def __init__(self, contract, *, natural_exit: bool = False):
        self.contract = contract
        self.calls: list[list[str]] = []
        self.volume_exists = False
        self.target_containers: set[str] = set()
        self.keepers: set[str] = set()
        self.natural_exit = natural_exit
        self.target_running = not natural_exit
        self.target_exit_code = 0 if natural_exit else 137
        self.expected_manifest = None
        self.workspace_mutated = False
        self.cleanup_volume_fails = False

    @staticmethod
    def _completed(argv, returncode=0, stdout="", stderr="", *, text=True):
        if not text:
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def __call__(self, argv, *, timeout, max_output_bytes, text=True):
        del timeout, max_output_bytes
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["docker", "volume", "create"]:
            self.volume_exists = True
            return self._completed(argv, stdout=argv[-1] + "\n", text=text)
        if argv[:3] == ["docker", "volume", "inspect"]:
            if not self.volume_exists:
                return self._completed(argv, 1, stderr="missing", text=text)
            run_id = self._run_id_for_volume_create()
            payload = [
                {
                    "Name": argv[-1],
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
                files = {
                    item["path"]: {"sha256": item["sha256"], "size": item["size"]}
                    for item in envelope["files"]
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
            self.target_running = not self.natural_exit
            self.target_exit_code = 0 if self.natural_exit else 137
            return self._completed(argv, stdout="a" * 64 + "\n", text=text)
        if argv[:3] == ["docker", "container", "inspect"]:
            name = argv[-1]
            if name in self.keepers:
                state = {
                    "Running": True,
                    "ExitCode": 0,
                    "OOMKilled": False,
                    "Error": "",
                }
                return self._completed(argv, stdout=json.dumps([{"State": state}]), text=text)
            if name not in self.target_containers:
                return self._completed(argv, 1, stderr="missing", text=text)
            state = {
                "Running": self.target_running,
                "ExitCode": 0 if self.target_running else self.target_exit_code,
                "OOMKilled": False,
                "Error": "",
            }
            return self._completed(argv, stdout=json.dumps([{"State": state}]), text=text)
        if argv[:3] == ["docker", "kill", "--signal"]:
            self.target_running = False
            self.target_exit_code = 137
            return self._completed(argv, stdout=argv[-1] + "\n", text=text)
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


class TestCodexContractAndImages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.contract_path = cls.repo / "contracts" / "codex-trust-enter-39487.toml"
        cls.gemini_path = cls.repo / "contracts" / "gemini-hooks-command-16049.toml"
        cls.contract = load_contract(cls.contract_path)
        cls.base_digest = "docker.io/library/node@sha256:" + "c" * 64
        cls.plans = {
            name: render_image_build_plan(
                cls.contract, name, base_image_digest=cls.base_digest
            )
            for name in ("baseline", "candidate")
        }

    def test_codex_contract_freezes_issue_versions_integrities_and_trusted_probe(self):
        contract = self.contract
        self.assertEqual(contract.contract_id, "codex-trust-enter-39487")
        self.assertEqual(contract.capture_date, "2026-08-19")
        self.assertEqual(
            contract.source_urls, ("https://github.com/openai/codex/issues/39487",)
        )
        self.assertEqual(contract.execution_lane, ExecutionLane.CONTAINER_PTY_NO_HOST_WRITE)
        self.assertEqual(contract.baseline.version, "0.147.0")
        self.assertEqual(contract.candidate.version, "0.148.0")
        self.assertEqual(contract.probe["argv"], ("codex",))
        self.assertEqual(contract.probe["marker"], b"Press enter to continue")
        self.assertEqual(contract.probe["input"], b"\r")
        self.assertEqual(contract.probe["input_delay_ms"], 0)
        self.assertIn(
            "fresh existing HOME=/tmp and no CODEX_HOME override",
            contract.probe["instruction"],
        )
        self.assertEqual(
            contract.baseline.npm_integrity,
            "sha512-EQLEXecAG2ptxI7UpBMo2TR/ga5596/c/OsYF/0LoUDh5JANZ7IoGqlzBEWbuEVQ76JePIbtTW/ihCkp1a7Z3w==",
        )
        self.assertEqual(
            contract.baseline.platform_npm_integrity,
            "sha512-SLC1JXw2TYfr/c3HhrJubyyLelq7vTOLWVmiThFA+z0+WgzCPmaseJ/kzDD3Gge/TO7fCnnj7UcPmC0d2c8XAg==",
        )
        self.assertEqual(
            contract.candidate.npm_integrity,
            "sha512-bh5kH9+BMrFaHGmLeoSansPdfRksvr4UXzjQInns/KRO7r8VJ+6AAW+SqUsE8XcG3+OW/mI4EEy8Gpo9UDXGvQ==",
        )
        self.assertEqual(
            contract.candidate.platform_npm_integrity,
            "sha512-51DCd+izzk6n4mMh4w2utWj3lTLhSTnCOEJQfRh0LS9nBDkcYZcK3iSKOST6fByRIlLSXuLO33LlYYA1VPot6A==",
        )
        self.assertEqual(
            contract.baseline.wrapper_sha256,
            "134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477",
        )
        self.assertEqual(
            contract.baseline.platform_binary_sha256,
            "e23d0be344d2496986c985cd3db61e6f649b1ddd900e6afc1b5aaabbffcbb4e2",
        )
        self.assertEqual(
            contract.candidate.platform_binary_sha256,
            "7515d0b61e723374c68d4acdcb8815e378f84d088b0c50638f27d1094bffe536",
        )

    def test_contract_cannot_author_stimulus_or_omit_platform_sri(self):
        original = self.contract_path.read_text(encoding="utf-8")
        injected_fields = {
            "argv": 'argv = ["codex"]\n',
            "shell": 'shell = "codex"\n',
            "regex": 'regex = "continue"\n',
            "marker": 'marker = "Press enter to continue"\n',
            "keystroke": 'keystroke = "ENTER"\n',
            "executable": 'executable = "codex"\n',
            "package": 'package = "@openai/codex"\n',
            "normalization": 'normalization = "strip-ansi"\n',
        }
        with tempfile.TemporaryDirectory(prefix="canary_codex_contract_") as root:
            for label, field in injected_fields.items():
                with self.subTest(label=label):
                    path = Path(root) / f"{label}.toml"
                    path.write_text(
                        original.replace("[fixture]", field + "\n[fixture]"),
                        encoding="utf-8",
                    )
                    with self.assertRaises(ContractError):
                        load_contract(path)
            missing = Path(root) / "missing-platform.toml"
            missing.write_text(
                original.replace(
                    'platform_npm_integrity = "sha512-SLC1JXw2TYfr/c3HhrJubyyLelq7vTOLWVmiThFA+z0+WgzCPmaseJ/kzDD3Gge/TO7fCnnj7UcPmC0d2c8XAg=="\n',
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ContractError):
                load_contract(missing)
        self.assertNotIn("@openai", original)

    def test_platform_sri_is_conditional_and_lane_is_probe_bound(self):
        gemini = self.gemini_path.read_text(encoding="utf-8")
        codex = self.contract_path.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="canary_conditional_sri_") as root:
            extra = Path(root) / "gemini-extra.toml"
            extra.write_text(
                gemini.replace(
                    "node_version = \"22\"",
                    'platform_npm_integrity = "sha512-'
                    + base64.b64encode(b"x" * 64).decode()
                    + '"\nnode_version = "22"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ContractError):
                load_contract(extra)
            wrong_lane = Path(root) / "codex-lane.toml"
            wrong_lane.write_text(
                codex.replace(
                    'execution_lane = "container_pty_no_host_write"',
                    'execution_lane = "container_no_host_write"',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ContractError, "requires container_pty"):
                load_contract(wrong_lane)

    def test_dual_sri_recipe_assembles_verified_platform_alias_without_install(self):
        baseline = self.plans["baseline"]
        candidate = self.plans["candidate"]
        self.assertEqual(baseline.dockerfile, candidate.dockerfile)
        self.assertEqual(baseline.recipe_sha256, candidate.recipe_sha256)
        text = baseline.dockerfile.decode()
        self.assertIn('npm pack --json "@openai/codex@${CANARY_TARGET_VERSION}"', text)
        self.assertIn(
            'npm pack --json "@openai/codex@${CANARY_TARGET_VERSION}-linux-arm64"',
            text,
        )
        self.assertIn("top-level npm SRI mismatch", text)
        self.assertIn("platform npm SRI mismatch", text)
        self.assertIn("wrapper SHA-256 mismatch", text)
        self.assertIn("platform binary SHA-256 mismatch", text)
        self.assertIn("@openai/codex-linux-arm64", text)
        self.assertIn("vendor/aarch64-unknown-linux-musl/bin/codex", text)
        self.assertIn("ln -s /usr/local/lib/node_modules/@openai/codex/bin/codex.js", text)
        self.assertIn('ENTRYPOINT []\nCMD []\n', text)
        self.assertNotIn("npm install", text)
        args = dict(baseline.build_args)
        self.assertEqual(args["CANARY_NPM_INTEGRITY"], self.contract.baseline.npm_integrity)
        self.assertEqual(
            args["CANARY_PLATFORM_NPM_INTEGRITY"],
            self.contract.baseline.platform_npm_integrity,
        )
        self.assertEqual(
            args["CANARY_WRAPPER_SHA256"], self.contract.baseline.wrapper_sha256
        )
        self.assertEqual(
            args["CANARY_PLATFORM_BINARY_SHA256"],
            self.contract.baseline.platform_binary_sha256,
        )
        self.assertIn("io.canary-matrix.platform-package-integrity", text)
        self.assertIn("io.canary-matrix.wrapper-sha256", text)
        self.assertIn("io.canary-matrix.platform-binary-sha256", text)

    def _fake_image_runner(self, target_name: str, *, origin_ok: bool = True):
        target = self.contract.baseline if target_name == "baseline" else self.contract.candidate
        plan = self.plans[target_name]
        image_id = "sha256:" + ("a" if target_name == "baseline" else "b") * 64
        labels = {
            "io.canary-matrix.base-image-digest": plan.base_image_digest,
            "io.canary-matrix.recipe-sha256": plan.recipe_sha256,
            "io.canary-matrix.target-version": target.version,
            "io.canary-matrix.package-integrity": target.npm_integrity,
            "io.canary-matrix.platform-package-integrity": target.platform_npm_integrity,
            "io.canary-matrix.wrapper-sha256": target.wrapper_sha256,
            "io.canary-matrix.platform-binary-sha256": target.platform_binary_sha256,
            "io.canary-matrix.node-version": target.node_version,
            "io.canary-matrix.os-release": target.os,
            "io.canary-matrix.architecture": target.arch,
            "io.canary-matrix.image-family": target.image_family,
            "io.canary-matrix.contract-sha256": self.contract.raw_sha256,
        }

        def runner(argv, *, timeout, max_output_bytes, **kwargs):
            del timeout, max_output_bytes, kwargs
            if argv[:3] == ["docker", "image", "inspect"]:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        [
                            {
                                "Id": image_id,
                                "Os": "linux",
                                "Architecture": "arm64",
                                "Config": {"Labels": labels},
                            }
                        ]
                    ),
                    "",
                )
            executable = argv[argv.index("--entrypoint") + 1]
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertNotIn("docker.sock", " ".join(argv))
            if executable == "codex":
                self.assertIn("CODEX_HOME=/tmp/codex-home", argv)
                return subprocess.CompletedProcess(argv, 0, f"codex-cli {target.version}\n", "")
            if executable == "node" and "-e" in argv:
                output = (
                    json.dumps(
                        {
                            "wrapper_sha256": target.wrapper_sha256,
                            "platform_binary_sha256": target.platform_binary_sha256,
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                    if origin_ok
                    else ""
                )
                return subprocess.CompletedProcess(argv, 0 if origin_ok else 75, output, "")
            if executable.endswith(
                "/vendor/aarch64-unknown-linux-musl/bin/codex"
            ):
                return subprocess.CompletedProcess(
                    argv, 0, f"codex-cli {target.version}\n", ""
                )
            if executable == "node":
                return subprocess.CompletedProcess(argv, 0, "v22.23.2\n", "")
            if executable == "cat":
                return subprocess.CompletedProcess(argv, 0, 'ID=debian\nVERSION_ID="12"\n', "")
            raise AssertionError(argv)

        return runner

    def test_active_attestation_binds_platform_sri_and_binary_origin(self):
        attestation = attest_image(
            self.contract,
            "baseline",
            self.plans["baseline"],
            runner=self._fake_image_runner("baseline"),
        )
        self.assertEqual(
            attestation.platform_package_integrity,
            self.contract.baseline.platform_npm_integrity,
        )
        self.assertEqual(
            attestation.wrapper_sha256, self.contract.baseline.wrapper_sha256
        )
        self.assertEqual(
            attestation.platform_binary_sha256,
            self.contract.baseline.platform_binary_sha256,
        )
        verify_image_attestation(self.contract, "baseline", attestation)
        with self.assertRaisesRegex(IntegrityError, "platform origin"):
            attest_image(
                self.contract,
                "baseline",
                self.plans["baseline"],
                runner=self._fake_image_runner("baseline", origin_ok=False),
            )

    def test_gemini_contract_and_recipe_are_byte_stable_and_default(self):
        gemini = load_contract(self.gemini_path)
        plan = render_image_build_plan(
            gemini, "baseline", base_image_digest=self.base_digest
        )
        self.assertEqual(
            gemini.raw_sha256,
            "b5ec6a74a2422ec3e92821127f75dc92e8f6010c3519604fb5a380b4edad9673",
        )
        self.assertEqual(
            plan.recipe_sha256,
            "55e6e18c36416f1b37f3137106b731655d1a469b42de49ca8259e9f22d68650d",
        )
        self.assertEqual(DEFAULT_CONTRACT_NAME, "gemini-hooks-command-16049.toml")
        self.assertNotIn(b"CANARY_PLATFORM_NPM_INTEGRITY", plan.dockerfile)


class TestCodexPtyStandalone(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.contract = load_contract(
            cls.repo / "contracts" / "codex-trust-enter-39487.toml"
        )
        cls.base_digest = "docker.io/library/node@sha256:" + "c" * 64
        cls.recipe_sha256 = "d" * 64

    def _attestation(self, target_name: str):
        target = self.contract.baseline if target_name == "baseline" else self.contract.candidate
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
            "node_version": "v22.23.2",
            "os": target.os,
            "arch": target.arch,
            "image_family": target.image_family,
            "platform_package_integrity": target.platform_npm_integrity,
            "wrapper_sha256": target.wrapper_sha256,
            "platform_binary_sha256": target.platform_binary_sha256,
        }
        digest = hashlib.sha256(canonical_json_bytes(values)).hexdigest()
        return ImageAttestation(**values, attestation_sha256=digest)

    @staticmethod
    def _pty_result(diagnostic: str):
        marker = b"Press enter to continue"
        if diagnostic == "advanced":
            output = b"\x1b[2J\x1b[H" + marker + b"\x1b[2J\x1b[HWorkspace trusted"
            seen = True
        elif diagnostic == "stuck":
            output = b"\x1b[2J\x1b[H" + marker
            seen = True
        elif diagnostic == "ambiguous":
            output = b"\x1b[2J\x1b[H" + marker + b"\x1b[1z"
            seen = True
        else:
            output = b"Codex exited before rendering a trust dialog"
            seen = False
        return PtyProbeResult(
            output=output,
            marker_seen=seen,
            marker_offset=output.find(marker) + len(marker) if seen else None,
            input_sent=seen,
            input_delay_ms=0 if seen else None,
            process_exited=True,
            deliberate_attach_termination=seen,
            raw_marker_seen=seen,
            marker_visibility_ambiguous=diagnostic == "ambiguous",
        )

    def _pty_runner(self, diagnostic: str):
        result = self._pty_result(diagnostic)

        def runner(argv, **kwargs):
            self.assertEqual(argv[:4], ["docker", "start", "--attach", "--interactive"])
            self.assertEqual(kwargs["marker"], b"Press enter to continue")
            self.assertEqual(kwargs["input_bytes"], b"\r")
            self.assertEqual(kwargs["input_delay_ms"], 0)
            self.assertEqual((kwargs["columns"], kwargs["rows"]), (80, 30))
            return result

        return runner

    def test_create_and_start_policy_are_exact_and_clean(self):
        attestation = self._attestation("candidate")
        create = build_target_create_argv(
            self.contract,
            "candidate",
            attestation,
            run_id="cm-candidate-deadbeef",
            container_name="cm-target-candidate-deadbeef",
            volume_name="cm-work-candidate-deadbeef",
        )
        self.assertEqual(
            validate_target_create_argv(
                create,
                self.contract,
                attestation.image_digest,
                "cm-work-candidate-deadbeef",
            ),
            (),
        )
        self.assertIn("--interactive", create)
        self.assertIn("--tty", create)
        self.assertIn("HOME=/tmp", create)
        self.assertFalse(any(item.startswith("CODEX_HOME=") for item in create))
        self.assertIn("TERM=xterm-256color", create)
        self.assertEqual(
            [
                create[index + 1]
                for index, item in enumerate(create[:-1])
                if item == "--env"
            ],
            ["HOME=/tmp", "TERM=xterm-256color"],
        )
        self.assertIn(
            "type=volume,src=cm-work-candidate-deadbeef,dst=/work,volume-nocopy,readonly",
            create,
        )
        self.assertNotIn("type=bind", " ".join(create))
        self.assertNotIn("docker.sock", " ".join(create))
        self.assertEqual(create[-1], attestation.image_digest)
        start = build_target_start_argv(self.contract, "cm-target-candidate-deadbeef")
        self.assertEqual(
            start,
            [
                "docker",
                "start",
                "--attach",
                "--interactive",
                "cm-target-candidate-deadbeef",
            ],
        )
        self.assertEqual(
            validate_target_start_argv(
                start, self.contract, "cm-target-candidate-deadbeef"
            ),
            (),
        )
        self.assertEqual(
            validate_target_start_argv(
                start + ["--detach"],
                self.contract,
                "cm-target-candidate-deadbeef",
            ),
            ("docker_start_stimulus",),
        )
        for injected in (
            "--mount=type=volume,src=foreign-secret,dst=/secret,readonly",
            "--env=SECRET=leak",
        ):
            with self.subTest(injected=injected):
                escaped = list(create)
                escaped.insert(escaped.index(attestation.image_digest), injected)
                errors = validate_target_create_argv(
                    escaped,
                    self.contract,
                    attestation.image_digest,
                    "cm-work-candidate-deadbeef",
                )
                self.assertIn("docker_argv_not_canonical", errors)

    def test_real_pty_sends_carriage_return_at_first_marker_and_sets_80x30(self):
        real_popen = subprocess.Popen
        child = (
            "import fcntl,os,struct,termios,time,tty; tty.setraw(0); "
            "rows,cols,_,_=struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8)); "
            "os.write(1,b'\\x1b[2J\\x1b[HPress enter to continue'); "
            "value=os.read(0,1); "
            "os.write(1,b'\\x1b[2J\\x1b[HINPUT='+value.hex().encode()+"
            "b' SIZE='+f'{cols}x{rows}'.encode()); "
            "time.sleep(5)"
        )

        def substitute_popen(_argv, **kwargs):
            return real_popen([sys.executable, "-c", child], **kwargs)

        start = time.monotonic()
        with patch("canary_matrix.standalone.subprocess.Popen", side_effect=substitute_popen):
            result = run_target_pty(
                ["docker", "start", "--attach", "--interactive", "cm-target-test"],
                marker=b"Press enter to continue",
                input_bytes=b"\r",
                input_delay_ms=0,
                post_marker_window_ms=1000,
                columns=80,
                rows=30,
                timeout=3,
                max_output_bytes=64 * 1024,
            )
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertTrue(result.marker_seen)
        self.assertTrue(result.raw_marker_seen)
        self.assertTrue(result.input_sent)
        self.assertEqual(result.input_delay_ms, 0)
        marker = b"Press enter to continue"
        rendered_prefix = normalize_terminal_tail(
            result.output[: result.marker_offset], columns=80, rows=30
        )
        self.assertFalse(rendered_prefix.ambiguity_codes)
        self.assertIn(marker.decode(), rendered_prefix.tail)
        self.assertIn(b"INPUT=0d", result.output)
        self.assertIn(b"SIZE=80x30", result.output)
        self.assertTrue(result.deliberate_attach_termination)

    def test_raw_markers_hidden_or_ambiguous_never_receive_enter(self):
        real_popen = subprocess.Popen
        marker = "Press enter to continue"
        sources = {
            "osc": (
                "import os,time,tty;tty.setraw(0);"
                f"os.write(1,b'\\x1b]0;{marker}');time.sleep(.05);"
                "os.write(1,b'\\x07');time.sleep(5)"
            ),
            "dcs": (
                "import os,time,tty;tty.setraw(0);"
                f"os.write(1,b'\\x1bP{marker}');time.sleep(.05);"
                "os.write(1,b'\\x1b\\\\');time.sleep(5)"
            ),
            "ambiguous": (
                "import os,time,tty;tty.setraw(0);"
                f"os.write(1,b'\\x1b[1z{marker}');time.sleep(5)"
            ),
        }
        for label, source in sources.items():
            with self.subTest(label=label):
                def substitute_popen(_argv, **kwargs):
                    return real_popen([sys.executable, "-c", source], **kwargs)

                with patch(
                    "canary_matrix.standalone.subprocess.Popen",
                    side_effect=substitute_popen,
                ):
                    result = run_target_pty(
                        [
                            "docker",
                            "start",
                            "--attach",
                            "--interactive",
                            "cm-target-hidden",
                        ],
                        marker=marker.encode(),
                        input_bytes=b"\r",
                        input_delay_ms=0,
                        post_marker_window_ms=1000,
                        columns=80,
                        rows=30,
                        timeout=3,
                        max_output_bytes=64 * 1024,
                    )
                self.assertTrue(result.raw_marker_seen)
                self.assertFalse(result.marker_seen)
                self.assertFalse(result.input_sent)
                self.assertIsNone(result.marker_offset)
                self.assertTrue(result.marker_visibility_ambiguous)

    def test_rendered_marker_drives_input_across_hidden_and_styled_sequences(self):
        real_popen = subprocess.Popen
        marker = "Press enter to continue"
        sources = {
            "hidden_then_visible": (
                "import os,time,tty;tty.setraw(0);"
                f"os.write(1,b'\\x1b]0;{marker}\\x07');time.sleep(.15);"
                f"os.write(1,b'\\x1b[2J\\x1b[H{marker}');"
                "value=os.read(0,1);os.write(1,b'\\x1b[2J\\x1b[HINPUT='+value.hex().encode());time.sleep(5)"
            ),
            "ansi_interleaved": (
                "import os,time,tty;tty.setraw(0);"
                "os.write(1,b'\\x1b[2J\\x1b[HPress \\x1b[1menter\\x1b[0m to continue');"
                "value=os.read(0,1);os.write(1,b'\\x1b[2J\\x1b[HINPUT='+value.hex().encode());time.sleep(5)"
            ),
            "visible_then_erased_one_write": (
                "import os,time,tty;tty.setraw(0);"
                f"os.write(1,b'\\x1b[2J\\x1b[H{marker}\\x1b[2J\\x1b[HWAITING');"
                "value=os.read(0,1);os.write(1,b'\\x1b[2J\\x1b[HINPUT='+value.hex().encode());time.sleep(5)"
            ),
            "many_terminal_e_bytes": (
                "import os,time,tty;tty.setraw(0);"
                f"os.write(1,b'e'*129+b'{marker}');"
                "value=os.read(0,1);os.write(1,b'\\x1b[2J\\x1b[HINPUT='+value.hex().encode());time.sleep(5)"
            ),
        }
        for label, source in sources.items():
            with self.subTest(label=label):
                def substitute_popen(_argv, **kwargs):
                    return real_popen([sys.executable, "-c", source], **kwargs)

                with patch(
                    "canary_matrix.standalone.subprocess.Popen",
                    side_effect=substitute_popen,
                ):
                    result = run_target_pty(
                        [
                            "docker",
                            "start",
                            "--attach",
                            "--interactive",
                            "cm-target-rendered",
                        ],
                        marker=marker.encode(),
                        input_bytes=b"\r",
                        input_delay_ms=0,
                        post_marker_window_ms=1000,
                        columns=80,
                        rows=30,
                        timeout=3,
                        max_output_bytes=64 * 1024,
                    )
                self.assertTrue(result.marker_seen)
                self.assertTrue(result.input_sent)
                self.assertIn(b"INPUT=0d", result.output)

    def test_real_pty_enforces_wall_and_output_budgets(self):
        real_popen = subprocess.Popen

        def run_child(source: str, *, timeout: float, max_output_bytes: int):
            def substitute_popen(_argv, **kwargs):
                return real_popen([sys.executable, "-c", source], **kwargs)

            with patch(
                "canary_matrix.standalone.subprocess.Popen",
                side_effect=substitute_popen,
            ):
                return run_target_pty(
                    [
                        "docker",
                        "start",
                        "--attach",
                        "--interactive",
                        "cm-target-budget",
                    ],
                    marker=b"Press enter to continue",
                    input_bytes=b"\r",
                    input_delay_ms=0,
                    post_marker_window_ms=1000,
                    columns=80,
                    rows=30,
                    timeout=timeout,
                    max_output_bytes=max_output_bytes,
                )

        with self.assertRaisesRegex(IntegrityError, "wall deadline"):
            run_child("import time; time.sleep(5)", timeout=0.05, max_output_bytes=1024)
        with self.assertRaisesRegex(IntegrityError, "output budget"):
            run_child(
                "import os,time; os.write(1,b'x'*4096); time.sleep(5)",
                timeout=1,
                max_output_bytes=32,
            )

    def test_terminal_normalization_handles_redraw_and_fails_closed_on_unknown_csi(self):
        marker = b"Press enter to continue"
        stuck = normalize_terminal_tail(b"\x1b[2J\x1b[H" + marker)
        advanced = normalize_terminal_tail(
            b"\x1b[2J\x1b[H" + marker + b"\x1b[2J\x1b[HAdvanced"
        )
        ambiguous = normalize_terminal_tail(marker + b"\x1b[1z")
        self.assertIn("Press enter to continue", stuck.tail)
        self.assertNotIn("Press enter to continue", advanced.tail)
        self.assertEqual(advanced.tail, "Advanced")
        self.assertTrue(ambiguous.ambiguity_codes)

    def test_pair_classifies_baseline_pass_candidate_fail_as_deterministic_delta(self):
        baseline_runner = FakeCodexDockerRunner(self.contract)
        candidate_runner = FakeCodexDockerRunner(self.contract)
        baseline = execute_target(
            self.contract,
            "baseline",
            self._attestation("baseline"),
            runner=baseline_runner,
            pty_runner=self._pty_runner("advanced"),
            run_nonce="deadbeef01",
        )
        candidate = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=candidate_runner,
            pty_runner=self._pty_runner("stuck"),
            run_nonce="deadbeef02",
        )
        self.assertEqual(baseline.run_result.state, RunState.PASS)
        self.assertEqual(candidate.run_result.state, RunState.FAIL)
        self.assertEqual(
            dict(baseline.run_result.normalized_observations)["diagnostic"],
            "trust_dialog_advanced",
        )
        self.assertEqual(
            dict(candidate.run_result.normalized_observations)["diagnostic"],
            "trust_dialog_stuck",
        )
        self.assertEqual(baseline.run_result.target_identity, "@openai/codex@0.147.0")
        self.assertEqual(candidate.run_result.target_identity, "@openai/codex@0.148.0")
        pair = compare_standalone_runs(self.contract, baseline, candidate)
        self.assertEqual(pair.state, PairState.OBSERVED_DIFFERENCE)
        self.assertEqual(pair.claim_tier, ClaimTier.DETERMINISTIC_CLI_DELTA)
        self.assertTrue(all(baseline.record["cleanup"].values()))
        self.assertTrue(all(candidate.record["cleanup"].values()))
        self.assertTrue(baseline.record["outcome"]["deliberate_target_termination"])
        self.assertNotIn("target_timeout", baseline.record["integrity_errors"])

        public_json, public_markdown = render_public_bundle(
            self.contract, baseline, candidate, pair
        )
        public = json.loads(public_json)
        self.assertEqual(public["runner"]["kind"], "standalone_pty")
        self.assertEqual(public["runner"]["policy_sha256"], PTY_POLICY_SHA256)
        self.assertIn(
            "package.platform_integrity",
            public["runs"]["baseline"]["evidence"],
        )
        self.assertNotIn("terminal_tail", public_json.decode())
        self.assertNotIn("Press enter to continue", public_json.decode())
        self.assertNotIn("Press enter to continue", public_markdown.decode())

    def test_unknown_marker_and_ambiguous_terminal_are_inconclusive(self):
        for label in ("unknown", "ambiguous"):
            with self.subTest(label=label):
                verified = execute_target(
                    self.contract,
                    "baseline",
                    self._attestation("baseline"),
                    runner=FakeCodexDockerRunner(self.contract),
                    pty_runner=self._pty_runner(label),
                    run_nonce="abcedf0101" if label == "unknown" else "abcedf0102",
                )
                self.assertEqual(verified.run_result.state, RunState.INCONCLUSIVE)

    def test_lifecycle_delta_does_not_create_an_observed_cli_difference(self):
        baseline = execute_target(
            self.contract,
            "baseline",
            self._attestation("baseline"),
            runner=FakeCodexDockerRunner(self.contract, natural_exit=True),
            pty_runner=self._pty_runner("advanced"),
            run_nonce="cafeaffe01",
        )
        candidate = execute_target(
            self.contract,
            "candidate",
            self._attestation("candidate"),
            runner=FakeCodexDockerRunner(self.contract),
            pty_runner=self._pty_runner("advanced"),
            run_nonce="cafeaffe02",
        )
        self.assertEqual(
            baseline.run_result.normalized_observations,
            candidate.run_result.normalized_observations,
        )
        self.assertEqual(baseline.record["outcome"]["exit_code"], 0)
        self.assertEqual(candidate.record["outcome"]["exit_code"], 137)
        self.assertIsNone(baseline.record["outcome"]["signal"])
        self.assertEqual(candidate.record["outcome"]["signal"], 9)
        pair = compare_standalone_runs(self.contract, baseline, candidate)
        self.assertEqual(pair.state, PairState.NO_OBSERVED_DIFFERENCE)

    def test_timeout_output_budget_and_cleanup_failure_are_runner_errors(self):
        failures = {
            "timeout": IntegrityError("PTY target exceeded wall deadline"),
            "budget": IntegrityError("PTY target exceeded output budget"),
        }
        for label, error in failures.items():
            with self.subTest(label=label):
                runner = FakeCodexDockerRunner(self.contract)

                def fail_pty(_argv, **_kwargs):
                    raise error

                verified = execute_target(
                    self.contract,
                    "baseline",
                    self._attestation("baseline"),
                    runner=runner,
                    pty_runner=fail_pty,
                    run_nonce="facefeed01" if label == "timeout" else "facefeed02",
                )
                self.assertEqual(verified.run_result.state, RunState.RUNNER_ERROR)
                self.assertTrue(all(verified.record["cleanup"].values()))

        cleanup_runner = FakeCodexDockerRunner(self.contract)
        cleanup_runner.cleanup_volume_fails = True
        cleanup = execute_target(
            self.contract,
            "baseline",
            self._attestation("baseline"),
            runner=cleanup_runner,
            pty_runner=self._pty_runner("advanced"),
            run_nonce="facefeed03",
        )
        self.assertEqual(cleanup.run_result.state, RunState.RUNNER_ERROR)
        self.assertTrue(
            any(code.startswith("cleanup_failed:volume") for code in cleanup.record["integrity_errors"])
        )


if __name__ == "__main__":
    unittest.main()
