"""Installable command-line entry point for Canary Matrix.

The CLI intentionally exposes only the fixed contract workflow.  It never
accepts a user-supplied executable or shell fragment and all control-plane
commands use :func:`bounded_run` with an argv list.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import sysconfig
from typing import Sequence

from . import __version__
from .contract import IntegrityError, Contract, load_contract
from .core import pair_result_to_dict
from .images import (
    attest_image,
    bounded_run,
    build_target_image,
    render_image_build_plan,
)
from .standalone import (
    compare_standalone_runs,
    execute_target,
    write_evidence_bundle,
)


DEFAULT_CONTRACT_NAME = "gemini-hooks-command-16049.toml"
_SUPPORTED_SYSTEMS = {"darwin", "linux"}
_SUPPORTED_MACHINES = {"amd64", "arm64", "x86_64", "aarch64"}
MIN_FREE_DISK_BYTES = 5 * 1024 * 1024 * 1024


def _default_contract_candidates() -> tuple[Path, ...]:
    """Return checkout and installed-data locations in deterministic order."""

    module_root = Path(__file__).resolve().parents[2]
    data_root = Path(sysconfig.get_path("data") or sys.prefix)
    return (
        Path.cwd() / "contracts" / DEFAULT_CONTRACT_NAME,
        module_root / "contracts" / DEFAULT_CONTRACT_NAME,
        data_root / "share" / "canary-matrix" / "contracts" / DEFAULT_CONTRACT_NAME,
    )


def resolve_contract(path: str | os.PathLike[str] | None = None) -> Path:
    """Resolve a requested contract or the packaged default contract."""

    if path is not None:
        candidate = Path(path)
        if not candidate.is_file():
            raise IntegrityError(f"contract does not exist: {candidate}")
        return candidate
    for candidate in _default_contract_candidates():
        if candidate.is_file():
            return candidate
    raise IntegrityError(
        "default contract is unavailable; install package data or run from the repository"
    )


def _assert_output_absent(destination: str | os.PathLike[str]) -> Path:
    root = Path(destination)
    # exists() follows symlinks; lexists also rejects a dangling symlink.
    if root.exists() or os.path.lexists(root):
        raise IntegrityError("output destination must be absent")
    return root


def _platform_preflight() -> dict[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system not in _SUPPORTED_SYSTEMS:
        raise IntegrityError(f"unsupported host platform: {system or 'unknown'}")
    if machine not in _SUPPORTED_MACHINES:
        raise IntegrityError(f"unsupported host architecture: {machine or 'unknown'}")
    return {"system": system, "machine": machine}


def _docker_preflight() -> str:
    if shutil.which("docker") is None:
        raise IntegrityError("Docker executable is not available on PATH")
    result = bounded_run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        timeout=15,
        max_output_bytes=64 * 1024,
    )
    if result.returncode != 0:
        raise IntegrityError("Docker daemon preflight failed")
    version = str(result.stdout).strip()
    if not version:
        raise IntegrityError("Docker daemon returned no server version")
    return version


def _disk_preflight(path: Path | None = None) -> int:
    root = (path or Path.cwd()).resolve()
    free = shutil.disk_usage(root).free
    if free < MIN_FREE_DISK_BYTES:
        raise IntegrityError(
            "insufficient free disk for image work: "
            f"{free / (1024 ** 3):.2f} GiB available; 5 GiB required"
        )
    return free


def _run_preflight(contract_path: str | os.PathLike[str] | None = None) -> dict[str, object]:
    resolved = resolve_contract(contract_path)
    contract = load_contract(resolved)
    host = _platform_preflight()
    docker_version = _docker_preflight()
    free_disk_bytes = _disk_preflight()
    return {
        "contract_id": contract.contract_id,
        "contract_sha256": contract.raw_sha256,
        "host": host,
        "docker_version": docker_version,
        "free_disk_bytes": free_disk_bytes,
    }


def _check(args: argparse.Namespace) -> int:
    summary = _run_preflight(args.contract)
    print(json.dumps({"ok": True, **summary}, sort_keys=True))
    return 0


def _run(args: argparse.Namespace) -> int:
    destination = _assert_output_absent(args.output)
    contract = load_contract(resolve_contract(args.contract))
    _platform_preflight()
    _docker_preflight()
    _disk_preflight()

    # Render both canonical recipes before any mutation.  Build order is fixed
    # baseline then candidate, which keeps the evidence chronology auditable.
    baseline_plan = render_image_build_plan(
        contract, "baseline", base_image_digest=args.base_image
    )
    candidate_plan = render_image_build_plan(
        contract, "candidate", base_image_digest=args.base_image
    )
    if not args.skip_build:
        build_target_image(baseline_plan)
    baseline_attestation = attest_image(contract, "baseline", baseline_plan)
    if not args.skip_build:
        build_target_image(candidate_plan)
    candidate_attestation = attest_image(contract, "candidate", candidate_plan)
    baseline = execute_target(contract, "baseline", baseline_attestation)
    candidate = execute_target(contract, "candidate", candidate_attestation)
    pair = compare_standalone_runs(contract, baseline, candidate)
    write_evidence_bundle(
        contract,
        baseline_attestation,
        candidate_attestation,
        baseline,
        candidate,
        pair,
        destination,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "contract_id": contract.contract_id,
                "contract_sha256": contract.raw_sha256,
                "output": str(destination.resolve()),
                "pair": pair_result_to_dict(pair),
            },
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canary-matrix")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="run non-mutating contract/platform/Docker preflight")
    check.add_argument("--contract", help=argparse.SUPPRESS)
    check.set_defaults(handler=_check)

    run = subparsers.add_parser("run", help="build, run, compare, and write an evidence bundle")
    run.add_argument("contract", metavar="CONTRACT", help="path to a TOML contract")
    run.add_argument("--base-image", required=True, metavar="DIGEST")
    run.add_argument("--output", required=True, metavar="DIR")
    run.add_argument("--skip-build", action="store_true", help="use existing target images")
    run.set_defaults(handler=_run)

    version = subparsers.add_parser("version", help="print the package version")
    version.set_defaults(handler=lambda _args: (print(__version__) or 0))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""

    parser = _parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except (IntegrityError, OSError, ValueError) as exc:
        print(f"canary-matrix: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
