# Changelog

All notable changes to Canary Matrix will be documented here.

## [0.2.0] - 2026-08-19

### Added

- Added a second tracked contract, `contracts/codex-trust-enter-39487.toml`, for official Codex issue [#39487](https://github.com/openai/codex/issues/39487).
- Added a fixed 80x30 PTY execution lane with zero-delay input at the first proven rendered marker.
- Added local evidence comparing `@openai/codex` `0.147.0` (pass) with `0.148.0` (fail): `observed_difference` at claim tier `deterministic_cli_delta`, with no mismatched controls.

### Changed

- Bumped package version from `0.1.0` to `0.2.0`.
- Expanded the scoped release from one contract/lane to two contracts and two credential-free lanes.
- Kept raw terminal and OAuth output in protected records only; the public bundle remains allowlisted local contract evidence.

### Validation

- Full unit discovery, bytecode compilation, package build/install smoke tests,
  and a fresh credential-free Docker calibration are release gates.

## [0.1.0] - 2026-08-19

### Added

- Declarative v0.1 contract schema and the Gemini CLI hooks-command calibration contract.
- Pure five-state run classification and three-state baseline/candidate comparison.
- Digest-addressed image attestation, bounded standalone execution, cleanup checks, and deterministic allowlisted public bundles.
- Installable `canary-matrix` CLI with `check`, `run`, and `version` commands.
- Fail-closed platform, Docker, output-destination, and 5 GiB free-disk preflights.
- Python 3.11–3.13 CI plus wheel/sdist build and installed-wheel smoke checks.
- Local evidence for Gemini CLI `0.24.0-preview.0` versus `0.42.0`: baseline `unsupported`, candidate `pass`, and pair `observed_difference` at claim tier `deterministic_cli_delta`.

### Validation

- Unit discovery and bytecode compilation are release gates.
- Package archives and installed-wheel contract resolution are verified before release.
- A fresh credential-free Docker calibration passed for the release candidate.

### Notes

- v0.1.0 is the initial GitHub release. Raw output and protected evidence are intentionally omitted from the public bundle.
