# Changelog

All notable changes to Canary Matrix will be documented here.

## [0.1.0] - Unreleased

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
- A fresh credential-free Docker calibration is required for the local release candidate.

### Notes

- v0.1 is not released or published. Raw output and protected evidence are intentionally omitted from the public bundle.
