# Canary Matrix

**Know whether an AI coding CLI upgrade changed a workflow before it reaches your team.**

Canary Matrix turns a narrowly scoped, issue-derived CLI contract into a
deterministic, reviewable baseline/candidate comparison.

## 30-second mental model

1. A versioned TOML contract defines one capability, its exact probe, matched controls, and the evidence that may be published.
2. The runner resolves or builds separately attested, digest-addressed target images and executes the probe in the `container_no_host_write` lane.
3. Canary Matrix classifies each run as `pass`, `fail`, `unsupported`, `inconclusive`, or `runner_error`.
4. It compares independently verified baseline and candidate records only when the contract, execution lane, and matched controls agree.
5. The public bundle is an allowlisted summary; protected records and raw target output are not public output.

## Prerequisites

The repository provides an installable Python distribution. For the checks below you need:

- Python 3.11, 3.12, or 3.13;
- the repository checkout; and
- Docker only for the real container execution lane (the unit tests do not start Docker).

The current contracts target Linux ARM64 containers and the CLI requires at
least 5 GiB of free host disk before image work. Other target architectures are
not yet a v0.2 claim.

Building target images may require npm/Docker network access to obtain pinned assets, unless the required image already exists locally. The target runtime itself is designed without credentials, network access, host binds, or a Docker socket.

## Install from source

Install the package and its console script from the checkout:

```bash
git clone https://github.com/ArshyaAI/canary-matrix.git
cd canary-matrix
python3 -m pip install -e .
```

The repository’s current verification command is:

```bash
python3 -m unittest discover -v
```

## Quickstart

The CLI commands are available from the source distribution in this checkout:

```bash
canary-matrix version
canary-matrix check --contract contracts/codex-trust-enter-39487.toml
canary-matrix run \
  contracts/codex-trust-enter-39487.toml \
  --base-image docker.io/library/node:22-bookworm-slim@sha256:253da19867dd03e2f817f433d7782adefd2a2bac8729fcd4ebc6770665167a24 \
  --output .canary/runs/codex-trust-enter-39487
```

`check` validates the contract, host platform, Docker daemon, and free-disk
floor. `run` builds and attests the baseline before building and attesting the
candidate, executes both sequentially, writes protected evidence, and derives
the public bundle. `--skip-build` reuses locally present images but still runs
full attestation. A real run remains an evidence action, not a universal
guarantee.

Expected summary shape:

```json
{
  "ok": true,
  "pair": {
    "state": "observed_difference",
    "claim_tier": "deterministic_cli_delta"
  }
}
```

Exit status `0` means Canary Matrix completed the trusted workflow and wrote a
valid evidence bundle. Exit status `1` means setup, integrity, or control-plane
execution failed. The measured result is always the explicit `pair.state` in
the JSON summary and bundle; an `observed_difference` is evidence, not a CLI
failure.

The Codex contract is derived from official issue
[#39487](https://github.com/openai/codex/issues/39487). It compares
`@openai/codex` `0.147.0` with `0.148.0` in a fixed Linux ARM64 80x30 PTY,
sending carriage return with zero intentional delay when the rendered trust
dialog marker first appears. The Gemini CLI contract from
[#16049](https://github.com/google-gemini/gemini-cli/issues/16049) remains
available as a second calibration case.

## Output semantics

Run states are deliberately separate from pair states:

- `pass`: all required assertions passed.
- `fail`: a required assertion failed.
- `unsupported`: a capability absence was proven deterministically.
- `inconclusive`: evidence is incomplete, contradictory, nondeterministic, or otherwise cannot support a safe conclusion.
- `runner_error`: the execution or integrity boundary failed; this is not a target verdict.

Pair comparison returns `no_observed_difference`, `observed_difference`, or `not_comparable`. A difference can carry the `deterministic_cli_delta` claim tier only when the contract’s deterministic oracle and comparison controls justify it; otherwise it remains `observational`.

The public bundle is deterministic and allowlisted. It may contain normalized diagnostics, exit/signal information, target versions, package/image identity, and hashes permitted by the contract. It intentionally omits raw output and other protected evidence.

## State and claim honesty

Canary Matrix reports what this contract and execution lane establish—not a universal statement about a vendor, release, or all environments. The current local calibration evidence is:

- baseline `@openai/codex 0.147.0`: `pass` (`trust_dialog_advanced`);
- candidate `0.148.0`: `fail` (`trust_dialog_stuck`);
- pair: `observed_difference`, claim tier `deterministic_cli_delta`;
- changed controls: target version and its pinned package/image identity;
- mismatched controls: none.

This is local evidence from the stated contract and run, not a universal guarantee.

## Architecture and safety

The trusted control plane owns contract parsing, image attestation, bounded capture, classification, comparison, and public rendering. The target runs in a fail-closed container lane with no credentials, no network, no writable host bind, and no Docker socket. A bounded run-scoped volume is removed and checked before a result is eligible for classification. Integrity failures produce `runner_error` or `not_comparable`, not a convenient target result.

Current scope is two contracts and two credential-free execution lanes:
`container_no_host_write` for command probes and `container_pty_no_host_write`
for the fixed Codex terminal probe. Public output omits raw terminal and OAuth
output and remains local contract evidence, not universal vendor coverage.

Image construction is a separate concern from target execution. Build inputs include exact package integrity and a digest-addressed base image; obtaining pinned assets during the build phase may need npm/Docker network access. The public bundle omits raw output by design.

## Current scope and non-goals

v0.2 supports two narrow, declarative, credential-free contract paths and
baseline/candidate comparison for AI coding CLIs. It is not a general benchmark
framework, multi-agent orchestrator, cloud service, subjective coding benchmark,
or adapter marketplace. It does not claim to reproduce every vendor environment
or infer a root cause beyond the evidence represented by a contract.

## Project status

v0.2.0 adds the Codex PTY contract while retaining the Gemini command contract.
GitHub release assets provide a wheel and source distribution; Canary Matrix is
not yet published on PyPI and does not make a production-support promise.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for contract-safety and verification
rules, [SECURITY.md](SECURITY.md) for the threat model and private reporting
guidance, [CHANGELOG.md](CHANGELOG.md) for release scope, and
[LICENSE](LICENSE) for the MIT license.
