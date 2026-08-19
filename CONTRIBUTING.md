# Contributing to Canary Matrix

Thanks for helping improve a small, safety-sensitive operational checker.

## Before changing a contract or runner

Keep changes grounded in reproducible evidence. A contract must state its source, exact probe, target identities, matched controls, intended changed controls, evidence allowlist, credential mode, and execution lane. Do not turn a synthetic fixture, unit fake, or local observation into a vendor-wide claim.

Preserve the fail-closed boundary: no credentials, network, writable host bind, Docker socket, implicit Docker fallback, or unbounded target output. Do not weaken cleanup, attestation, integrity, timeout, or public-sink checks to make a target pass. If a target needs a prohibited capability, report it as unsupported/inconclusive or stop the run rather than changing the safety contract.

Never commit `.canary/` evidence, raw target output, secrets, private data, or machine-local paths. Review the public allowlist and generated diff before sharing results.

## Local verification

From the repository root, run:

```bash
PYTHONPATH=src python3 -m unittest discover -v
PYTHONPATH=src python3 -m compileall -q src tests
```

These checks use unit fakes and do not start Docker or perform live target tests. A real container run is a separate, explicitly reviewed evidence action. Building target images may require npm/Docker network access; that is distinct from the no-network target runtime.

The source snapshot provides the `canary-matrix` console script. The `check`, `run ...`, and `version` commands documented in the README are the fixed v0.1 interface; a real `run` still requires the separately reviewed Docker evidence lane.

## Pull requests

Describe the contract or safety boundary affected, the evidence behind the change, exact verification commands and results, and any limitations. Keep pull requests focused. Do not claim a release, publication, universal guarantee, or external vendor regression unless the repository contains the corresponding verified evidence and the release action is separately authorized.
