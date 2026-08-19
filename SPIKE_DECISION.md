# SWITCH_STANDALONE

Decision date: 2026-08-19
OpenBench baseline: `9e26c96a7df012ca9173e9725211c4cc58e11948`

## Decision

Activate the Standalone Vertical Slice for Canary Matrix. Preserve Canary Core,
the declarative contract schema, image attestation, export-integrity rules,
comparison semantics, and public sink gate. Do not adopt or maintain the
OpenBench spike patch as the v0 execution substrate.

This is a substrate decision, not a Gemini CLI result. No vendor pass, failure,
or regression claim was emitted.

## Why the proceed gate failed

The approved gate required a real baseline and candidate execution in
`container_no_host_write`, verified cleanup, a fresh-checkout rerun, and a
byte-identical public bundle from real validated inputs. Unit fakes were allowed
for branch coverage but could not satisfy that final gate.

Four facts prevent `PROCEED_OPENBENCH`:

1. **The real Docker gate was correctly aborted.** The latest preflight found
   `11,965,456 KiB` free (`11.41 GiB`), below the hard `15 GiB` floor. Memory was
   healthy at `42%` free, the host soft open-file limit was only `256`, and macOS
   did not expose a thermal-warning reading. No image was pulled or built and no
   target container was started.
2. **The chosen Gemini calibration is not faithful in the secure lane.** The
   reported `0.42.0` failure occurs while Gemini starts its sandbox through an
   inner Docker invocation and the sandbox image reparses `bash -c`. Faithful
   reproduction therefore requires a nested container runtime. Giving the
   untrusted target the host Docker socket would violate the no-socket,
   no-writable-host boundary, so the contract is disqualified rather than
   weakened. Source: <https://github.com/google-gemini/gemini-cli/issues/26964>
3. **OpenBench no longer remains a thin substrate.** Preserving the required
   semantics needed a patch across four upstream files: `879` insertions and
   `74` deletions. It adds bounded stream capture, process cleanup, a bounded
   tmpfs work volume, safe archive copy-in/copy-out, effective Docker-policy
   enforcement, cleanup verification, and Docker-lane host-probe suppression.
   That is execution-runner ownership, not a small external pack or wrapper.
4. **The mandatory real-run evidence is absent.** There is consequently no
   verified real export pair, no real residual-resource proof, and no public
   artifact eligible for a product claim. The decision gate explicitly forbids
   treating partial integration or synthetic rows as a proceed result.

The device preflight alone would require postponing real execution. The decisive
architecture signal is that the safety contract forced Canary Matrix to replace
most of OpenBench's target-execution boundary while still lacking a faithful
calibration stimulus.

## Evidence completed

- Canary Core and Bridge: `41/41` tests passed.
- Focused patched OpenBench suite: `65/65` tests passed.
- Broader adjacent OpenBench suite: `150/151` tests passed. The sole error was an
  environment-owned sandbox denial when an unchanged auth-persistence test tried
  to write `~/.openbench-test-persist-auth.json`; it did not exercise a changed
  file and is not represented as a green gate.
- The exported patch applies to the pinned index with:

  ```bash
  git apply --check --cached --unidiff-zero patches/openbench-canary-spike.patch
  ```

- Patch SHA-256:
  `7390fcc5654a128e950e7e21bb27fa41bfcf8f5e786103edd6b4c1164cd37783`
- Docker-mode version probing is covered by a negative test proving the target
  CLI is not invoked on the host.
- Contract-authored executable fields, custom redaction regular expressions,
  unsafe fixture paths, malformed npm SRI values, pack symlinks, hard links,
  export tampering, attestation tampering, writable host binds, Docker sockets,
  Docker fallback, version drift, and output-budget bypasses all fail closed.

## Assets retained

The following work transfers directly to the standalone runner:

- pure five-state run classification and three-state pair comparison;
- separate immutable baseline/candidate identities;
- strict declarative contract parsing and fixed probe registry;
- npm SHA-512 package identity and digest-pinned image recipe;
- active image, CLI-version, Node-version, OS, and architecture attestation;
- bounded control-plane output and target-output policy;
- deterministic JSON/Markdown rendering with an explicit public allowlist;
- export and image-attestation SHA-256 binding;
- fail-closed matched-control and execution-lane comparison.

The OpenBench patch remains evidence of the evaluated interface and a source of
tested implementation ideas. It is not the start of a long-lived fork.

## Standalone vertical slice boundary

The next runner should own only the narrow contract path:

1. build or resolve one exact digest-addressed target image;
2. attest it independently;
3. stage one inert fixture into a bounded run-scoped volume;
4. invoke one fixed trusted probe with no network, credentials, Docker socket,
   writable host bind, or fallback lane;
5. capture exact exit/signal/timeout plus bounded stream hashes and samples;
6. verify container and volume removal before classification;
7. write one immutable protected record and derive one allowlisted public bundle;
8. compare two separately verified records through Canary Core.

It should not become a general benchmark framework, multi-agent orchestrator,
subjective coding benchmark, cloud service, or adapter marketplace.

The replacement calibration must be credential-free, deterministic, issue
derived, and runnable without nested Docker. Resume any real image work only
after the host has at least `15 GiB` free and the resource preflight passes.

## Repository state at decision

- `2970210` — canonical run and pair classifiers
- `fd43ab8` — isolated OpenBench execution spike patch
- `7e17c78` — immutable export bridge and image attestation

No repository publication, package release, upstream PR, or public X claim is
authorized by this decision artifact.

## Standalone follow-through — 2026-08-19

The Standalone Vertical Slice subsequently satisfied its first real,
credential-free calibration gate without invoking OpenBench:

- Contract: `gemini-hooks-command-16049`
- Baseline `0.24.0-preview.0`: `unsupported` (`hooks_command_absent`)
- Candidate `0.42.0`: `pass` (`hooks_help`)
- Pair: `observed_difference`, claim tier `deterministic_cli_delta`
- Changed controls: `target.version`, `package.integrity`, `image.digest`
- Mismatched controls: none
- Baseline record SHA-256:
  `acaadb94982414f10f12dd6a0ba8c2b54f14d25d73dd71cd15e761a41a1b9407`
- Candidate record SHA-256:
  `e56d1857474aace3f775b9f6b43dda7026a1a98870307c57f741d2bfd3eff1a5`
- Baseline attestation SHA-256:
  `bd55e4b724b7a754c8995fee8560025fc63ef602148ef1c5b7a63a2e1fc311fd`
- Candidate attestation SHA-256:
  `6773b4e607137339686e2fc548120e6a8253039276445cd33dad0a2a738b95a0`
- All protected/public bundle file hashes verified independently.
- Post-run inventory found zero Canary-labeled containers and volumes.
- Local verification suite: `52/52` tests passed.

The local evidence bundle is intentionally gitignored under
`.canary/evidence/gemini-hooks-16049-20260819T2041Z/`. Publication remains a
separate review and release action.
