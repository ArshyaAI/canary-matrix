# Security policy

## Scope

Canary Matrix executes versioned AI coding CLI targets and records operational evidence. Treat target images, fixtures, protected records, and host Docker access as security-sensitive even when a contract is credential-free.

## Threat model

The target CLI and its dependencies are not trusted. The trusted control plane must therefore:

- run the target with no credentials, network, writable host bind, or Docker socket;
- use digest-addressed images and independently verify image/package identity;
- stage only inert, bounded fixture data;
- enforce bounded output, time, and resource policies;
- verify target container and run-scoped volume cleanup before classification; and
- render only the contract’s explicit public allowlist.

The model does not claim to protect a host from a Docker daemon compromise or a misconfigured environment outside the supported lane. Do not weaken the lane to reproduce a target that requires nested Docker or host access.

## Supported versions

The current security policy applies to the unreleased v0.1 source snapshot on the default branch and its source-built package. There is no published package or supported release series yet. Support status may change when a release process and compatibility policy are added.

## Reporting a vulnerability

Please do not disclose sensitive details in a public issue. If GitHub private vulnerability reporting is enabled for this repository, use that channel. Otherwise, do not file a sensitive public issue; ask a maintainer for a private reporting route first.

Include the affected revision, a minimal reproduction, impact, and any relevant contract or execution-lane details. Do not include credentials, private target output, or protected evidence unless a maintainer has provided a private channel.

## No-secrets policy

Never commit credentials, tokens, private keys, personal data, protected evidence, raw target output, or local Docker configuration. Keep local evidence under the ignored `.canary/` directory and review generated bundles before sharing them. The first contract uses `credential_mode = "none"`; a local secret or host bind is not an acceptable workaround.
