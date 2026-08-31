# Governance

## Overview

ATOM is an open-source sovereign agent runtime developed by Crypty Root / Rootlabs.
This document defines governance structure, decision-making processes, and community expectations.

## Roles

### Trusted Core

| Role | Person | Scope |
|------|--------|-------|
| **Project Lead** | Crypty Root | Architecture, release decisions, security policy |
| **Lead Orchestrator** | LUNA (Hermes Agent) | Build coordination, merge gate, conformance |
| **Security Lead** | Crypty Root | Vulnerability response, threat model, security releases |

### Contributors

Anyone who submits a pull request, reports a bug, or improves documentation.
Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign commits with DCO.

## Decision Making

### Architecture Decisions

- Recorded in `spec/` as ADR (Architecture Decision Records)
- ADR-001 through ADR-040 are normative for v4.0
- New ADRs require Trusted Core approval
- ADRs are immutable once accepted; supersession is by new ADR

### Code Changes

- All changes via pull request to `main` branch
- Required: CI green, clippy clean, 1+ Trusted Core review
- Security-impacting changes: 2 Trusted Core reviews + SECURITY.md review
- Merge gate: LUNA verifies test count, clippy, and conformance before merge

### Releases

- Semantic versioning (MAJOR.MINOR.PATCH)
- Release decisions signed by Project Lead
- Release artifacts include: source, spec, test evidence, SBOM, checksums
- Security releases may bypass normal cadence

## Contribution Process

1. Fork repository
2. Create feature branch from `main`
3. Implement with tests (TDD preferred)
4. Ensure `cargo test --workspace` and `cargo clippy --workspace` pass
5. Submit PR with description linking to requirement ID (e.g., `ATOM-V4-KRN-001`)
6. Address review feedback
7. Trusted Core merges after CI + review

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Code of Conduct

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report conduct issues to conduct@rootlabs.fun.

## License

Apache License 2.0. See [LICENSE](LICENSE).

All contributions are assumed to be under Apache-2.0 unless explicitly stated otherwise.
Contributors retain copyright to their contributions.

## Security Disclosure

See [SECURITY.md](SECURITY.md) for vulnerability reporting process.

## Amendment

This governance document may be amended by Trusted Core consensus.
Amendments are recorded as commits to this file with rationale in commit message.
