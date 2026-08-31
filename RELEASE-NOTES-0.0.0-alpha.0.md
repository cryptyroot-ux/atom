# ATOM 0.0.0-alpha.0 Release Notes

**Release Date:** 2026-08-31
**Tag:** 0.0.0-alpha.0
**Commit:** c2d0c52
**License:** Apache-2.0

## Summary

ATOM 0.0.0-alpha.0 is the first complete implementation of the Sovereign Recursive Agent Architecture — a Rust workspace implementing 26 crates that enforce the boundary between probabilistic cognition and authoritative state mutation.

This is an **alpha release** of the core runtime. Research tracks (Foundry, Evolution, Benchmark, Experience Compiler, JIT, Architecture Learner) and UI/API surface are deferred to future releases.

## What's Included

### Core Runtime (26 crates)

| Crate | Area | Description |
|-------|------|-------------|
| atom-kernel | Sovereign Kernel | Authorize→commit two-gate boundary |
| atom-ledger | Ledger | Tamper-evident event store with hash-chain |
| atom-mission | Mission | Mission lifecycle state machine |
| atom-capability | Authority | Capability grant attenuation (subset-only delegation) |
| atom-effect | Effects | Effect intent, commit permit, reconciliation |
| atom-secret | Secrets | Brokered secret handles (no ambient env) |
| atom-privd | Operations | Privilege daemon (typed host operations) |
| atom-scheduler | Scheduler | Mission scheduling |
| atom-approval | Authority | Durable approval grants |
| atom-claim | Epistemics | Claims with provenance and lifecycle |
| atom-evidence | Evidence | Observations and evidence lifecycle |
| atom-fault | Reliability | Fault classification and recovery |
| atom-replay | Replay | Replay honesty (R0-R4 classes) |
| atom-context | Context | Taint labels and governed declassify |
| atom-runtime | Cognition | Native unprivileged cognition loop |
| atom-identity | Identity | Content-addressed identity binding |
| atom-cert | Certification | Behavior certificates |
| atom-provider | Provider | Provider-agnostic loop |
| atom-restore | Restore | Deterministic restore fencing |
| atom-target | Target | Target resolution |
| atom-connector | Connector | Connector conformance suite |
| atom-memory | Memory | Memory lifecycle (write/execute/forget) |
| atom-worker | Worker | Worker isolation |
| atom-adapter | Adapter | Protocol adapters (MCP, A2A, Hermes, OpenClaw) |
| atom-artifact | Supply Chain | Artifact content verification |
| atom-ui | UI | Mission Control (PWA — not in Rust workspace) |

### Specification

- 40 requirements (26 P0, 14 P1)
- 20 invariants
- 15 acceptance tests (VT-001 through VT-015)
- 8 JSON schemas
- 4 state machines
- OpenAPI 3.1 stub
- Traceability graph (req ↔ test ↔ invariant ↔ crate)
- OWASP Agentic Top 10 crosswalk
- G0 release checklist

### CLI & Packaging

- `atom` binary with `run`, `seal`, `verify`
- `cargo install --path cli/atom-cli`
- Dockerfile (distroless)
- systemd unit (`pkg/atom.service`)
- Installation guide (`pkg/INSTALL.md`)
- Smoke test script (`scripts/deploy-smoke-test.sh`)

### Verified Evidence

```
cargo test --workspace: 374 passed, 0 failed
cargo clippy --workspace --all-targets -- -D warnings: 0 warnings
GitHub Actions CI: Build/Test/Clippy/Secret scan green
Smoke test: 10/10 passed
```

### Dependencies

249 total dependencies (see `sbom.txt` for full list).

## What's NOT Included (Deferred)

| Area | Status |
|------|--------|
| API server / persistent daemon | Not implemented in alpha |
| Capability Foundry | Designed, not built (P1) |
| Evolution | Designed, not built (P1) |
| Benchmark | Designed, not built (P1) |
| Experience Compiler | Designed, not built (P1) |
| Cognition JIT | Designed, not built (P1) |
| Architecture Learner | Designed, not built (P1) |
| Signed release bundle | Deferred |
| Installer/update trust | Deferred |
| v3.1 disposition ledger | Deferred |

## Claims Policy

**No "2G" superiority claim is made with this release.**

Per INV-020: No superiority claim is valid without pinned versions, comparable budgets, reproducible seeds, and independent evaluation. The benchmark harness (atom-benchmark) is not yet built.

## Security

- OWASP Agentic Top 10 crosswalk: `spec/security/owasp-crosswalk.yaml`
- Vulnerability reporting: `SECURITY.md`
- All crates: `#![forbid(unsafe_code)]`
- Root shell exec: denied by default
- Secret scan: CI-enforced

## Upgrade Path

This is the initial alpha release. No upgrade path from prior versions.

## Acknowledgments

Built via multi-agent orchestration:
- **LUNA** (Hermes Agent) — Lead orchestrator, merge gate, conformance
- **Claude Code** (Architect) — Kernel, identity, cert, privd, fault
- **Codex** (Engineer) — Ledger, mission, scheduler, provider, restore, runtime
- **OpenCode** (Challenger) — Capability, effect, policy, secret, approval, context, claim, evidence, replay, target, connector, memory, worker, adapter, artifact

## Artifacts

- Repository: https://github.com/cryptyroot-ux/atom
- Spec: `spec/` directory
- Traceability: `spec/traceability.yaml`
- OWASP Crosswalk: `spec/security/owasp-crosswalk.yaml`
- Release Checklist: `spec/g0-release-checklist.yaml`
