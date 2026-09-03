# ATOM v4.1 Release Notes

**Release Date:** 2026-09-03
**Version:** 0.0.0-alpha.1
**License:** Apache-2.0

## Summary

ATOM v4.1 is a Sovereign Recursive Agent Architecture — a Rust workspace enforcing the boundary between probabilistic cognition and authoritative state mutation. This release implements **142 requirements** (95 P0, 47 P1) across **45 workspace crates**.

## What's Included

### Core Kernel

| Crate | Area | Description |
|-------|------|-------------|
| atom-kernel | Sovereign Kernel | Authorize→commit two-gate boundary (KRN-001/002) |
| atom-ledger | Ledger | Tamper-evident event store with hash-chain, durable nonces |
| atom-capability | Authority | Capability grant attenuation (AUT-001/002/003) |
| atom-effect | Effects | Effect intent, commit permit, reconciliation (EFX-001/002/003/004) |
| atom-approval | Authority | Durable approval grants |
| atom-privd | Operations | Privilege daemon (typed host operations) |

### Mission Runtime

| Crate | Area | Description |
|-------|------|-------------|
| atom-mission | Mission | Mission lifecycle state machine |
| atom-scheduler | Scheduler | Mission scheduling |
| atom-runtime | Cognition | Native unprivileged cognition loop |
| atom-worker | Worker | Worker isolation (deny-by-default) |
| atom-executor | Executor | Durable execution spine |
| atom-context | Context | Taint labels and governed declassify |

### Identity & Evidence

| Crate | Area | Description |
|-------|------|-------------|
| atom-identity | Identity | Content-addressed identity binding |
| atom-evidence | Evidence | Observations and evidence lifecycle |
| atom-claim | Epistemics | Claims with provenance and lifecycle |
| atom-cert | Certification | Behavior certificates |
| atom-secret | Secrets | Brokered secret handles (no ambient env) |

### Reliability & Supply Chain

| Crate | Area | Description |
|-------|------|-------------|
| atom-fault | Reliability | Fault classification and recovery |
| atom-replay | Replay | Replay honesty (R0-R4 classes) |
| atom-restore | Restore | Deterministic restore fencing |
| atom-artifact | Supply Chain | Artifact content verification (SUP-001) |
| atom-provider | Provider | Provider-agnostic loop |

### Adapters & Platform

| Crate | Area | Description |
|-------|------|-------------|
| atom-adapter | Adapter | Protocol adapters (MCP, A2A, Hermes, OpenClaw, Agent Skills) |
| atom-target | Target | Target resolution |
| atom-connector | Connector | Connector conformance suite |
| atom-memory | Memory | Memory lifecycle (write/execute/forget) |
| atom-cli | CLI | Sovereign process CLI (setup, model, status, doctor, run, serve, seal, verify) |
| atom-server | Server | HTTP API server (OpenAPI spec) |
| atom-sdk | SDK | Typed API client |

### Specification (v4.1)

- **142 requirements** (95 P0, 47 P1)
- **30 invariants**
- **142 traceability rows**
- **142 acceptance tests**
- **184 legacy dispositions**
- **12 semantic rules**
- **51 schema bodies**
- **11 state machines**

## Status: CANDIDATE_BASELINE

G0 = PASS_AT_DOCUMENT_PACKAGE
Implementation = NOT_ASSESSED (in progress)

## Known Gaps

- 18 requirements MISSING (Architecture Council, Open Governance, Experience Compiler, Cognition JIT, Architecture Learning)
- 9 evidence directories (G1–G9) belum dibuat (artefak runtime)
- 2 state machines non-standard (evolution.yaml, foundry.yaml)
- 1 state machine invalid YAML (agent-self-revision.yaml)

## Last Changes

- P0-1: Bind DurabilityProof to exact EffectIntent via payload digest
- P0-3: Budget conservation across all child grants (max_cost AND max_seconds)
- Display layer: banners, panels, markdown rendering, spinners
- NLU routing: 20 patterns for status/version/model/uptime queries
