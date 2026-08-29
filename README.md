# ATOM v4 — Sovereign Recursive Agent Architecture

> Capability may recursively grow; authority may not.
> Cognition proposes. Sovereign authority permits. Reality determines outcome.

Open-source, provider-agnostic **Sovereign Agentic Operating System** with a recursive
capability compiler. Mission is the durable product primitive; verified experience is the
compounding primitive.

## Normative precedence

1. `spec/` — canonical machine-readable schemas, state-machines, enums (**authoritative**)
2. `spec/requirements.yaml` + `spec/invariants.yaml`
3. ATOM ADR v1.0 (`/root/docs/atom-v4/ATOM_ADR_v1.0.docx`)
4. PRD / Blueprint / Threat Model / Benchmark (explanatory)

Prose MUST NOT redefine the machine-readable contracts. When in doubt, `spec/` wins.

## Layout (Blueprint §19)

```
spec/                canonical contracts (precedence 1)
crates/              26 Rust crates — sovereign core + planes
evolution/           Evolution Lab (candidate-only): foundry, experience-compiler, jit, learner, evaluator
adapters/            mcp, a2a, agent-skills, hermes, openclaw (versioned profiles; cannot widen authority)
cli/atom-cli         `atom` CLI (Blueprint §17)
sdk/atom-sdk         typed clients for /v1 API
workers/ dashboard/ conformance/ chaos/ benchmarks/ domain-packs/
```

## Milestones

| Gate | Scope |
|---|---|
| **G0 Spec Freeze** | canonical schemas/enums/state-machines + workspace skeleton (**current**) |
| G1 Sovereign Core | ledger, mission reducer, grants/policy, SecretHandle, effect kernel, native cognition |
| G2 Useful Operator | SSH/fs/shell/HTTP/Git/Docker, scheduler, PWA approvals/reconciliation |
| G3 Epistemics | claim graph, taint, replay, fault classifier |
| G4 Foundry | artifact build/test/cert/supply-chain |
| G5 Compounding | Experience Compiler + JIT |
| G6 Architecture Learning | constrained topology learner |
| G7 Evolution Proof | recursive rings + public 2G benchmark |

## Build

```sh
cargo check --workspace     # G0 skeleton compiles
cargo build --workspace
cargo test --workspace
```

## Parallel development discipline

**ONE TASK = ONE SESSION = ONE GIT WORKTREE.** No two agents write the same checkout.
Orchestrated via Agent of Empires (AoE); Hermes/Luna acts as external supervisor.

License: MIT.
