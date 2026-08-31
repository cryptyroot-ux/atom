# TASK: atom-capability-foundry — G5 Compounding

**Wave:** G5 Compounding (Evolution Lab)
**Owner:** Codex (Engineer/Implementer)
**Base:** master @ e51787f

## Objective
Implement Capability Foundry (ATOM-FND-001/002/003) per spec:
- Tool Foundry: synthesize multiple candidate interfaces/implementations
- Gate activation on: hermetic build, tests, property/fuzz/adversarial checks, hidden holdout, certificate (ATOM-FND-001)
- Workflow Foundry: produce typed durable workflows with explicit failure/timeout/retry/reconciliation/compensation transitions (ATOM-FND-002)
- Verifier Foundry: label verifier independence using V0-V5 taxonomy (ATOM-FND-003)

## Spec References
- requirements.yaml: ATOM-FND-001/002/003 (P1)
- acceptance/catalog.yaml: VT-010 (foundry holdout)
- enums.yaml: evolution_class E0-E8, verifier_level V0-V5, foundry_state
- invariants.yaml: INV-008 (generated capability requires cert), INV-017 (separated eval)

## Deliverables
1. `crates/atom-capability-foundry/src/tool.rs` — ToolFoundry struct + synthesize candidates
2. `crates/atom-capability-foundry/src/workflow.rs` — WorkflowFoundry + typed transitions
3. `crates/atom-capability-foundry/src/verifier.rs` — VerifierFoundry + V0-V5 labeling
4. `crates/atom-capability-foundry/src/gate.rs` — Activation gate (build+test+fuzz+holdout+cert)
5. `crates/atom-capability-foundry/tests/foundry.rs` — VT-010 holdout suite + cert gate
5. `crates/atom-capability-foundry/Cargo.toml` — deps: atom-capability, atom-artifact, atom-cert, atom-claim

## Acceptance
- `cargo test -p atom-capability-foundry` passes (VT-010 + property tests)
- `cargo clippy -p atom-capability-foundry --all-targets -- -D warnings` clean
- `#![forbid(unsafe_code)]` in lib.rs
- Authority boundary: foundry emits Candidate + Certificate, never direct CapabilityGrant

## Definition of Done
All tests pass, clippy clean, VT-010 holdout blocks uncertified candidates, cert required for ACTIVE.