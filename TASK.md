# TASK — atom-capability (OpenCode · Challenger/Reviewer)

Branch: `feat/capability` · Crate: `crates/atom-capability`

## Requirement (spec/ is AUTHORITATIVE — precedence 1)
- **AUT-001** (P0): CapabilityGrant MUST bind subject/workload identity, operation, resource selector, purpose, validity interval, budget, delegation depth, audience, generation, revocation, and parent grant where delegated.
- **AUT-002** (P0): Delegation MUST be syntactically AND semantically subset-only.
- **INV-003**: Capability delegation can ONLY attenuate authority; child authority never broader than parent.
- **INV-012**: Resource pressure, urgency, model recommendation, or repeated success NEVER increases authority.
- **ADR-015**: Capability Contract v1 as universal substrate.
- **ADR-017**: Authority profiles (Observe/Operate/Admin/Unattended/Custom) compile to explicit grants; profiles never bypass policy.

## Canonical schema (spec/schemas/capability-grant.schema.json — match EXACTLY)
required: grant_id, subject_id, workload_id, operations, resources, purpose, not_before, expires_at, budget, delegation_depth, audience, generation, revocation_state
optional: parent_grant_id, nonce, constraints

## Deliverable
1. `CapabilityGrant` struct matching the schema (validate against it).
2. `subset_check(parent, child) -> Result` enforcing over EVERY dimension:
   - operations ⊆ parent operations
   - resources semantically contained
   - budget ≤ parent remaining reservation
   - time window inside parent
   - delegation_depth strictly decreases
   - audience/purpose cannot widen
3. Authority profile → grant compiler (Observe/Operate/Admin/Unattended/Custom).

## TDD (write tests FIRST from acceptance/catalog.yaml)
- **ATOM-VT-005**: child requests broader targets/operation/budget → kernel DENIES + records evidence.
- Property test: for random parent/child, subset_check(parent, child)=OK ⟹ child authority ⊆ parent (lattice property, AUT-002).
- INV-012 test: no code path raises authority under any "pressure" signal.

## Hard rules
- INV-003/012 are the whole point: attenuate-only, NEVER widen. Adversarial mindset — try to break your own subset_check.
- `#![forbid(unsafe_code)]`. Do NOT touch other crates or spec/.

## Definition of Done
- `cargo test -p atom-capability` green, VT-005 + lattice property covered.
- `cargo clippy` clean. Commit to `feat/capability`. Do NOT merge — Luna owns merge gate.
