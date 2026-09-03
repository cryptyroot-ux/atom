# ATOM Master Implementation — Execution Plan

## Phase 0: Foundation (Current State)
- [x] P0-1: DurabilityProof binding ✅
- [x] P0-3: CapabilityGrant field expansion ✅
- [x] Display layer ✅
- [x] NLU routing ✅
- [x] G0 truth drift reconciliation ✅
- [x] GOVERNANCE.md, SECURITY.md ✅

---

## Phase 1: Constitutional Agent Self Addendum (PR B) ✅ COMPLETE

### 1.1 Create `spec/addenda/agent-self-v1/` (complete)
- manifest.yaml (version, digest, parent baseline)
- constitution-addendum.yaml (constitutional clauses)
- requirements.yaml (28 requirements)
- invariants.yaml (6 invariants)
- semantic-rules.yaml (8 rules)
- traceability.yaml (28 rows)
- acceptance-catalog.yaml (28 tests)
- schemas/ (12 schema files)
- state-machines/ (3 state machines)

### 1.2 Constitutional Clauses (§5)
- Persona Non-Authority
- Identity Domain Separation
- Governed Self-Modification
- Constitutional Enforcement Is Not Prompt Compliance
- Identity Continuity and Tenant Isolation

### 1.3 Data Model (§6) — New crate `atom-agent-profile`
- AgentIdentityProfile
- SoulProfile
- AgentSelfRevision
- EffectiveSelfView

---

## Phase 2: Authority Kernel P0 Hardening (PR C)

### 2.1 Immutable Delegation Lineage (§10)
- parent_grant_id, parent_authority_digest
- delegation_depth, max_delegation_depth
- holder_binding, authority_digest
- Child commits to exact canonical parent

### 2.2 Deterministic Monotonic Attenuation (§10)
- `attenuate(parent, request) -> Result<child, DenyReason>`
- All dimensions: operation, resource, purpose, audience, budget, time, depth, egress, risk, classification, constraints
- Unknown comparator → DENY

### 2.3 Fan-out Budget Conservation (§10)
- Durable reservation/accounting
- `sum(active child allocations) + consumed parent budget ≤ parent budget`
- Concurrency, crash recovery, revocation, release

### 2.4 EffectiveAuthorityView (§10)
- Derived from: root grant, lineage, policy, revocation generation, remaining budget, approval envelope, composition restrictions, workload/holder identity
- Short-lived, not persistent grant

### 2.5 CommitPermit Finality (§10)
- Bound to: effect_digest, dispatch_sink_id, connector_identity, connector_version, connector_instance_epoch, target/resource witness, principal/workload identity, policy generation, grant/revocation generation, one_shot_nonce, expiry
- Effect Kernel compares permit with actual invocation before dispatch
- Nonce + budget consumption durable and atomic
- DurabilityWitness verified against authoritative ledger

---

## Phase 3: Governed Agent Workspace (PR D)

### 3.1 Workspace Layout (§7)
- templates/workspace/ (AGENTS.md, SOUL.md, IDENTITY.md, USER.md, MEMORY.md)
- Runtime: ${ATOM_STATE_DIR}/workspaces/<agent_id>/
- File semantics: IDENTITY.md, SOUL.md, USER.md, AGENTS.md, MEMORY.md, CONSTITUTION.md

### 3.2 Context Assembly (§8)
- Deterministic precedence: Constitution → Owner Policy → AgentIdentityProfile → SoulProfile → UserProfile → MissionSpec → ContextItems → User turn
- All items carry provenance, trust, sensitivity, injection-risk, digest
- Identity/soul/constitution digests in session metadata, provider-call record, mission trace, decision trace, replay input, audit evidence
- No raw USER.md/MEMORY.md in group channel, peer protocol, subagent, external provider

### 3.3 CLI Extension (§9)
- `atom workspace init`
- `atom identity show/edit/propose/history/rollback`
- `atom soul show/edit/propose/approve/history/rollback`
- `atom workspace import --from openclaw`
- `atom workspace import --from hermes`

---

## Phase 4: v4.1 G2 Conformance Cutover (PR E)

### 4.1 Executable Conformance (§11)
- Loader reads spec/v4.1/acceptance-catalog.yaml
- ID: ATOM-VT41-*
- Legacy v4.0 compatibility mapping
- Coverage registry: IMPLEMENTED, MAPPED_EXISTING, PARTIAL, NOT_IMPLEMENTED, BLOCKED
- Test requirements: production logic, deterministic oracle, negative/tampered control, evidence, fail on deliberate corruption, linked to requirement/invariant

### 4.2 Acceptance Tests (§12)
- Agent Self: soul_authority_escalation, identity_display_change_does_not_change_workload_identity, unapproved_self_mutation, agent_self_approves_own_change, tampered_soul_digest, constitution_digest_mismatch, provider_switch_preserves_agent_identity, agent_restart_preserves_active_self_generation, tenant_a_profile_visible_to_tenant_b, private_user_profile_in_shared_channel, private_user_profile_in_subagent, rollback_restores_exact_prior_profile
- Delegation: delegation_chain_parent_substitution, delegation_chain_splicing, child_operation_wider_than_parent, child_resource_wider_than_parent, child_budget_greater_than_parent, fanout_total_exceeds_parent_budget, child_expiry_longer_than_parent, unknown_constraint_semantics, parent_revoked_after_child_created, offline_chain_verification
- Effect: valid_permit_wrong_connector, valid_permit_wrong_sink, valid_permit_stale_instance_epoch, valid_permit_modified_arguments, replayed_one_shot_nonce_after_restart, synthetic_durability_witness, permit_after_policy_generation_change, parallel_calls_share_one_permit
- E2E: Constitutional path (11 steps)

---

## Phase 5: CI & Evidence (§13)

### 5.1 Required Checks
- cargo fmt --all -- --check
- cargo build --workspace
- cargo test --workspace
- cargo clippy --workspace --all-targets -- -D warnings
- bash tools/secret_scan.sh .
- python tools/validate_release.py --root . --emit evidence/g0/gate-result.json

### 5.2 Evidence Format
- exact commit SHA, branch, test ID, requirement/invariant links, timestamp, toolchain version, result, evidence digest

---

## Phase 6: Release Discipline (§15)

- No release tag until evidence supports
- No version bump just to look finished
- No VS2 frozen claim
- No G2 PASS claim
- No production-ready claim
- No 142/142 executable tests claim

Release only after:
- master protected checks green
- G0 truth drift done
- P0 Authority/Effect tests PASS
- conformance coverage reported honestly
- signed/annotated tag
- consistent commit identity
- provenance and attestable SBOM
- user approval

---

## Execution Order

1. **Phase 1** (Agent Self Addendum) — spec + schemas + state machines
2. **Phase 2** (Authority Kernel P0) — delegation, attenuation, budget, EffectiveAuthorityView, CommitPermit
3. **Phase 3** (Governed Workspace) — templates, context assembly, CLI
4. **Phase 4** (G2 Conformance) — loader, coverage registry, acceptance tests
5. **Phase 5** (CI & Evidence) — integrate all validators
6. **Phase 6** (Release) — only after all above complete

---

## PR Strategy (§14)

| PR | Scope | Depends On |
|----|-------|------------|
| PR A | G0 Truth Reconciliation | Done |
| PR B | Constitutional Agent Self Addendum | Phase 1 |
| PR C | Authority and Effect P0 Hardening | Phase 2 |
| PR D | Governed Agent Workspace | Phase 3 |
| PR E | v4.1 G2 Conformance Cutover | Phase 4 |

Each PR: narrow scope, migration notes, test evidence, rollback story, no auto-merge.
