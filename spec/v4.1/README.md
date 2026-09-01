# ATOM v4.1 Canonical Specification (migration namespace)

This directory holds the **canonical, machine-readable ATOM v4.1 contract**. It was landed
from the controlled v4.1 document package (`ATOM_PRD_v4.1`, `ATOM_VTA_v4.1`,
`ATOM_Architecture_Constitution_v4.1`, `ATOM_Technical_Blueprint_v4.1`,
`ATOM_v4.1_Correction_and_Completion_Release`) without weakening the specification.

The legacy `spec/*.yaml` (v4.0.0) pack is intentionally **left in place** during cutover so a
partial migration cannot produce a false-green CI. Top-level pointers are replaced only after
code and conformance are migrated and the v4.1 G0 validator passes.

## Precedence (authority order)

1. Architecture Constitution (invariants)
2. This machine-readable canonical pack (`spec/v4.1/`)
3. Ratified ADR
4. PRD
5. Technical Blueprint
6. Explanatory / audit material

## Controlled baseline (verified this session)

| Artifact | Controlled total | Machine-readable here | Body coverage |
|---|---|---|---|
| Requirements | 142 | ✅ `requirements.yaml` (142) | n/a |
| Invariants | 30 | ✅ `invariants.yaml` (30) | n/a |
| Traceability rows | 142 | ✅ `traceability.yaml` (142, bidirectional) | n/a |
| Acceptance tests | 142 | ✅ `acceptance-catalog.yaml` (142) | executable coverage tracked by conformance, not G0 |
| Legacy v3.1 dispositions | 184 | ✅ `legacy-disposition.yaml` (184 unique) | n/a |
| Semantic rules | 12 | ✅ `semantic-rules.yaml` (12) | n/a |
| JSON Schemas | 51 | ⚠️ `schemas/inventory.yaml` (51 declared) | **7 v4.0 bodies pending review, 0 fixtures** → G0 BLOCKED |
| State machines | 9 | ⚠️ `state-machines/inventory.yaml` (9 declared) | **2 v4.0 bodies pending review** → G0 BLOCKED |
| Gates | G0–G9 | ✅ referenced by requirements + traceability | evidence-backed per gate |

Counts are **verified** (`requirements=142, invariants=30, schemas=51 distinct contracts,
state_machines=9, acceptance=142, legacy=184`). The 51 schema contracts are the distinct
`spec/schemas/*.schema.json` paths referenced by `traceability.yaml`; the 9 state machines and
their state/transition counts come from the canonical VTA state-machine table.

## Honest gaps (do NOT report these as complete)

- **Schema bodies + fixtures**: v4.1 G0 requires all 51 schema bodies plus one valid and one
  invalid fixture each (102 fixtures). Only 7 v4.0-era bodies exist and none are fixture-backed.
  These are inventoried with `body_status`, never claimed complete.
- **State-machine bodies**: 9 declared; only `effect` and `mission` have v4.0 bodies (pending
  v4.1 review for the exact states/transitions in the VTA table).
- Because of the two gaps above, **repository G0 is FAIL/BLOCKED** on schema-fixture and
  state-machine completeness. The document-package G0 (`manifest.yaml: g0:
  PASS_AT_DOCUMENT_PACKAGE`) is a distinct, weaker claim about the DOCX pack only.

## M-NEW-01 finding — constitutional invariant traceability asymmetry (RESOLVED)

The audit asked whether INV-021..030 missing from per-requirement traceability meant traceability
was incomplete. **Verified answer: by design, not a defect.**

- The Constitution defines exactly 30 invariants (INV-001..030), all present in `invariants.yaml`.
- Per-requirement traceability rows reference only INV-001..020 (`class: requirement-linked`).
- INV-021..030 (`class: global-meta`) are cross-cutting governance invariants — release
  truthfulness (021), traceability completeness (022), semantic-rule gating (023), external
  no-authority (024), update integrity (025), data-egress control (026), sealed-evidence
  immutability (027), fallback safety (028), no-generic-shell privileged surface (029),
  deterministic gate decisions (030). They are enforced at the release/gate/governance layer
  (G0/G1/G9), which is why they are not bound to any single requirement's data flow.

No per-requirement trace mappings were fabricated to make a validator green. The G0 validator
asserts all 30 are present, that every INV-001..020 is referenced by ≥1 requirement, and that
INV-021..030 are declared `global-meta`.
