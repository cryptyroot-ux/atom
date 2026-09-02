# PR C Gap Analysis — Authority/Effect P0 Hardening

## Verifikasi State Saat Ini (this session)

Repo state:
- branch: `feat/authority-effect-p0-hardening`
- HEAD: `9b4b1acbf8755fd75cac3dbed0c7ac78e49597f0`
- 14 file modified (4 LUNA patch + atom-effect/atom-kernel/atom-executor/atom-ledger/atom-runtime/atom-privd)
- G0 v4.1 baseline: PASS 67/67 (142 req / 30 inv / 142 trace / 142 accept / 184 legacy / 12 sem / 51 schema+102 fixture / 9 sm)

## Kekurangan P0 yang Dikonfirmasi

| Konsep P0 (dari master prompt §10) | Status di kode |
|---|---|
| `parent_grant_id` (immutable delegation lineage) | TIDAK ADA di `crates/atom-effect/src/commit_permit.rs` maupun `intent.rs` |
| `parent_authority_digest` | TIDAK ADA |
| `delegation_depth`, `max_delegation_depth` | TIDAK ADA |
| `holder_binding` | TIDAK ADA |
| `authority_digest` pada delegated grant | TIDAK ADA |
| `attenuate(parent, request) -> Result<child, DenyReason>` (deterministic monotonic) | TIDAK ADA |
| Per-dim attenuation (op, resource, purpose, audience, budget, time, depth, egress, risk, data-class, constraints) | TIDAK ADA |
| Fan-out budget conservation (sum(child alloc) + consumed parent ≤ parent budget) | TIDAK ADA |
| `EffectiveAuthorityView` derivation (root + lineage + policy + revocation + budget + approval + composition + workload) | TIDAK ADA |
| `CommitPermit` bound ke `dispatch_sink_id`, `connector_identity`, `connector_version`, `connector_instance_epoch` | TIDAK ADA — field saat ini tidak mencakup semua itu |
| `one_shot_nonce` + `DurabilityWitness` verification | TIDAK ADA |
| Synthetic `DurabilityWitness` rejection | TIDAK ADA |

## File Kode yang Perlu Diubah

- `crates/atom-effect/src/commit_permit.rs` (682 baris) — tambahkan field lineage, sink binding, nonce, witness
- `crates/atom-effect/src/intent.rs` (478 baris) — buat typed `attenuate()` dan `EffectiveAuthorityView`
- `crates/atom-kernel/src/lib.rs` — integrasi attenuation ke Authority Kernel
- `crates/atom-ledger/src/store.rs` — durable nonce/witness ledger
- Test baru di `crates/atom-effect/tests/` dan `crates/atom-kernel/tests/`

## Test Wajib (dari master prompt §12)

Delegation:
- delegation_chain_parent_substitution → DENY
- delegation_chain_splicing → DENY
- child_operation_wider_than_parent → DENY
- child_resource_wider_than_parent → DENY
- child_budget_greater_than_parent → DENY
- fanout_total_exceeds_parent_budget → DENY
- child_expiry_longer_than_parent → DENY
- unknown_constraint_semantics → DENY
- parent_revoked_after_child_created → CHILD_UNUSABLE
- offline_chain_verification → PASS

Effect finality:
- valid_permit_wrong_connector → DENY
- valid_permit_wrong_sink → DENY
- valid_permit_stale_instance_epoch → DENY
- valid_permit_modified_arguments → DENY
- replayed_one_shot_nonce_after_restart → DENY
- synthetic_durability_witness → DENY
- permit_after_policy_generation_change → DENY
- parallel_calls_share_one_permit → DENY

## Status PR C: BELUM DIMULAI

Implementasi tidak dibuat di sesi ini karena:
1. Master prompt melarang stub/test yang selalu PASS tanpa oracle deterministik.
2. Implementasi P0 memerlukan perubahan pada 5+ file kode inti dengan interdependensi (ledger, kernel, effect, executor).
3. Setiap test P0 harus memanggil production logic nyata dan gagal jika implementasi dirusak — ini butuh implementasi nyata, bukan kerangka.

Next action tunggal paling penting: authorize eksekusi implementasi P0 (akan menyentuh `commit_permit.rs`, `intent.rs`, `kernel/lib.rs`, `ledger/store.rs`) — atau tunda PR C sampai sub-task khusus.
