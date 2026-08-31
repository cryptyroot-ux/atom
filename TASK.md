# TASK — G4 Foundry: atom-sdk (Codex · Engineer)

Worktree: `feat/foundry-sdk` · Edit ONLY `sdk/atom-sdk/`

## Objective
Ship `atom-sdk`: a typed Rust client for ATOM's `/v1` API so external tools and
the CLI can drive a running ATOM node over HTTP without hand-rolling JSON.

## Deliverables
1. `sdk/atom-sdk/src/lib.rs` — REAL client (replace the G0 skeleton stub).
2. Typed client with methods covering at least:
   - `submit_effect(EffectIntent)` → returns CommitToken-shaped response
   - `verify_artifact(Artifact)` → bool / result
   - `get_claim(id)` / `put_claim(Claim)` against atom-claim/atom-evidence
   - `health()` → node status
   Define endpoint paths/structs yourself; keep consistent with the OpenAPI 3.1
   stub in repo root (`spec/openapi.yaml`) and structs in atom-effect, atom-kernel,
   atom-artifact, atom-claim.
3. JSON via serde; HTTP via reqwest (async preferred) or ureq.
4. Error type wrapping transport + API errors.
5. `#![forbid(unsafe_code)]`.

## Acceptance
- `cargo build -p atom-sdk` compiles.
- `cargo test -p atom-sdk` passes (client constructs, request serializes to
  expected shape, mock/recorded response deserializes, error path works).
- `cargo clippy -p atom-sdk --all-targets` clean (0 warnings).
- Public API documented (`///`) enough to use without reading internals.
- No API key/secret hardcoded; caller supplies auth via client builder.

## Constraints
- Read-only vs other crates: depend on them, do NOT change them.
- Types must match canonical structs (reuse atom_effect::EffectIntent,
  atom_artifact::Artifact, atom_kernel::CommitToken) so wire format can't drift.
- Commit to `feat/foundry-sdk` when tests pass. Then STOP (wait for merge gate).
