//! The authoritative wire schemas, embedded straight from `spec/schemas/`.
//!
//! They are included rather than copied: a schema change in `spec/` reaches the
//! conformance suite on the next build, so the code cannot quietly disagree
//! with the normative source.

/// `spec/schemas/effect-intent.schema.json` — the EFX-002 field set.
pub const EFFECT_INTENT_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/schemas/effect-intent.schema.json"
));

/// `spec/schemas/commit-permit.schema.json` — the EFX-004 commit permit.
pub const COMMIT_PERMIT_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/schemas/commit-permit.schema.json"
));
