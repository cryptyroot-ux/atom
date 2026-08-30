//! atom-effect: EffectIntent, commit boundary, CommitPermit, UNKNOWN_OUTCOME.
//!
//! ATOM v4 — normative source is `spec/` (precedence 1). This crate implements
//! EFX-001..004: durability-before-dispatch, the 16-state effect lifecycle,
//! UNKNOWN_OUTCOME as a first-class state, and the one-shot commit permit that
//! gates the dispatch boundary against TOCTOU and authority drift.

#![forbid(unsafe_code)]

pub mod commit_permit;
pub mod digest;
pub mod event;
pub mod intent;
pub mod reducer;
pub mod semantics;
pub mod state;

pub use commit_permit::{
    admit_dispatch, issue_commit_permit, AdmissionError, CommitPermit, ConsumeRequest, DurabilityWitness,
    NonceRegistry, PermitError, PermitRequest, ResourceWitness, COMMIT_PERMIT_SCHEMA,
    EFFECT_INTENT_SCHEMA, MAX_PERMIT_TTL_SECONDS,
};
pub use event::{CommitPermitted, EffectEvent, ObservedOutcome, ReconciledOutcome};
pub use intent::{EffectIntent, EffectIntentBuilder, IntentError};
pub use reducer::{project, reduce, trajectory_digest, try_project, try_reduce, ReduceError};
pub use semantics::{
    Compensation, CompensationStrategy, Condition, Idempotency, IdempotencyMode, Reconciliation,
    ReconciliationClass, RetryClass,
};
pub use state::EffectState;
