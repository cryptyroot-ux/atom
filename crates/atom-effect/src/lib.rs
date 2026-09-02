//! atom-effect: EffectIntent, commit boundary, CommitPermit, UNKNOWN_OUTCOME.
//!
//! ATOM — normative source is `spec/` (precedence 1). This crate implements
//! EFX-001..004: durability-before-dispatch, the 16-state effect lifecycle,
//! UNKNOWN_OUTCOME as a first-class state, and the one-shot commit permit that
//! gates the dispatch boundary against TOCTOU and authority drift.

#![forbid(unsafe_code)]

pub mod attenuation;
pub mod admission;
pub mod canonical;
pub mod commit_permit;
pub mod event;
pub mod intent;
pub mod reducer;
pub mod schema;
pub mod semantics;
pub mod state;

mod digest;

pub use admission::{admit_dispatch, AdmissionError};
pub use atom_ledger::DurabilityProof;
pub use canonical::{canonical_request_digest, to_canonical_bytes, CanonicalizationError};
pub use commit_permit::{
    issue_commit_permit, CommitPermit, ConsumeRequest, NonceRegistry, PermitError, PermitRequest,
    ResourceWitness, MAX_PERMIT_TTL_SECONDS,
};
pub use event::{CommitPermitted, EffectEvent, ObservedOutcome, ReconciledOutcome};
pub use intent::{EffectIntent, EffectIntentBuilder, IntentError};
pub use reducer::{project, reduce, trajectory_digest, try_project, try_reduce, ReduceError};
pub use schema::{COMMIT_PERMIT_SCHEMA, EFFECT_INTENT_SCHEMA};
pub use semantics::{
    Compensation, CompensationStrategy, Condition, Idempotency, IdempotencyMode, Reconciliation,
    ReconciliationClass, RetryClass,
};
pub use state::EffectState;
