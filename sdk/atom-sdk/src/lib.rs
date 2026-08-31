//! atom-sdk: Public SDK — typed clients for the ATOM /v1 API.
//!
//! This crate provides a Rust client that serializes/deserializes the exact
//! wire types defined in the canonical crates (atom-effect, atom-artifact,
//! atom-kernel, atom-claim) so the SDK cannot drift from the in-process model.
//!
//! # Design
//! - Re-uses canonical types from sibling crates (no duplicate definitions)
//! - serde + reqwest for HTTP/JSON
//! - Async-first (blocking helper provided)
//! - No API keys or secrets in source — caller supplies auth via builder

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod types;

pub use client::{AtomClient, AtomClientBuilder, BlockingAtomClient};
pub use error::{SdkError, SdkResult};

/// Re-exports of canonical wire types so callers don't need to import
/// individual crates. These are the exact types that go on the wire.
pub mod wire {
    pub use atom_artifact::{Artifact, ArtifactError, ArtifactId, Provenance, Sbom, SbomComponent, Signature};
    pub use atom_claim::{Claim, ClaimBuilder, ClaimError, ClaimId, ClaimKind, ClaimState, Confidence, ProvenanceGraph, Proposition, RetrievalPolicy, RetentionPolicy};
    pub use atom_effect::{EffectIntent, EffectIntentBuilder, EffectState, EffectEvent, IntentError, Idempotency, IdempotencyMode, Reconciliation, ReconciliationClass, RetryClass, Compensation, CompensationStrategy};
    pub use atom_kernel::{Authorization, CommitToken, AuthorizeRequest, CommitRequest, KernelError};
}

/// Current crate stage marker (used by conformance tooling).
pub const CRATE_STAGE: &str = "G4-Foundry";