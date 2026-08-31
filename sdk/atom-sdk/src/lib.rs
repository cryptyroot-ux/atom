//! atom-sdk: Public SDK — typed clients for the ATOM /v1 API.
//!
//! This crate provides a Rust client that serializes/deserializes the exact
//! wire types matching the OpenAPI spec v4.0.
//!
//! # Design
//! - Uses hand-written DTOs that match the spec (no kernel authority types on wire)
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
    pub use atom_artifact::{
        Artifact, ArtifactError, ArtifactId, Provenance, Sbom, SbomComponent, Signature,
    };
    pub use atom_claim::{
        Claim, ClaimBuilder, ClaimError, ClaimId, ClaimKind, ClaimState, Confidence, Proposition,
        ProvenanceGraph, RetentionPolicy, RetrievalPolicy,
    };
    pub use atom_effect::{
        Compensation, CompensationStrategy, EffectEvent, EffectIntent, EffectIntentBuilder,
        EffectState, Idempotency, IdempotencyMode, IntentError, Reconciliation,
        ReconciliationClass, RetryClass,
    };
}

/// Current crate stage marker (used by conformance tooling).
pub const CRATE_STAGE: &str = "G4-public-sdk";