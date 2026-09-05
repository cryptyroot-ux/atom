//! Core types for Agent Self.

use serde::{Deserialize, Serialize};

/// Lifecycle states for AgentSelfRevision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevisionState {
    Draft,
    Proposed,
    PendingAuthorization,
    Active,
    Superseded,
    Revoked,
    RolledBack,
    Quarantined,
    Denied,
}

impl RevisionState {
    /// Whether this state allows activation.
    pub fn can_activate(&self) -> bool {
        matches!(self, RevisionState::PendingAuthorization)
    }

    /// Whether this state is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            RevisionState::Superseded
                | RevisionState::Revoked
                | RevisionState::RolledBack
                | RevisionState::Quarantined
                | RevisionState::Denied
        )
    }
}

/// Type of self-change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Identity,
    Soul,
    User,
}

/// Errors from Agent Self operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentProfileError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("invalid state transition: from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("digest mismatch: expected {expected}, found {found}")]
    DigestMismatch { expected: String, found: String },

    #[error("tenant isolation violation: {0}")]
    TenantIsolationViolation(String),

    #[error("self-approval forbidden")]
    SelfApprovalForbidden,

    #[error("quarantined: {0}")]
    Quarantined(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, AgentProfileError>;

/// Compute SHA-256 digest of content.
pub fn content_digest(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(content);
    format!("sha256:{}", hex::encode(hash))
}

/// Current crate stage marker.
pub const CRATE_STAGE: &str = "F6-agent-profile";
