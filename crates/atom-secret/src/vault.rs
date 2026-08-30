//! SecretVault trait — abstract secret redemption interface.
//!
//! The vault validates all SecretHandle constraints before returning the SecretValue.

use crate::handle::SecretHandle;
use crate::value::SecretValue;
use thiserror::Error;

/// Errors that can occur during secret vault operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretVaultError {
    /// The secret handle was not found in the vault.
    #[error("secret not found: secret_id={secret_id}")]
    NotFound { secret_id: String },

    /// The secret handle has expired.
    #[error("secret expired: secret_id={secret_id}, expiry={expiry}")]
    Expired { secret_id: String, expiry: String },

    /// The secret handle has exhausted its maximum redemptions.
    #[error("secret exhausted: secret_id={secret_id}, max_redemptions={max_redemptions}")]
    Exhausted {
        secret_id: String,
        max_redemptions: u32,
    },

    /// The principal attempting redemption does not match the handle.
    #[error("principal mismatch: expected={expected}, got={got}")]
    PrincipalMismatch { expected: String, got: String },

    /// The audience does not match the handle.
    #[error("audience mismatch: expected={expected}, got={got}")]
    AudienceMismatch { expected: String, got: String },

    /// The mission ID does not match the handle.
    #[error("mission mismatch: expected={expected:?}, got={got:?}")]
    MissionMismatch {
        expected: Option<String>,
        got: Option<String>,
    },

    /// The capability grant ID does not match the handle.
    #[error("capability grant mismatch: expected={expected:?}, got={got:?}")]
    CapabilityGrantMismatch {
        expected: Option<String>,
        got: Option<String>,
    },

    /// The target does not match the handle.
    #[error("target mismatch: expected={expected}, got={got}")]
    TargetMismatch { expected: String, got: String },

    /// The operation does not match the handle.
    #[error("operation mismatch: expected={expected}, got={got}")]
    OperationMismatch { expected: String, got: String },

    /// The generation is stale (does not match expected generation).
    #[error("stale generation: secret_id={secret_id}, expected={expected}, got={got}")]
    StaleGeneration {
        secret_id: String,
        expected: u64,
        got: u64,
    },

    /// Internal vault error.
    #[error("vault error: {0}")]
    Internal(String),
}

/// Trait for secret vault implementations.
///
/// A SecretVault stores secrets and validates all constraints on the SecretHandle
/// before releasing the SecretValue. This ensures secrets are never ambient
/// (INV-006) and are only delivered to authorized principals with matching
/// audience, mission, capability, target, operation, expiry, redemptions, and
/// generation constraints (SEC-001).
pub trait SecretVault: Send + Sync {
    /// Redeem a secret using the provided handle.
    ///
    /// Validates all constraints before returning the secret:
    /// - secret_id exists
    /// - not expired
    /// - redemptions remaining
    /// - principal_id matches
    /// - audience matches
    /// - mission_id matches (if specified)
    /// - capability_grant_id matches (if specified)
    /// - target matches
    /// - operation matches
    /// - generation matches
    ///
    /// On successful redemption, increments `redemptions_used` and returns the SecretValue.
    /// The SecretValue will zeroize on drop.
    fn redeem(&self, handle: &SecretHandle) -> Result<SecretValue, SecretVaultError>;

    /// Plant a secret in the vault for later redemption.
    ///
    /// This is typically used by the secret issuer to store a secret that
    /// can later be redeemed by authorized principals.
    fn plant(&self, handle: SecretHandle, secret: SecretValue) -> Result<(), SecretVaultError>;

    /// Check if a secret exists without redeeming it.
    fn exists(&self, secret_id: &str) -> bool;

    /// Get the current redemption count for a secret.
    fn redemption_count(&self, secret_id: &str) -> Option<u32>;
}