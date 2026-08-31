//! SecretHandle — scoped secret delivery token.
//!
//! Per SEC-001: Secrets MUST be delivered by SecretHandle with audience, principal,
//! mission, capability, target, operation, expiry, redemptions and generation constraints.
//!
//! Per INV-006 / ADR-019: SecretHandle is scoped; secrets are never ambient.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A scoped handle for secret redemption.
///
/// The handle carries all constraints that must be validated before the secret
/// is released. This ensures secrets are never ambient in environment variables,
/// model context, or standard telemetry (INV-006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretHandle {
    /// Unique identifier for this secret handle.
    pub secret_id: String,

    /// The audience this secret is intended for (e.g., "api-gateway", "worker-pool").
    pub audience: String,

    /// The principal (identity) authorized to redeem this secret.
    pub principal_id: String,

    /// Optional mission ID this secret is scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,

    /// Optional capability grant ID this secret is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_grant_id: Option<String>,

    /// The target resource or service this secret accesses (e.g., "api.example.com", "db:primary").
    pub target: String,

    /// The operation this secret authorizes (e.g., "read", "write", "admin").
    pub operation: String,

    /// Expiry timestamp — handle is rejected after this time.
    pub expiry: DateTime<Utc>,

    /// Maximum number of times this handle can be redeemed.
    pub max_redemptions: u32,

    /// Number of times this handle has already been redeemed.
    #[serde(default)]
    pub redemptions_used: u32,

    /// Generation counter — stale generations are rejected.
    pub generation: u64,
}

impl SecretHandle {
    /// Create a new secret handle with a generated secret_id.
    pub fn new(
        audience: impl Into<String>,
        principal_id: impl Into<String>,
        target: impl Into<String>,
        operation: impl Into<String>,
        expiry: DateTime<Utc>,
        max_redemptions: u32,
        generation: u64,
    ) -> Self {
        Self {
            secret_id: Uuid::new_v4().to_string(),
            audience: audience.into(),
            principal_id: principal_id.into(),
            mission_id: None,
            capability_grant_id: None,
            target: target.into(),
            operation: operation.into(),
            expiry,
            max_redemptions,
            redemptions_used: 0,
            generation,
        }
    }

    /// Check if the handle is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expiry
    }

    /// Check if the handle has remaining redemptions.
    pub fn has_redemptions_remaining(&self) -> bool {
        self.redemptions_used < self.max_redemptions
    }

    /// Create a builder for more complex handles.
    pub fn builder() -> SecretHandleBuilder {
        SecretHandleBuilder::default()
    }
}

/// Builder for SecretHandle.
#[derive(Default)]
pub struct SecretHandleBuilder {
    secret_id: Option<String>,
    audience: Option<String>,
    principal_id: Option<String>,
    mission_id: Option<String>,
    capability_grant_id: Option<String>,
    target: Option<String>,
    operation: Option<String>,
    expiry: Option<DateTime<Utc>>,
    max_redemptions: Option<u32>,
    redemptions_used: Option<u32>,
    generation: Option<u64>,
}

impl SecretHandleBuilder {
    pub fn secret_id(mut self, secret_id: impl Into<String>) -> Self {
        self.secret_id = Some(secret_id.into());
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn principal_id(mut self, principal_id: impl Into<String>) -> Self {
        self.principal_id = Some(principal_id.into());
        self
    }

    pub fn mission_id(mut self, mission_id: impl Into<String>) -> Self {
        self.mission_id = Some(mission_id.into());
        self
    }

    pub fn capability_grant_id(mut self, capability_grant_id: impl Into<String>) -> Self {
        self.capability_grant_id = Some(capability_grant_id.into());
        self
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    pub fn expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub fn max_redemptions(mut self, max_redemptions: u32) -> Self {
        self.max_redemptions = Some(max_redemptions);
        self
    }

    pub fn redemptions_used(mut self, redemptions_used: u32) -> Self {
        self.redemptions_used = Some(redemptions_used);
        self
    }

    pub fn generation(mut self, generation: u64) -> Self {
        self.generation = Some(generation);
        self
    }

    pub fn build(self) -> SecretHandle {
        SecretHandle {
            secret_id: self.secret_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            audience: self.audience.expect("audience is required"),
            principal_id: self.principal_id.expect("principal_id is required"),
            mission_id: self.mission_id,
            capability_grant_id: self.capability_grant_id,
            target: self.target.expect("target is required"),
            operation: self.operation.expect("operation is required"),
            expiry: self.expiry.expect("expiry is required"),
            max_redemptions: self.max_redemptions.unwrap_or(1),
            redemptions_used: self.redemptions_used.unwrap_or(0),
            generation: self.generation.unwrap_or(0),
        }
    }
}
