//! The 14 fault classes of `spec/enums.yaml` `fault_class`.
//!
//! The spec is authoritative: this module transcribes the list and its order
//! and adds nothing. The `tests/acceptance.rs` conformance test reparses
//! `spec/enums.yaml` and compares it name for name, so drift fails the build.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The kind of fault a failure represents, from `spec/enums.yaml` `fault_class`.
///
/// A [`FaultClass`] is produced by [`crate::classify`] and consumed by
/// [`crate::recovery_for`]. The wire form is `SCREAMING_SNAKE_CASE`, matching
/// the spec enum exactly.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FaultClass {
    /// A transient provider/transport error; the same request may be sent again.
    ProviderTransient,
    /// The provider asked the caller to slow down (for example, HTTP 429).
    RateLimit,
    /// A call violated a tool's contract or schema (caller-side, deterministic).
    ToolContractError,
    /// A capability the step requires is not present or not granted.
    CapabilityMissing,
    /// A resource is contended or locked (for example, a concurrency clash).
    ResourceConflict,
    /// The environment or topology drifted out from under the plan.
    EnvironmentDrift,
    /// The observation the action relied on is stale.
    StaleEvidence,
    /// The authority (capability grant) drifted: revoked, regenerated, expired.
    AuthorityDrift,
    /// A policy gate denied the action.
    PolicyDenial,
    /// The effect's outcome is genuinely unknown (ATOM-INV-002).
    EffectUnknown,
    /// The plan itself is semantically wrong; the model mis-planned.
    SemanticMisplan,
    /// Verifiers disagree about the outcome.
    VerifierDisagreement,
    /// The execution sandbox failed to provision or run.
    SandboxFailure,
    /// An external connector failed.
    ConnectorFailure,
}

impl FaultClass {
    /// Every fault class, in `spec/enums.yaml` order.
    pub const ALL: [Self; 14] = [
        Self::ProviderTransient,
        Self::RateLimit,
        Self::ToolContractError,
        Self::CapabilityMissing,
        Self::ResourceConflict,
        Self::EnvironmentDrift,
        Self::StaleEvidence,
        Self::AuthorityDrift,
        Self::PolicyDenial,
        Self::EffectUnknown,
        Self::SemanticMisplan,
        Self::VerifierDisagreement,
        Self::SandboxFailure,
        Self::ConnectorFailure,
    ];

    /// Canonical wire representation, matching `spec/enums.yaml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderTransient => "PROVIDER_TRANSIENT",
            Self::RateLimit => "RATE_LIMIT",
            Self::ToolContractError => "TOOL_CONTRACT_ERROR",
            Self::CapabilityMissing => "CAPABILITY_MISSING",
            Self::ResourceConflict => "RESOURCE_CONFLICT",
            Self::EnvironmentDrift => "ENVIRONMENT_DRIFT",
            Self::StaleEvidence => "STALE_EVIDENCE",
            Self::AuthorityDrift => "AUTHORITY_DRIFT",
            Self::PolicyDenial => "POLICY_DENIAL",
            Self::EffectUnknown => "EFFECT_UNKNOWN",
            Self::SemanticMisplan => "SEMANTIC_MISPLAN",
            Self::VerifierDisagreement => "VERIFIER_DISAGREEMENT",
            Self::SandboxFailure => "SANDBOX_FAILURE",
            Self::ConnectorFailure => "CONNECTOR_FAILURE",
        }
    }

    /// The recovery retry class for this fault, per [`crate::recovery_for`].
    #[must_use]
    pub fn recovery(self) -> crate::RetryClass {
        crate::recovery_for(self)
    }

    /// The mission-level recovery directive for this fault, per
    /// [`crate::directive_for`].
    #[must_use]
    pub fn directive(self) -> crate::RecoveryDirective {
        crate::directive_for(self)
    }
}

impl fmt::Display for FaultClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A string that is not one of the 14 spec fault classes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("`{value}` is not a fault class in spec/enums.yaml")]
pub struct ParseFaultClassError {
    /// The rejected input.
    pub value: String,
}

impl FromStr for FaultClass {
    type Err = ParseFaultClassError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| ParseFaultClassError {
                value: value.to_owned(),
            })
    }
}
