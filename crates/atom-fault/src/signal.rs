//! [`FaultSignal`]: the typed, observable facts of a failure.
//!
//! Every field is a small, closed facet with a benign default, so a signal is
//! built by setting only the facts that actually hold, for example:
//!
//! ```
//! use atom_fault::{FaultSignal, PolicyDecision};
//!
//! let signal = FaultSignal {
//!     policy: PolicyDecision::Denied,
//!     ..FaultSignal::default()
//! };
//! ```
//!
//! The facets are deliberately verdicts, not raw inputs: staleness, authority
//! drift, and verifier disagreement are decided by the caller (which may read a
//! clock or a registry) and passed in already reduced to a category. That is
//! what keeps [`crate::classify`] pure and clock-free.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use atom_effect::EffectState;

/// The decision of the policy gate for the attempted action.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    /// Policy permits the action.
    #[default]
    Allowed,
    /// Policy denied the action; no lower-level recovery may override it.
    Denied,
}

/// The result of re-checking the capability grant behind the action.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityStatus {
    /// The grant is still valid for this action.
    #[default]
    Valid,
    /// The grant drifted: revoked, regenerated, expired, or the wrong generation.
    Drifted,
}

/// Whether a capability the step requires is available.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityStatus {
    /// The required capability is present and granted.
    #[default]
    Present,
    /// The required capability is missing.
    Missing,
}

/// Whether the plan step is semantically sound.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanStatus {
    /// The plan step is sound.
    #[default]
    Sound,
    /// The plan step is semantically wrong; the model mis-planned.
    Misplanned,
}

/// The outcome of a tool/API call against its declared contract.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolStatus {
    /// The call satisfied the tool contract.
    #[default]
    Ok,
    /// The call violated the tool's contract or schema.
    ContractError,
}

/// The freshness of the observation the action relied on.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    /// The observation is fresh enough to act on.
    #[default]
    Fresh,
    /// The observation is stale and must be renewed before acting.
    Stale,
}

impl EvidenceStatus {
    /// Decide freshness from an already-measured age against a horizon.
    ///
    /// This is pure and clock-free: the caller measures `age` with its own
    /// clock and passes the elapsed [`Duration`] in. An observation is
    /// [`Stale`](Self::Stale) once its age exceeds `horizon`.
    #[must_use]
    pub fn from_age(age: Duration, horizon: Duration) -> Self {
        if age > horizon {
            Self::Stale
        } else {
            Self::Fresh
        }
    }
}

/// Whether independent verifiers agree on the outcome.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifierStatus {
    /// Verifiers agree.
    #[default]
    Agreement,
    /// Verifiers disagree about the outcome.
    Disagreement,
}

/// Whether the environment or topology matches what the plan assumed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnvironmentStatus {
    /// The environment matches the plan's assumptions.
    #[default]
    Stable,
    /// The environment or topology drifted.
    Drifted,
}

/// Whether a resource the action needs is contended.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceStatus {
    /// The resource is available.
    #[default]
    Clear,
    /// The resource is contended or locked (for example, a concurrency clash).
    Conflict,
}

/// The health of the execution sandbox.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SandboxStatus {
    /// The sandbox is healthy.
    #[default]
    Ok,
    /// The sandbox failed to provision or run.
    Failed,
}

/// The health of an external connector.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectorStatus {
    /// The connector is healthy.
    #[default]
    Ok,
    /// The connector failed.
    Failed,
}

/// The provider/transport status of the request (for example, HTTP class).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportStatus {
    /// No transport-level fault.
    #[default]
    Ok,
    /// A transient transport error (for example, a 5xx or a reset).
    Transient,
    /// The provider asked the caller to slow down (for example, HTTP 429).
    RateLimited,
}

/// The observable facts of a failure, fed to [`crate::classify`].
///
/// Each facet defaults to its benign value, so a signal is built by naming only
/// the facts that hold. A [`FaultSignal`] is cheap ([`Copy`]) and carries no
/// clock, handle, or I/O: it is a plain record of verdicts.
///
/// Classifying a fully benign signal (nothing set) yields
/// [`crate::FaultClass::EffectUnknown`] — the fail-safe residue for a fault
/// that no facet explains (see [`crate::classify`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FaultSignal {
    /// The effect lifecycle state, when the fault sits on an effect path.
    ///
    /// [`EffectState::UnknownOutcome`] or [`EffectState::Reconciling`] make the
    /// outcome ambiguous and dominate every other facet (ATOM-INV-002).
    pub effect_state: Option<EffectState>,
    /// The policy gate's decision.
    pub policy: PolicyDecision,
    /// The capability grant re-check result.
    pub authority: AuthorityStatus,
    /// Whether a required capability is present.
    pub capability: CapabilityStatus,
    /// Whether the plan step is sound.
    pub plan: PlanStatus,
    /// The tool contract outcome.
    pub tool: ToolStatus,
    /// The freshness of the observation the action relied on.
    pub evidence: EvidenceStatus,
    /// Whether verifiers agree.
    pub verifier: VerifierStatus,
    /// Whether the environment drifted.
    pub environment: EnvironmentStatus,
    /// Whether a needed resource is contended.
    pub resource: ResourceStatus,
    /// The execution sandbox health.
    pub sandbox: SandboxStatus,
    /// The external connector health.
    pub connector: ConnectorStatus,
    /// The provider/transport status.
    pub transport: TransportStatus,
}

impl FaultSignal {
    /// A signal with every facet benign.
    ///
    /// Equivalent to [`FaultSignal::default`]; provided as a named base for the
    /// `..FaultSignal::benign()` struct-update idiom.
    #[must_use]
    pub fn benign() -> Self {
        Self::default()
    }

    /// Whether the effect outcome is ambiguous (ATOM-INV-002).
    ///
    /// True when [`Self::effect_state`] is [`EffectState::UnknownOutcome`] or
    /// [`EffectState::Reconciling`] — the states for which the effect has not
    /// settled into success or failure.
    #[must_use]
    pub fn is_effect_ambiguous(self) -> bool {
        matches!(
            self.effect_state,
            Some(EffectState::UnknownOutcome | EffectState::Reconciling)
        )
    }
}
