//! Durable effect events: the only input the reducer accepts.
//!
//! Every variant corresponds to something that has already happened and been
//! written down. Commands, intentions and model output are not events, so they
//! cannot move an effect's state.

use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::digest::digest_component;

/// What an observation of the target concluded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservedOutcome {
    Success,
    Failure,
    /// The effect landed in part: some postconditions hold, others do not.
    Partial,
    /// The observation itself was inconclusive (INV-002).
    Ambiguous,
}

impl ObservedOutcome {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::Partial => "PARTIAL",
            Self::Ambiguous => "AMBIGUOUS",
        }
    }
}

/// What a reconciliation probe concluded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciledOutcome {
    Success,
    Failure,
    Partial,
    /// The probe could not settle the question; the effect stays unknown.
    Inconclusive,
}

impl ReconciledOutcome {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::Partial => "PARTIAL",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// A human-readable cause, carried by the events that record a refusal or loss.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Reason {
    /// Why the step ended the way it did.
    pub reason: String,
}

/// The authority the commit boundary will later revalidate (EFX-004).
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AuthorizationGranted {
    /// The grant that authorised the effect.
    pub capability_grant_id: String,
    /// Its generation at the moment of authorisation.
    pub grant_generation: u64,
}

/// Proof that a one-shot [`crate::CommitPermit`] was consumed.
///
/// This is what opens the dispatch window, and it is emitted by
/// [`crate::NonceRegistry::consume`] alone.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CommitPermitted {
    /// The permit that was burned.
    pub permit_id: String,
    /// The nonce that can never be presented again.
    pub one_shot_nonce: String,
    /// The effect identity the permit was bound to.
    pub effect_digest: String,
}

/// The external operation identity discovered at dispatch, when the target
/// returned one.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Dispatched {
    /// The target's own handle for the operation, used by reconciliation.
    pub external_operation_id: Option<String>,
}

/// The conclusion of an observation.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Observed {
    /// What the observation concluded.
    pub outcome: ObservedOutcome,
}

/// The conclusion of a reconciliation probe.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Reconciled {
    /// What the probe concluded.
    pub outcome: ReconciledOutcome,
}

/// A durable fact about an effect.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "event_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectEvent {
    /// The intent was submitted for authorisation.
    AuthorizationRequested,
    /// Authority was granted, and pinned to a generation.
    AuthorizationGranted(AuthorizationGranted),
    /// The commit boundary began revalidating authority and resource state.
    CommitRevalidationStarted,
    /// A one-shot commit permit was consumed: dispatch may proceed once.
    CommitPermitted(CommitPermitted),
    /// Revalidation found drift; the effect must be authorised again.
    CommitRevalidationFailed(Reason),
    /// The effect was cancelled before anything could have happened.
    Cancelled(Reason),
    /// The request reached the target, which acknowledged it.
    Dispatched(Dispatched),
    /// The target refused the request; nothing happened (EFX-003).
    DispatchRejected(Reason),
    /// The request may or may not have reached the target (INV-002).
    DispatchAmbiguous(Reason),
    /// Observation of the target began.
    ObservationStarted,
    /// The response was lost, so the outcome is unknown (INV-002).
    ObservationLost(Reason),
    /// The observation concluded.
    Observed(Observed),
    /// A reconciliation probe began: a read, never a second write.
    ReconciliationStarted,
    /// The probe concluded.
    Reconciled(Reconciled),
    /// Compensation of a landed or partial effect began.
    CompensationStarted,
    /// The compensating action succeeded.
    Compensated,
    /// The compensating action was refused.
    CompensationFailed(Reason),
    /// The compensating action's own outcome is unknown (INV-002).
    CompensationAmbiguous(Reason),
}

impl EffectEvent {
    /// Authority was granted by `capability_grant_id` at `grant_generation`.
    #[must_use]
    pub fn authorization_granted(capability_grant_id: &str, grant_generation: u64) -> Self {
        Self::AuthorizationGranted(AuthorizationGranted {
            capability_grant_id: capability_grant_id.to_owned(),
            grant_generation,
        })
    }

    /// Revalidation at the commit boundary failed for `reason`.
    #[must_use]
    pub fn commit_revalidation_failed(reason: &str) -> Self {
        Self::CommitRevalidationFailed(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The effect was cancelled before dispatch for `reason`.
    #[must_use]
    pub fn cancelled(reason: &str) -> Self {
        Self::Cancelled(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The target acknowledged the request, optionally naming the operation.
    #[must_use]
    pub fn dispatched(external_operation_id: Option<&str>) -> Self {
        Self::Dispatched(Dispatched {
            external_operation_id: external_operation_id.map(str::to_owned),
        })
    }

    /// The target refused the request for `reason`: nothing happened.
    #[must_use]
    pub fn dispatch_rejected(reason: &str) -> Self {
        Self::DispatchRejected(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The dispatch outcome is unknown because of `reason`.
    #[must_use]
    pub fn dispatch_ambiguous(reason: &str) -> Self {
        Self::DispatchAmbiguous(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The response was lost because of `reason`.
    #[must_use]
    pub fn observation_lost(reason: &str) -> Self {
        Self::ObservationLost(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The observation concluded with `outcome`.
    #[must_use]
    pub fn observed(outcome: ObservedOutcome) -> Self {
        Self::Observed(Observed { outcome })
    }

    /// The reconciliation probe concluded with `outcome`.
    #[must_use]
    pub fn reconciled(outcome: ReconciledOutcome) -> Self {
        Self::Reconciled(Reconciled { outcome })
    }

    /// Compensation was refused for `reason`.
    #[must_use]
    pub fn compensation_failed(reason: &str) -> Self {
        Self::CompensationFailed(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The compensating action's outcome is unknown because of `reason`.
    #[must_use]
    pub fn compensation_ambiguous(reason: &str) -> Self {
        Self::CompensationAmbiguous(Reason {
            reason: reason.to_owned(),
        })
    }

    /// The variant name, used in refusal messages and trajectory digests.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::AuthorizationRequested => "AUTHORIZATION_REQUESTED",
            Self::AuthorizationGranted(_) => "AUTHORIZATION_GRANTED",
            Self::CommitRevalidationStarted => "COMMIT_REVALIDATION_STARTED",
            Self::CommitPermitted(_) => "COMMIT_PERMITTED",
            Self::CommitRevalidationFailed(_) => "COMMIT_REVALIDATION_FAILED",
            Self::Cancelled(_) => "CANCELLED",
            Self::Dispatched(_) => "DISPATCHED",
            Self::DispatchRejected(_) => "DISPATCH_REJECTED",
            Self::DispatchAmbiguous(_) => "DISPATCH_AMBIGUOUS",
            Self::ObservationStarted => "OBSERVATION_STARTED",
            Self::ObservationLost(_) => "OBSERVATION_LOST",
            Self::Observed(_) => "OBSERVED",
            Self::ReconciliationStarted => "RECONCILIATION_STARTED",
            Self::Reconciled(_) => "RECONCILED",
            Self::CompensationStarted => "COMPENSATION_STARTED",
            Self::Compensated => "COMPENSATED",
            Self::CompensationFailed(_) => "COMPENSATION_FAILED",
            Self::CompensationAmbiguous(_) => "COMPENSATION_AMBIGUOUS",
        }
    }

    /// Feeds this event's canonical, length-prefixed encoding into `hasher`.
    pub(crate) fn digest_into(&self, hasher: &mut Sha256) {
        digest_component(hasher, self.kind());
        match self {
            Self::AuthorizationRequested
            | Self::CommitRevalidationStarted
            | Self::ObservationStarted
            | Self::ReconciliationStarted
            | Self::CompensationStarted
            | Self::Compensated => {}
            Self::AuthorizationGranted(payload) => {
                digest_component(hasher, &payload.capability_grant_id);
                digest_component(hasher, &payload.grant_generation.to_string());
            }
            Self::CommitPermitted(payload) => {
                digest_component(hasher, &payload.permit_id);
                digest_component(hasher, &payload.one_shot_nonce);
                digest_component(hasher, &payload.effect_digest);
            }
            Self::CommitRevalidationFailed(payload)
            | Self::Cancelled(payload)
            | Self::DispatchRejected(payload)
            | Self::DispatchAmbiguous(payload)
            | Self::ObservationLost(payload)
            | Self::CompensationFailed(payload)
            | Self::CompensationAmbiguous(payload) => {
                digest_component(hasher, &payload.reason);
            }
            Self::Dispatched(payload) => match &payload.external_operation_id {
                Some(id) => digest_component(hasher, id),
                None => digest_component(hasher, "<null>"),
            },
            Self::Observed(payload) => digest_component(hasher, payload.outcome.as_str()),
            Self::Reconciled(payload) => digest_component(hasher, payload.outcome.as_str()),
        }
    }
}
