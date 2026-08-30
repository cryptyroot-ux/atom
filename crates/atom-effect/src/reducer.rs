//! The pure effect reducer.
//!
//! No IO, no clock, no randomness: `(state, event) -> state` is a function, so
//! replaying a durable event log always lands in the same place. Every proposed
//! transition is checked against [`EffectState::allowed_transitions`] before it
//! is returned, which makes `spec/state-machines/effect.yaml` the only authority
//! on what may happen.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::digest::{digest_component, finish};
use crate::event::{EffectEvent, ObservedOutcome, ReconciledOutcome};
use crate::state::EffectState;

/// The reducer refused an event.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReduceError {
    /// No spec edge leaves `state` on `event`.
    #[error("state {state} does not accept event {event}")]
    EventNotAccepted {
        /// The state the effect was in.
        state: EffectState,
        /// The refused event's kind.
        event: &'static str,
    },
}

/// Applies one durable event, refusing anything the spec does not allow.
///
/// # Errors
///
/// [`ReduceError::EventNotAccepted`] when no spec edge leaves `state` on
/// `event` — including every event presented to a terminal state.
pub fn try_reduce(state: EffectState, event: &EffectEvent) -> Result<EffectState, ReduceError> {
    use EffectEvent as E;
    use EffectState as S;

    let proposed = match (state, event) {
        (S::IntentDurable, E::AuthorizationRequested) => Some(S::AuthorizationPending),
        (
            S::IntentDurable | S::AuthorizationPending | S::Authorized | S::CommitRevalidating,
            E::Cancelled(_),
        ) => Some(S::CancelledBeforeEffect),
        (S::AuthorizationPending, E::AuthorizationGranted(_)) => Some(S::Authorized),
        (S::Authorized, E::CommitRevalidationStarted) => Some(S::CommitRevalidating),
        (S::CommitRevalidating, E::CommitPermitted(_)) => Some(S::Dispatching),
        (S::CommitRevalidating, E::CommitRevalidationFailed(_)) => Some(S::AuthorizationPending),
        (S::Dispatching, E::Dispatched(_)) => Some(S::Dispatched),
        (S::Dispatching, E::DispatchRejected(_)) => Some(S::ConfirmedFailure),
        (S::Dispatching, E::DispatchAmbiguous(_)) => Some(S::UnknownOutcome),
        (S::Dispatched, E::ObservationStarted) => Some(S::Observing),
        (S::Dispatched, E::ObservationLost(_)) => Some(S::UnknownOutcome),
        (S::Observing, E::Observed(observed)) => Some(match observed.outcome {
            ObservedOutcome::Success => S::ConfirmedSuccess,
            ObservedOutcome::Failure => S::ConfirmedFailure,
            ObservedOutcome::Partial => S::Partial,
            ObservedOutcome::Ambiguous => S::UnknownOutcome,
        }),
        (S::UnknownOutcome, E::ReconciliationStarted) => Some(S::Reconciling),
        (S::Reconciling, E::Reconciled(reconciled)) => Some(match reconciled.outcome {
            ReconciledOutcome::Success => S::ConfirmedSuccess,
            ReconciledOutcome::Failure => S::ConfirmedFailure,
            ReconciledOutcome::Partial => S::Partial,
            ReconciledOutcome::Inconclusive => S::UnknownOutcome,
        }),
        (S::Reconciling | S::Partial, E::CompensationStarted) => Some(S::Compensating),
        (S::Compensating, E::Compensated) => Some(S::Compensated),
        (S::Compensating, E::CompensationFailed(_)) => Some(S::CompensationFailed),
        (S::Compensating, E::CompensationAmbiguous(_)) => Some(S::UnknownOutcome),
        _ => None,
    };

    // The table above is a convenience; the spec adjacency map is the authority.
    match proposed {
        Some(next) if state.can_transition_to(next) => Ok(next),
        _ => Err(ReduceError::EventNotAccepted {
            state,
            event: event.kind(),
        }),
    }
}

/// The total reducer: a refused event is a no-op.
///
/// Use this to replay a log that may contain events belonging to another effect
/// or to an earlier attempt. Use [`try_reduce`] when a refusal is a bug.
#[must_use]
pub fn reduce(state: EffectState, event: &EffectEvent) -> EffectState {
    try_reduce(state, event).unwrap_or(state)
}

/// Replays `events` from `initial`, stopping at the first refusal.
///
/// # Errors
///
/// The first [`ReduceError`] the log produces.
pub fn try_project(
    initial: EffectState,
    events: &[EffectEvent],
) -> Result<EffectState, ReduceError> {
    events.iter().try_fold(initial, try_reduce)
}

/// Replays `events` from `initial`, skipping refusals.
#[must_use]
pub fn project(initial: EffectState, events: &[EffectEvent]) -> EffectState {
    events.iter().fold(initial, reduce)
}

/// A digest of the whole trajectory: the route, not just the destination.
///
/// Two logs that end in the same state but travelled differently digest
/// differently, which is what makes a replay divergence detectable.
#[must_use]
pub fn trajectory_digest(initial: EffectState, events: &[EffectEvent]) -> String {
    let mut hasher = Sha256::new();
    digest_component(&mut hasher, "initial");
    digest_component(&mut hasher, initial.as_str());

    let mut state = initial;
    for event in events {
        digest_component(&mut hasher, "event");
        event.digest_into(&mut hasher);
        state = reduce(state, event);
        digest_component(&mut hasher, "state");
        digest_component(&mut hasher, state.as_str());
    }

    finish(hasher)
}
