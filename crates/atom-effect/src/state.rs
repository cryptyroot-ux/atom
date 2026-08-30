//! The 16 effect states and the adjacency map of
//! `spec/state-machines/effect.yaml`.
//!
//! The spec is authoritative: this module transcribes it and adds nothing. The
//! conformance suite parses `effect.yaml` and compares it edge for edge, so a
//! disagreement fails the build.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Lifecycle state of an effect, from `spec/state-machines/effect.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectState {
    IntentDurable,
    AuthorizationPending,
    Authorized,
    CommitRevalidating,
    Dispatching,
    Dispatched,
    Observing,
    ConfirmedSuccess,
    ConfirmedFailure,
    Partial,
    CancelledBeforeEffect,
    UnknownOutcome,
    Reconciling,
    Compensating,
    Compensated,
    CompensationFailed,
}

impl EffectState {
    /// Every state, in spec order.
    pub const ALL: [Self; 16] = [
        Self::IntentDurable,
        Self::AuthorizationPending,
        Self::Authorized,
        Self::CommitRevalidating,
        Self::Dispatching,
        Self::Dispatched,
        Self::Observing,
        Self::ConfirmedSuccess,
        Self::ConfirmedFailure,
        Self::Partial,
        Self::CancelledBeforeEffect,
        Self::UnknownOutcome,
        Self::Reconciling,
        Self::Compensating,
        Self::Compensated,
        Self::CompensationFailed,
    ];

    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntentDurable => "INTENT_DURABLE",
            Self::AuthorizationPending => "AUTHORIZATION_PENDING",
            Self::Authorized => "AUTHORIZED",
            Self::CommitRevalidating => "COMMIT_REVALIDATING",
            Self::Dispatching => "DISPATCHING",
            Self::Dispatched => "DISPATCHED",
            Self::Observing => "OBSERVING",
            Self::ConfirmedSuccess => "CONFIRMED_SUCCESS",
            Self::ConfirmedFailure => "CONFIRMED_FAILURE",
            Self::Partial => "PARTIAL",
            Self::CancelledBeforeEffect => "CANCELLED_BEFORE_EFFECT",
            Self::UnknownOutcome => "UNKNOWN_OUTCOME",
            Self::Reconciling => "RECONCILING",
            Self::Compensating => "COMPENSATING",
            Self::Compensated => "COMPENSATED",
            Self::CompensationFailed => "COMPENSATION_FAILED",
        }
    }

    /// The states reachable in one step, exactly as `effect.yaml` lists them.
    ///
    /// An empty slice means terminal.
    #[must_use]
    pub const fn allowed_transitions(self) -> &'static [Self] {
        match self {
            Self::IntentDurable => &[Self::AuthorizationPending, Self::CancelledBeforeEffect],
            Self::AuthorizationPending => &[Self::Authorized, Self::CancelledBeforeEffect],
            Self::Authorized => &[Self::CommitRevalidating, Self::CancelledBeforeEffect],
            Self::CommitRevalidating => &[
                Self::Dispatching,
                Self::AuthorizationPending,
                Self::CancelledBeforeEffect,
            ],
            Self::Dispatching => &[
                Self::Dispatched,
                Self::UnknownOutcome,
                Self::ConfirmedFailure,
            ],
            Self::Dispatched => &[Self::Observing, Self::UnknownOutcome],
            Self::Observing => &[
                Self::ConfirmedSuccess,
                Self::ConfirmedFailure,
                Self::Partial,
                Self::UnknownOutcome,
            ],
            Self::UnknownOutcome => &[Self::Reconciling],
            Self::Reconciling => &[
                Self::ConfirmedSuccess,
                Self::ConfirmedFailure,
                Self::Partial,
                Self::UnknownOutcome,
                Self::Compensating,
            ],
            Self::Partial => &[Self::Compensating],
            Self::Compensating => &[
                Self::Compensated,
                Self::CompensationFailed,
                Self::UnknownOutcome,
            ],
            Self::ConfirmedSuccess
            | Self::ConfirmedFailure
            | Self::CancelledBeforeEffect
            | Self::Compensated
            | Self::CompensationFailed => &[],
        }
    }

    /// Whether `self -> target` is an edge of the spec machine.
    #[must_use]
    pub fn can_transition_to(self, target: Self) -> bool {
        self.allowed_transitions().contains(&target)
    }

    /// Whether the effect has settled: no further transition exists.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        self.allowed_transitions().is_empty()
    }

    /// INV-002: the outcome is genuinely unknown, neither success nor failure.
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(self, Self::UnknownOutcome)
    }

    /// The only failure a caller may retry.
    ///
    /// `UNKNOWN_OUTCOME` is deliberately excluded: retrying an ambiguity is how
    /// a duplicate side effect gets created (INV-002).
    #[must_use]
    pub const fn is_retryable_failure(self) -> bool {
        matches!(self, Self::ConfirmedFailure)
    }

    /// EFX-003: dependent mutations wait until the ambiguity is resolved.
    #[must_use]
    pub const fn blocks_dependents(self) -> bool {
        matches!(self, Self::UnknownOutcome | Self::Reconciling)
    }

    /// Apply `event` via the pure reducer, treating a refused event as an error.
    ///
    /// Convenience over [`crate::try_reduce`] for callers that already hold a
    /// state and do not want to import the reducer module.
    ///
    /// # Errors
    ///
    /// [`crate::reducer::ReduceError`] when the event has no edge from `self`.
    pub fn try_advance(
        self,
        event: &crate::event::EffectEvent,
    ) -> Result<Self, crate::reducer::ReduceError> {
        crate::try_reduce(self, event)
    }
}

impl fmt::Display for EffectState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A string that is not one of the 16 spec states.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("`{value}` is not an effect state in spec/state-machines/effect.yaml")]
pub struct ParseEffectStateError {
    /// The rejected input.
    pub value: String,
}

impl FromStr for EffectState {
    type Err = ParseEffectStateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|state| state.as_str() == value)
            .ok_or_else(|| ParseEffectStateError {
                value: value.to_owned(),
            })
    }
}
