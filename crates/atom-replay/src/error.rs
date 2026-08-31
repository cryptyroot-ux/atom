//! [`ReplayError`]: every way a replay refuses.
//!
//! A refusal is always typed and always names what was missing or unsupported.
//! Two refusals carry the whole safety story of this crate:
//!
//! * [`ReplayError::CassetteMiss`] — R2 found no recorded response and will not
//!   fall through to a live call or fabricate one (INV-010, TASK.md item 4).
//! * [`ReplayError::Unsupported`] — R3/R4 are labeled, not executed; the label
//!   is carried so the caller sees the semantics, not a fabricated success
//!   (ATOM-RPL-001).

use thiserror::Error;

use crate::class::ReplayClass;

/// Why a replay could not be produced.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReplayError {
    /// The requested class is not executed for the alpha (R3/R4).
    ///
    /// This is the typed labeled refusal: it names the class, its
    /// `SCREAMING_SNAKE_CASE` label and the bounded guarantee, so nothing is
    /// silently treated as a success (ATOM-RPL-001).
    #[error(
        "replay class {code} ({label}) is not implemented for alpha; semantics labeled {label}: {guarantee}"
    )]
    Unsupported {
        /// The class that was requested.
        class: ReplayClass,
        /// Its `Rn` code, e.g. `R3`.
        code: &'static str,
        /// Its `SCREAMING_SNAKE_CASE` label.
        label: &'static str,
        /// The bounded guarantee (never an exact-replay claim).
        guarantee: &'static str,
    },

    /// R2 was asked to resolve a request that the cassette does not record.
    ///
    /// Replay STOPS here. It never falls through to a live connector and never
    /// fabricates a response (TASK.md item 4, INV-010).
    #[error("cassette miss: no recorded response for request_digest {request_digest}")]
    CassetteMiss {
        /// The request whose recorded response was absent.
        request_digest: String,
    },

    /// A required replay input was absent.
    #[error("replay input `{field}` is required for {code}")]
    MissingInput {
        /// The absent input.
        field: &'static str,
        /// The class the input was required for.
        code: &'static str,
    },

    /// The committed log did not project cleanly under the effect reducer.
    ///
    /// Wraps [`atom_effect::ReduceError`]: an off-spec event in a log that was
    /// presented as committed is a divergence, not a silent no-op.
    #[error("committed log failed to project: {0}")]
    Reduce(#[from] atom_effect::ReduceError),

    /// A live-fork policy field was blank, so a NEW identity could not be minted.
    #[error("live-fork policy field `{field}` must not be blank")]
    BlankForkField {
        /// The blank field.
        field: &'static str,
    },
}

impl ReplayError {
    /// The typed labeled refusal for an unsupported class (R3/R4).
    #[must_use]
    pub(crate) fn unsupported(class: ReplayClass) -> Self {
        Self::Unsupported {
            class,
            code: class.code(),
            label: class.label(),
            guarantee: class.guarantee(),
        }
    }
}
