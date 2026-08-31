//! [`ReplayClass`]: the five replay classes of `spec/enums.yaml`.
//!
//! ```text
//! R0 STATE_REPLAY               SUPPORTED
//! R1 REDUCER_REPLAY             SUPPORTED
//! R2 ACTIVITY_CASSETTE_REPLAY   SUPPORTED
//! R3 LIVE_FORK_MODEL_REEXECUTION  LABELED, not executed for alpha
//! R4 STATISTICAL_REPRODUCTION     LABELED, not executed for alpha
//! ```
//!
//! Support status is a property of the class, not of the caller: R3/R4 are not
//! "hard", they are out of scope for the alpha (see TASK.md boundary decisions
//! and ATOM-RPL-001). Calling replay at R3/R4 is a typed refusal, never a
//! fabricated result — see [`crate::ReplayError::Unsupported`].

use serde::{Deserialize, Serialize};

/// The replay class requested of the engine, from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayClass {
    /// R0 — rebuild authoritative state by projecting a committed event log.
    StateReplay,
    /// R1 — pure reducer re-execution yielding a byte-identical trajectory.
    ReducerReplay,
    /// R2 — resolve external interactions from a recorded cassette only.
    ActivityCassetteReplay,
    /// R3 — live-fork model re-execution. Labeled, not executed for alpha.
    LiveForkModelReexecution,
    /// R4 — statistical reproduction. Labeled, not executed for alpha.
    StatisticalReproduction,
}

impl ReplayClass {
    /// Every class, in `spec/enums.yaml` order.
    pub const ALL: [Self; 5] = [
        Self::StateReplay,
        Self::ReducerReplay,
        Self::ActivityCassetteReplay,
        Self::LiveForkModelReexecution,
        Self::StatisticalReproduction,
    ];

    /// The `Rn` code, exactly as `spec/enums.yaml` keys the class.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StateReplay => "R0",
            Self::ReducerReplay => "R1",
            Self::ActivityCassetteReplay => "R2",
            Self::LiveForkModelReexecution => "R3",
            Self::StatisticalReproduction => "R4",
        }
    }

    /// The `SCREAMING_SNAKE_CASE` label, exactly as `spec/enums.yaml` names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StateReplay => "STATE_REPLAY",
            Self::ReducerReplay => "REDUCER_REPLAY",
            Self::ActivityCassetteReplay => "ACTIVITY_CASSETTE_REPLAY",
            Self::LiveForkModelReexecution => "LIVE_FORK_MODEL_REEXECUTION",
            Self::StatisticalReproduction => "STATISTICAL_REPRODUCTION",
        }
    }

    /// Whether this class is executed for the 0.0.0-alpha.0 (R0/R1/R2 only).
    ///
    /// R3/R4 return `false`: they are labeled, not implemented (ATOM-RPL-001,
    /// TASK.md boundary decisions).
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(
            self,
            Self::StateReplay | Self::ReducerReplay | Self::ActivityCassetteReplay
        )
    }

    /// The bounded guarantee this class offers.
    ///
    /// Deliberately narrow: there is NO universal exact-replay claim
    /// (ATOM-RPL-001). R2 is bounded to the recorded cassette; R3/R4 make no
    /// execution claim at all.
    #[must_use]
    pub const fn guarantee(self) -> &'static str {
        match self {
            Self::StateReplay => {
                "deterministic: the same committed log projects to the same state digest"
            }
            Self::ReducerReplay => {
                "deterministic: the same committed log yields a byte-identical trajectory digest"
            }
            Self::ActivityCassetteReplay => {
                "bounded to the recorded cassette; a missing entry is a typed miss, never a live call"
            }
            Self::LiveForkModelReexecution => {
                "labeled, not executed for alpha; would mint a NEW effect identity under a live-fork policy"
            }
            Self::StatisticalReproduction => {
                "labeled, not executed for alpha; a distributional claim, never an exact-replay claim"
            }
        }
    }
}
