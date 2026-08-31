//! Vector reward components for architecture selection (ATOM-ARC-001).
//!
//! The reward vector includes: verified success, effect integrity, security,
//! cost, latency, and human attention — all normalized to `[0, 1]`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned when a reward component is invalid.
#[derive(Debug, Error)]
pub enum RewardError {
    /// A component value is outside the valid `[0, 1]` range.
    #[error("reward component `{name}` has value {value} outside [0, 1]")]
    OutOfRange {
        /// Which component failed validation.
        name: &'static str,
        /// The invalid value.
        value: f64,
    },
    /// A weight value is negative.
    #[error("reward weight `{name}` is negative: {value}")]
    NegativeWeight {
        /// Which weight failed validation.
        name: &'static str,
        /// The invalid value.
        value: f64,
    },
}

/// A six-component vector reward per ATOM-ARC-001.
///
/// Every component is in `[0, 1]` where 1 is best. Cost and latency are
/// *inverted* (1 = cheapest / fastest) so that all axes share the same polarity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VectorReward {
    /// Fraction of outcomes verified as successful.
    pub verified_success: f64,
    /// Fraction of effects whose integrity was maintained.
    pub effect_integrity: f64,
    /// Security score (1 = no policy violations).
    pub security: f64,
    /// Inverted cost (1 = cheapest).
    pub cost: f64,
    /// Inverted latency (1 = fastest).
    pub latency: f64,
    /// Inverted human attention (1 = fully autonomous, no human needed).
    pub human_attention: f64,
}

impl VectorReward {
    /// All six component values as a slice, in canonical order.
    #[must_use]
    pub fn components(&self) -> [f64; 6] {
        [
            self.verified_success,
            self.effect_integrity,
            self.security,
            self.cost,
            self.latency,
            self.human_attention,
        ]
    }

    /// Canonical component names for diagnostics.
    pub const COMPONENT_NAMES: [&'static str; 6] = [
        "verified_success",
        "effect_integrity",
        "security",
        "cost",
        "latency",
        "human_attention",
    ];

    /// Validate that all components are in `[0, 1]`.
    ///
    /// # Errors
    ///
    /// Returns [`RewardError::OutOfRange`] for the first invalid component.
    pub fn validate(&self) -> Result<(), RewardError> {
        let vals = self.components();
        for (v, name) in vals.iter().zip(Self::COMPONENT_NAMES.iter()) {
            if !v.is_finite() || !((0.0)..=1.0).contains(v) {
                return Err(RewardError::OutOfRange { name, value: *v });
            }
        }
        Ok(())
    }

    /// Scalarize into a single scalar via weighted sum.
    ///
    /// The caller is responsible for ensuring the weights represent an
    /// appropriate trade-off. No normalization is applied.
    #[must_use]
    pub fn scalarize(&self, weights: &RewardWeights) -> f64 {
        let c = self.components();
        let w = weights.as_array();
        c.iter().zip(w.iter()).map(|(ci, wi)| ci * wi).sum()
    }

    /// Pareto dominance: `self` dominates `other` when every component of
    /// `self` is ≥ the corresponding component of `other` and at least one
    /// is strictly greater.
    #[must_use]
    pub fn dominates(&self, other: &VectorReward) -> bool {
        let sc = self.components();
        let oc = other.components();
        let all_geq = sc.iter().zip(oc.iter()).all(|(a, b)| a >= b);
        let any_gt = sc.iter().zip(oc.iter()).any(|(a, b)| a > b);
        all_geq && any_gt
    }
}

/// Scalarization weights for [`VectorReward::scalarize`].
///
/// Each weight must be non-negative.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RewardWeights {
    pub verified_success: f64,
    pub effect_integrity: f64,
    pub security: f64,
    pub cost: f64,
    pub latency: f64,
    pub human_attention: f64,
}

impl RewardWeights {
    /// All six weights as an array, in canonical component order.
    #[must_use]
    pub fn as_array(&self) -> [f64; 6] {
        [
            self.verified_success,
            self.effect_integrity,
            self.security,
            self.cost,
            self.latency,
            self.human_attention,
        ]
    }

    /// Validate that all weights are non-negative.
    ///
    /// # Errors
    ///
    /// Returns [`RewardError::NegativeWeight`] for the first invalid weight.
    pub fn validate(&self) -> Result<(), RewardError> {
        let ws = self.as_array();
        for (w, name) in ws.iter().zip(VectorReward::COMPONENT_NAMES.iter()) {
            if *w < 0.0 || !w.is_finite() {
                return Err(RewardError::NegativeWeight { name, value: *w });
            }
        }
        Ok(())
    }

    /// Equal weights (each component contributes equally).
    #[must_use]
    pub fn uniform() -> Self {
        Self {
            verified_success: 1.0,
            effect_integrity: 1.0,
            security: 1.0,
            cost: 1.0,
            latency: 1.0,
            human_attention: 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_reward() -> VectorReward {
        VectorReward {
            verified_success: 0.9,
            effect_integrity: 0.8,
            security: 1.0,
            cost: 0.7,
            latency: 0.6,
            human_attention: 0.5,
        }
    }

    #[test]
    fn validate_good_reward() {
        assert!(sample_reward().validate().is_ok());
    }

    #[test]
    fn validate_out_of_range() {
        let mut r = sample_reward();
        r.cost = 1.5;
        let err = r.validate().unwrap_err();
        assert!(err.to_string().contains("cost"));
    }

    #[test]
    fn validate_nan() {
        let mut r = sample_reward();
        r.security = f64::NAN;
        assert!(r.validate().is_err());
    }

    #[test]
    fn scalarize_uniform() {
        let r = sample_reward();
        let w = RewardWeights::uniform();
        let s = r.scalarize(&w);
        let expected: f64 = r.components().iter().sum();
        assert!((s - expected).abs() < 1e-12);
    }

    #[test]
    fn scalarize_weighted() {
        let r = VectorReward {
            verified_success: 1.0,
            effect_integrity: 0.0,
            security: 0.0,
            cost: 0.0,
            latency: 0.0,
            human_attention: 0.0,
        };
        let w = RewardWeights {
            verified_success: 3.0,
            effect_integrity: 1.0,
            security: 1.0,
            cost: 1.0,
            latency: 1.0,
            human_attention: 1.0,
        };
        assert!((r.scalarize(&w) - 3.0).abs() < 1e-12);
    }

    #[test]
    fn pareto_dominance_strict() {
        let a = VectorReward {
            verified_success: 0.9,
            effect_integrity: 0.9,
            security: 0.9,
            cost: 0.9,
            latency: 0.9,
            human_attention: 0.9,
        };
        let b = VectorReward {
            verified_success: 0.8,
            effect_integrity: 0.8,
            security: 0.8,
            cost: 0.8,
            latency: 0.8,
            human_attention: 0.8,
        };
        assert!(a.dominates(&b));
        assert!(!b.dominates(&a));
    }

    #[test]
    fn pareto_equal_not_dominating() {
        let a = sample_reward();
        assert!(!a.dominates(&a));
    }

    #[test]
    fn pareto_incomparable() {
        let a = VectorReward {
            verified_success: 1.0,
            effect_integrity: 0.0,
            security: 0.5,
            cost: 0.5,
            latency: 0.5,
            human_attention: 0.5,
        };
        let b = VectorReward {
            verified_success: 0.0,
            effect_integrity: 1.0,
            security: 0.5,
            cost: 0.5,
            latency: 0.5,
            human_attention: 0.5,
        };
        assert!(!a.dominates(&b));
        assert!(!b.dominates(&a));
    }

    #[test]
    fn weights_validate_negative() {
        let mut w = RewardWeights::uniform();
        w.cost = -0.1;
        assert!(w.validate().is_err());
    }
}
