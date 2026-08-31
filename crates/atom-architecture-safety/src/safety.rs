//! Hard architecture-learner constraints and six-dimensional reward vectors.
//!
//! `RewardVector` is deliberately only an input to the learner. The learner
//! may rank candidate topology actions with it, but [`SafetyContract`] remains
//! outside the learner and independently rejects unsafe candidates.

use atom_claim::{Claim, ClaimId, ClaimState};
use atom_policy::PolicyDecision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The six independent dimensions required by ATOM-ARC-001.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RewardDimension {
    /// Evidence-backed successful completion rate.
    VerifiedSuccess,
    /// Correctly authorized, committed, and reconciled effects.
    EffectIntegrity,
    /// Security posture / absence of safety regressions.
    Security,
    /// Resource cost consumed by the action.
    Cost,
    /// End-to-end latency of the action.
    Latency,
    /// Human-attention burden needed to operate the action.
    HumanAttention,
}

impl RewardDimension {
    /// All dimensions in the required stable order.
    pub const ALL: [Self; 6] = [
        Self::VerifiedSuccess,
        Self::EffectIntegrity,
        Self::Security,
        Self::Cost,
        Self::Latency,
        Self::HumanAttention,
    ];

    /// Canonical field name for the dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedSuccess => "verified_success",
            Self::EffectIntegrity => "effect_integrity",
            Self::Security => "security",
            Self::Cost => "cost",
            Self::Latency => "latency",
            Self::HumanAttention => "human_attention",
        }
    }

    /// Whether a larger value is intrinsically better for this dimension.
    #[must_use]
    pub const fn is_benefit(self) -> bool {
        matches!(
            self,
            Self::VerifiedSuccess | Self::EffectIntegrity | Self::Security
        )
    }
}

/// Vector reward reported for one architecture/topology candidate.
///
/// The first three dimensions are normalized quality scores in `0..=1` where
/// larger is better. Cost, latency, and human attention are non-negative,
/// caller-unit burdens where smaller is better. Keeping the latter as burdens
/// avoids hiding a safety-relevant tradeoff behind an arbitrary scalarization.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct RewardVector {
    /// Evidence-backed successful completion score in `0..=1`.
    pub verified_success: f64,
    /// Effect-integrity score in `0..=1`.
    pub effect_integrity: f64,
    /// Security score in `0..=1`.
    pub security: f64,
    /// Non-negative candidate cost in the caller's fixed unit.
    pub cost: f64,
    /// Non-negative candidate latency in the caller's fixed unit.
    pub latency: f64,
    /// Non-negative human-attention burden in the caller's fixed unit.
    pub human_attention: f64,
}

impl RewardVector {
    /// Creates and validates a six-dimensional reward vector.
    ///
    /// # Errors
    ///
    /// Returns [`RewardVectorError`] if a quality score is outside `0..=1`, a
    /// burden is negative, or any value is non-finite.
    pub fn new(
        verified_success: f64,
        effect_integrity: f64,
        security: f64,
        cost: f64,
        latency: f64,
        human_attention: f64,
    ) -> Result<Self, RewardVectorError> {
        let vector = Self {
            verified_success,
            effect_integrity,
            security,
            cost,
            latency,
            human_attention,
        };
        vector.validate()?;
        Ok(vector)
    }

    /// Validates a vector, including a literal constructed through its public
    /// fields. [`SafetyContract`] always calls this before admitting a choice.
    ///
    /// # Errors
    ///
    /// Returns [`RewardVectorError`] for malformed dimensions.
    pub fn validate(&self) -> Result<(), RewardVectorError> {
        for (dimension, value) in [
            (RewardDimension::VerifiedSuccess, self.verified_success),
            (RewardDimension::EffectIntegrity, self.effect_integrity),
            (RewardDimension::Security, self.security),
        ] {
            validate_score(dimension, value)?;
        }
        for (dimension, value) in [
            (RewardDimension::Cost, self.cost),
            (RewardDimension::Latency, self.latency),
            (RewardDimension::HumanAttention, self.human_attention),
        ] {
            validate_burden(dimension, value)?;
        }
        Ok(())
    }

    /// Returns the dimensions in [`RewardDimension::ALL`] order.
    #[must_use]
    pub const fn as_array(self) -> [f64; 6] {
        [
            self.verified_success,
            self.effect_integrity,
            self.security,
            self.cost,
            self.latency,
            self.human_attention,
        ]
    }

    /// Looks up one dimension without collapsing the vector to a scalar.
    #[must_use]
    pub const fn value(self, dimension: RewardDimension) -> f64 {
        match dimension {
            RewardDimension::VerifiedSuccess => self.verified_success,
            RewardDimension::EffectIntegrity => self.effect_integrity,
            RewardDimension::Security => self.security,
            RewardDimension::Cost => self.cost,
            RewardDimension::Latency => self.latency,
            RewardDimension::HumanAttention => self.human_attention,
        }
    }
}

/// Invalid reward-vector dimension.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum RewardVectorError {
    /// Scores must be finite and normalized to the inclusive `0..=1` range.
    #[error("{dimension:?} must be a finite score in 0..=1, got {value}")]
    InvalidScore {
        /// Score dimension that failed validation.
        dimension: RewardDimension,
        /// Invalid score.
        value: f64,
    },
    /// Resource burdens must be finite and non-negative.
    #[error("{dimension:?} must be finite and non-negative, got {value}")]
    InvalidBurden {
        /// Burden dimension that failed validation.
        dimension: RewardDimension,
        /// Invalid burden.
        value: f64,
    },
}

/// Immutable hard limits applied outside the learner.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct SafetyLimits {
    /// Lowest permitted verified-success score.
    pub minimum_verified_success: f64,
    /// Lowest permitted effect-integrity score.
    pub minimum_effect_integrity: f64,
    /// Lowest permitted security score.
    pub minimum_security: f64,
    /// Largest permitted cost, in the candidate's declared unit.
    pub maximum_cost: f64,
    /// Largest permitted latency, in the candidate's declared unit.
    pub maximum_latency: f64,
    /// Largest permitted human-attention burden, in the candidate's declared unit.
    pub maximum_human_attention: f64,
}

impl SafetyLimits {
    /// Builds validated hard safety limits.
    ///
    /// Callers must use one fixed unit per burden dimension within an
    /// evaluation. The contract compares values but does not guess units.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyLimitsError`] if any minimum is outside `0..=1` or any
    /// maximum is negative/non-finite.
    pub fn new(
        minimum_verified_success: f64,
        minimum_effect_integrity: f64,
        minimum_security: f64,
        maximum_cost: f64,
        maximum_latency: f64,
        maximum_human_attention: f64,
    ) -> Result<Self, SafetyLimitsError> {
        let limits = Self {
            minimum_verified_success,
            minimum_effect_integrity,
            minimum_security,
            maximum_cost,
            maximum_latency,
            maximum_human_attention,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Validates a literal-constructed limit set.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyLimitsError`] if a limit is malformed.
    pub fn validate(&self) -> Result<(), SafetyLimitsError> {
        for (dimension, value) in [
            (
                RewardDimension::VerifiedSuccess,
                self.minimum_verified_success,
            ),
            (
                RewardDimension::EffectIntegrity,
                self.minimum_effect_integrity,
            ),
            (RewardDimension::Security, self.minimum_security),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(SafetyLimitsError::InvalidMinimum { dimension, value });
            }
        }
        for (dimension, value) in [
            (RewardDimension::Cost, self.maximum_cost),
            (RewardDimension::Latency, self.maximum_latency),
            (
                RewardDimension::HumanAttention,
                self.maximum_human_attention,
            ),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(SafetyLimitsError::InvalidMaximum { dimension, value });
            }
        }
        Ok(())
    }
}

impl Default for SafetyLimits {
    /// A conservative baseline that callers should replace with their governed
    /// deployment limits before admitting real topology changes.
    fn default() -> Self {
        Self {
            minimum_verified_success: 0.95,
            minimum_effect_integrity: 1.0,
            minimum_security: 1.0,
            maximum_cost: 10_000.0,
            maximum_latency: 10_000.0,
            maximum_human_attention: 1_800.0,
        }
    }
}

/// Malformed [`SafetyLimits`].
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum SafetyLimitsError {
    /// A quality minimum was non-finite or outside `0..=1`.
    #[error("minimum for {dimension:?} must be a finite score in 0..=1, got {value}")]
    InvalidMinimum {
        /// Score dimension whose lower bound is malformed.
        dimension: RewardDimension,
        /// Invalid lower bound.
        value: f64,
    },
    /// A burden maximum was negative or non-finite.
    #[error("maximum for {dimension:?} must be finite and non-negative, got {value}")]
    InvalidMaximum {
        /// Burden dimension whose upper bound is malformed.
        dimension: RewardDimension,
        /// Invalid upper bound.
        value: f64,
    },
}

/// The learner-external safety gate for architecture/topology selections.
#[derive(Clone, Debug, PartialEq)]
pub struct SafetyContract {
    limits: SafetyLimits,
    require_corrobated_evaluation: bool,
}

impl SafetyContract {
    /// Creates a safety contract with the supplied immutable limits.
    #[must_use]
    pub const fn new(limits: SafetyLimits) -> Self {
        Self {
            limits,
            require_corrobated_evaluation: true,
        }
    }

    /// Creates a contract from the six hard limits without exposing mutable
    /// contract internals.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyLimitsError`] for malformed limits.
    pub fn with_limits(
        minimum_verified_success: f64,
        minimum_effect_integrity: f64,
        minimum_security: f64,
        maximum_cost: f64,
        maximum_latency: f64,
        maximum_human_attention: f64,
    ) -> Result<Self, SafetyLimitsError> {
        Ok(Self::new(SafetyLimits::new(
            minimum_verified_success,
            minimum_effect_integrity,
            minimum_security,
            maximum_cost,
            maximum_latency,
            maximum_human_attention,
        )?))
    }

    /// Returns an otherwise identical contract that permits a supported (rather
    /// than corroborated) evaluation claim. This is intended only for governed
    /// non-production evaluation; policy allowance and all six hard limits
    /// remain mandatory.
    #[must_use]
    pub const fn allowing_supported_evaluation(mut self) -> Self {
        self.require_corrobated_evaluation = false;
        self
    }

    /// Immutable hard limits owned by this contract.
    #[must_use]
    pub const fn limits(&self) -> SafetyLimits {
        self.limits
    }

    /// Checks the six hard metric limits before a learner selection is used.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyError`] when a vector is malformed or any hard limit is
    /// exceeded. No score may compensate for another dimension.
    pub fn check_reward(&self, reward: &RewardVector) -> Result<(), SafetyError> {
        reward.validate()?;
        self.limits.validate()?;
        if reward.verified_success < self.limits.minimum_verified_success {
            return Err(SafetyError::BelowMinimum {
                dimension: RewardDimension::VerifiedSuccess,
                observed: reward.verified_success,
                required: self.limits.minimum_verified_success,
            });
        }
        if reward.effect_integrity < self.limits.minimum_effect_integrity {
            return Err(SafetyError::BelowMinimum {
                dimension: RewardDimension::EffectIntegrity,
                observed: reward.effect_integrity,
                required: self.limits.minimum_effect_integrity,
            });
        }
        if reward.security < self.limits.minimum_security {
            return Err(SafetyError::BelowMinimum {
                dimension: RewardDimension::Security,
                observed: reward.security,
                required: self.limits.minimum_security,
            });
        }
        if reward.cost > self.limits.maximum_cost {
            return Err(SafetyError::AboveMaximum {
                dimension: RewardDimension::Cost,
                observed: reward.cost,
                maximum: self.limits.maximum_cost,
            });
        }
        if reward.latency > self.limits.maximum_latency {
            return Err(SafetyError::AboveMaximum {
                dimension: RewardDimension::Latency,
                observed: reward.latency,
                maximum: self.limits.maximum_latency,
            });
        }
        if reward.human_attention > self.limits.maximum_human_attention {
            return Err(SafetyError::AboveMaximum {
                dimension: RewardDimension::HumanAttention,
                observed: reward.human_attention,
                maximum: self.limits.maximum_human_attention,
            });
        }
        Ok(())
    }

    /// Enforces that architecture selection has an actual policy allowance.
    ///
    /// `RequireApproval` is not an allowance. It remains a hard denial until
    /// the caller obtains and re-evaluates a durable approval through
    /// `atom-policy`.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyError`] for denied or still-unapproved policy decisions.
    pub fn check_policy(&self, decision: &PolicyDecision) -> Result<(), SafetyError> {
        match decision {
            PolicyDecision::Allow(_) => Ok(()),
            PolicyDecision::Deny(reason) => Err(SafetyError::PolicyDenied {
                reason: reason.clone(),
            }),
            PolicyDecision::RequireApproval(_) => Err(SafetyError::PolicyApprovalRequired),
        }
    }

    /// Enforces independent, non-tainted evaluation evidence.
    ///
    /// The caller is responsible for selecting an evaluator separated from the
    /// learner. The claim's lifecycle state and taint are then checked here as
    /// a hard gate rather than included in a reward calculation.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyError`] when corroboration is required but absent or
    /// when the claim remains tainted for unauthorized effect eligibility.
    pub fn check_evaluation_claim(&self, claim: &Claim) -> Result<(), SafetyError> {
        let required_state = if self.require_corrobated_evaluation {
            ClaimState::Corroborated
        } else {
            ClaimState::Supported
        };
        let state_ok = if self.require_corrobated_evaluation {
            claim.state() == ClaimState::Corroborated
        } else {
            matches!(
                claim.state(),
                ClaimState::Supported | ClaimState::Corroborated
            )
        };
        if !state_ok {
            return Err(SafetyError::EvaluationClaimInsufficient {
                claim_id: claim.claim_id().clone(),
                observed: claim.state(),
                required: required_state,
            });
        }
        if claim.blocks_unauthorized_effect_eligibility() {
            return Err(SafetyError::EvaluationClaimTainted {
                claim_id: claim.claim_id().clone(),
            });
        }
        Ok(())
    }

    /// Applies all learner-external constraints and returns the policy approval
    /// reference when a candidate may proceed.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyError`] on the first hard constraint violation. The
    /// method does not mutate the contract, reward, claim, or policy decision.
    pub fn admit(
        &self,
        reward: &RewardVector,
        policy: &PolicyDecision,
        evaluation_claim: &Claim,
    ) -> Result<SafetyApproval, SafetyError> {
        self.check_reward(reward)?;
        self.check_policy(policy)?;
        self.check_evaluation_claim(evaluation_claim)?;
        let PolicyDecision::Allow(approval_id) = policy else {
            unreachable!("check_policy only returns Ok for PolicyDecision::Allow");
        };
        Ok(SafetyApproval {
            approval_id: approval_id.clone(),
            evaluation_claim_id: evaluation_claim.claim_id().clone(),
        })
    }
}

impl Default for SafetyContract {
    fn default() -> Self {
        Self::new(SafetyLimits::default())
    }
}

/// Evidence that a candidate passed every hard gate at one point in time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyApproval {
    approval_id: String,
    evaluation_claim_id: ClaimId,
}

impl SafetyApproval {
    /// Durable approval identifier returned by `atom-policy`.
    #[must_use]
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// Corroborated evaluation claim accepted by the contract.
    #[must_use]
    pub fn evaluation_claim_id(&self) -> &ClaimId {
        &self.evaluation_claim_id
    }
}

/// A learner-external safety rejection.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum SafetyError {
    /// Reward data itself was malformed.
    #[error(transparent)]
    InvalidReward(#[from] RewardVectorError),
    /// Contract limits were malformed (including a literal built without
    /// [`SafetyLimits::new`]).
    #[error(transparent)]
    InvalidLimits(#[from] SafetyLimitsError),
    /// A quality score fell below its non-negotiable minimum.
    #[error("{dimension:?} {observed} is below required minimum {required}")]
    BelowMinimum {
        /// Quality dimension that failed.
        dimension: RewardDimension,
        /// Candidate value.
        observed: f64,
        /// Required inclusive minimum.
        required: f64,
    },
    /// A burden exceeded its non-negotiable maximum.
    #[error("{dimension:?} {observed} exceeds permitted maximum {maximum}")]
    AboveMaximum {
        /// Burden dimension that failed.
        dimension: RewardDimension,
        /// Candidate value.
        observed: f64,
        /// Permitted inclusive maximum.
        maximum: f64,
    },
    /// `atom-policy` explicitly denied the architecture action.
    #[error("policy denied the architecture action: {reason}")]
    PolicyDenied {
        /// Policy evaluator's reason.
        reason: String,
    },
    /// The action still needs a durable policy approval.
    #[error("policy approval is required before architecture selection")]
    PolicyApprovalRequired,
    /// The evaluation claim has not reached the required lifecycle state.
    #[error(
        "evaluation claim {claim_id} is {observed:?}; required at least {required:?} evidence"
    )]
    EvaluationClaimInsufficient {
        /// Claim offered as evaluation evidence.
        claim_id: ClaimId,
        /// State held by the claim.
        observed: ClaimState,
        /// Minimum state accepted by this contract.
        required: ClaimState,
    },
    /// Tainted evidence cannot directly justify an architecture action.
    #[error("evaluation claim {claim_id} is tainted for unauthorized effect eligibility")]
    EvaluationClaimTainted {
        /// Tainted claim identity.
        claim_id: ClaimId,
    },
}

/// Compatibility name for a [`SafetyError`].
pub type SafetyViolation = SafetyError;
/// Compatibility name for a [`SafetyError`].
pub type SafetyContractError = SafetyError;

fn validate_score(dimension: RewardDimension, value: f64) -> Result<(), RewardVectorError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(RewardVectorError::InvalidScore { dimension, value })
    }
}

fn validate_burden(dimension: RewardDimension, value: f64) -> Result<(), RewardVectorError> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(RewardVectorError::InvalidBurden { dimension, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SafetyLimits {
        SafetyLimits::new(0.9, 0.95, 1.0, 100.0, 20.0, 5.0).expect("valid limits")
    }

    fn passing_reward() -> RewardVector {
        RewardVector::new(0.95, 1.0, 1.0, 50.0, 10.0, 2.0).expect("valid reward")
    }

    #[test]
    fn vector_has_exactly_six_ordered_dimensions() {
        assert_eq!(RewardDimension::ALL.len(), 6);
        assert_eq!(
            passing_reward().as_array(),
            [0.95, 1.0, 1.0, 50.0, 10.0, 2.0]
        );
    }

    #[test]
    fn no_high_score_compensates_for_a_security_failure() {
        let contract = SafetyContract::new(limits());
        let unsafe_reward =
            RewardVector::new(1.0, 1.0, 0.99, 0.0, 0.0, 0.0).expect("syntactically valid vector");

        assert_eq!(
            contract.check_reward(&unsafe_reward),
            Err(SafetyError::BelowMinimum {
                dimension: RewardDimension::Security,
                observed: 0.99,
                required: 1.0,
            })
        );
    }

    #[test]
    fn all_six_hard_limits_are_checked() {
        let contract = SafetyContract::new(limits());
        assert!(contract.check_reward(&passing_reward()).is_ok());

        let excessive_attention =
            RewardVector::new(0.95, 1.0, 1.0, 50.0, 10.0, 5.1).expect("syntactically valid vector");
        assert!(matches!(
            contract.check_reward(&excessive_attention),
            Err(SafetyError::AboveMaximum {
                dimension: RewardDimension::HumanAttention,
                ..
            })
        ));
    }

    #[test]
    fn policy_must_be_an_actual_allowance() {
        let contract = SafetyContract::new(limits());
        assert!(contract
            .check_policy(&PolicyDecision::Allow("approval-1".to_owned()))
            .is_ok());
        assert!(matches!(
            contract.check_policy(&PolicyDecision::Deny("out of scope".to_owned())),
            Err(SafetyError::PolicyDenied { .. })
        ));
    }
}
