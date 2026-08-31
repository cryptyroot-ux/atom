//! Constrained policy over topology actions with hard safety constraints
//! outside the learner and contextual-bandit offline evaluation (ATOM-ARC-001).
//!
//! INV-016 enforcement: the learner may increase capability but MUST NOT
//! self-promote trusted-core changes or authority expansion.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use atom_evolution::{ChangeClass, ChangeOrigin, ProposedChange};

use crate::reward::{RewardWeights, VectorReward};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the architecture learner subsystem.
#[derive(Debug, Error)]
pub enum LearnerError {
    /// A safety constraint vetoed the action.
    #[error("safety constraint `{constraint}` rejected action {action:?}: {reason}")]
    SafetyViolation {
        /// Name of the constraint that fired.
        constraint: String,
        /// The vetoed action.
        action: TopologyAction,
        /// Why it was rejected.
        reason: String,
    },
    /// No candidate action survived the safety filter.
    #[error("no safe action available from {total} candidates")]
    NoSafeAction {
        /// How many candidates were offered.
        total: usize,
    },
    /// INV-016: self-promotion of trusted-core or authority detected.
    #[error("INV-016 violation: topology action {action:?} would self-promote {class:?}")]
    SelfPromotionForbidden {
        /// The offending action.
        action: TopologyAction,
        /// Why it was classified as self-promotion.
        class: ChangeClass,
    },
    /// Bandit evaluation input is empty.
    #[error("contextual bandit: {0}")]
    BanditError(String),
}

// ---------------------------------------------------------------------------
// Topology actions
// ---------------------------------------------------------------------------

/// Actions the architecture learner may propose over the system topology.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyAction {
    /// Add a new worker instance of a given worker type.
    AddWorker { worker_type: String },
    /// Remove an existing worker by id.
    RemoveWorker { worker_id: String },
    /// Scale a provider's capacity.
    ScaleProvider { provider_id: String, target: u32 },
    /// Change the routing table for a target.
    RouteChange { target: String, new_route: String },
    /// Add a specialist capability for a task family.
    AddSpecialist { task_family: String },
    /// Remove a specialist capability.
    RemoveSpecialist { specialist_id: String },
}

// ---------------------------------------------------------------------------
// Safety constraints (hard, OUTSIDE the learner — ATOM-ARC-001)
// ---------------------------------------------------------------------------

/// A single hard safety constraint that gates topology actions.
///
/// Safety constraints live *outside* the learner — they are not learned or
/// adapted; they are configured by policy.
#[derive(Clone, Debug)]
pub struct SafetyConstraint {
    /// Human-readable name for audit logs.
    pub name: String,
    /// Maximum number of workers allowed (if applicable).
    pub max_workers: Option<u32>,
    /// Topology actions that are unconditionally forbidden.
    pub forbidden_actions: Vec<ForbiddenPattern>,
}

/// A pattern that matches a forbidden topology action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForbiddenPattern {
    /// No worker of this type may be added.
    WorkerType(String),
    /// This provider may not be scaled.
    ProviderId(String),
    /// No specialist may be added for this task family.
    TaskFamily(String),
}

impl SafetyConstraint {
    /// Check whether `action` is allowed by this constraint.
    ///
    /// # Errors
    ///
    /// Returns [`LearnerError::SafetyViolation`] when the action is vetoed.
    pub fn check(&self, action: &TopologyAction) -> Result<(), LearnerError> {
        // Max-worker cap.
        if let Some(max) = self.max_workers {
            if let TopologyAction::ScaleProvider { target, .. } = action {
                if *target > max {
                    return Err(LearnerError::SafetyViolation {
                        constraint: self.name.clone(),
                        action: action.clone(),
                        reason: format!("scale target {target} exceeds max {max}"),
                    });
                }
            }
        }

        // Forbidden-pattern matching.
        for pat in &self.forbidden_actions {
            let matched = match (pat, action) {
                (ForbiddenPattern::WorkerType(t), TopologyAction::AddWorker { worker_type })
                    if t == worker_type =>
                {
                    true
                }
                (
                    ForbiddenPattern::ProviderId(p),
                    TopologyAction::ScaleProvider { provider_id, .. },
                ) if p == provider_id => true,
                (
                    ForbiddenPattern::TaskFamily(tf),
                    TopologyAction::AddSpecialist { task_family },
                ) if tf == task_family => true,
                _ => false,
            };
            if matched {
                return Err(LearnerError::SafetyViolation {
                    constraint: self.name.clone(),
                    action: action.clone(),
                    reason: format!("matches forbidden pattern {pat:?}"),
                });
            }
        }
        Ok(())
    }
}

/// A set of safety constraints that must ALL pass for an action to be allowed.
#[derive(Clone, Debug, Default)]
pub struct SafetyConstraintSet {
    constraints: Vec<SafetyConstraint>,
}

impl SafetyConstraintSet {
    /// Create an empty constraint set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint to the set.
    pub fn add(&mut self, constraint: SafetyConstraint) {
        self.constraints.push(constraint);
    }

    /// Check all constraints against `action`.
    ///
    /// # Errors
    ///
    /// Returns the first [`LearnerError::SafetyViolation`] encountered.
    pub fn check_all(&self, action: &TopologyAction) -> Result<(), LearnerError> {
        for c in &self.constraints {
            c.check(action)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// INV-016 enforcement
// ---------------------------------------------------------------------------

/// Assert that a topology action does NOT self-promote trusted-core or
/// authority (INV-016).
///
/// The check delegates to `atom_evolution::ProposedChange::assert_no_self_promotion`
/// by classifying `AddSpecialist` as `ChangeClass::Capability` (allowed) and
/// treating any action that *would* touch trusted-core or authority as forbidden
/// when originating from production cognition.
///
/// # Errors
///
/// Returns [`LearnerError::SelfPromotionForbidden`] when the action implies
/// a trusted-core or authority change from production cognition.
pub fn assert_no_self_promotion(action: &TopologyAction) -> Result<(), LearnerError> {
    // Classify the topology action.
    let class = classify_action(action);
    let proposed = ProposedChange {
        class,
        origin: ChangeOrigin::ProductionCognition,
        parent_grant: None,
        child_grant: None,
    };
    proposed
        .assert_no_self_promotion()
        .map_err(|_| LearnerError::SelfPromotionForbidden {
            action: action.clone(),
            class,
        })
}

/// Map a topology action to an evolution change class.
///
/// Only `Capability` and `Behavior` are reachable from the learner — the
/// learner is structurally unable to propose `TrustedCore` or `AuthorityPolicy`
/// actions through the normal API.  This function exists for defence-in-depth.
#[must_use]
fn classify_action(action: &TopologyAction) -> ChangeClass {
    match action {
        TopologyAction::AddSpecialist { .. } | TopologyAction::RemoveSpecialist { .. } => {
            ChangeClass::Capability
        }
        _ => ChangeClass::Behavior,
    }
}

// ---------------------------------------------------------------------------
// Constrained policy
// ---------------------------------------------------------------------------

/// A constrained policy that filters topology actions through safety constraints,
/// then selects the highest-reward action.
#[derive(Clone, Debug)]
pub struct ConstrainedPolicy {
    safety: SafetyConstraintSet,
    weights: RewardWeights,
}

impl ConstrainedPolicy {
    /// Create a new constrained policy.
    #[must_use]
    pub fn new(safety: SafetyConstraintSet, weights: RewardWeights) -> Self {
        Self { safety, weights }
    }

    /// Select the best action from `candidates` by:
    /// 1. Filtering through safety constraints (hard, outside the learner).
    /// 2. Checking INV-016 (no self-promotion).
    /// 3. Picking the candidate with the highest scalarized reward.
    ///
    /// `rewards` must be parallel to `candidates` (same length and order).
    ///
    /// # Errors
    ///
    /// Returns [`LearnerError::NoSafeAction`] when every candidate is vetoed.
    pub fn select_action(
        &self,
        candidates: &[TopologyAction],
        rewards: &[VectorReward],
    ) -> Result<TopologyAction, LearnerError> {
        assert_eq!(candidates.len(), rewards.len());
        let total = candidates.len();

        let mut best: Option<(f64, &TopologyAction)> = None;

        for (action, reward) in candidates.iter().zip(rewards.iter()) {
            // Hard safety filter.
            if self.safety.check_all(action).is_err() {
                continue;
            }
            // INV-016 filter.
            if assert_no_self_promotion(action).is_err() {
                continue;
            }
            let score = reward.scalarize(&self.weights);
            if best.is_none_or(|(s, _)| score > s) {
                best = Some((score, action));
            }
        }

        best.map(|(_, a)| a.clone())
            .ok_or(LearnerError::NoSafeAction { total })
    }
}

// ---------------------------------------------------------------------------
// Contextual bandit — offline/canary evaluation (ATOM-ARC-001)
// ---------------------------------------------------------------------------

/// A single logged sample for offline bandit evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanditSample {
    /// Context features observed before the action was chosen.
    pub context: Vec<f64>,
    /// Index of the action that was chosen by the logging policy.
    pub chosen_action: usize,
    /// Scalar reward observed.
    pub reward: f64,
    /// Probability the logging policy assigned to the chosen action (for IPS).
    pub propensity: f64,
}

/// Inverse-propensity-scored (IPS) offline policy evaluator.
///
/// Implements the Horvitz-Thompson estimator for off-policy evaluation of a
/// target policy given data logged under a different (logging) policy.
#[derive(Clone, Debug, Default)]
pub struct ContextualBandit {
    samples: Vec<BanditSample>,
}

impl ContextualBandit {
    /// Create an empty evaluator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a logged sample.
    pub fn add_sample(&mut self, sample: BanditSample) {
        self.samples.push(sample);
    }

    /// Evaluate a target policy using the inverse-propensity scoring (IPS)
    /// estimator.
    ///
    /// `policy_fn` maps a context feature vector to the action index the target
    /// policy would choose.
    ///
    /// Returns the IPS estimate of the expected reward under the target policy.
    ///
    /// # Errors
    ///
    /// Returns [`LearnerError::BanditError`] when there are no samples.
    pub fn evaluate_policy(
        &self,
        policy_fn: &dyn Fn(&[f64]) -> usize,
    ) -> Result<f64, LearnerError> {
        if self.samples.is_empty() {
            return Err(LearnerError::BanditError(
                "no logged samples for evaluation".into(),
            ));
        }

        let mut total = 0.0;
        let mut count = 0usize;

        for s in &self.samples {
            let target_action = policy_fn(&s.context);
            if target_action == s.chosen_action {
                // IPS weight: 1 / propensity
                total += s.reward / s.propensity;
            }
            count += 1;
        }

        Ok(total / count as f64)
    }

    /// Number of logged samples.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reward::RewardWeights;

    // -- Safety constraints -------------------------------------------------

    #[test]
    fn safety_constraint_allows_valid_action() {
        let c = SafetyConstraint {
            name: "test".into(),
            max_workers: Some(10),
            forbidden_actions: vec![],
        };
        let action = TopologyAction::AddWorker {
            worker_type: "standard".into(),
        };
        assert!(c.check(&action).is_ok());
    }

    #[test]
    fn safety_constraint_blocks_forbidden_worker() {
        let c = SafetyConstraint {
            name: "no-gpu".into(),
            max_workers: None,
            forbidden_actions: vec![ForbiddenPattern::WorkerType("gpu-heavy".into())],
        };
        let action = TopologyAction::AddWorker {
            worker_type: "gpu-heavy".into(),
        };
        assert!(c.check(&action).is_err());
    }

    #[test]
    fn safety_constraint_blocks_over_scale() {
        let c = SafetyConstraint {
            name: "cap".into(),
            max_workers: Some(5),
            forbidden_actions: vec![],
        };
        let action = TopologyAction::ScaleProvider {
            provider_id: "p1".into(),
            target: 10,
        };
        assert!(c.check(&action).is_err());
    }

    #[test]
    fn constraint_set_all_pass() {
        let mut set = SafetyConstraintSet::new();
        set.add(SafetyConstraint {
            name: "a".into(),
            max_workers: Some(100),
            forbidden_actions: vec![],
        });
        set.add(SafetyConstraint {
            name: "b".into(),
            max_workers: None,
            forbidden_actions: vec![],
        });
        let action = TopologyAction::AddWorker {
            worker_type: "std".into(),
        };
        assert!(set.check_all(&action).is_ok());
    }

    // -- INV-016 no self-promotion ------------------------------------------

    #[test]
    fn inv016_capability_action_allowed() {
        // AddSpecialist is ChangeClass::Capability — allowed from production cognition.
        let action = TopologyAction::AddSpecialist {
            task_family: "translation".into(),
        };
        assert!(assert_no_self_promotion(&action).is_ok());
    }

    #[test]
    fn inv016_behavior_action_allowed() {
        let action = TopologyAction::RouteChange {
            target: "t1".into(),
            new_route: "r1".into(),
        };
        assert!(assert_no_self_promotion(&action).is_ok());
    }

    // -- Constrained policy -------------------------------------------------

    #[test]
    fn policy_selects_best_safe_action() {
        let mut safety = SafetyConstraintSet::new();
        safety.add(SafetyConstraint {
            name: "block-gpu".into(),
            max_workers: None,
            forbidden_actions: vec![ForbiddenPattern::WorkerType("gpu".into())],
        });

        let policy = ConstrainedPolicy::new(safety, RewardWeights::uniform());

        let candidates = vec![
            TopologyAction::AddWorker {
                worker_type: "gpu".into(),
            }, // blocked
            TopologyAction::AddWorker {
                worker_type: "cpu".into(),
            }, // reward 0.5 each
            TopologyAction::AddWorker {
                worker_type: "tpu".into(),
            }, // reward 0.8 each
        ];
        let rewards = vec![
            VectorReward {
                verified_success: 1.0,
                effect_integrity: 1.0,
                security: 1.0,
                cost: 1.0,
                latency: 1.0,
                human_attention: 1.0,
            },
            VectorReward {
                verified_success: 0.5,
                effect_integrity: 0.5,
                security: 0.5,
                cost: 0.5,
                latency: 0.5,
                human_attention: 0.5,
            },
            VectorReward {
                verified_success: 0.8,
                effect_integrity: 0.8,
                security: 0.8,
                cost: 0.8,
                latency: 0.8,
                human_attention: 0.8,
            },
        ];

        let selected = policy.select_action(&candidates, &rewards).unwrap();
        // GPU is blocked, TPU (0.8 * 6 = 4.8) beats CPU (0.5 * 6 = 3.0).
        assert_eq!(
            selected,
            TopologyAction::AddWorker {
                worker_type: "tpu".into()
            }
        );
    }

    #[test]
    fn policy_no_safe_action() {
        let mut safety = SafetyConstraintSet::new();
        safety.add(SafetyConstraint {
            name: "block-all".into(),
            max_workers: None,
            forbidden_actions: vec![ForbiddenPattern::WorkerType("only".into())],
        });

        let policy = ConstrainedPolicy::new(safety, RewardWeights::uniform());
        let candidates = vec![TopologyAction::AddWorker {
            worker_type: "only".into(),
        }];
        let rewards = vec![VectorReward {
            verified_success: 1.0,
            effect_integrity: 1.0,
            security: 1.0,
            cost: 1.0,
            latency: 1.0,
            human_attention: 1.0,
        }];

        let result = policy.select_action(&candidates, &rewards);
        assert!(result.is_err());
    }

    // -- Contextual bandit --------------------------------------------------

    #[test]
    fn bandit_ips_estimator() {
        let mut bandit = ContextualBandit::new();
        // Two samples where the target policy agrees with the logging policy.
        bandit.add_sample(BanditSample {
            context: vec![1.0],
            chosen_action: 0,
            reward: 1.0,
            propensity: 0.5,
        });
        bandit.add_sample(BanditSample {
            context: vec![2.0],
            chosen_action: 1,
            reward: 0.0,
            propensity: 0.5,
        });

        // Target policy always picks action 0.
        let target = |_ctx: &[f64]| -> usize { 0 };
        let value = bandit.evaluate_policy(&target).unwrap();
        // Sample 0: match, weight = 1.0 / 0.5 = 2.0
        // Sample 1: no match, contributes 0
        // IPS = 2.0 / 2 = 1.0
        assert!((value - 1.0).abs() < 1e-12);
    }

    #[test]
    fn bandit_empty_samples() {
        let bandit = ContextualBandit::new();
        let target = |_ctx: &[f64]| -> usize { 0 };
        assert!(bandit.evaluate_policy(&target).is_err());
    }

    #[test]
    fn bandit_no_match() {
        let mut bandit = ContextualBandit::new();
        bandit.add_sample(BanditSample {
            context: vec![1.0],
            chosen_action: 0,
            reward: 1.0,
            propensity: 0.5,
        });
        // Target always picks action 1, but logged action was 0.
        let target = |_ctx: &[f64]| -> usize { 1 };
        let value = bandit.evaluate_policy(&target).unwrap();
        assert!((value - 0.0).abs() < 1e-12);
    }
}
