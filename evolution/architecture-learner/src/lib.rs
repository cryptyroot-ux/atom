//! atom-architecture-learner: constrained policy over topology actions with
//! hard safety constraints and vector reward (ATOM-ARC-001).
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-ARC-001** — Architecture selection MUST be a constrained policy over
//!   topology actions with hard safety constraints outside the learner and vector
//!   reward including verified success, effect integrity, security, cost, latency
//!   and human attention.
//! * **INV-016** — Self-improvement may recursively increase capability but cannot
//!   self-promote trusted-core changes or authority expansion.
//!
//! Verification: Offline/canary contextual-bandit evaluation (ATOM-ARC-001).

#![forbid(unsafe_code)]

pub mod learner;
pub mod reward;

pub use learner::{
    BanditSample, ConstrainedPolicy, ContextualBandit, LearnerError, SafetyConstraint,
    SafetyConstraintSet, TopologyAction,
};
pub use reward::{RewardError, RewardWeights, VectorReward};
