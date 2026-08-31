//! PolicyRecommendation and HoldoutResult types for the Experience Compiler.

use crate::signature::TaskSignature;
use serde::{Deserialize, Serialize};

/// Non-authoritative recommendation emitted by the Experience Compiler.
/// Per INV-016: must NOT emit autonomous authority expansion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyRecommendation {
    /// The capability this recommendation relates to (if extending existing).
    pub target_capability_id: Option<String>,
    /// The proposed operation(s) and resource selector.
    pub proposed_operations: Vec<String>,
    /// The resource selector for the proposed capability.
    pub proposed_resource: String,
    /// The policy rationale (auditable).
    pub rationale: String,
    /// The source task signature this was derived from.
    pub source_signature: TaskSignature,
    /// Confidence score [0, 1] based on holdout evaluation.
    pub confidence: f64,
    /// The holdout evaluation result.
    pub holdout_result: HoldoutResult,
}

impl PolicyRecommendation {
    /// Creates a new policy recommendation.
    #[must_use]
    pub fn new(
        target_capability_id: Option<String>,
        proposed_operations: Vec<String>,
        proposed_resource: String,
        rationale: String,
        source_signature: TaskSignature,
        confidence: f64,
        holdout_result: HoldoutResult,
    ) -> Self {
        Self {
            target_capability_id,
            proposed_operations,
            proposed_resource,
            rationale,
            source_signature,
            confidence,
            holdout_result,
        }
    }

    /// Whether this recommendation is actionable (passed holdout, confidence >= 0.8).
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.holdout_result.passed && self.confidence >= 0.8
    }
}

/// Result of evaluating on the hidden holdout set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HoldoutResult {
    /// Whether the candidate passed the holdout evaluation.
    pub passed: bool,
    /// Number of test cases in holdout.
    pub test_cases: usize,
    /// Number of passed cases.
    pub passed_cases: usize,
    /// Cost improvement ratio (1.0 = no change, <1.0 = improvement).
    pub cost_improvement_ratio: f64,
    /// Correctness preservation ratio (1.0 = perfect).
    pub correctness_ratio: f64,
}

impl HoldoutResult {
    /// Creates a new holdout result.
    #[must_use]
    pub fn new(passed: bool, test_cases: usize, passed_cases: usize, cost_improvement_ratio: f64, correctness_ratio: f64) -> Self {
        Self {
            passed,
            test_cases,
            passed_cases,
            cost_improvement_ratio,
            correctness_ratio,
        }
    }

    /// Pass rate as a fraction.
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        if self.test_cases == 0 {
            0.0
        } else {
            self.passed_cases as f64 / self.test_cases as f64
        }
    }
}