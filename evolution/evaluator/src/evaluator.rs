//! Separated evaluation evidence and promotion decisions (INV-017, VT-010).
//!
//! This crate produces *separated* evaluation evidence: promotion decisions must
//! rely on a holdout suite that was NOT used for training. INV-016: the evaluator
//! NEVER grants authority or self-promotes — it only emits a `PromotionDecision`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use atom_evidence::VerifierLevel;

/// Where an evaluation evidence record came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Evidence drawn from training trajectories (NOT sufficient alone for promotion).
    Training,
    /// Evidence drawn from a separated holdout suite (required for promotion).
    Holdout,
}

/// V0–V5 verifier independence label (ATOM-FND-003 taxonomy, reused here).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VerifierLabel {
    /// Self-verification (no independence).
    V0 = 0,
    /// Same-process re-check.
    V1 = 1,
    /// Cross-module check.
    V2 = 2,
    /// Independent agent.
    V3 = 3,
    /// Adversarial red-team.
    V4 = 4,
    /// External/human attestation.
    V5 = 5,
}

impl From<VerifierLevel> for VerifierLabel {
    fn from(v: VerifierLevel) -> Self {
        match v {
            VerifierLevel::V0 => VerifierLabel::V0,
            VerifierLevel::V1 => VerifierLabel::V1,
            VerifierLevel::V2 => VerifierLabel::V2,
            VerifierLevel::V3 => VerifierLabel::V3,
            VerifierLevel::V4 => VerifierLabel::V4,
            VerifierLevel::V5 => VerifierLabel::V5,
        }
    }
}

/// A single evaluation record on a candidate capability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvaluationRecord {
    /// Candidate capability id under evaluation.
    pub candidate_id: String,
    /// Source of the evidence (training vs holdout).
    pub source: EvidenceSource,
    /// Verifier independence label.
    pub verifier: VerifierLabel,
    /// Observed correctness rate in `[0, 1]`.
    pub correctness_rate: f64,
    /// Whether the record passed its gate.
    pub passed: bool,
}

/// Promotion decision emitted by the separated evaluator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PromotionDecision {
    /// Candidate may be promoted — separated holdout evidence passed.
    Promote {
        /// Candidate capability id.
        candidate_id: String,
    },
    /// Candidate is blocked — holdout evidence failed or was absent.
    Block {
        /// Candidate capability id.
        candidate_id: String,
        /// Human-readable reason (auditable).
        reason: String,
    },
}

/// Errors from the separated evaluator.
#[derive(Debug, Error, PartialEq)]
pub enum EvalError {
    /// No holdout evidence was supplied for a promotion decision (INV-017).
    #[error("promotion requires separated holdout evidence; none supplied for `{0}`")]
    MissingHoldout(String),
    /// Holdout evidence was supplied but at insufficient verifier independence.
    #[error("holdout verifier independence below V2 for `{0}`")]
    InsufficientIndependence(String),
}

/// The separated evaluator: promotion requires HOLDOUT (not training) evidence
/// at independent verifier level (>= V2).
#[derive(Clone, Debug, Default)]
pub struct SeparatedEvaluator {
    /// Minimum correctness rate required on holdout.
    pub min_holdout_correctness: f64,
}

impl SeparatedEvaluator {
    /// Creates a new evaluator with the given holdout correctness floor.
    #[must_use]
    pub fn new(min_holdout_correctness: f64) -> Self {
        Self { min_holdout_correctness }
    }

    /// Decides promotion from a set of evaluation records.
    ///
    /// # Errors
    /// Returns [`EvalError::MissingHoldout`] when no `Holdout` record exists, or
    /// [`EvalError::InsufficientIndependence`] when the best holdout verifier is
    /// below `V2`. INV-017: training evidence alone is NEVER sufficient.
    pub fn decide(&self, candidate_id: &str, records: &[EvaluationRecord]) -> Result<PromotionDecision, EvalError> {
        let holdout: Vec<&EvaluationRecord> = records.iter().filter(|r| r.source == EvidenceSource::Holdout).collect();
        if holdout.is_empty() {
            return Err(EvalError::MissingHoldout(candidate_id.to_owned()));
        }
        let best = holdout.iter().map(|r| r.verifier as u8).max().unwrap_or(0);
        if best < 2 {
            return Err(EvalError::InsufficientIndependence(candidate_id.to_owned()));
        }
        let passed = holdout.iter().all(|r| r.passed && r.correctness_rate >= self.min_holdout_correctness);
        if passed {
            Ok(PromotionDecision::Promote { candidate_id: candidate_id.to_owned() })
        } else {
            Ok(PromotionDecision::Block {
                candidate_id: candidate_id.to_owned(),
                reason: "holdout evidence failed correctness gate".to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, source: EvidenceSource, v: VerifierLabel, rate: f64, passed: bool) -> EvaluationRecord {
        EvaluationRecord {
            candidate_id: id.to_owned(),
            source,
            verifier: v,
            correctness_rate: rate,
            passed,
        }
    }

    #[test]
    fn blocks_without_holdout_evidence() {
        let ev = SeparatedEvaluator::new(0.95);
        let records = vec![rec("cap1", EvidenceSource::Training, VerifierLabel::V5, 1.0, true)];
        assert!(matches!(ev.decide("cap1", &records), Err(EvalError::MissingHoldout(_))));
    }

    #[test]
    fn blocks_with_self_verified_holdout_only() {
        let ev = SeparatedEvaluator::new(0.95);
        // Holdout exists but verifier is V0 (self) -> insufficient independence.
        let records = vec![rec("cap1", EvidenceSource::Holdout, VerifierLabel::V0, 1.0, true)];
        assert!(matches!(ev.decide("cap1", &records), Err(EvalError::InsufficientIndependence(_))));
    }

    #[test]
    fn promotes_with_independent_holdout() {
        let ev = SeparatedEvaluator::new(0.95);
        let records = vec![
            rec("cap1", EvidenceSource::Training, VerifierLabel::V5, 1.0, true),
            rec("cap1", EvidenceSource::Holdout, VerifierLabel::V3, 0.98, true),
        ];
        assert!(matches!(ev.decide("cap1", &records), Ok(PromotionDecision::Promote { .. })));
    }

    #[test]
    fn blocks_when_holdout_fails_correctness() {
        let ev = SeparatedEvaluator::new(0.95);
        let records = vec![rec("cap1", EvidenceSource::Holdout, VerifierLabel::V3, 0.80, false)];
        assert!(matches!(ev.decide("cap1", &records), Ok(PromotionDecision::Block { .. })));
    }
}
