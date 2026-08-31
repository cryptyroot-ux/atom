//! Hidden holdout suite for promotion decisions (VT-010, INV-017).
//!
//! A holdout suite is reserved and MUST NOT be used for training. A candidate that
//! passes generated tests but FAILS hidden holdout cases is blocked from promotion.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evaluator::{EvaluationRecord, EvidenceSource, VerifierLabel};

/// Difficulty tier of a holdout case. Higher tiers stress edge behaviors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldoutDifficulty {
    /// Basic functional case.
    Easy,
    /// Edge-case / boundary condition.
    Hard,
    /// Adversarial / metamorphic case.
    Adversarial,
}

/// A single hidden holdout case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HoldoutCase {
    /// Stable id of the case (content-addressed in production).
    pub id: String,
    /// Difficulty tier.
    pub difficulty: HoldoutDifficulty,
    /// Verifier independence used to grade the case.
    pub verifier: VerifierLabel,
    /// Whether the candidate passed this case.
    pub passed: bool,
}

/// Aggregate result of running a holdout suite.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HoldoutResult {
    /// Candidate capability id.
    pub candidate_id: String,
    /// Total cases.
    pub total: usize,
    /// Cases passed.
    pub passed: usize,
    /// Pass rate in `[0, 1]`.
    pub pass_rate: f64,
}

/// Errors from the holdout suite.
#[derive(Debug, Error, PartialEq)]
pub enum HoldoutError {
    /// The suite is empty (cannot evaluate promotion on zero cases).
    #[error("holdout suite for `{0}` is empty")]
    EmptySuite(String),
}

/// A reserved holdout suite — kept separate from training data.
#[derive(Clone, Debug, Default)]
pub struct HoldoutSuite {
    cases: Vec<HoldoutCase>,
}

impl HoldoutSuite {
    /// Creates an empty reserved suite.
    #[must_use]
    pub fn new() -> Self {
        Self { cases: Vec::new() }
    }

    /// Adds a case to the reserved suite.
    pub fn add_case(&mut self, case: HoldoutCase) {
        self.cases.push(case);
    }

    /// Number of reserved cases.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    /// Whether the suite has no cases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    /// Runs the suite against `candidate_id`, converting each case to a
    /// separated [`EvaluationRecord`] (source = `Holdout`).
    ///
    /// # Errors
    /// Returns [`HoldoutError::EmptySuite`] when no cases are reserved.
    pub fn run(&self, candidate_id: &str) -> Result<HoldoutResult, HoldoutError> {
        if self.cases.is_empty() {
            return Err(HoldoutError::EmptySuite(candidate_id.to_owned()));
        }
        let passed = self.cases.iter().filter(|c| c.passed).count();
        let total = self.cases.len();
        let pass_rate = passed as f64 / total as f64;
        Ok(HoldoutResult {
            candidate_id: candidate_id.to_owned(),
            total,
            passed,
            pass_rate,
        })
    }

    /// Materializes the suite as separated evaluation records (INV-017).
    #[must_use]
    pub fn to_records(&self, candidate_id: &str) -> Vec<EvaluationRecord> {
        self.cases
            .iter()
            .map(|c| EvaluationRecord {
                candidate_id: candidate_id.to_owned(),
                source: EvidenceSource::Holdout,
                verifier: c.verifier,
                correctness_rate: if c.passed { 1.0 } else { 0.0 },
                passed: c.passed,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str, difficulty: HoldoutDifficulty, passed: bool) -> HoldoutCase {
        HoldoutCase {
            id: id.to_owned(),
            difficulty,
            verifier: VerifierLabel::V3,
            passed,
        }
    }

    #[test]
    fn empty_suite_is_error() {
        let s = HoldoutSuite::new();
        assert!(matches!(s.run("cap1"), Err(HoldoutError::EmptySuite(_))));
    }

    #[test]
    fn pass_rate_computed() {
        let mut s = HoldoutSuite::new();
        s.add_case(case("a", HoldoutDifficulty::Easy, true));
        s.add_case(case("b", HoldoutDifficulty::Hard, true));
        s.add_case(case("c", HoldoutDifficulty::Adversarial, false));
        let r = s.run("cap1").unwrap();
        assert_eq!(r.total, 3);
        assert_eq!(r.passed, 2);
        assert!((r.pass_rate - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn to_records_are_separated_holdout() {
        let mut s = HoldoutSuite::new();
        s.add_case(case("a", HoldoutDifficulty::Easy, true));
        let recs = s.to_records("cap1");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].source, EvidenceSource::Holdout);
        assert!(recs[0].passed);
    }
}
