//! ExperienceCompiler: mines recurring subtrajectories, synthesizes candidates,
//! evaluates on hidden holdout, emits PolicyRecommendation (non-authoritative).
//!
//! Normative: spec/requirements.yaml (ATOM-EXP-001/002), spec/invariants.yaml (INV-016, INV-017).

use crate::recommendation::{HoldoutResult, PolicyRecommendation};
use crate::signature::{
    CompilerError, CompilerResult, CostSnapshot, ExecutionTrajectory, Polarity, Subtrajectory,
    TaskSignature, TrajectoryStep,
};
use std::collections::HashMap;

/// The Experience Compiler.
pub struct ExperienceCompiler {
    /// Minimum trajectories required for mining.
    min_trajectories: usize,
    /// Holdout fraction (e.g., 0.2 = 20% held out).
    holdout_fraction: f64,
    /// Minimum frequency for a pattern to be considered.
    min_frequency: usize,
    /// Holdout correctness threshold below which a candidate is rejected.
    correctness_threshold: f64,
    /// Confidence threshold for actionability.
    confidence_threshold: f64,
}

impl ExperienceCompiler {
    /// Creates a new compiler with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_trajectories: 10,
            holdout_fraction: 0.2,
            min_frequency: 3,
            correctness_threshold: 0.90,
            confidence_threshold: 0.8,
        }
    }

    /// Mines recurring subtrajectories from a task family's execution history.
    ///
    /// # Errors
    /// Returns `CompilerError::InsufficientTrajectories` if fewer than `min_trajectories`
    /// are provided.
    pub fn mine_subtrajectories(
        &self,
        trajectories: &[ExecutionTrajectory],
    ) -> CompilerResult<Vec<Subtrajectory>> {
        if trajectories.len() < self.min_trajectories {
            return Err(CompilerError::InsufficientTrajectories {
                min: self.min_trajectories,
                got: trajectories.len(),
            });
        }

        // Split into training and holdout; the holdout is reserved and never mined from.
        let (training, _holdout) = self.split_holdout(trajectories);

        // Mine n-grams from successful trajectories only (positive polarity).
        let mut pattern_counts: HashMap<Vec<TrajectoryStep>, (usize, Polarity)> = HashMap::new();
        for traj in training {
            if !traj.success {
                continue;
            }
            for len in 2..=5.min(traj.steps.len()) {
                for window in traj.steps.windows(len) {
                    let key = window.to_vec();
                    let entry = pattern_counts.entry(key).or_insert((0, Polarity::Positive));
                    entry.0 += 1;
                }
            }
        }

        let mut results = Vec::new();
        for (steps, (freq, polarity)) in pattern_counts {
            if freq >= self.min_frequency {
                let signature = TaskSignature::of(&ExecutionTrajectory {
                    task_family: "mined".to_owned(),
                    steps: steps.clone(),
                    success: true,
                    cost: CostSnapshot { tokens: 0, latency_ms: 0, cost_cents: 0 },
                    timestamp: 0,
                });
                results.push(Subtrajectory {
                    signature,
                    steps,
                    frequency: freq,
                    avg_cost_savings: CostSnapshot { tokens: 0, latency_ms: 0, cost_cents: 0 },
                    polarity,
                });
            }
        }

        results.sort_by_key(|s| std::cmp::Reverse(s.frequency));
        Ok(results)
    }

    /// Splits trajectories into `(training, holdout)`.
    ///
    /// The first `ceil(len * holdout_fraction)` trajectories are reserved as the
    /// hidden holdout and are NEVER mined from; the remainder is training data.
    /// This is the split VT-011 relies on: a pattern is learned from training and
    /// must then prove itself on data it has never seen.
    #[must_use]
    pub fn split_holdout<'a>(
        &self,
        trajectories: &'a [ExecutionTrajectory],
    ) -> (&'a [ExecutionTrajectory], &'a [ExecutionTrajectory]) {
        let holdout_count = ((trajectories.len() as f64 * self.holdout_fraction).ceil() as usize)
            .min(trajectories.len());
        let (holdout, training) = trajectories.split_at(holdout_count);
        (training, holdout)
    }

    /// Synthesizes a candidate artifact from a mined subtrajectory.
    ///
    /// Returns a `PolicyRecommendation` (not a `CapabilityGrant`) per INV-016.
    /// Authority boundary: a synthesized candidate MUST NOT expand authority; the
    /// output is a non-authoritative recommendation for a human/sovereign to ratify.
    ///
    /// `holdout` is the reserved slice from [`split_holdout`](Self::split_holdout);
    /// the candidate is only actionable if the pattern actually generalizes there.
    pub fn synthesize_candidate(
        &self,
        subtrajectory: &Subtrajectory,
        family: &str,
        holdout: &[ExecutionTrajectory],
    ) -> CompilerResult<PolicyRecommendation> {
        // Evaluate the mined pattern against the reserved holdout it has never seen.
        let holdout_result = self.evaluate_on_holdout(subtrajectory, holdout);

        // Authority boundary: correctness below threshold blocks promotion (INV-016).
        if holdout_result.correctness_ratio < self.correctness_threshold {
            return Err(CompilerError::AuthorityExpansion {
                detail: format!(
                    "holdout correctness {:.3} below threshold {:.3}",
                    holdout_result.correctness_ratio, self.correctness_threshold
                ),
            });
        }

        // Non-authoritative recommendation — no CapabilityGrant, no self-promotion.
        Ok(PolicyRecommendation::new(
            None,
            vec!["execute".to_owned()],
            family.to_owned(),
            format!(
                "Mined from experience-compiler; freq={} across task family '{}'",
                subtrajectory.frequency, family
            ),
            subtrajectory.signature.clone(),
            holdout_result.correctness_ratio,
            holdout_result,
        ))
    }

    /// Evaluates a subtrajectory against the reserved holdout set (VT-011).
    ///
    /// This is a real generalization test, not a frequency heuristic: among the
    /// held-out trajectories that actually CONTAIN the mined step-pattern, what
    /// fraction ended in success? A pattern that predicts success on unseen data
    /// scores high; a pattern absent from the holdout has no evidence (correctness
    /// 0.0) and is therefore rejected. Cost improvement compares the mean cost of
    /// pattern-bearing successes against the non-pattern baseline in the same holdout.
    fn evaluate_on_holdout(&self, sub: &Subtrajectory, holdout: &[ExecutionTrajectory]) -> HoldoutResult {
        let mut test_cases = 0usize; // holdout trajectories containing the pattern
        let mut passed_cases = 0usize; // ... of which actually succeeded
        let mut cost_pattern_success: u64 = 0;
        let mut cost_baseline_sum: u64 = 0;
        let mut baseline_n = 0usize;

        for traj in holdout {
            if Self::contains_pattern(&traj.steps, &sub.steps) {
                test_cases += 1;
                if traj.success {
                    passed_cases += 1;
                    cost_pattern_success += traj.cost.cost_cents;
                }
            } else {
                cost_baseline_sum += traj.cost.cost_cents;
                baseline_n += 1;
            }
        }

        let correctness_ratio = if test_cases == 0 {
            0.0
        } else {
            passed_cases as f64 / test_cases as f64
        };

        // Cost improvement ratio: <1.0 means pattern-bearing runs are cheaper than
        // the non-pattern baseline; 1.0 means no measurable change (doc convention).
        let cost_improvement_ratio = if passed_cases == 0 || baseline_n == 0 {
            1.0
        } else {
            let mean_pattern = cost_pattern_success as f64 / passed_cases as f64;
            let mean_baseline = cost_baseline_sum as f64 / baseline_n as f64;
            if mean_baseline <= 0.0 {
                1.0
            } else {
                (mean_pattern / mean_baseline).min(1.0)
            }
        };

        let passed = test_cases > 0 && correctness_ratio >= self.correctness_threshold;
        HoldoutResult::new(passed, test_cases, passed_cases, cost_improvement_ratio, correctness_ratio)
    }

    /// Returns true if `needle` appears as a contiguous window inside `haystack`.
    fn contains_pattern(haystack: &[TrajectoryStep], needle: &[TrajectoryStep]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Evaluates a recommendation against the confidence gate.
    pub fn evaluate_recommendation(&self, rec: &PolicyRecommendation) -> CompilerResult<()> {
        if rec.confidence < self.confidence_threshold {
            return Err(CompilerError::HoldoutFailed {
                reason: format!("confidence {:.3} below threshold {:.3}", rec.confidence, self.confidence_threshold),
            });
        }
        Ok(())
    }

    /// Full pipeline: mine -> synthesize -> evaluate -> recommend.
    pub fn compile_experience(
        &self,
        trajectories: &[ExecutionTrajectory],
        family: &str,
    ) -> CompilerResult<Vec<PolicyRecommendation>> {
        let subtrajectories = self.mine_subtrajectories(trajectories)?;
        let (_training, holdout) = self.split_holdout(trajectories);
        let mut recommendations = Vec::new();
        for sub in subtrajectories {
            let rec = self.synthesize_candidate(&sub, family, holdout)?;
            self.evaluate_recommendation(&rec)?;
            recommendations.push(rec);
        }
        Ok(recommendations)
    }
}

impl Default for ExperienceCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TrajectoryStep;

    fn sample_trajectories(n: usize) -> Vec<ExecutionTrajectory> {
        // Deterministic, IDENTICAL step sequence for every trajectory so that
        // subtrajectory mining finds a recurring pattern (the point of VT-011).
        let steps = vec![
            TrajectoryStep {
                tool_id: "tool_a".to_owned(),
                input: serde_json::json!({"op": "read"}),
                output: serde_json::Value::Null,
                is_decision: false,
            },
            TrajectoryStep {
                tool_id: "tool_b".to_owned(),
                input: serde_json::json!({"op": "transform"}),
                output: serde_json::Value::Null,
                is_decision: true,
            },
        ];
        (0..n)
            .map(|i| ExecutionTrajectory {
                task_family: "test".to_owned(),
                steps: steps.clone(),
                success: true,
                cost: CostSnapshot { tokens: 100, latency_ms: 50, cost_cents: 1 },
                timestamp: i as i64,
            })
            .collect()
    }

    #[test]
    fn insufficient_trajectories_is_error() {
        let c = ExperienceCompiler::new();
        let r = c.mine_subtrajectories(&sample_trajectories(3));
        assert!(matches!(r, Err(CompilerError::InsufficientTrajectories { .. })));
    }

    #[test]
    fn mines_recurring_subtrajectory() {
        let c = ExperienceCompiler::new();
        let subs = c.mine_subtrajectories(&sample_trajectories(20)).unwrap();
        assert!(!subs.is_empty(), "expected mined patterns from repeated trajectories");
        for s in &subs {
            assert!(s.frequency >= c.min_frequency);
        }
    }

    #[test]
    fn synthesized_recommendation_is_non_authoritative() {
        let c = ExperienceCompiler::new();
        let fam = sample_trajectories(20);
        let (_training, holdout) = c.split_holdout(&fam);
        let subs = c.mine_subtrajectories(&fam).unwrap();
        let rec = c.synthesize_candidate(&subs[0], "test-family", holdout).unwrap();
        // INV-016: no authority expansion — target must be None (no CapabilityGrant).
        assert!(rec.target_capability_id.is_none());
        assert!(!rec.proposed_operations.is_empty());
        assert!((0.0..=1.0).contains(&rec.confidence));
        assert!(rec.is_actionable());
    }

    #[test]
    fn holdout_blocks_low_correctness() {
        let c = ExperienceCompiler::new();
        let subs = c.mine_subtrajectories(&sample_trajectories(20)).unwrap();
        // The pattern IS present in the holdout, but every held-out run failed:
        // it does not generalize to success, so promotion must be blocked (INV-016).
        let failing_holdout: Vec<ExecutionTrajectory> = sample_trajectories(5)
            .into_iter()
            .map(|mut t| {
                t.success = false;
                t
            })
            .collect();
        let res = c.synthesize_candidate(&subs[0], "test", &failing_holdout);
        assert!(matches!(res, Err(CompilerError::AuthorityExpansion { .. })));
    }

    #[test]
    fn holdout_blocks_absent_pattern() {
        let c = ExperienceCompiler::new();
        let subs = c.mine_subtrajectories(&sample_trajectories(20)).unwrap();
        // Empty holdout => no evidence the pattern generalizes => rejected.
        let res = c.synthesize_candidate(&subs[0], "test", &[]);
        assert!(matches!(res, Err(CompilerError::AuthorityExpansion { .. })));
    }

    #[test]
    fn full_pipeline_compiles_experience() {
        let c = ExperienceCompiler::new();
        let recs = c.compile_experience(&sample_trajectories(20), "test-family").unwrap();
        assert!(!recs.is_empty());
        for r in &recs {
            assert!(r.is_actionable());
        }
    }
}
