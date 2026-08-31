//! Correctness preservation policy for compiled capabilities (ATOM-JIT-001).
//!
//! Verifies that a compiled capability preserves correctness within the policy
//! threshold before it may advance beyond `Stage::Lab`. INV-016: this module
//! ONLY checks correctness — it never grants promotion or authority.

use serde::{Deserialize, Serialize};

use crate::jit::{CompiledCapability, DeliberativeTrace};

/// A correctness policy: the minimum verified-success rate a compiled capability
/// must demonstrate before it may leave `Stage::Lab`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CorrectnessPolicy {
    /// Minimum verified-success rate in `[0, 1]`.
    pub min_correct_rate: f64,
    /// Minimum number of verified traces required for a stable estimate.
    pub min_verified_traces: usize,
}

impl Default for CorrectnessPolicy {
    fn default() -> Self {
        Self {
            min_correct_rate: 0.95,
            min_verified_traces: 2,
        }
    }
}

/// The outcome of comparing a candidate's observed correctness against the policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CorrectnessCheckResult {
    /// Whether correctness is preserved within the policy threshold.
    pub preserved: bool,
    /// Observed verified-success rate.
    pub observed_rate: f64,
    /// The policy threshold that was applied.
    pub threshold: f64,
    /// Number of verified traces that informed the estimate.
    pub verified_traces: usize,
}

/// Compares a compiled capability's source traces against a [`CorrectnessPolicy`].
#[derive(Clone, Debug, Default)]
pub struct CorrectnessCompare;

impl CorrectnessCompare {
    /// Evaluates correctness of `capability` against `policy` using its `source_traces`.
    ///
    /// A trace counts as "verified correct" when `trace.verified` is true AND its
    /// `verifier_level` is at or above `VerifierLevel::V2` (independent verification).
    #[must_use]
    pub fn evaluate(
        capability: &CompiledCapability,
        traces: &[DeliberativeTrace],
        policy: &CorrectnessPolicy,
    ) -> CorrectnessCheckResult {
        let sources: std::collections::HashSet<&String> = capability.source_traces.iter().collect();
        let used: Vec<&DeliberativeTrace> = traces
            .iter()
            .filter(|t| sources.contains(&t.id))
            .collect();

        let verified = used
            .iter()
            .filter(|t| t.verified && t.verifier_level as u8 >= 2)
            .count();

        let observed_rate = if used.is_empty() {
            0.0
        } else {
            verified as f64 / used.len() as f64
        };

        let preserved =
            verified >= policy.min_verified_traces && observed_rate >= policy.min_correct_rate;

        CorrectnessCheckResult {
            preserved,
            observed_rate,
            threshold: policy.min_correct_rate,
            verified_traces: verified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jit::CognitionJitCompiler;
    use atom_evidence::VerifierLevel;
    use chrono::Utc;

    fn trace(id: &str, verified: bool, level: VerifierLevel) -> DeliberativeTrace {
        DeliberativeTrace {
            id: id.to_owned(),
            task_family: "summarize".to_owned(),
            tokens_used: 500,
            model_calls: 3,
            verified,
            verifier_level: level,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn preserves_correctness_when_verified_and_independent() {
        let mut c = CognitionJitCompiler::new(0.5);
        for i in 0..5 {
            c.record_trace(trace(&format!("t{i}"), true, VerifierLevel::V3));
        }
        let cap = c.compile("summarize").unwrap();
        let traces: Vec<DeliberativeTrace> = (0..5).map(|i| trace(&format!("t{i}"), true, VerifierLevel::V3)).collect();
        let r = CorrectnessCompare::evaluate(&cap, &traces, &CorrectnessPolicy::default());
        assert!(r.preserved);
        assert!((r.observed_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rejects_when_only_self_verified() {
        // V0 self-verification must NOT count as independent verification.
        let mut c = CognitionJitCompiler::new(0.5);
        for i in 0..5 {
            c.record_trace(trace(&format!("s{i}"), true, VerifierLevel::V0));
        }
        let cap = c.compile("summarize").unwrap();
        let traces: Vec<DeliberativeTrace> = (0..5).map(|i| trace(&format!("s{i}"), true, VerifierLevel::V0)).collect();
        let r = CorrectnessCompare::evaluate(&cap, &traces, &CorrectnessPolicy::default());
        assert!(!r.preserved);
        assert_eq!(r.verified_traces, 0);
    }

    #[test]
    fn rejects_below_threshold() {
        // Build a capability whose source traces mix verified + failed, so the
        // observed correctness rate drops below the 0.95 policy threshold.
        let cap = CompiledCapability {
            id: "cap-mixed".to_owned(),
            task_family: "summarize".to_owned(),
            source_traces: vec!["v0".to_owned(), "v1".to_owned(), "v2".to_owned(), "b0".to_owned(), "b1".to_owned()],
            tokens_per_call: 500,
            model_calls_per_invocation: 3,
            evolution_stage: atom_evolution::Stage::Lab,
            compiled_at: Utc::now(),
        };
        let traces: Vec<DeliberativeTrace> = (0..3)
            .map(|i| trace(&format!("v{i}"), true, VerifierLevel::V3))
            .chain((0..2).map(|i| trace(&format!("b{i}"), false, VerifierLevel::V1)))
            .collect();
        let r = CorrectnessCompare::evaluate(&cap, &traces, &CorrectnessPolicy::default());
        assert!(!r.preserved);
        assert!((r.observed_rate - 0.6).abs() < f64::EPSILON);
    }
}
