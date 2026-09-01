//! Cognition JIT compiler: compile recurrent verified deliberative behavior
//! into cheaper workflow/tool/specialist capability (ATOM-JIT-001).
//!
//! INV-016: compiled capabilities start at `Stage::Lab` and MUST NOT
//! self-promote to trusted-core or authority.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use atom_evidence::VerifierLevel;
use atom_evolution::Stage;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the cognition JIT subsystem.
#[derive(Debug, Error)]
pub enum JitError {
    /// Not enough verified traces to compile.
    #[error("task family `{family}` has {have} verified traces, need at least {need}")]
    InsufficientTraces {
        /// The task family id.
        family: String,
        /// How many verified traces exist.
        have: usize,
        /// Minimum required.
        need: usize,
    },
    /// Correctness rate is below the policy threshold.
    #[error("correctness rate {rate:.4} is below threshold {threshold:.4} for `{family}`")]
    CorrectnessBelowThreshold {
        /// Task family.
        family: String,
        /// Observed correctness rate.
        rate: f64,
        /// Required threshold.
        threshold: f64,
    },
    /// Unknown task family.
    #[error("unknown task family `{0}`")]
    UnknownFamily(String),
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Identifies a family of recurring tasks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFamily {
    /// Unique identifier for this task family.
    pub id: String,
    /// Human-readable description.
    pub description: String,
}

/// A single deliberative execution trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliberativeTrace {
    /// Unique trace identifier.
    pub id: String,
    /// Task family this trace belongs to.
    pub task_family: String,
    /// Number of tokens consumed.
    pub tokens_used: u64,
    /// Number of model calls made.
    pub model_calls: u32,
    /// Whether the outcome was verified as correct.
    pub verified: bool,
    /// Which verifier level confirmed the outcome.
    pub verifier_level: VerifierLevel,
    /// When this trace was recorded.
    pub timestamp: DateTime<Utc>,
}

/// A compiled capability produced by the JIT compiler.
///
/// INV-016: always starts at `Stage::Lab`. Promotion requires external
/// evaluation evidence (INV-017) via the evaluator crate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompiledCapability {
    /// Unique capability identifier.
    pub id: String,
    /// The task family this capability handles.
    pub task_family: String,
    /// IDs of the source traces this was compiled from.
    pub source_traces: Vec<String>,
    /// Expected tokens per invocation (average of verified traces).
    pub tokens_per_call: u64,
    /// Expected model calls per invocation (average of verified traces).
    pub model_calls_per_invocation: u32,
    /// Evolution stage — always starts at Lab (INV-016).
    pub evolution_stage: Stage,
    /// When this capability was compiled.
    pub compiled_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// JIT Compiler
// ---------------------------------------------------------------------------

/// The cognition JIT compiler.
///
/// Records deliberative traces and compiles recurring verified behavior into
/// cheaper capabilities when correctness is preserved within the policy
/// threshold (ATOM-JIT-001).
#[derive(Clone, Debug)]
pub struct CognitionJitCompiler {
    traces: Vec<DeliberativeTrace>,
    /// Minimum correctness rate required to compile.
    correctness_threshold: f64,
}

impl CognitionJitCompiler {
    /// Create a new compiler with the given correctness threshold.
    ///
    /// `correctness_threshold` is in `[0, 1]`: the fraction of traces for a
    /// task family that must be verified-correct before compilation is allowed.
    #[must_use]
    pub fn new(correctness_threshold: f64) -> Self {
        Self {
            traces: Vec::new(),
            correctness_threshold,
        }
    }

    /// Record a deliberative execution trace.
    pub fn record_trace(&mut self, trace: DeliberativeTrace) {
        self.traces.push(trace);
    }

    /// All recorded traces (read-only).
    #[must_use]
    pub fn traces(&self) -> &[DeliberativeTrace] {
        &self.traces
    }

    /// Check if a task family should be compiled.
    ///
    /// Returns `true` when:
    /// 1. The family has been seen at least `min_occurrences` times.
    /// 2. The verified success rate meets the correctness threshold.
    #[must_use]
    pub fn should_compile(&self, task_family: &str, min_occurrences: usize) -> bool {
        let family_traces: Vec<&DeliberativeTrace> = self
            .traces
            .iter()
            .filter(|t| t.task_family == task_family)
            .collect();

        if family_traces.len() < min_occurrences {
            return false;
        }

        let verified = family_traces.iter().filter(|t| t.verified).count();
        let rate = verified as f64 / family_traces.len() as f64;
        rate >= self.correctness_threshold
    }

    /// Compile traces for `task_family` into a [`CompiledCapability`].
    ///
    /// The compiled capability starts at `Stage::Lab` (INV-016: no
    /// self-promotion of trusted-core or authority).
    ///
    /// # Errors
    ///
    /// - [`JitError::UnknownFamily`] if no traces exist for the family.
    /// - [`JitError::InsufficientTraces`] if fewer than 2 verified traces exist.
    /// - [`JitError::CorrectnessBelowThreshold`] if the correctness rate is
    ///   below the threshold.
    pub fn compile(&self, task_family: &str) -> Result<CompiledCapability, JitError> {
        let family_traces: Vec<&DeliberativeTrace> = self
            .traces
            .iter()
            .filter(|t| t.task_family == task_family)
            .collect();

        if family_traces.is_empty() {
            return Err(JitError::UnknownFamily(task_family.into()));
        }

        let verified: Vec<&&DeliberativeTrace> =
            family_traces.iter().filter(|t| t.verified).collect();

        if verified.len() < 2 {
            return Err(JitError::InsufficientTraces {
                family: task_family.into(),
                have: verified.len(),
                need: 2,
            });
        }

        let rate = verified.len() as f64 / family_traces.len() as f64;
        if rate < self.correctness_threshold {
            return Err(JitError::CorrectnessBelowThreshold {
                family: task_family.into(),
                rate,
                threshold: self.correctness_threshold,
            });
        }

        let avg_tokens =
            verified.iter().map(|t| t.tokens_used).sum::<u64>() / verified.len() as u64;
        let avg_calls =
            verified.iter().map(|t| t.model_calls as u64).sum::<u64>() / verified.len() as u64;

        let source_traces = verified.iter().map(|t| t.id.clone()).collect();

        Ok(CompiledCapability {
            id: format!("jit-{task_family}-{}", Utc::now().timestamp_millis()),
            task_family: task_family.into(),
            source_traces,
            tokens_per_call: avg_tokens,
            model_calls_per_invocation: avg_calls as u32,
            // INV-016: always start at Lab, never self-promote.
            evolution_stage: Stage::Lab,
            compiled_at: Utc::now(),
        })
    }

    /// Cost trend for a task family: `(invocation_number, tokens_used)` pairs
    /// in chronological order (VT-011).
    ///
    /// After a compiled capability is deployed, this trend should show
    /// decreasing token usage.
    #[must_use]
    pub fn cost_trend(&self, task_family: &str) -> Vec<(usize, u64)> {
        self.traces
            .iter()
            .filter(|t| t.task_family == task_family)
            .enumerate()
            .map(|(i, t)| (i + 1, t.tokens_used))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace(family: &str, tokens: u64, calls: u32, verified: bool) -> DeliberativeTrace {
        DeliberativeTrace {
            id: format!("trace-{family}-{tokens}"),
            task_family: family.into(),
            tokens_used: tokens,
            model_calls: calls,
            verified,
            verifier_level: if verified {
                VerifierLevel::V3
            } else {
                VerifierLevel::V0
            },
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn should_compile_meets_threshold() {
        let mut compiler = CognitionJitCompiler::new(0.8);
        // 5 traces, 4 verified => 80% rate.
        for i in 0..4 {
            compiler.record_trace(make_trace("translate", 1000 - i * 100, 5, true));
        }
        compiler.record_trace(make_trace("translate", 1200, 6, false));

        assert!(compiler.should_compile("translate", 3));
    }

    #[test]
    fn should_compile_insufficient_occurrences() {
        let mut compiler = CognitionJitCompiler::new(0.8);
        compiler.record_trace(make_trace("rare", 500, 3, true));
        assert!(!compiler.should_compile("rare", 5));
    }

    #[test]
    fn should_compile_below_threshold() {
        let mut compiler = CognitionJitCompiler::new(0.9);
        // 5 traces, 3 verified => 60% rate.
        for _ in 0..3 {
            compiler.record_trace(make_trace("flaky", 500, 3, true));
        }
        for _ in 0..2 {
            compiler.record_trace(make_trace("flaky", 800, 5, false));
        }
        assert!(!compiler.should_compile("flaky", 3));
    }

    #[test]
    fn compile_produces_lab_stage() {
        let mut compiler = CognitionJitCompiler::new(0.5);
        for i in 0..5 {
            compiler.record_trace(make_trace("summarize", 800 + i * 10, 4, true));
        }

        let cap = compiler.compile("summarize").unwrap();
        // INV-016: MUST start at Lab.
        assert_eq!(cap.evolution_stage, Stage::Lab);
        assert_eq!(cap.task_family, "summarize");
        assert_eq!(cap.source_traces.len(), 5);
    }

    #[test]
    fn compile_unknown_family() {
        let compiler = CognitionJitCompiler::new(0.5);
        assert!(matches!(
            compiler.compile("nonexistent"),
            Err(JitError::UnknownFamily(_))
        ));
    }

    #[test]
    fn compile_insufficient_verified() {
        let mut compiler = CognitionJitCompiler::new(0.5);
        compiler.record_trace(make_trace("once", 500, 3, true));
        assert!(matches!(
            compiler.compile("once"),
            Err(JitError::InsufficientTraces { .. })
        ));
    }

    #[test]
    fn cost_trend_shows_chronological_order() {
        let mut compiler = CognitionJitCompiler::new(0.5);
        // Decreasing cost over time (VT-011 scenario).
        for tokens in [1000u64, 800, 600, 400, 200] {
            compiler.record_trace(make_trace("optimize", tokens, 5, true));
        }

        let trend = compiler.cost_trend("optimize");
        assert_eq!(trend.len(), 5);
        assert_eq!(trend[0], (1, 1000));
        assert_eq!(trend[4], (5, 200));

        // Verify decreasing trend.
        for window in trend.windows(2) {
            assert!(window[0].1 >= window[1].1);
        }
    }

    #[test]
    fn inv016_compiled_capability_never_self_promotes() {
        let mut compiler = CognitionJitCompiler::new(0.5);
        for _ in 0..5 {
            compiler.record_trace(make_trace("task", 500, 3, true));
        }
        let cap = compiler.compile("task").unwrap();
        // There is no method on CompiledCapability that allows promotion —
        // promotion must go through the evaluator (INV-017) and evolution
        // crate. Structurally, Stage::Lab is the only value set here.
        assert_eq!(cap.evolution_stage, Stage::Lab);
    }
}
