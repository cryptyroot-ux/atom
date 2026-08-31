//! atom-experience-compiler: mines repeated subtrajectories from execution traces,
//! synthesizes candidate artifacts, evaluates on hidden holdout before promotion (ATOM-EXP-001/002).
//!
//! # Design
//! - TaskSignature: fingerprint of a task execution trajectory
//! - SubtrajectoryMiner: mines recurring patterns across task family
//! - ExperienceCompiler: synthesizes candidates, evaluates on hidden holdout
//! - PolicyRecommendation: non-authoritative output (INV-016)
//!
//! Normative references: requirements.yaml (ATOM-EXP-001/002), acceptance/catalog.yaml (VT-011), invariants.yaml (INV-016, INV-017), enums.yaml (evolution_class, evolution_ring).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Unique identifier for a task signature — content-addressed hash of the trajectory.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskSignature(String);

impl TaskSignature {
    /// Computes the signature from a serialized execution trajectory.
    #[must_use]
    pub fn of(trajectory: &ExecutionTrajectory) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"atom-experience-sig-v1");
        hasher.update(serde_json::to_vec(trajectory).expect("trajectory serializes"));
        Self(format!("sig:{:x}", hasher.finalize()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TaskSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single execution trajectory from a task family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionTrajectory {
    /// The task family this trajectory belongs to (e.g., "file-write", "api-call").
    pub task_family: String,
    /// Ordered sequence of steps (tool calls, decisions, observations).
    pub steps: Vec<TrajectoryStep>,
    /// Whether the trajectory ended in success (true) or failure (false).
    pub success: bool,
    /// Wall-clock cost (tokens, latency, cost).
    pub cost: CostSnapshot,
    /// Timestamp of execution (for time-windowing).
    pub timestamp: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TrajectoryStep {
    /// The tool or capability invoked.
    pub tool_id: String,
    /// The input to the tool (serialized).
    pub input: serde_json::Value,
    /// The output from the tool (serialized).
    pub output: serde_json::Value,
    /// Whether this step was a decision point (branch).
    pub is_decision: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CostSnapshot {
    /// Total tokens consumed.
    pub tokens: u64,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// Estimated cost in USD cents.
    pub cost_cents: u64,
}

/// A mined subtrajectory — a recurring pattern across trajectories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Subtrajectory {
    /// The pattern's unique signature.
    pub signature: TaskSignature,
    /// The steps comprising this pattern.
    pub steps: Vec<TrajectoryStep>,
    /// How many trajectories in the family contain this pattern.
    pub frequency: usize,
    /// Average cost savings when this pattern is extracted.
    pub avg_cost_savings: CostSnapshot,
    /// Whether this pattern was present in positive (success) or negative (failure) trajectories.
    pub polarity: Polarity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Polarity {
    /// Pattern observed in successful trajectories.
    Positive,
    /// Pattern observed in failed trajectories.
    Negative,
}

/// Errors from the experience compiler.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompilerError {
    #[error("insufficient trajectories for mining (need at least {min}, got {got})")]
    InsufficientTrajectories { min: usize, got: usize },
    #[error("holdout evaluation failed: {reason}")]
    HoldoutFailed { reason: String },
    #[error("synthesized candidate failed verification: {reason}")]
    VerificationFailed { reason: String },
    #[error("authority expansion attempted: {detail}")]
    AuthorityExpansion { detail: String },
}

pub type CompilerResult<T> = Result<T, CompilerError>;
