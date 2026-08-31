//! atom-experience-compiler: mines repeated subtrajectories from execution traces,
//! synthesizes candidate artifacts, evaluates on hidden holdout before promotion (ATOM-EXP-001/002).
//!
//! # Design
//! - TaskSignature: fingerprint of a task execution trajectory
//! - SubtrajectoryMiner: mines recurring patterns across task family
//! - ExperienceCompiler: synthesizes candidates, evaluates on hidden holdout
//! - PolicyRecommendation: non-authoritative output (INV-016)
//!
//! Normative references: requirements.yaml ATOM-EXP-001/002; acceptance/catalog.yaml VT-011; invariants.yaml INV-016 INV-017; enums.yaml evolution_class evolution_ring.

#![forbid(unsafe_code)]

pub mod compiler;
pub mod recommendation;
pub mod signature;

pub use compiler::ExperienceCompiler;
pub use recommendation::{HoldoutResult, PolicyRecommendation};
pub use signature::{CompilerError, CompilerResult, CostSnapshot, ExecutionTrajectory, Polarity, Subtrajectory, TaskSignature, TrajectoryStep};

/// Current crate stage marker (used by conformance tooling).
pub const CRATE_STAGE: &str = "G5-Compounding";
