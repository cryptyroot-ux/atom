//! Architecture safety controls for ATOM's learner and adaptive artifacts.
//!
//! This crate keeps architecture selection safety outside the learner itself:
//!
//! * [`EvolutionBoundary`] enforces the fixed evolution-ring order, bans E7/E8
//!   production-cognition self-promotion, and restores the previous active
//!   artifact on a verified regression (ATOM-EVO-001/002, VT-012).
//! * [`SafetyContract`] applies independent hard constraints to the six-axis
//!   [`RewardVector`] used by architecture selection (ATOM-ARC-001).
//! * [`AuditLog`] records decisions in a tamper-evident hash chain whose head
//!   can be independently checkpointed.

#![forbid(unsafe_code)]

/// Tamper-evident architecture-safety audit records.
pub mod audit;
/// Adaptive-artifact evolution-ring boundary.
pub mod boundary;
/// Learner-external hard safety constraints and reward vectors.
pub mod safety;

pub use audit::{
    AuditAction, AuditCheckpoint, AuditEntry, AuditError, AuditEvent, AuditHash, AuditLog,
    AuditPolicyOutcome, AuditVerification,
};
pub use boundary::{
    ArtifactState, BoundaryError, ChangeClass, ChangeOrigin, EvolutionBoundary, EvolutionClass,
    EvolutionRing, Promotion, Ring, RollbackAction, Stage,
};
pub use safety::{
    RewardDimension, RewardVector, RewardVectorError, SafetyApproval, SafetyContract,
    SafetyContractError, SafetyError, SafetyLimits, SafetyLimitsError, SafetyViolation,
};

/// Implementation maturity marker for the architecture safety boundary.
pub const CRATE_STAGE: &str = "G7-architecture-safety";
