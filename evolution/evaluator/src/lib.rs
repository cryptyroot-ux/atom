//! atom-evaluator: separated evaluation evidence, holdout suite for promotion
//! decisions, and V0–V5 verifier labeling (INV-017, VT-010).
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **INV-017** — Learning/promotion decisions require separated evaluation
//!   evidence and cannot rely only on training trajectories.
//! * **VT-010** — Candidate passes generated tests but fails hidden holdout
//!   cases → promotion is blocked.
//! * **INV-016** — Self-improvement may recursively increase capability but cannot
//!   self-promote trusted-core changes or authority expansion.

#![forbid(unsafe_code)]

pub mod evaluator;
pub mod holdout;

pub use evaluator::{
    EvalError, EvaluationRecord, EvidenceSource, PromotionDecision, SeparatedEvaluator,
    VerifierLabel,
};
pub use holdout::{HoldoutCase, HoldoutDifficulty, HoldoutError, HoldoutResult, HoldoutSuite};
