//! atom-cognition-jit: compile recurrent verified deliberative behavior into
//! cheaper workflow/tool/specialist capability (ATOM-JIT-001).
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-JIT-001** — Recurrent verified deliberative behavior SHOULD compile to
//!   cheaper workflow/tool/specialist capability when correctness is preserved
//!   within policy threshold.
//! * **INV-016** — Self-improvement may recursively increase capability but cannot
//!   self-promote trusted-core changes or authority expansion.
//!
//! Verification: Tokens/model-calls per verified success trend metric (VT-011).

#![forbid(unsafe_code)]

pub mod correctness;
pub mod jit;

pub use correctness::{CorrectnessCheckResult, CorrectnessCompare, CorrectnessPolicy};
pub use jit::{
    CognitionJitCompiler, CompiledCapability, DeliberativeTrace, JitError, TaskFamily,
};
