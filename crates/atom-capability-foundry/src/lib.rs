//! Capability Foundry (ATOM-FND-001/002/003).
//!
//! The Foundry is a candidate-only laboratory boundary. It can synthesize and
//! evaluate candidate tools and workflows, and it can return the certificate
//! that was independently verified for a candidate. It deliberately contains
//! no authority-issuance API: activation is evidence and certificate gated.
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-FND-001** — tool candidates require hermetic build, tests,
//!   property/fuzz/adversarial checks, a hidden holdout, and a certificate.
//! * **ATOM-FND-002** — generated workflows have typed, durable explicit
//!   failure, timeout, retry, reconciliation, and compensation transitions.
//! * **ATOM-FND-003** — verifier independence is labeled with V0--V5.
//! * **ATOM-INV-008 / ATOM-INV-017** — executable candidates require a valid
//!   certificate and separated evaluation evidence before activation.

#![forbid(unsafe_code)]

pub mod gate;
pub mod tool;
pub mod verifier;
pub mod workflow;

pub use atom_cert::Certificate;
pub use gate::{
    ActivatedCandidate, ActivationDecision, ActivationGate, ActivationPolicy, CheckStatus,
    FoundryState, GateError, GateEvidence, GateFailure, HiddenHoldout, QuarantinedCandidate,
    RequiredCheck, ValidationEvidence,
};
pub use tool::{
    Candidate, CandidateCertificationMaterial, CandidateError, CandidateInterface, CandidateKind,
    ToolCandidateSpec, ToolFoundry, ToolFoundryError, ToolInterface,
};
pub use verifier::{
    VerificationMethod, VerifierError, VerifierFoundry, VerifierInput, VerifierLabel, VerifierLevel,
};
pub use workflow::{
    DurableWorkflow, StepKind, WorkflowCandidate, WorkflowCandidateSpec, WorkflowError,
    WorkflowFoundry, WorkflowFoundryError, WorkflowInterface, WorkflowOutputTypes, WorkflowSpec,
    WorkflowStep, WorkflowTransition, WorkflowTransitionKind,
};

/// Stage marker for the G5 Compounding implementation.
pub const CRATE_STAGE: &str = "G5-compounding";
