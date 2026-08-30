//! `atom-fault`: classify a fault before choosing how to recover from it.
//!
//! ATOM v4 — the normative source is `spec/` (precedence 1); this crate is one
//! implementation of it.
//!
//! # What this crate is
//!
//! [`classify`] is a **pure, total, deterministic** function from a typed
//! [`FaultSignal`] (the observable facts of a failure) to a [`FaultClass`] —
//! one of the 14 fault classes of `spec/enums.yaml`. [`recovery_for`] then maps
//! a [`FaultClass`] onto the authoritative recovery vocabulary,
//! [`atom_effect::RetryClass`] (`spec/enums.yaml` `retry_class`, 7 variants).
//! Classification always precedes recovery: **there is no blind retry.**
//!
//! Nothing here touches a clock, the filesystem, or the network. A caller that
//! needs "now" (for example, to decide whether an observation is stale) does
//! the comparison itself and passes the verdict in as a facet of the signal;
//! see [`EvidenceStatus::from_age`]. This keeps the whole path reproducible.
//!
//! # ATOM-INV-002 is the spine of the design
//!
//! `spec/invariants.yaml` ATOM-INV-002: *UNKNOWN_OUTCOME is first-class and is
//! never coerced to success, failure, or safe-to-retry.* Concretely:
//!
//! * When the effect state is ambiguous ([`atom_effect::EffectState::UnknownOutcome`]
//!   or `Reconciling`), [`classify`] returns [`FaultClass::EffectUnknown`] **no
//!   matter what else the signal says** — it sits at the top of the priority
//!   ladder (see [`classify`]).
//! * [`recovery_for`]`(EffectUnknown)` is [`RetryClass::ReconcileBeforeRetry`],
//!   which [`is_plain_retry`] rejects. An ambiguous effect can therefore never
//!   be sent again without first being reconciled.
//!
//! [`FaultClass::EffectUnknown`] is also the fail-safe residue: a reported fault
//! that matches no specific facet is classified as an unknown outcome, because
//! `ReconcileBeforeRetry` is the only recovery that is safe to apply to a fault
//! we cannot explain — it neither retries blindly, nor declares an outcome, nor
//! abandons the effect.
//!
//! # Recovery is a retry class, plus a thin mission-level wrapper
//!
//! The authoritative machine vocabulary is [`RetryClass`], reused verbatim from
//! `atom-effect` (this crate does not redefine it). `replan` and `stop` are
//! *mission-level* actions, not retry classes, so they live in a separate
//! [`RecoveryDirective`] that wraps a [`RetryClass`] and adds `Replan`/`Stop`
//! for the two classes retry cannot help: `SEMANTIC_MISPLAN` and
//! `POLICY_DENIAL`. See [`directive_for`].

#![forbid(unsafe_code)]

mod class;
mod classify;
mod recovery;
mod signal;

pub use class::{FaultClass, ParseFaultClassError};
pub use classify::classify;
pub use recovery::{directive_for, is_plain_retry, recovery_for, RecoveryDirective};
pub use signal::{
    AuthorityStatus, CapabilityStatus, ConnectorStatus, EnvironmentStatus, EvidenceStatus,
    FaultSignal, PlanStatus, PolicyDecision, ResourceStatus, SandboxStatus, ToolStatus,
    TransportStatus, VerifierStatus,
};

// Re-exported so downstream callers get the recovery vocabulary without also
// depending on `atom-effect` directly. This crate uses the enum verbatim; it
// does not redefine it.
pub use atom_effect::RetryClass;
