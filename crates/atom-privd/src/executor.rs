//! The host-facing edge of the privilege boundary (KRN-002).
//!
//! A [`HostExecutor`] is the only thing in the system that touches the real
//! host. The broker owns one privately and hands it a [`HostOp`] only after a
//! [`atom_effect::CommitPermit`] has been consumed, so this trait never sees an
//! unadmitted operation. Tests substitute a recording fake; production wires a
//! real implementation behind the same one-way gate.

use thiserror::Error;

use crate::op::HostOp;

/// What the host reported after running an admitted [`HostOp`].
///
/// The outcome is deliberately opaque data, not a fresh capability: executing
/// one op grants nothing toward the next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpOutcome {
    /// The [`HostOp::kind`] of the op that produced this outcome.
    pub op_kind: &'static str,
    /// A host-supplied description of what happened, for the audit trail.
    pub detail: String,
}

impl OpOutcome {
    /// Records that `op_kind` completed with `detail`.
    #[must_use]
    pub fn new(op_kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            op_kind,
            detail: detail.into(),
        }
    }
}

/// Why the host refused or failed to carry out an already-admitted op.
///
/// This is a *post-admission* failure: the permit was validly spent before the
/// executor ran, so an `ExecError` never means "denied at the boundary".
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("host operation `{op_kind}` failed: {message}")]
pub struct ExecError {
    /// The [`HostOp::kind`] that failed.
    pub op_kind: &'static str,
    /// The host's account of the failure.
    pub message: String,
}

impl ExecError {
    /// A failure of `op_kind`, described by `message`.
    #[must_use]
    pub fn failed(op_kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            op_kind,
            message: message.into(),
        }
    }
}

/// Carries out host operations that have already crossed the privilege boundary.
///
/// Implementations MUST assume every [`HostOp`] handed to them is already
/// admitted: authorisation is the broker's job, not the executor's. The
/// `&mut self` receiver lets a real executor hold host handles; the broker
/// keeps its executor private so nothing else can call this.
pub trait HostExecutor {
    /// Runs `op` against the host.
    ///
    /// # Errors
    ///
    /// [`ExecError`] if the host refused or failed the operation. This is not a
    /// boundary denial — the permit is already spent by the time this runs.
    fn execute(&mut self, op: &HostOp) -> Result<OpOutcome, ExecError>;
}
