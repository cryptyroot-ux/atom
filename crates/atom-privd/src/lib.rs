//! `atom-privd`: the privilege boundary of the ATOM kernel (KRN-002).
//!
//! The main runtime is unprivileged. Every host-administration action it needs
//! is a typed [`HostOp`] — a closed enum with no "run arbitrary command" — that
//! it hands to a [`PrivilegeBroker`]. The broker admits an op only after a valid,
//! one-shot [`atom_effect::CommitPermit`] is spent through the real commit gate,
//! and only an admitted op reaches the host through a [`HostExecutor`].
//!
//! ATOM — the normative source is `spec/` (precedence 1); this crate is one
//! implementation of it.

#![forbid(unsafe_code)]

mod broker;
mod executor;
mod op;
mod sandbox;

pub use broker::{AdmissionRequest, Admitted, DenyReason, PrivilegeBroker};
pub use executor::{ExecError, HostExecutor, OpOutcome};
pub use op::{HostOp, OpError};
pub use sandbox::SandboxedHostExecutor;
