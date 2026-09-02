//! ATOM daemon execution spine.
//!
//! [`AtomExecutor`] is the persistent mission-queue driver for the sovereign
//! runtime. It claims missions in `READY` phase idempotently (never executing a
//! mission twice across a restart), drives each through the native sovereign
//! runtime via [`atom_runtime::Runtime::run_until_terminal`], and records every
//! durable phase transition on the server ledger (`atom_server::Store`).
//!
//! The executor performs **no host side effects**. Effects are only proposed
//! and persisted as `AUTHORIZATION_PENDING`; external mutation is deferred until
//! the external-effect gate is opened. A mission that reaches `Terminal` is
//! sealed with a canonical `atom-mission` outcome; a mission whose run is cut
//! short is honestly marked with a non-success outcome rather than claimed
//! successful.

pub mod executor;
pub mod provider;
pub mod queue;

pub use executor::{AtomExecutor, ExecutorConfig};
pub use provider::{CachedProvider, HttpProposalClient, ProviderConfig, ProviderError, ProviderPlan};
pub use queue::{ClaimOutcome, MissionPhaseTag, MissionQueue, RunResult, TransitionError};
