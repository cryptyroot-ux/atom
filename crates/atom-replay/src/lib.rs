//! atom-replay: replay classes R0-R2 + recorded cassettes; R3/R4 labeled.
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-V4-RPL-001** (P0, v4.0-alpha) — implement R0-R2 replay and label
//!   R3/R4 semantics explicitly. **No universal exact-replay claim is allowed.**
//! * **ATOM-INV-010** — replay cannot re-emit consequential external effects
//!   unless an explicit live-fork policy authorizes a NEW effect identity.
//! * **`spec/enums.yaml`** `replay_class` — R0=STATE_REPLAY, R1=REDUCER_REPLAY,
//!   R2=ACTIVITY_CASSETTE_REPLAY, R3=LIVE_FORK_MODEL_REEXECUTION,
//!   R4=STATISTICAL_REPRODUCTION.
//!
//! This crate builds R0/R1 on `atom-effect`'s pure reducer and trajectory
//! digest, so a replay of a committed log is deterministic by reusing the same
//! semantics the effect kernel commits under. R2 resolves recorded external
//! interactions from a [`Cassette`] and nothing else. R3/R4 are typed labeled
//! refusals, never executed.
//!
//! # The three guarantees
//!
//! 1. **Determinism (R0/R1).** The same committed log replays to the same state
//!    and trajectory digest — the ATOM-V4-RPL-001 verification.
//! 2. **Bounded recording (R2).** A cassette miss is a typed
//!    [`ReplayError::CassetteMiss`]; there is no live-call path and no
//!    fabrication.
//! 3. **No re-emit (INV-010).** [`replay`] re-derives consequential effects but
//!    never re-dispatches them. The only escape is [`live_fork`], which mints a
//!    NEW effect identity — the replayed effect's identity is never reused.
//!
//! # There is no universal exact-replay
//!
//! See [`NO_UNIVERSAL_EXACT_REPLAY`]. R0/R1 are exact only for the *derivable*
//! projection of a committed log; R2 is exact only within its recording; R3/R4
//! make no exact-replay claim at all.
//!
//! ```
//! use atom_effect::{EffectEvent, EffectState};
//! use atom_replay::{replay, ReplayClass, ReplayInput};
//!
//! // A committed log: authorize, revalidate. Replaying it twice is identical.
//! let events = vec![
//!     EffectEvent::AuthorizationRequested,
//!     EffectEvent::authorization_granted("grant/x", 1),
//! ];
//! let input = ReplayInput::new(EffectState::IntentDurable, events);
//!
//! let a = replay(ReplayClass::ReducerReplay, &input).unwrap();
//! let b = replay(ReplayClass::ReducerReplay, &input).unwrap();
//! assert_eq!(a.digest, b.digest);
//! assert!(!a.re_emitted(), "replay never re-emits (INV-010)");
//! ```

#![forbid(unsafe_code)]

mod cassette;
mod class;
mod digest;
mod engine;
mod error;
mod live_fork;

pub use cassette::{Cassette, RecordedResponse};
pub use class::ReplayClass;
pub use engine::{replay, CassetteResolution, ReplayInput, ReplayReport};
pub use error::ReplayError;
pub use live_fork::{live_fork, ForkedEffect, LiveForkPolicy};

/// The crate's explicit non-claim (ATOM-V4-RPL-001).
///
/// Exposed as a constant so a caller — or a test — can assert on the exact
/// wording rather than trusting prose. No code path in this crate promises
/// universal exact replay; each class states its own bounded guarantee via
/// [`ReplayClass::guarantee`].
pub const NO_UNIVERSAL_EXACT_REPLAY: &str = "ATOM makes no universal exact-replay claim: \
R0/R1 are deterministic only over a committed event log's derivable projection, \
R2 is bounded to its recorded cassette, and R3/R4 are labeled and not executed for alpha.";
