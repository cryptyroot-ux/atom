//! The replay engine: R0/R1/R2 execution and the INV-010 no-re-emit guarantee.
//!
//! Replay is read/derive only. [`replay`] takes a committed event log and
//! *re-derives* state from it; it returns a [`ReplayReport`], a value type that
//! carries digests and counts and **nothing that can be dispatched**. There is
//! no code path in this function — or field on its result — that reaches an
//! external connector or emits an effect event under the original identity.
//!
//! Consequential effects in the log are counted (they are re-derived, because
//! state depends on them) but never re-emitted. The only way to act on the
//! world again is [`crate::live_fork`], which mints a NEW effect identity
//! (INV-010, ATOM-RPL-001).

use atom_effect::{try_project, EffectEvent, EffectState};
use sha2::{Digest, Sha256};

use crate::cassette::Cassette;
use crate::class::ReplayClass;
use crate::digest::{component, finish};
use crate::error::ReplayError;

/// Everything a replay derives from. Read-only by construction.
#[derive(Clone, Debug)]
pub struct ReplayInput {
    /// The state the committed log is replayed from.
    pub initial_state: EffectState,
    /// The committed event log, in order.
    pub events: Vec<EffectEvent>,
    /// The recorded external interactions, used only by R2.
    pub cassette: Cassette,
    /// The request digests R2 must resolve, in order. Ignored by R0/R1.
    pub cassette_requests: Vec<String>,
}

impl ReplayInput {
    /// A replay over `events` starting from `initial_state`.
    #[must_use]
    pub fn new(initial_state: EffectState, events: Vec<EffectEvent>) -> Self {
        Self {
            initial_state,
            events,
            cassette: Cassette::new(),
            cassette_requests: Vec::new(),
        }
    }

    /// Attaches the cassette and the request digests R2 will resolve.
    #[must_use]
    pub fn with_cassette(mut self, cassette: Cassette, requests: Vec<String>) -> Self {
        self.cassette = cassette;
        self.cassette_requests = requests;
        self
    }
}

/// A cassette lookup that resolved from the recording (never a live call).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CassetteResolution {
    /// The request that was resolved.
    pub request_digest: String,
    /// The recorded outcome tag that was returned.
    pub outcome: String,
}

/// The result of a replay: derived facts only, nothing dispatchable.
///
/// The absence is the point. There is no field here that names a connector, an
/// outbound request, or a freshly-emitted effect event. [`re_dispatched`] is
/// always empty and [`re_emitted`] is always `false`: a replay cannot, by the
/// shape of its own result, have acted on the world (INV-010).
///
/// [`re_dispatched`]: ReplayReport::re_dispatched
/// [`re_emitted`]: ReplayReport::re_emitted
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayReport {
    /// The class that produced this report (always a supported class).
    pub class: ReplayClass,
    /// The state the committed log projected to.
    pub derived_state: EffectState,
    /// The comparable digest: a state digest for R0, a trajectory digest for
    /// R1, and a trajectory-plus-cassette digest for R2. Deterministic.
    pub digest: String,
    /// How many consequential effects the log dispatched — re-derived, not
    /// re-emitted. This is what INV-010 protects.
    pub consequential_in_log: usize,
    /// The cassette lookups R2 resolved, in order. Empty for R0/R1.
    pub cassette_resolutions: Vec<CassetteResolution>,
    /// Effects re-dispatched by this replay. **Always empty** (INV-010): kept as
    /// a field so the guarantee is visible in the type, not just the prose.
    pub re_dispatched: Vec<String>,
}

impl ReplayReport {
    /// Whether this replay emitted any consequential effect. Always `false`.
    ///
    /// Replay re-derives; it never re-emits. Acting on the world again requires
    /// [`crate::live_fork`], which changes identity (INV-010).
    #[must_use]
    pub fn re_emitted(&self) -> bool {
        !self.re_dispatched.is_empty()
    }
}

/// How many times the log legally arrived in `DISPATCHED`.
///
/// Each such arrival is a consequential external effect that really happened.
/// Replay re-derives them (state depends on them) but emits none of them again.
fn consequential_dispatches(initial: EffectState, events: &[EffectEvent]) -> usize {
    let mut state = initial;
    let mut dispatches = 0;
    for event in events {
        let next = state.try_advance(event).unwrap_or(state);
        if state == EffectState::Dispatching
            && next == EffectState::Dispatched
            && matches!(event, EffectEvent::Dispatched(_))
        {
            dispatches += 1;
        }
        state = next;
    }
    dispatches
}

/// The R0 destination digest: initial and final state, and nothing between.
fn state_replay_digest(initial: EffectState, final_state: EffectState) -> String {
    let mut hasher = Sha256::new();
    component(&mut hasher, "replay-class");
    component(&mut hasher, ReplayClass::StateReplay.code());
    component(&mut hasher, "initial");
    component(&mut hasher, initial.as_str());
    component(&mut hasher, "final");
    component(&mut hasher, final_state.as_str());
    finish(hasher)
}

/// The R2 digest: the R1 trajectory, then every resolved recording, in order.
fn cassette_replay_digest(trajectory: &str, resolutions: &[CassetteResolution]) -> String {
    let mut hasher = Sha256::new();
    component(&mut hasher, "replay-class");
    component(&mut hasher, ReplayClass::ActivityCassetteReplay.code());
    component(&mut hasher, "trajectory");
    component(&mut hasher, trajectory);
    component(&mut hasher, "resolutions");
    for resolution in resolutions {
        component(&mut hasher, &resolution.request_digest);
        component(&mut hasher, &resolution.outcome);
    }
    finish(hasher)
}

/// Replays `input` under `class`, deriving state without ever re-emitting.
///
/// * **R0** projects the committed log to a state digest.
/// * **R1** re-runs the pure reducer to a byte-identical trajectory digest,
///   reusing `atom_effect::trajectory_digest`.
/// * **R2** does R1 and additionally resolves each requested interaction from
///   the cassette — and only from the cassette.
///
/// In every case the returned [`ReplayReport`] re-dispatches nothing (INV-010).
///
/// # Errors
///
/// * [`ReplayError::Unsupported`] for R3/R4 — the typed labeled refusal.
/// * [`ReplayError::Reduce`] if a log presented as committed is off-spec.
/// * [`ReplayError::CassetteMiss`] if R2 requests an unrecorded interaction.
pub fn replay(class: ReplayClass, input: &ReplayInput) -> Result<ReplayReport, ReplayError> {
    if !class.is_supported() {
        return Err(ReplayError::unsupported(class));
    }

    // A committed log must project cleanly; an off-spec event is a divergence,
    // not a silent no-op. This re-derives state without acting.
    let derived_state = try_project(input.initial_state, &input.events)?;
    let consequential_in_log = consequential_dispatches(input.initial_state, &input.events);
    let trajectory = atom_effect::trajectory_digest(input.initial_state, &input.events);

    let (digest, cassette_resolutions) = match class {
        ReplayClass::StateReplay => (
            state_replay_digest(input.initial_state, derived_state),
            Vec::new(),
        ),
        ReplayClass::ReducerReplay => (trajectory, Vec::new()),
        ReplayClass::ActivityCassetteReplay => {
            let mut resolutions = Vec::with_capacity(input.cassette_requests.len());
            for request_digest in &input.cassette_requests {
                // The only external-interaction path R2 has: a cassette lookup.
                // A miss stops replay — it never falls through to a live call.
                let recorded = input.cassette.resolve(request_digest)?;
                resolutions.push(CassetteResolution {
                    request_digest: request_digest.clone(),
                    outcome: recorded.outcome.clone(),
                });
            }
            (
                cassette_replay_digest(&trajectory, &resolutions),
                resolutions,
            )
        }
        // Unreachable: guarded by is_supported above, but exhaustive by design.
        ReplayClass::LiveForkModelReexecution | ReplayClass::StatisticalReproduction => {
            return Err(ReplayError::unsupported(class));
        }
    };

    Ok(ReplayReport {
        class,
        derived_state,
        digest,
        consequential_in_log,
        cassette_resolutions,
        // INV-010: replay re-dispatches nothing, ever.
        re_dispatched: Vec::new(),
    })
}
