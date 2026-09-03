//! Provider-free, deterministic, unprivileged mission orchestration.
//!
//! Cognition only proposes structured actions. The runtime persists observed
//! facts and applies atom-mission and atom-effect reducers afterwards. Host
//! operations cross atom-privd through a typed, permit-bound gateway.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use atom_capability::CapabilityGrant;
use atom_effect::{
    CommitPermit, DurabilityProof, EffectEvent, EffectIntent, EffectState,
    ReduceError as EffectReduceError, ResourceWitness,
};
use atom_ledger::Ledger;
use atom_mission::{
    try_reduce as try_reduce_mission, Activity, ActivityKind, ActivityResult, ActivityResultEvent,
    CommandValidationError, MissionCommand, MissionCondition, MissionEvent, MissionPhase,
    MissionState, ReduceError as MissionReduceError,
};
use atom_privd::{AdmissionRequest, Admitted, DenyReason, HostExecutor, HostOp, PrivilegeBroker};
use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

/// Implementation maturity marker.
pub const CRATE_STAGE: &str = "G1-native-unprivileged-runtime";

/// Injected source of UTC time. The runtime provides no wall-clock source.
pub trait Clock {
    /// Returns the cycle timestamp.
    fn now(&self) -> DateTime<Utc>;
}

impl Clock for DateTime<Utc> {
    fn now(&self) -> DateTime<Utc> {
        *self
    }
}

/// A fixed, injected time source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedClock {
    now: DateTime<Utc>,
}

impl FixedClock {
    /// Creates a fixed clock.
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

/// Injected source of proposal identities.
pub trait RandomSource {
    /// Returns the next deterministic identity.
    fn next_u64(&mut self) -> u64;
}

/// A counter-backed deterministic random source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterRng {
    next: u64,
}

impl CounterRng {
    /// Starts the sequence at seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { next: seed }
    }
}

impl RandomSource for CounterRng {
    fn next_u64(&mut self) -> u64 {
        let value = self.next;
        self.next = self.next.wrapping_add(1);
        value
    }
}

/// An error from an injected unprivileged activity port.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("activity port error: {message}")]
pub struct ActivityError {
    /// Operator-safe explanation.
    pub message: String,
}

impl ActivityError {
    /// Creates an activity error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// A reducer-approved action request.
#[derive(Clone, Copy, Debug)]
pub struct ActionRequest<'a> {
    /// Mission that owns the action.
    pub mission_id: &'a str,
    /// Validated lifecycle activity.
    pub activity: Activity,
    /// Durable consequential intent, if action is effect-gated.
    pub effect: Option<&'a EffectIntent>,
    /// Single injected timestamp for the loop cycle.
    pub at: DateTime<Utc>,
}

/// Facts observed after an action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityObservation {
    /// A non-consequential mission activity result.
    Mission {
        /// Reducer input.
        result: ActivityResult,
        /// Optional durable context.
        reason: Option<String>,
    },
    /// Facts for the effect state machine.
    Effect {
        /// Ordered effect events.
        events: Vec<EffectEvent>,
    },
}

/// Unprivileged action and observation port.
///
/// Any host-administration implementation must use UnprivilegedHostGateway.
/// This trait deliberately has no host handle, shell, filesystem, or process
/// capability.
pub trait ActivityPort {
    /// Starts an action after its intent has become durable.
    fn act(&mut self, request: &ActionRequest<'_>) -> Result<(), ActivityError>;

    /// Returns observed facts for the started action.
    fn observe(
        &mut self,
        request: &ActionRequest<'_>,
    ) -> Result<ActivityObservation, ActivityError>;

    /// Performs a read-only reconciliation of an ambiguous effect.
    fn reconcile(
        &mut self,
        effect: &EffectIntent,
        at: DateTime<Utc>,
    ) -> Result<Vec<EffectEvent>, ActivityError>;
}

/// Built-in provider-free activity port for the VT-007 reference mission.
///
/// It has no host side effects and uses no Hermes or OpenClaw integration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferenceActivityPort {
    activities: Vec<ActivityKind>,
}

impl ReferenceActivityPort {
    /// Returns lifecycle activities requested by the loop.
    #[must_use]
    pub fn activities(&self) -> &[ActivityKind] {
        &self.activities
    }
}

impl ActivityPort for ReferenceActivityPort {
    fn act(&mut self, request: &ActionRequest<'_>) -> Result<(), ActivityError> {
        self.activities.push(request.activity.kind);
        Ok(())
    }

    fn observe(
        &mut self,
        request: &ActionRequest<'_>,
    ) -> Result<ActivityObservation, ActivityError> {
        Ok(ActivityObservation::Mission {
            result: ActivityResult::Succeeded,
            reason: Some(format!(
                "native reference {:?} completed",
                request.activity.kind
            )),
        })
    }

    fn reconcile(
        &mut self,
        _effect: &EffectIntent,
        _at: DateTime<Utc>,
    ) -> Result<Vec<EffectEvent>, ActivityError> {
        Err(ActivityError::new(
            "the reference mission has no consequential effect to reconcile",
        ))
    }
}

/// Nonterminal effect data available to cognition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPerception {
    /// Effect identity.
    pub effect_id: String,
    /// Current reducer state.
    pub state: EffectState,
    /// Whether its declared semantics allow a reconciliation read.
    pub reconcilable: bool,
}

/// Immutable data inspected by cognition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Perception {
    /// Mission identity.
    pub mission_id: String,
    /// Injected observation time.
    pub observed_at: DateTime<Utc>,
    /// Rebuildable mission projection.
    pub mission_state: MissionState,
    /// First nonterminal effect in deterministic effect-id order.
    pub pending_effect: Option<EffectPerception>,
}

/// Structured activity proposal emitted by cognition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityProposal {
    /// Injected deterministic proposal identity.
    pub proposal_id: u64,
    /// Mission command, still validated by the runtime.
    pub command: MissionCommand,
    /// Intent to make durable before action.
    pub effect: Option<EffectIntent>,
}

/// A cognitive decision. No variant mutates authoritative state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Propose an activity.
    Act(Box<ActivityProposal>),
    /// Reconcile an existing ambiguity instead of emitting another action.
    Reconcile {
        /// Proposal identity.
        proposal_id: u64,
        /// Effect to reconcile.
        effect_id: String,
    },
    /// Safely do nothing.
    Hold {
        /// Proposal identity.
        proposal_id: u64,
        /// Reason for holding.
        reason: HoldReason,
    },
}

impl Decision {
    /// Returns the proposal identity.
    #[must_use]
    pub const fn proposal_id(&self) -> u64 {
        match self {
            Self::Act(proposal) => proposal.proposal_id,
            Self::Reconcile { proposal_id, .. } | Self::Hold { proposal_id, .. } => *proposal_id,
        }
    }
}

/// Reasons native cognition holds rather than emits a write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HoldReason {
    /// Terminal missions accept no command.
    Terminal,
    /// A non-normal mission condition needs an external resolution.
    MissionCondition(MissionCondition),
    /// An effect is in flight but not ready for reconciliation.
    EffectInFlight {
        /// Effect identity.
        effect_id: String,
        /// Current state.
        state: EffectState,
    },
    /// The effect's declared semantics cannot settle the ambiguity.
    PermanentUnknown {
        /// Effect identity.
        effect_id: String,
    },
}

/// Provider-agnostic cognition interface.
///
/// Implementations receive no mutable reducer state or host authority.
pub trait Cognition {
    /// Produces a proposal from immutable perception.
    fn decide(&mut self, perception: &Perception, proposal_id: u64) -> Decision;
}

/// Built-in deterministic lifecycle cognition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeCognition {
    effect_bindings: Vec<(ActivityKind, EffectIntent)>,
}

impl NativeCognition {
    /// Creates native cognition with no effect bindings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds one predeclared effect intent to one lifecycle activity.
    #[must_use]
    pub fn with_effect(mut self, activity: ActivityKind, intent: EffectIntent) -> Self {
        if let Some((_, existing)) = self
            .effect_bindings
            .iter_mut()
            .find(|(bound, _)| *bound == activity)
        {
            *existing = intent;
        } else {
            self.effect_bindings.push((activity, intent));
        }
        self
    }

    fn effect_for(&self, activity: ActivityKind) -> Option<EffectIntent> {
        self.effect_bindings
            .iter()
            .find(|(bound, _)| *bound == activity)
            .map(|(_, intent)| intent.clone())
    }
}

impl Cognition for NativeCognition {
    fn decide(&mut self, perception: &Perception, proposal_id: u64) -> Decision {
        if let Some(effect) = &perception.pending_effect {
            if effect.state.blocks_dependents() {
                return if effect.reconcilable {
                    Decision::Reconcile {
                        proposal_id,
                        effect_id: effect.effect_id.clone(),
                    }
                } else {
                    Decision::Hold {
                        proposal_id,
                        reason: HoldReason::PermanentUnknown {
                            effect_id: effect.effect_id.clone(),
                        },
                    }
                };
            }
            return Decision::Hold {
                proposal_id,
                reason: HoldReason::EffectInFlight {
                    effect_id: effect.effect_id.clone(),
                    state: effect.state,
                },
            };
        }

        if perception.mission_state.phase == MissionPhase::Terminal {
            return Decision::Hold {
                proposal_id,
                reason: HoldReason::Terminal,
            };
        }
        if perception.mission_state.condition != MissionCondition::Normal {
            return Decision::Hold {
                proposal_id,
                reason: HoldReason::MissionCondition(perception.mission_state.condition),
            };
        }

        let command = match perception.mission_state.phase {
            MissionPhase::Created => MissionCommand::Compile,
            MissionPhase::Compiled => MissionCommand::Prepare,
            MissionPhase::Ready => MissionCommand::Start,
            MissionPhase::Running => MissionCommand::Execute,
            MissionPhase::Verifying => MissionCommand::Verify,
            MissionPhase::Terminal => unreachable!("terminal state handled above"),
        };
        Decision::Act(Box::new(ActivityProposal {
            proposal_id,
            command,
            effect: self.effect_for(command.activity().kind),
        }))
    }
}

/// An effect tracked after its intent was appended to its own ledger stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedEffect {
    /// Mission activity gated by the effect.
    pub activity: ActivityKind,
    /// Current reducer-derived intent.
    pub intent: EffectIntent,
    /// Ledger-issued proof the intent was appended before dispatch (EFX-001).
    pub durability: DurabilityProof,
}

/// One phase of a cognition cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopPhase {
    /// Read projection.
    Perceive,
    /// Make proposal.
    Decide,
    /// Begin action after durable prerequisites.
    Act,
    /// Persist observed facts then reduce.
    Observe,
}

/// Diagnostic trace of complete loop phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopTrace {
    /// Completed phase.
    pub phase: LoopPhase,
    /// Injected timestamp.
    pub at: DateTime<Utc>,
    /// Proposal identity when applicable.
    pub proposal_id: Option<u64>,
    /// Activity when applicable.
    pub activity: Option<ActivityKind>,
    /// Effect when applicable.
    pub effect_id: Option<String>,
}

/// A started action that awaits observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingAction {
    /// A lifecycle activity.
    Activity {
        /// Proposal identity.
        proposal_id: u64,
        /// Validated activity.
        activity: Activity,
        /// Durable effect identity when any.
        effect_id: Option<String>,
    },
    /// A read-only reconciliation.
    Reconciliation {
        /// Proposal identity.
        proposal_id: u64,
        /// Effect identity.
        effect_id: String,
    },
    /// No action.
    Hold {
        /// Proposal identity.
        proposal_id: u64,
        /// Hold reason.
        reason: HoldReason,
    },
}

/// Result of one perceive-decide-act-observe cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoopStep {
    /// A durable mission event advanced its projection.
    Advanced {
        /// Activity that completed.
        activity: ActivityKind,
        /// New mission projection.
        state: MissionState,
    },
    /// Effect outcome remains unresolved.
    UnknownOutcome {
        /// Effect identity.
        effect_id: String,
    },
    /// Effect has not reached a terminal result.
    EffectPending {
        /// Effect identity.
        effect_id: String,
        /// Current effect state.
        state: EffectState,
    },
    /// Cognition held safely.
    Idle {
        /// Hold reason.
        reason: HoldReason,
    },
    /// Mission was already terminal.
    AlreadyTerminal {
        /// Terminal state.
        state: MissionState,
    },
}

/// Result of bounded loop driving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunStatus {
    /// Terminal reducer state reached.
    Terminal {
        /// Terminal state.
        state: MissionState,
        /// Number of cycles.
        steps: usize,
    },
    /// An effect remains unknown.
    BlockedOnUnknown {
        /// Effect identity.
        effect_id: String,
        /// Current mission state.
        state: MissionState,
    },
    /// An external resolution is required.
    Blocked {
        /// Why progress stopped.
        reason: HoldReason,
        /// Current mission state.
        state: MissionState,
    },
    /// Caller-supplied bound ended before terminal state.
    Exhausted {
        /// Number of cycles.
        steps: usize,
        /// Current mission state.
        state: MissionState,
    },
}

/// Runtime boundary errors.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Mission ledger stream id cannot be blank.
    #[error("mission_id must not be blank")]
    EmptyMissionId,
    /// Cognitive command was not valid for the reducer state.
    #[error("invalid mission command proposal: {0}")]
    InvalidCommand(#[from] CommandValidationError),
    /// Mission reducer rejected an observation.
    #[error("mission reducer rejected observation: {0}")]
    MissionReduce(#[source] MissionReduceError),
    /// Effect belongs to another mission.
    #[error("effect {effect_id} belongs to {actual}, not {expected}")]
    EffectMissionMismatch {
        /// Effect identity.
        effect_id: String,
        /// Actual mission id.
        actual: String,
        /// Runtime mission id.
        expected: String,
    },
    /// Effect ids cannot be reused.
    #[error("effect {effect_id} is already tracked")]
    DuplicateEffect {
        /// Effect identity.
        effect_id: String,
    },
    /// Effect must begin in the durable intent state.
    #[error("effect {effect_id} is {state}, not INTENT_DURABLE")]
    EffectNotFresh {
        /// Effect identity.
        effect_id: String,
        /// Incorrect state.
        state: EffectState,
    },
    /// Named effect is absent.
    #[error("effect {effect_id} is not tracked")]
    UnknownEffect {
        /// Effect identity.
        effect_id: String,
    },
    /// Reconciliation was requested for a non-ambiguous effect.
    #[error("effect {effect_id} is {state}, not unresolved")]
    EffectNotAmbiguous {
        /// Effect identity.
        effect_id: String,
        /// Actual state.
        state: EffectState,
    },
    /// No observed effect event was supplied.
    #[error("effect {effect_id} observation contained no events")]
    EmptyEffectObservation {
        /// Effect identity.
        effect_id: String,
    },
    /// Effect-gated activity tried to bypass effect facts.
    #[error("activity {activity:?} requires an effect observation")]
    EffectObservationRequired {
        /// Activity kind.
        activity: ActivityKind,
    },
    /// Effect facts arrived without a durable intent.
    #[error("activity {activity:?} has no durable effect intent")]
    EffectObservationWithoutIntent {
        /// Activity kind.
        activity: ActivityKind,
    },
    /// Effect reducer rejected an observation.
    #[error("effect {effect_id} reducer rejected observation: {source}")]
    EffectReduce {
        /// Effect identity.
        effect_id: String,
        /// Source reducer error.
        #[source]
        source: EffectReduceError,
    },
    /// The intent's declared payload could not be canonicalised for the ledger.
    #[error("effect {effect_id} declared payload is not canonicalisable: {reason}")]
    EffectPayloadNotCanonicalizable {
        /// Effect identity.
        effect_id: String,
        /// Why canonicalisation failed.
        reason: String,
    },
    /// The durable payload does not match the intent being committed.
    #[error("durable payload for effect {effect_id} does not match intent digest")]
    EffectPayloadMismatch {
        /// Effect identity.
        effect_id: String,
    },
    /// Ledger append failed.
    #[error(transparent)]
    Ledger(#[from] atom_ledger::Error),
    /// JSON conversion for ledger input failed.
    #[error("runtime event serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Port failed.
    #[error(transparent)]
    Activity(#[from] ActivityError),
}

/// Deterministic native runtime.
///
/// C, R, and N make clock, proposal identity source, and cognition explicit.
pub struct Runtime<C, R, N = NativeCognition> {
    mission_id: String,
    state: MissionState,
    ledger: Ledger,
    clock: C,
    random: R,
    cognition: N,
    effects: BTreeMap<String, TrackedEffect>,
    trace: Vec<LoopTrace>,
}

impl<C, R> Runtime<C, R, NativeCognition>
where
    C: Clock,
    R: RandomSource,
{
    /// Creates a native provider-free runtime.
    pub fn native(
        mission_id: impl Into<String>,
        ledger: Ledger,
        clock: C,
        random: R,
    ) -> Result<Self, RuntimeError> {
        Self::new(mission_id, ledger, clock, random, NativeCognition::new())
    }
}

impl<C, R, N> Runtime<C, R, N>
where
    C: Clock,
    R: RandomSource,
    N: Cognition,
{
    /// Creates a runtime at the canonical CREATED state.
    pub fn new(
        mission_id: impl Into<String>,
        ledger: Ledger,
        clock: C,
        random: R,
        cognition: N,
    ) -> Result<Self, RuntimeError> {
        let mission_id = mission_id.into();
        if mission_id.trim().is_empty() {
            return Err(RuntimeError::EmptyMissionId);
        }
        Ok(Self {
            mission_id,
            state: MissionState::created(),
            ledger,
            clock,
            random,
            cognition,
            effects: BTreeMap::new(),
            trace: Vec::new(),
        })
    }

    /// Mission id and mission ledger stream id.
    #[must_use]
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    /// Current mission projection.
    #[must_use]
    pub fn state(&self) -> &MissionState {
        &self.state
    }

    /// Append-only ledger owned by this runtime.
    #[must_use]
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Nonce-burn stream name on the ledger: the single durable store for
    /// one-shot commit permits (ATOM-V4-EFX-004 · durable nonce).
    pub const NONCE_BURN_STREAM: &'static str = "nonce-burns";

    /// The nonces that `ledger` has already recorded as burned, in append order.
    ///
    /// A cold start calls this before opening the commit gate to rehydrate its
    /// one-shot memory, so a restart refuses a permit burned in a prior life.
    #[must_use]
    pub fn burned_nonces_from(ledger: &Ledger) -> Vec<String> {
        let Ok(records) = ledger.scan(Self::NONCE_BURN_STREAM, 0) else {
            return Vec::new();
        };
        records
            .into_iter()
            .filter_map(|record| record.payload.get("nonce")?.as_str().map(ToOwned::to_owned))
            .collect()
    }

    /// Durably records `nonce` as burned on the ledger's nonce-burn stream.
    ///
    /// The one-shot guarantee becomes durable only once this append has
    /// committed: on a crash before it returns, the nonce is not yet persistent
    /// and a restart would legitimately re-serve it (no spurious replay block).
    pub fn burn_nonce(
        &mut self,
        nonce: &str,
        at: DateTime<Utc>,
    ) -> Result<atom_ledger::Event, RuntimeError> {
        let payload = serde_json::json!({ "nonce": nonce });
        Ok(self
            .ledger
            .append(Self::NONCE_BURN_STREAM, &payload, at.timestamp_millis())?)
    }

    /// Returns a tracked effect and its durability witness.
    #[must_use]
    pub fn effect(&self, effect_id: &str) -> Option<&TrackedEffect> {
        self.effects.get(effect_id)
    }

    /// Returns the completed pipeline trace.
    #[must_use]
    pub fn trace(&self) -> &[LoopTrace] {
        &self.trace
    }

    /// Reads reducer projections only.
    #[must_use]
    pub fn perceive(&self, observed_at: DateTime<Utc>) -> Perception {
        let pending_effect = self
            .effects
            .values()
            .find(|effect| !effect.intent.state.is_terminal())
            .map(|effect| EffectPerception {
                effect_id: effect.intent.effect_id.clone(),
                state: effect.intent.state,
                reconcilable: !matches!(
                    effect.intent.reconciliation.class,
                    atom_effect::ReconciliationClass::NotReconcilable
                ),
            });
        Perception {
            mission_id: self.mission_id.clone(),
            observed_at,
            mission_state: self.state.clone(),
            pending_effect,
        }
    }

    /// Requests a proposal from cognition without applying a reducer.
    pub fn decide(&mut self, perception: &Perception) -> Decision {
        let proposal_id = self.random.next_u64();
        let decision = self.cognition.decide(perception, proposal_id);
        self.trace.push(LoopTrace {
            phase: LoopPhase::Decide,
            at: perception.observed_at,
            proposal_id: Some(proposal_id),
            activity: decision_activity(&decision),
            effect_id: decision_effect_id(&decision),
        });
        decision
    }

    /// Validates and starts a proposal after making any effect intent durable.
    pub fn act<P: ActivityPort>(
        &mut self,
        decision: Decision,
        port: &mut P,
        at: DateTime<Utc>,
    ) -> Result<PendingAction, RuntimeError> {
        match decision {
            Decision::Act(proposal) => {
                let activity = proposal.command.validate(&self.state)?;
                let effect_id = match proposal.effect {
                    Some(intent) => Some(self.persist_effect_intent(activity.kind, intent, at)?),
                    None => None,
                };
                self.record_action(
                    proposal.proposal_id,
                    Some(activity.kind),
                    effect_id.clone(),
                    false,
                    at,
                )?;
                self.trace.push(LoopTrace {
                    phase: LoopPhase::Act,
                    at,
                    proposal_id: Some(proposal.proposal_id),
                    activity: Some(activity.kind),
                    effect_id: effect_id.clone(),
                });
                let request = ActionRequest {
                    mission_id: &self.mission_id,
                    activity,
                    effect: effect_id
                        .as_deref()
                        .and_then(|id| self.effects.get(id))
                        .map(|effect| &effect.intent),
                    at,
                };
                port.act(&request)?;
                Ok(PendingAction::Activity {
                    proposal_id: proposal.proposal_id,
                    activity,
                    effect_id,
                })
            }
            Decision::Reconcile {
                proposal_id,
                effect_id,
            } => {
                let effect =
                    self.effects
                        .get(&effect_id)
                        .ok_or_else(|| RuntimeError::UnknownEffect {
                            effect_id: effect_id.clone(),
                        })?;
                if !effect.intent.state.blocks_dependents() {
                    return Err(RuntimeError::EffectNotAmbiguous {
                        effect_id,
                        state: effect.intent.state,
                    });
                }
                let activity = effect.activity;
                self.record_action(
                    proposal_id,
                    Some(activity),
                    Some(effect_id.clone()),
                    true,
                    at,
                )?;
                self.trace.push(LoopTrace {
                    phase: LoopPhase::Act,
                    at,
                    proposal_id: Some(proposal_id),
                    activity: Some(activity),
                    effect_id: Some(effect_id.clone()),
                });
                Ok(PendingAction::Reconciliation {
                    proposal_id,
                    effect_id,
                })
            }
            Decision::Hold {
                proposal_id,
                reason,
            } => {
                self.trace.push(LoopTrace {
                    phase: LoopPhase::Act,
                    at,
                    proposal_id: Some(proposal_id),
                    activity: None,
                    effect_id: None,
                });
                Ok(PendingAction::Hold {
                    proposal_id,
                    reason,
                })
            }
        }
    }

    /// Persists observed facts and only then updates reducer projections.
    pub fn observe<P: ActivityPort>(
        &mut self,
        pending: PendingAction,
        port: &mut P,
        at: DateTime<Utc>,
    ) -> Result<LoopStep, RuntimeError> {
        match pending {
            PendingAction::Activity {
                proposal_id,
                activity,
                effect_id,
            } => {
                let request = ActionRequest {
                    mission_id: &self.mission_id,
                    activity,
                    effect: effect_id
                        .as_deref()
                        .and_then(|id| self.effects.get(id))
                        .map(|effect| &effect.intent),
                    at,
                };
                let observation = port.observe(&request)?;
                self.trace.push(LoopTrace {
                    phase: LoopPhase::Observe,
                    at,
                    proposal_id: Some(proposal_id),
                    activity: Some(activity.kind),
                    effect_id: effect_id.clone(),
                });
                match (effect_id, observation) {
                    (None, ActivityObservation::Mission { result, reason }) => {
                        self.apply_mission_result(activity.kind, result, reason, at)
                    }
                    (Some(_), ActivityObservation::Mission { .. }) => {
                        Err(RuntimeError::EffectObservationRequired {
                            activity: activity.kind,
                        })
                    }
                    (None, ActivityObservation::Effect { .. }) => {
                        Err(RuntimeError::EffectObservationWithoutIntent {
                            activity: activity.kind,
                        })
                    }
                    (Some(effect_id), ActivityObservation::Effect { events }) => {
                        self.observe_effect(&effect_id, events, at)
                    }
                }
            }
            PendingAction::Reconciliation {
                proposal_id,
                effect_id,
            } => {
                let effect = self
                    .effects
                    .get(&effect_id)
                    .ok_or_else(|| RuntimeError::UnknownEffect {
                        effect_id: effect_id.clone(),
                    })?
                    .intent
                    .clone();
                let activity = self.effects.get(&effect_id).map(|tracked| tracked.activity);
                let events = port.reconcile(&effect, at)?;
                self.trace.push(LoopTrace {
                    phase: LoopPhase::Observe,
                    at,
                    proposal_id: Some(proposal_id),
                    activity,
                    effect_id: Some(effect_id.clone()),
                });
                self.observe_effect(&effect_id, events, at)
            }
            PendingAction::Hold {
                proposal_id,
                reason,
            } => {
                self.trace.push(LoopTrace {
                    phase: LoopPhase::Observe,
                    at,
                    proposal_id: Some(proposal_id),
                    activity: None,
                    effect_id: None,
                });
                if self.state.phase == MissionPhase::Terminal {
                    Ok(LoopStep::AlreadyTerminal {
                        state: self.state.clone(),
                    })
                } else {
                    Ok(LoopStep::Idle { reason })
                }
            }
        }
    }

    /// Runs one perceive-decide-act-observe cycle using one injected timestamp.
    pub fn tick<P: ActivityPort>(&mut self, port: &mut P) -> Result<LoopStep, RuntimeError> {
        let at = self.clock.now();
        let perception = self.perceive(at);
        self.record_perception(&perception)?;
        self.trace.push(LoopTrace {
            phase: LoopPhase::Perceive,
            at,
            proposal_id: None,
            activity: None,
            effect_id: perception
                .pending_effect
                .as_ref()
                .map(|effect| effect.effect_id.clone()),
        });
        let decision = self.decide(&perception);
        self.record_decision(&decision, at)?;
        let pending = self.act(decision, port, at)?;
        self.observe(pending, port, at)
    }

    /// Drives until terminal, unknown, safe hold, or caller-supplied bound.
    pub fn run_until_terminal<P: ActivityPort>(
        &mut self,
        port: &mut P,
        max_steps: usize,
    ) -> Result<RunStatus, RuntimeError> {
        let mut steps = 0;
        while steps < max_steps {
            if self.state.phase == MissionPhase::Terminal {
                return Ok(RunStatus::Terminal {
                    state: self.state.clone(),
                    steps,
                });
            }
            match self.tick(port)? {
                LoopStep::Advanced { .. } => steps += 1,
                LoopStep::UnknownOutcome { effect_id } => {
                    return Ok(RunStatus::BlockedOnUnknown {
                        effect_id,
                        state: self.state.clone(),
                    });
                }
                LoopStep::EffectPending { effect_id, state } => {
                    return Ok(RunStatus::Blocked {
                        reason: HoldReason::EffectInFlight { effect_id, state },
                        state: self.state.clone(),
                    });
                }
                LoopStep::Idle { reason } => {
                    return Ok(RunStatus::Blocked {
                        reason,
                        state: self.state.clone(),
                    });
                }
                LoopStep::AlreadyTerminal { state } => {
                    return Ok(RunStatus::Terminal { state, steps });
                }
            }
        }
        if self.state.phase == MissionPhase::Terminal {
            Ok(RunStatus::Terminal {
                state: self.state.clone(),
                steps,
            })
        } else {
            Ok(RunStatus::Exhausted {
                steps,
                state: self.state.clone(),
            })
        }
    }

    fn persist_effect_intent(
        &mut self,
        activity: ActivityKind,
        intent: EffectIntent,
        at: DateTime<Utc>,
    ) -> Result<String, RuntimeError> {
        if intent.mission_id != self.mission_id {
            return Err(RuntimeError::EffectMissionMismatch {
                effect_id: intent.effect_id,
                actual: intent.mission_id,
                expected: self.mission_id.clone(),
            });
        }
        if intent.state != EffectState::IntentDurable {
            return Err(RuntimeError::EffectNotFresh {
                effect_id: intent.effect_id,
                state: intent.state,
            });
        }
        let effect_id = intent.effect_id.clone();
        if self.effects.contains_key(&effect_id) {
            return Err(RuntimeError::DuplicateEffect { effect_id });
        }

        // The intent's declared payload is appended to its own ledger stream
        // (named for the effect id) and the ledger itself seals the durability
        // proof. Only the ledger can mint one, so nothing downstream can forge
        // durable-before-dispatch. The declared payload holds the caller's
        // declaration only — identity fields, no lifecycle position — so it is
        // byte-stable and the proof still binds when the effect reaches the
        // commit boundary (EFX-001, ATOM-INV-004).
        let payload = intent.declared_payload().map_err(|error| {
            RuntimeError::EffectPayloadNotCanonicalizable {
                effect_id: effect_id.clone(),
                reason: error.to_string(),
            }
        })?;
        let (_event, durability) =
            self.ledger
                .append_durable(&effect_id, &payload, at.timestamp_millis())?;
        self.effects.insert(
            effect_id.clone(),
            TrackedEffect {
                activity,
                intent,
                durability,
            },
        );
        Ok(effect_id)
    }

    fn observe_effect(
        &mut self,
        effect_id: &str,
        events: Vec<EffectEvent>,
        at: DateTime<Utc>,
    ) -> Result<LoopStep, RuntimeError> {
        if events.is_empty() {
            return Err(RuntimeError::EmptyEffectObservation {
                effect_id: effect_id.to_owned(),
            });
        }
        for event in events {
            self.advance_effect(effect_id, event, at)?;
        }
        let tracked = self
            .effects
            .get(effect_id)
            .ok_or_else(|| RuntimeError::UnknownEffect {
                effect_id: effect_id.to_owned(),
            })?;
        let state = tracked.intent.state;
        if matches!(
            state,
            EffectState::UnknownOutcome | EffectState::Reconciling
        ) {
            return Ok(LoopStep::UnknownOutcome {
                effect_id: effect_id.to_owned(),
            });
        }
        if let Some(result) = mission_result_for_effect(state) {
            return self.apply_mission_result(tracked.activity, result, None, at);
        }
        Ok(LoopStep::EffectPending {
            effect_id: effect_id.to_owned(),
            state,
        })
    }

    fn advance_effect(
        &mut self,
        effect_id: &str,
        event: EffectEvent,
        at: DateTime<Utc>,
    ) -> Result<(), RuntimeError> {
        let next = self
            .effects
            .get(effect_id)
            .ok_or_else(|| RuntimeError::UnknownEffect {
                effect_id: effect_id.to_owned(),
            })?
            .intent
            .try_advance(&event)
            .map_err(|source| RuntimeError::EffectReduce {
                effect_id: effect_id.to_owned(),
                source,
            })?;

        // Preflight the pure reducer first, append the observed fact, then
        // replace the in-memory projection. This preserves durable-first order.
        self.append_event(
            effect_id,
            RuntimeLedgerEvent::EffectObserved {
                effect_id: effect_id.to_owned(),
                event,
            },
            at,
        )?;
        self.effects
            .get_mut(effect_id)
            .expect("effect remains present during single-threaded reduction")
            .intent = next;
        Ok(())
    }

    fn apply_mission_result(
        &mut self,
        activity: ActivityKind,
        result: ActivityResult,
        reason: Option<String>,
        at: DateTime<Utc>,
    ) -> Result<LoopStep, RuntimeError> {
        let event = MissionEvent::from(ActivityResultEvent::new(activity, result, reason));
        let next = try_reduce_mission(&self.state, &event).map_err(RuntimeError::MissionReduce)?;
        let stream_id = self.mission_id.clone();
        self.append_event(
            &stream_id,
            RuntimeLedgerEvent::MissionObserved {
                event: event.clone(),
            },
            at,
        )?;
        self.state = next.clone();
        Ok(LoopStep::Advanced {
            activity,
            state: next,
        })
    }

    fn record_perception(&mut self, perception: &Perception) -> Result<(), RuntimeError> {
        let stream_id = self.mission_id.clone();
        self.append_event(
            &stream_id,
            RuntimeLedgerEvent::Perceived {
                observed_at: perception.observed_at,
                state: perception.mission_state.clone(),
                pending_effect: perception
                    .pending_effect
                    .as_ref()
                    .map(|effect| effect.effect_id.clone()),
            },
            perception.observed_at,
        )?;
        Ok(())
    }

    fn record_decision(
        &mut self,
        decision: &Decision,
        at: DateTime<Utc>,
    ) -> Result<(), RuntimeError> {
        let stream_id = self.mission_id.clone();
        self.append_event(
            &stream_id,
            RuntimeLedgerEvent::Decided {
                proposal_id: decision.proposal_id(),
                kind: decision_kind(decision).to_owned(),
                activity: decision_activity(decision),
                effect_id: decision_effect_id(decision),
            },
            at,
        )?;
        Ok(())
    }

    fn record_action(
        &mut self,
        proposal_id: u64,
        activity: Option<ActivityKind>,
        effect_id: Option<String>,
        reconciliation: bool,
        at: DateTime<Utc>,
    ) -> Result<(), RuntimeError> {
        let stream_id = self.mission_id.clone();
        self.append_event(
            &stream_id,
            RuntimeLedgerEvent::ActionStarted {
                proposal_id,
                activity,
                effect_id,
                reconciliation,
            },
            at,
        )?;
        Ok(())
    }

    /// Appends `event` to `stream_id`.
    ///
    /// The intent append is handled by [`Runtime::submit_effect`], which writes
    /// the intent's declared payload through the ledger's durable path so it can
    /// seal a proof no downstream code could have forged (EFX-001).
    fn append_event(
        &mut self,
        stream_id: &str,
        event: RuntimeLedgerEvent,
        at: DateTime<Utc>,
    ) -> Result<atom_ledger::Event, RuntimeError> {
        let payload = serde_json::to_value(event)?;
        Ok(self
            .ledger
            .append(stream_id, &payload, at.timestamp_millis())?)
    }
}

fn mission_result_for_effect(state: EffectState) -> Option<ActivityResult> {
    match state {
        EffectState::ConfirmedSuccess => Some(ActivityResult::Succeeded),
        EffectState::ConfirmedFailure
        | EffectState::Compensated
        | EffectState::CompensationFailed => Some(ActivityResult::Failed),
        EffectState::CancelledBeforeEffect => Some(ActivityResult::Cancelled),
        EffectState::IntentDurable
        | EffectState::AuthorizationPending
        | EffectState::Authorized
        | EffectState::CommitRevalidating
        | EffectState::Dispatching
        | EffectState::Dispatched
        | EffectState::Observing
        | EffectState::UnknownOutcome
        | EffectState::Reconciling
        | EffectState::Partial
        | EffectState::Compensating => None,
    }
}

fn decision_activity(decision: &Decision) -> Option<ActivityKind> {
    match decision {
        Decision::Act(proposal) => Some(proposal.command.activity().kind),
        Decision::Reconcile { .. } | Decision::Hold { .. } => None,
    }
}

fn decision_effect_id(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Act(proposal) => proposal
            .effect
            .as_ref()
            .map(|effect| effect.effect_id.clone()),
        Decision::Reconcile { effect_id, .. } => Some(effect_id.clone()),
        Decision::Hold { .. } => None,
    }
}

fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Act(_) => "ACT",
        Decision::Reconcile { .. } => "RECONCILE",
        Decision::Hold { .. } => "HOLD",
    }
}

/// Permit-bound typed request to atom-privd.
#[derive(Clone, Debug)]
pub struct HostOperationRequest<'a> {
    /// Closed typed host operation.
    pub op: &'a HostOp,
    /// Valid one-shot permit expected by atom-privd.
    pub permit: &'a CommitPermit,
    /// Durable effect at the commit boundary.
    pub intent: &'a EffectIntent,
    /// Current capability grant.
    pub grant: &'a CapabilityGrant,
    /// Current resource witness.
    pub observed_witness: &'a ResourceWitness,
    /// Injected crossing time.
    pub now: DateTime<Utc>,
    /// The sink this permit is bound to.
    pub dispatch_sink_id: &'a str,
    /// The connector identity presenting the permit.
    pub connector_identity: &'a str,
    /// The connector version presenting the permit.
    pub connector_version: &'a str,
    /// The connector instance epoch.
    pub connector_instance_epoch: u64,
}

/// Client interface to atom-privd.
pub trait PrivdClient {
    /// Requests one permit-gated host crossing.
    fn admit(&mut self, request: HostOperationRequest<'_>) -> Result<Admitted, DenyReason>;
}

/// Embedded adapter for atom-privd's real permit gate.
impl<E: HostExecutor> PrivdClient for PrivilegeBroker<E> {
    fn admit(&mut self, request: HostOperationRequest<'_>) -> Result<Admitted, DenyReason> {
        PrivilegeBroker::admit(
            self,
            AdmissionRequest {
                op: request.op,
                permit: request.permit,
                intent: request.intent,
                grant: request.grant,
                observed_witness: request.observed_witness,
                now: request.now,
                dispatch_sink_id: request.dispatch_sink_id,
                connector_identity: request.connector_identity,
                connector_version: request.connector_version,
                connector_instance_epoch: request.connector_instance_epoch,
            },
        )
    }
}

/// Unprivileged facade over a privileged daemon client.
///
/// It contains no host executor and has only one operation: forwarding a typed
/// operation and valid permit to atom-privd.
pub struct UnprivilegedHostGateway<P> {
    client: P,
}

impl<P> UnprivilegedHostGateway<P> {
    /// Creates an unprivileged facade.
    #[must_use]
    pub fn new(client: P) -> Self {
        Self { client }
    }

    /// Read-only access to the client for inspection.
    #[must_use]
    pub fn client(&self) -> &P {
        &self.client
    }
}

impl<P: PrivdClient> UnprivilegedHostGateway<P> {
    /// Forwards the request to atom-privd. It never executes the operation.
    pub fn submit(&mut self, request: HostOperationRequest<'_>) -> Result<Admitted, DenyReason> {
        self.client.admit(request)
    }
}

#[derive(Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
enum RuntimeLedgerEvent {
    Perceived {
        observed_at: DateTime<Utc>,
        state: MissionState,
        pending_effect: Option<String>,
    },
    Decided {
        proposal_id: u64,
        kind: String,
        activity: Option<ActivityKind>,
        effect_id: Option<String>,
    },
    ActionStarted {
        proposal_id: u64,
        activity: Option<ActivityKind>,
        effect_id: Option<String>,
        reconciliation: bool,
    },
    EffectObserved {
        effect_id: String,
        event: EffectEvent,
    },
    MissionObserved {
        event: MissionEvent,
    },
}
