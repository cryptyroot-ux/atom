//! Durable mission specifications and deterministic mission-state reduction.
//!
//! Mission state is authoritative only when derived from durable
//! [`MissionEvent`] values. Commands may be validated into [`Activity`] values,
//! but [`reduce`] deliberately accepts neither commands nor model output.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use jsonschema::{Draft, JSONSchema};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical state schema embedded from the authoritative `spec/` directory.
pub const MISSION_STATE_SCHEMA: &str =
    include_str!("../../../spec/schemas/mission-state.schema.json");

/// Canonical mission phase from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionPhase {
    Created,
    Compiled,
    Ready,
    Running,
    Verifying,
    Terminal,
}

impl MissionPhase {
    /// Canonical wire representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Compiled => "COMPILED",
            Self::Ready => "READY",
            Self::Running => "RUNNING",
            Self::Verifying => "VERIFYING",
            Self::Terminal => "TERMINAL",
        }
    }
}

/// Canonical mission condition from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionCondition {
    Normal,
    Waiting,
    ApprovalRequired,
    Paused,
    Degraded,
    Blocked,
}

impl MissionCondition {
    /// Canonical wire representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Waiting => "WAITING",
            Self::ApprovalRequired => "APPROVAL_REQUIRED",
            Self::Paused => "PAUSED",
            Self::Degraded => "DEGRADED",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// Canonical terminal outcome from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionOutcome {
    Succeeded,
    Failed,
    Cancelled,
    Unsatisfiable,
    Rejected,
}

impl MissionOutcome {
    /// Canonical wire representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Unsatisfiable => "UNSATISFIABLE",
            Self::Rejected => "REJECTED",
        }
    }
}

/// Short aliases for consumers using the canonical three-axis terminology.
pub type Phase = MissionPhase;
/// Short aliases for consumers using the canonical three-axis terminology.
pub type Condition = MissionCondition;
/// Short aliases for consumers using the canonical three-axis terminology.
pub type Outcome = MissionOutcome;

/// A validated projection of the canonical phase/condition/outcome state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionState {
    pub phase: MissionPhase,
    pub condition: MissionCondition,
    /// Present if and only if phase is [`MissionPhase::Terminal`].
    pub outcome: Option<MissionOutcome>,
    pub reason: Option<String>,
}

impl MissionState {
    /// Creates a new mission's initial state.
    #[must_use]
    pub fn created() -> Self {
        Self {
            phase: MissionPhase::Created,
            condition: MissionCondition::Normal,
            outcome: None,
            reason: None,
        }
    }

    /// Creates a state after enforcing all cross-axis rules.
    pub fn new(
        phase: MissionPhase,
        condition: MissionCondition,
        outcome: Option<MissionOutcome>,
        reason: Option<String>,
    ) -> Result<Self, MissionStateError> {
        let state = Self {
            phase,
            condition,
            outcome,
            reason,
        };
        state.validate()?;
        Ok(state)
    }

    /// Enforces `TERMINAL ⇔ outcome` from the canonical state machine.
    pub fn validate(&self) -> Result<(), MissionStateError> {
        match (self.phase, self.outcome) {
            (MissionPhase::Terminal, None) => Err(MissionStateError::TerminalOutcomeMissing),
            (MissionPhase::Terminal, Some(_)) | (_, None) => Ok(()),
            (_, Some(_)) => Err(MissionStateError::OutcomeBeforeTerminal),
        }
    }

    /// Parses JSON after validation against `spec/schemas/mission-state.schema.json`.
    pub fn from_json(input: &str) -> Result<Self, MissionStateError> {
        let value: Value = serde_json::from_str(input)
            .map_err(|error| MissionStateError::InvalidJson(error.to_string()))?;
        validate_state_schema(&value)?;
        serde_json::from_value(value)
            .map_err(|error| MissionStateError::InvalidJson(error.to_string()))
    }

    /// Returns a stable SHA-256 digest of this canonical state.
    #[must_use]
    pub fn digest(&self) -> String {
        state_digest(self)
    }
}

impl<'de> Deserialize<'de> for MissionState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireState {
            phase: MissionPhase,
            condition: MissionCondition,
            outcome: Option<MissionOutcome>,
            reason: Option<String>,
        }

        let wire = WireState::deserialize(deserializer)?;
        Self::new(wire.phase, wire.condition, wire.outcome, wire.reason).map_err(D::Error::custom)
    }
}

/// Errors reported while parsing or validating mission state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionStateError {
    #[error("TERMINAL mission state requires a non-null outcome")]
    TerminalOutcomeMissing,
    #[error("outcome must be null unless the mission phase is TERMINAL")]
    OutcomeBeforeTerminal,
    #[error("invalid mission-state JSON: {0}")]
    InvalidJson(String),
    #[error("mission state violates spec/schemas/mission-state.schema.json: {0}")]
    SchemaViolation(String),
}

/// The durable objective primitive required by MSN-001.
///
/// Ledger stream identity, sequence, and hashing remain owned by atom-ledger;
/// this payload defines the durable objective contract within that stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionSpec {
    pub goal: String,
    pub success_criteria: Vec<String>,
    pub constraints: Vec<String>,
    /// Named positive limits, such as `max_steps` or `max_cost_micros`.
    pub budgets: BTreeMap<String, u64>,
    pub authority_profile_ref: String,
    pub evidence_requirements: Vec<String>,
    pub stopping_rules: Vec<String>,
}

impl MissionSpec {
    /// Builds a complete, validated mission specification.
    pub fn new(
        goal: String,
        success_criteria: Vec<String>,
        constraints: Vec<String>,
        budgets: BTreeMap<String, u64>,
        authority_profile_ref: String,
        evidence_requirements: Vec<String>,
        stopping_rules: Vec<String>,
    ) -> Result<Self, MissionSpecError> {
        let spec = Self {
            goal,
            success_criteria,
            constraints,
            budgets,
            authority_profile_ref,
            evidence_requirements,
            stopping_rules,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validates the required durable-objective fields.
    pub fn validate(&self) -> Result<(), MissionSpecError> {
        validate_non_blank("goal", &self.goal)?;
        validate_entries("success_criteria", &self.success_criteria, true)?;
        validate_entries("constraints", &self.constraints, false)?;
        if self.budgets.is_empty() {
            return Err(MissionSpecError::EmptyCollection { field: "budgets" });
        }
        for (name, value) in &self.budgets {
            if name.trim().is_empty() {
                return Err(MissionSpecError::BlankBudgetName);
            }
            if *value == 0 {
                return Err(MissionSpecError::ZeroBudget { name: name.clone() });
            }
        }
        validate_non_blank("authority_profile_ref", &self.authority_profile_ref)?;
        validate_entries("evidence_requirements", &self.evidence_requirements, false)?;
        validate_entries("stopping_rules", &self.stopping_rules, false)?;
        Ok(())
    }

    /// Parses a complete mission specification, rejecting missing and extra fields.
    pub fn from_json(input: &str) -> Result<Self, MissionSpecError> {
        serde_json::from_str(input)
            .map_err(|error| MissionSpecError::InvalidJson(error.to_string()))
    }
}

impl<'de> Deserialize<'de> for MissionSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSpec {
            goal: String,
            success_criteria: Vec<String>,
            constraints: Vec<String>,
            budgets: BTreeMap<String, u64>,
            authority_profile_ref: String,
            evidence_requirements: Vec<String>,
            stopping_rules: Vec<String>,
        }

        let wire = WireSpec::deserialize(deserializer)?;
        Self::new(
            wire.goal,
            wire.success_criteria,
            wire.constraints,
            wire.budgets,
            wire.authority_profile_ref,
            wire.evidence_requirements,
            wire.stopping_rules,
        )
        .map_err(D::Error::custom)
    }
}

/// Errors reported while validating a [`MissionSpec`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionSpecError {
    #[error("{field} must not be blank")]
    BlankField { field: &'static str },
    #[error("{field} must contain at least one item")]
    EmptyCollection { field: &'static str },
    #[error("{field}[{index}] must not be blank")]
    BlankEntry { field: &'static str, index: usize },
    #[error("budget names must not be blank")]
    BlankBudgetName,
    #[error("budget `{name}` must be greater than zero")]
    ZeroBudget { name: String },
    #[error("invalid mission-spec JSON: {0}")]
    InvalidJson(String),
}

/// A command that can be validated into a deterministic activity request.
/// Commands are deliberately not valid reducer inputs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionCommand {
    Compile,
    Prepare,
    Start,
    Execute,
    Verify,
}

impl MissionCommand {
    /// Returns the external activity this command requests.
    #[must_use]
    pub const fn activity(self) -> Activity {
        Activity {
            kind: match self {
                Self::Compile => ActivityKind::Compile,
                Self::Prepare => ActivityKind::Prepare,
                Self::Start => ActivityKind::Start,
                Self::Execute => ActivityKind::Execute,
                Self::Verify => ActivityKind::Verify,
            },
        }
    }

    /// Ensures the command is legal for the current lifecycle phase.
    pub fn validate(self, state: &MissionState) -> Result<Activity, CommandValidationError> {
        state
            .validate()
            .map_err(CommandValidationError::InvalidState)?;
        if state.phase == MissionPhase::Terminal {
            return Err(CommandValidationError::TerminalMission);
        }

        let activity = self.activity();
        let expected = activity.kind.expected_phase();
        if state.phase != expected {
            return Err(CommandValidationError::UnexpectedPhase {
                command: self,
                expected,
                actual: state.phase,
            });
        }
        Ok(activity)
    }
}

/// A deterministic request to perform work outside the reducer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Activity {
    pub kind: ActivityKind,
}

/// External activity types understood by the mission lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivityKind {
    Compile,
    Prepare,
    Start,
    Execute,
    Verify,
}

impl ActivityKind {
    /// The phase in which this activity may successfully complete.
    pub const fn expected_phase(self) -> MissionPhase {
        match self {
            Self::Compile => MissionPhase::Created,
            Self::Prepare => MissionPhase::Compiled,
            Self::Start => MissionPhase::Ready,
            Self::Execute => MissionPhase::Running,
            Self::Verify => MissionPhase::Verifying,
        }
    }
}

/// Error raised by command validation before dispatch.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CommandValidationError {
    #[error("cannot validate command against invalid mission state: {0}")]
    InvalidState(MissionStateError),
    #[error("cannot validate a command for a terminal mission")]
    TerminalMission,
    #[error("{command:?} requires phase {expected:?}, but mission is in {actual:?}")]
    UnexpectedPhase {
        command: MissionCommand,
        expected: MissionPhase,
        actual: MissionPhase,
    },
}

/// Durable observation emitted by a completed nondeterministic activity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivityResult {
    Succeeded,
    Failed,
    Cancelled,
    Unsatisfiable,
    Rejected,
    Waiting,
    ApprovalRequired,
    Paused,
    Degraded,
    Blocked,
}

/// Payload persisted in the ledger before it is given to the reducer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityResultEvent {
    pub activity: ActivityKind,
    pub result: ActivityResult,
    pub reason: Option<String>,
}

impl ActivityResultEvent {
    /// Builds a success result for an activity.
    #[must_use]
    pub const fn succeeded(activity: ActivityKind) -> Self {
        Self {
            activity,
            result: ActivityResult::Succeeded,
            reason: None,
        }
    }

    /// Builds a result with optional durable context.
    #[must_use]
    pub fn new(activity: ActivityKind, result: ActivityResult, reason: Option<String>) -> Self {
        Self {
            activity,
            result,
            reason,
        }
    }
}

/// The only input accepted by the authoritative state reducer.
///
/// The atom-ledger envelope owns event sequence and hashes. This payload must
/// be made durable in that envelope before it is passed to [`reduce`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionEvent {
    ActivityResult(ActivityResultEvent),
}

impl From<ActivityResultEvent> for MissionEvent {
    fn from(event: ActivityResultEvent) -> Self {
        Self::ActivityResult(event)
    }
}

/// Error reported for an invalid state/event transition.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReduceError {
    #[error("invalid input mission state: {0}")]
    InvalidState(MissionStateError),
    #[error("terminal missions cannot accept further activity results")]
    TerminalMission,
    #[error("successful {activity:?} activity is not valid while mission phase is {phase:?}")]
    UnexpectedSuccessfulActivity {
        activity: ActivityKind,
        phase: MissionPhase,
    },
}

/// Applies one durable event to an authoritative state projection.
///
/// This is pure: it only reads its arguments and never accesses a clock,
/// randomness, HTTP, I/O, or a model provider.
pub fn try_reduce(state: &MissionState, event: &MissionEvent) -> Result<MissionState, ReduceError> {
    state.validate().map_err(ReduceError::InvalidState)?;
    if state.phase == MissionPhase::Terminal {
        return Err(ReduceError::TerminalMission);
    }
    match event {
        MissionEvent::ActivityResult(event) => reduce_activity_result(state, event),
    }
}

/// Total reducer used for deterministic replay.
///
/// Invalid transition pairs are explicitly returned by [`try_reduce`]; this
/// projection helper leaves state unchanged for such pairs so replay remains
/// total and deterministic.
#[must_use]
pub fn reduce(state: &MissionState, event: &MissionEvent) -> MissionState {
    try_reduce(state, event).unwrap_or_else(|_| state.clone())
}

/// Projects a durable event log from an explicit initial state.
#[must_use]
pub fn project(initial: MissionState, events: &[MissionEvent]) -> MissionState {
    events
        .iter()
        .fold(initial, |state, event| reduce(&state, event))
}

/// Projects a durable event log while rejecting an invalid transition.
pub fn try_project(
    initial: MissionState,
    events: &[MissionEvent],
) -> Result<MissionState, ReduceError> {
    events
        .iter()
        .try_fold(initial, |state, event| try_reduce(&state, event))
}

/// Stable SHA-256 digest used to assert identical replay state.
#[must_use]
pub fn state_digest(state: &MissionState) -> String {
    let mut hasher = Sha256::new();
    digest_component(&mut hasher, "phase");
    digest_component(&mut hasher, state.phase.as_str());
    digest_component(&mut hasher, "condition");
    digest_component(&mut hasher, state.condition.as_str());
    digest_component(&mut hasher, "outcome");
    match state.outcome {
        Some(outcome) => digest_component(&mut hasher, outcome.as_str()),
        None => digest_component(&mut hasher, "<null>"),
    }
    digest_component(&mut hasher, "reason");
    match &state.reason {
        Some(reason) => digest_component(&mut hasher, reason),
        None => digest_component(&mut hasher, "<null>"),
    }
    format!("{:x}", hasher.finalize())
}

fn reduce_activity_result(
    state: &MissionState,
    event: &ActivityResultEvent,
) -> Result<MissionState, ReduceError> {
    match event.result {
        ActivityResult::Succeeded => reduce_success(state, event),
        ActivityResult::Failed => terminal_state(MissionOutcome::Failed, event.reason.clone()),
        ActivityResult::Cancelled => {
            terminal_state(MissionOutcome::Cancelled, event.reason.clone())
        }
        ActivityResult::Unsatisfiable => {
            terminal_state(MissionOutcome::Unsatisfiable, event.reason.clone())
        }
        ActivityResult::Rejected => terminal_state(MissionOutcome::Rejected, event.reason.clone()),
        ActivityResult::Waiting => {
            condition_state(state, MissionCondition::Waiting, event.reason.clone())
        }
        ActivityResult::ApprovalRequired => {
            if event.activity == ActivityKind::Start && state.phase == MissionPhase::Ready {
                MissionState::new(
                    MissionPhase::Running,
                    MissionCondition::ApprovalRequired,
                    None,
                    event.reason.clone(),
                )
                .map_err(ReduceError::InvalidState)
            } else {
                condition_state(
                    state,
                    MissionCondition::ApprovalRequired,
                    event.reason.clone(),
                )
            }
        }
        ActivityResult::Paused => {
            condition_state(state, MissionCondition::Paused, event.reason.clone())
        }
        ActivityResult::Degraded => {
            condition_state(state, MissionCondition::Degraded, event.reason.clone())
        }
        ActivityResult::Blocked => {
            condition_state(state, MissionCondition::Blocked, event.reason.clone())
        }
    }
}

fn reduce_success(
    state: &MissionState,
    event: &ActivityResultEvent,
) -> Result<MissionState, ReduceError> {
    let (phase, outcome) = match (state.phase, event.activity) {
        (MissionPhase::Created, ActivityKind::Compile) => (MissionPhase::Compiled, None),
        (MissionPhase::Compiled, ActivityKind::Prepare) => (MissionPhase::Ready, None),
        (MissionPhase::Ready, ActivityKind::Start) => (MissionPhase::Running, None),
        (MissionPhase::Running, ActivityKind::Execute) => (MissionPhase::Verifying, None),
        (MissionPhase::Verifying, ActivityKind::Verify) => {
            (MissionPhase::Terminal, Some(MissionOutcome::Succeeded))
        }
        (phase, activity) => {
            return Err(ReduceError::UnexpectedSuccessfulActivity { phase, activity });
        }
    };
    MissionState::new(
        phase,
        MissionCondition::Normal,
        outcome,
        event.reason.clone(),
    )
    .map_err(ReduceError::InvalidState)
}

fn condition_state(
    state: &MissionState,
    condition: MissionCondition,
    reason: Option<String>,
) -> Result<MissionState, ReduceError> {
    MissionState::new(state.phase, condition, None, reason).map_err(ReduceError::InvalidState)
}

fn terminal_state(
    outcome: MissionOutcome,
    reason: Option<String>,
) -> Result<MissionState, ReduceError> {
    MissionState::new(
        MissionPhase::Terminal,
        MissionCondition::Normal,
        Some(outcome),
        reason,
    )
    .map_err(ReduceError::InvalidState)
}

fn validate_state_schema(instance: &Value) -> Result<(), MissionStateError> {
    let schema: Value = serde_json::from_str(MISSION_STATE_SCHEMA).map_err(|error| {
        MissionStateError::SchemaViolation(format!("embedded schema is invalid JSON: {error}"))
    })?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .map_err(|error| {
            MissionStateError::SchemaViolation(format!("embedded schema cannot compile: {error}"))
        })?;
    if let Err(mut errors) = compiled.validate(instance) {
        let message = errors.next().map_or_else(
            || "unknown schema violation".to_owned(),
            |error| error.to_string(),
        );
        return Err(MissionStateError::SchemaViolation(message));
    }
    Ok(())
}

fn validate_non_blank(field: &'static str, value: &str) -> Result<(), MissionSpecError> {
    if value.trim().is_empty() {
        return Err(MissionSpecError::BlankField { field });
    }
    Ok(())
}

fn validate_entries(
    field: &'static str,
    entries: &[String],
    require_one: bool,
) -> Result<(), MissionSpecError> {
    if require_one && entries.is_empty() {
        return Err(MissionSpecError::EmptyCollection { field });
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.trim().is_empty() {
            return Err(MissionSpecError::BlankEntry { field, index });
        }
    }
    Ok(())
}

fn digest_component(hasher: &mut Sha256, value: &str) {
    let length =
        u64::try_from(value.len()).expect("string lengths fit in u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}
