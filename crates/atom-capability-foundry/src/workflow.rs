//! Typed durable workflow synthesis for ATOM-FND-002.
//!
//! The Foundry validates the workflow graph before returning it. Every
//! nonterminal step therefore has an explicit, type-compatible transition for
//! success, failure, timeout, retry, reconciliation, and compensation.

use std::collections::{BTreeMap, BTreeSet};

use atom_artifact::Artifact;
use thiserror::Error;

use crate::tool::{Candidate, CandidateCertificationMaterial, CandidateError, CandidateInterface};

/// Typed interface exposed by a durable workflow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowInterface {
    /// Stable workflow name.
    pub name: String,
    /// Type accepted at workflow entry.
    pub input_type: String,
    /// Type produced on normal workflow completion.
    pub output_type: String,
}

impl WorkflowInterface {
    /// Creates a typed workflow interface.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        input_type: impl Into<String>,
        output_type: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            input_type: input_type.into(),
            output_type: output_type.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), CandidateError> {
        if self.name.trim().is_empty() {
            return Err(CandidateError::EmptyInterfaceName);
        }
        if self.input_type.trim().is_empty() || self.output_type.trim().is_empty() {
            return Err(CandidateError::EmptyType);
        }
        Ok(())
    }
}

/// The durable outcome ports an activity step exposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowOutputTypes {
    /// Payload type produced by a successful activity execution.
    pub success: String,
    /// Payload type produced by a recoverable or terminal failure.
    pub failure: String,
    /// Payload type produced when an activity times out.
    pub timeout: String,
    /// Payload type used to schedule a retry.
    pub retry: String,
    /// Payload type used to reconcile a possibly completed activity.
    pub reconciliation: String,
    /// Payload type passed to a compensator.
    pub compensation: String,
}

impl WorkflowOutputTypes {
    /// Creates explicit types for every activity outcome port.
    #[must_use]
    pub fn new(
        success: impl Into<String>,
        failure: impl Into<String>,
        timeout: impl Into<String>,
        retry: impl Into<String>,
        reconciliation: impl Into<String>,
        compensation: impl Into<String>,
    ) -> Self {
        Self {
            success: success.into(),
            failure: failure.into(),
            timeout: timeout.into(),
            retry: retry.into(),
            reconciliation: reconciliation.into(),
            compensation: compensation.into(),
        }
    }

    fn for_transition(&self, kind: WorkflowTransitionKind) -> &str {
        match kind {
            WorkflowTransitionKind::Success => &self.success,
            WorkflowTransitionKind::Failure => &self.failure,
            WorkflowTransitionKind::Timeout => &self.timeout,
            WorkflowTransitionKind::Retry => &self.retry,
            WorkflowTransitionKind::Reconciliation => &self.reconciliation,
            WorkflowTransitionKind::Compensation => &self.compensation,
        }
    }

    fn validate(&self, step_id: &str) -> Result<(), WorkflowError> {
        for (outcome, value) in [
            (WorkflowTransitionKind::Success, &self.success),
            (WorkflowTransitionKind::Failure, &self.failure),
            (WorkflowTransitionKind::Timeout, &self.timeout),
            (WorkflowTransitionKind::Retry, &self.retry),
            (WorkflowTransitionKind::Reconciliation, &self.reconciliation),
            (WorkflowTransitionKind::Compensation, &self.compensation),
        ] {
            if value.trim().is_empty() {
                return Err(WorkflowError::EmptyOutcomeType {
                    step_id: step_id.to_owned(),
                    outcome,
                });
            }
        }
        Ok(())
    }
}

/// Whether a workflow step executes work or terminates a branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// A durable activity with six explicit outcome ports.
    Activity(WorkflowOutputTypes),
    /// A terminal durable record; it has no outgoing transition.
    Terminal,
}

/// A step in a durable workflow graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowStep {
    /// Stable step identity.
    pub step_id: String,
    /// Type required to enter this step.
    pub input_type: String,
    /// Whether this is an activity or terminal record.
    pub kind: StepKind,
}

impl WorkflowStep {
    /// Creates a nonterminal activity step.
    #[must_use]
    pub fn activity(
        step_id: impl Into<String>,
        input_type: impl Into<String>,
        output_types: WorkflowOutputTypes,
    ) -> Self {
        Self {
            step_id: step_id.into(),
            input_type: input_type.into(),
            kind: StepKind::Activity(output_types),
        }
    }

    /// Creates a terminal step.
    #[must_use]
    pub fn terminal(step_id: impl Into<String>, input_type: impl Into<String>) -> Self {
        Self {
            step_id: step_id.into(),
            input_type: input_type.into(),
            kind: StepKind::Terminal,
        }
    }

    /// Whether no transition may leave this step.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.kind, StepKind::Terminal)
    }

    fn output_type(&self, transition: WorkflowTransitionKind) -> Option<&str> {
        match &self.kind {
            StepKind::Activity(types) => Some(types.for_transition(transition)),
            StepKind::Terminal => None,
        }
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        if self.step_id.trim().is_empty() {
            return Err(WorkflowError::EmptyStepId);
        }
        if self.input_type.trim().is_empty() {
            return Err(WorkflowError::EmptyStepInputType {
                step_id: self.step_id.clone(),
            });
        }
        if let StepKind::Activity(output_types) = &self.kind {
            output_types.validate(&self.step_id)?;
        }
        Ok(())
    }
}

/// The explicit outcome that causes a workflow transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkflowTransitionKind {
    /// Normal activity completion.
    Success,
    /// Activity failure.
    Failure,
    /// Activity timeout.
    Timeout,
    /// Retry scheduling or execution.
    Retry,
    /// Reconciliation of an uncertain outcome.
    Reconciliation,
    /// Compensation for an already-applied partial result.
    Compensation,
}

impl WorkflowTransitionKind {
    /// Every transition kind an activity must declare.
    pub const ALL: [Self; 6] = [
        Self::Success,
        Self::Failure,
        Self::Timeout,
        Self::Retry,
        Self::Reconciliation,
        Self::Compensation,
    ];

    /// Canonical diagnostic name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::Timeout => "TIMEOUT",
            Self::Retry => "RETRY",
            Self::Reconciliation => "RECONCILIATION",
            Self::Compensation => "COMPENSATION",
        }
    }
}

/// A type-preserving directed edge in a workflow graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowTransition {
    /// Step whose output port caused the transition.
    pub from_step: String,
    /// Outcome port selected on the source step.
    pub kind: WorkflowTransitionKind,
    /// Step receiving the outcome payload.
    pub to_step: String,
    /// Type carried over the edge.
    pub payload_type: String,
}

impl WorkflowTransition {
    /// Creates an explicit workflow transition.
    #[must_use]
    pub fn new(
        from_step: impl Into<String>,
        kind: WorkflowTransitionKind,
        to_step: impl Into<String>,
        payload_type: impl Into<String>,
    ) -> Self {
        Self {
            from_step: from_step.into(),
            kind,
            to_step: to_step.into(),
            payload_type: payload_type.into(),
        }
    }
}

/// Input to [`WorkflowFoundry::synthesize`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowSpec {
    /// Stable workflow identity.
    pub workflow_id: String,
    /// Entry step id.
    pub start_step: String,
    /// Type accepted at the public workflow entrypoint.
    pub input_type: String,
    /// Type returned from a normal public workflow completion.
    pub output_type: String,
    /// All workflow steps.
    pub steps: Vec<WorkflowStep>,
    /// All durable outcome transitions.
    pub transitions: Vec<WorkflowTransition>,
}

/// A validated immutable workflow graph. Its graph is suitable for durable
/// event persistence because all nonterminal outcomes are declared up front.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableWorkflow {
    spec: WorkflowSpec,
}

impl DurableWorkflow {
    /// Stable workflow identity.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.spec.workflow_id
    }

    /// Public typed interface.
    #[must_use]
    pub fn interface(&self) -> WorkflowInterface {
        WorkflowInterface::new(
            self.spec.workflow_id.clone(),
            self.spec.input_type.clone(),
            self.spec.output_type.clone(),
        )
    }

    /// Entry step identity.
    #[must_use]
    pub fn start_step(&self) -> &str {
        &self.spec.start_step
    }

    /// Immutable steps in the validated graph.
    #[must_use]
    pub fn steps(&self) -> &[WorkflowStep] {
        &self.spec.steps
    }

    /// Immutable typed transitions in the validated graph.
    #[must_use]
    pub fn transitions(&self) -> &[WorkflowTransition] {
        &self.spec.transitions
    }

    /// A workflow returned by this Foundry is always durable-by-definition.
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        true
    }
}

/// Input to [`WorkflowFoundry::synthesize_candidate`].
#[derive(Clone, Debug)]
pub struct WorkflowCandidateSpec {
    /// Stable candidate id.
    pub candidate_id: String,
    /// Typed workflow graph to validate and synthesize.
    pub workflow: WorkflowSpec,
    /// Content-addressed executable/workflow artifact.
    pub artifact: Artifact,
    /// Live material required for certificate verification.
    pub certification: CandidateCertificationMaterial,
}

/// A workflow paired with the candidate artifact representing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowCandidate {
    candidate: Candidate,
    workflow: DurableWorkflow,
}

impl WorkflowCandidate {
    /// The candidate sent to the common activation gate.
    #[must_use]
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// The typed durable workflow that was synthesized.
    #[must_use]
    pub fn workflow(&self) -> &DurableWorkflow {
        &self.workflow
    }

    /// Consumes the wrapper and returns the candidate and workflow together.
    #[must_use]
    pub fn into_parts(self) -> (Candidate, DurableWorkflow) {
        (self.candidate, self.workflow)
    }
}

/// Synthesizes typed, durable workflows.
#[derive(Clone, Debug, Default)]
pub struct WorkflowFoundry;

impl WorkflowFoundry {
    /// Creates a Workflow Foundry.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validates and returns a durable workflow.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowError`] if any required transition is missing, a
    /// transition references an unknown step, or a transition is not typed.
    pub fn synthesize(
        &self,
        specification: WorkflowSpec,
    ) -> Result<DurableWorkflow, WorkflowError> {
        validate_workflow(&specification)?;
        Ok(DurableWorkflow {
            spec: specification,
        })
    }

    /// Synthesizes a durable workflow and packages it as a candidate for the
    /// shared certificate-gated activation path.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowFoundryError`] for either workflow validation or
    /// candidate construction failures.
    pub fn synthesize_candidate(
        &self,
        specification: WorkflowCandidateSpec,
    ) -> Result<WorkflowCandidate, WorkflowFoundryError> {
        let workflow = self.synthesize(specification.workflow)?;
        let implementation_id = format!("workflow:{}", workflow.workflow_id());
        let candidate = Candidate::new(
            specification.candidate_id,
            CandidateInterface::Workflow(workflow.interface()),
            implementation_id,
            specification.artifact,
            specification.certification,
        )?;
        Ok(WorkflowCandidate {
            candidate,
            workflow,
        })
    }
}

fn validate_workflow(specification: &WorkflowSpec) -> Result<(), WorkflowError> {
    if specification.workflow_id.trim().is_empty() {
        return Err(WorkflowError::EmptyWorkflowId);
    }
    if specification.start_step.trim().is_empty() {
        return Err(WorkflowError::EmptyStartStep);
    }
    if specification.input_type.trim().is_empty() || specification.output_type.trim().is_empty() {
        return Err(WorkflowError::EmptyWorkflowType);
    }
    if specification.steps.is_empty() {
        return Err(WorkflowError::NoSteps);
    }

    let mut steps = BTreeMap::new();
    let mut has_terminal = false;
    for step in &specification.steps {
        step.validate()?;
        if steps.insert(step.step_id.as_str(), step).is_some() {
            return Err(WorkflowError::DuplicateStepId {
                step_id: step.step_id.clone(),
            });
        }
        has_terminal |= step.is_terminal();
    }
    if !has_terminal {
        return Err(WorkflowError::NoTerminalStep);
    }

    let start = steps
        .get(specification.start_step.as_str())
        .ok_or_else(|| WorkflowError::UnknownStartStep {
            step_id: specification.start_step.clone(),
        })?;
    if start.input_type != specification.input_type {
        return Err(WorkflowError::EntryTypeMismatch {
            expected: specification.input_type.clone(),
            actual: start.input_type.clone(),
        });
    }

    let mut declared = BTreeSet::new();
    for transition in &specification.transitions {
        let source =
            steps
                .get(transition.from_step.as_str())
                .ok_or_else(|| WorkflowError::UnknownStep {
                    step_id: transition.from_step.clone(),
                })?;
        let target =
            steps
                .get(transition.to_step.as_str())
                .ok_or_else(|| WorkflowError::UnknownStep {
                    step_id: transition.to_step.clone(),
                })?;
        let expected_payload = source.output_type(transition.kind).ok_or_else(|| {
            WorkflowError::TerminalHasOutgoingTransition {
                step_id: source.step_id.clone(),
            }
        })?;

        if transition.payload_type.trim().is_empty() {
            return Err(WorkflowError::EmptyTransitionType {
                from_step: transition.from_step.clone(),
                kind: transition.kind,
            });
        }
        if transition.payload_type != expected_payload {
            return Err(WorkflowError::SourceTypeMismatch {
                from_step: transition.from_step.clone(),
                kind: transition.kind,
                expected: expected_payload.to_owned(),
                actual: transition.payload_type.clone(),
            });
        }
        if transition.payload_type != target.input_type {
            return Err(WorkflowError::TargetTypeMismatch {
                from_step: transition.from_step.clone(),
                to_step: transition.to_step.clone(),
                expected: target.input_type.clone(),
                actual: transition.payload_type.clone(),
            });
        }

        let key = (transition.from_step.as_str(), transition.kind);
        if !declared.insert(key) {
            return Err(WorkflowError::DuplicateTransition {
                from_step: transition.from_step.clone(),
                kind: transition.kind,
            });
        }
    }

    for step in &specification.steps {
        if step.is_terminal() {
            continue;
        }
        for kind in WorkflowTransitionKind::ALL {
            if !declared.contains(&(step.step_id.as_str(), kind)) {
                return Err(WorkflowError::MissingTransition {
                    step_id: step.step_id.clone(),
                    kind,
                });
            }
        }
    }
    Ok(())
}

/// Durable workflow validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WorkflowError {
    /// Workflow ids are durable graph identities and cannot be blank.
    #[error("workflow id must not be empty")]
    EmptyWorkflowId,
    /// A workflow needs an entry step.
    #[error("workflow start step must not be empty")]
    EmptyStartStep,
    /// Public input/output types cannot be blank.
    #[error("workflow input and output types must not be empty")]
    EmptyWorkflowType,
    /// A workflow cannot be durable without steps.
    #[error("workflow has no steps")]
    NoSteps,
    /// A durable graph needs at least one terminal record.
    #[error("workflow has no terminal step")]
    NoTerminalStep,
    /// Step identities cannot be blank.
    #[error("workflow step id must not be empty")]
    EmptyStepId,
    /// Step entry types cannot be blank.
    #[error("workflow step `{step_id}` has an empty input type")]
    EmptyStepInputType {
        /// Step with the malformed type.
        step_id: String,
    },
    /// Every activity outcome must be typed.
    #[error("workflow step `{step_id}` has an empty {outcome:?} output type")]
    EmptyOutcomeType {
        /// Step with the malformed outcome port.
        step_id: String,
        /// Outcome whose type was blank.
        outcome: WorkflowTransitionKind,
    },
    /// Step ids must be unique.
    #[error("duplicate workflow step `{step_id}`")]
    DuplicateStepId {
        /// Duplicate id.
        step_id: String,
    },
    /// The configured entry step was not declared.
    #[error("unknown workflow start step `{step_id}`")]
    UnknownStartStep {
        /// Missing id.
        step_id: String,
    },
    /// The public entry and first step must agree on type.
    #[error("workflow entry type mismatch: expected `{expected}`, got `{actual}`")]
    EntryTypeMismatch {
        /// Declared workflow input type.
        expected: String,
        /// Input type of the start step.
        actual: String,
    },
    /// A transition named a step that does not exist.
    #[error("unknown workflow step `{step_id}`")]
    UnknownStep {
        /// Missing id.
        step_id: String,
    },
    /// Terminal records have no output ports.
    #[error("terminal step `{step_id}` has an outgoing transition")]
    TerminalHasOutgoingTransition {
        /// Terminal step with an invalid edge.
        step_id: String,
    },
    /// Edge payload types cannot be blank.
    #[error("transition {from_step} --{kind:?}--> has an empty payload type")]
    EmptyTransitionType {
        /// Source step.
        from_step: String,
        /// Source outcome.
        kind: WorkflowTransitionKind,
    },
    /// An edge does not carry the type advertised by its source port.
    #[error(
        "transition {from_step} --{kind:?}--> has source type `{actual}`, expected `{expected}`"
    )]
    SourceTypeMismatch {
        /// Source step.
        from_step: String,
        /// Source outcome.
        kind: WorkflowTransitionKind,
        /// Type advertised by the source port.
        expected: String,
        /// Type carried by the edge.
        actual: String,
    },
    /// An edge does not carry the type required by its target step.
    #[error(
        "transition {from_step} -> {to_step} has target type `{actual}`, expected `{expected}`"
    )]
    TargetTypeMismatch {
        /// Source step.
        from_step: String,
        /// Target step.
        to_step: String,
        /// Type required by the target.
        expected: String,
        /// Type carried by the edge.
        actual: String,
    },
    /// A step may declare each outcome edge only once.
    #[error("duplicate {kind:?} transition from step `{from_step}`")]
    DuplicateTransition {
        /// Source step.
        from_step: String,
        /// Repeated outcome port.
        kind: WorkflowTransitionKind,
    },
    /// Every activity must explicitly handle all six outcomes.
    #[error("workflow step `{step_id}` is missing its {kind:?} transition")]
    MissingTransition {
        /// Step without a required edge.
        step_id: String,
        /// Missing outcome port.
        kind: WorkflowTransitionKind,
    },
}

/// Error from synthesizing a workflow candidate.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WorkflowFoundryError {
    /// The workflow graph was invalid.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// Candidate packaging failed.
    #[error(transparent)]
    Candidate(#[from] CandidateError),
}
