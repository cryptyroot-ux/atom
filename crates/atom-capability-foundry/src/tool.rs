//! Tool candidate synthesis for ATOM-FND-001.
//!
//! A candidate is immutable in the dimensions that a certificate binds:
//! identity, interface, artifact, and certification material. The activation
//! gate owns lifecycle changes; this module only produces candidates in
//! [`FoundryState::Draft`].

use std::collections::BTreeSet;

use atom_artifact::Artifact;
use atom_cert::{BehaviorManifestV2, EnvironmentScope, EvaluationContext, EvaluationSuite};
use atom_ledger::{canonicalize, domain_digest, Hash};
use chrono::{DateTime, Utc};
use serde_json::json;
use thiserror::Error;

use crate::gate::FoundryState;
use crate::verifier::VerifierLevel;
use crate::workflow::WorkflowInterface;

/// Domain separator for the certificate subject digest of a Foundry candidate.
pub const CANDIDATE_SUBJECT_DOMAIN: &str = "ATOM-FOUNDRY-CANDIDATE-v1:";

/// A typed tool interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolInterface {
    /// Stable API/interface name.
    pub name: String,
    /// Canonical input type or schema identifier.
    pub input_type: String,
    /// Canonical output type or schema identifier.
    pub output_type: String,
}

impl ToolInterface {
    /// Creates a typed tool interface.
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

    fn validate(&self) -> Result<(), CandidateError> {
        if self.name.trim().is_empty() {
            return Err(CandidateError::EmptyInterfaceName);
        }
        if self.input_type.trim().is_empty() || self.output_type.trim().is_empty() {
            return Err(CandidateError::EmptyType);
        }
        Ok(())
    }
}

/// The interface shape represented by a candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateInterface {
    /// A callable tool interface.
    Tool(ToolInterface),
    /// A typed durable workflow interface.
    Workflow(WorkflowInterface),
}

impl CandidateInterface {
    /// Candidate kind implied by this interface.
    #[must_use]
    pub const fn kind(&self) -> CandidateKind {
        match self {
            Self::Tool(_) => CandidateKind::Tool,
            Self::Workflow(_) => CandidateKind::Workflow,
        }
    }

    fn validate(&self) -> Result<(), CandidateError> {
        match self {
            Self::Tool(interface) => interface.validate(),
            Self::Workflow(interface) => interface.validate(),
        }
    }
}

/// The class of artifact a candidate carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    /// A synthesized tool implementation.
    Tool,
    /// A synthesized durable workflow.
    Workflow,
}

impl CandidateKind {
    /// Canonical stable name for certificate subject binding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "TOOL",
            Self::Workflow => "WORKFLOW",
        }
    }
}

/// Material that a candidate certificate must bind.
///
/// The gate derives an [`EvaluationContext`] directly from this material, so a
/// certificate for a changed behavior manifest, evaluation suite, or
/// environment cannot be reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCertificationMaterial {
    behavior_manifest: BehaviorManifestV2,
    evaluation_suite: EvaluationSuite,
    environment_scope: EnvironmentScope,
}

impl CandidateCertificationMaterial {
    /// Bundles the three live artifacts against which a certificate is checked.
    #[must_use]
    pub fn new(
        behavior_manifest: BehaviorManifestV2,
        evaluation_suite: EvaluationSuite,
        environment_scope: EnvironmentScope,
    ) -> Self {
        Self {
            behavior_manifest,
            evaluation_suite,
            environment_scope,
        }
    }

    /// The behavior manifest currently attached to the candidate.
    #[must_use]
    pub fn behavior_manifest(&self) -> &BehaviorManifestV2 {
        &self.behavior_manifest
    }

    /// The complete evaluation suite, including the holdout declaration.
    #[must_use]
    pub fn evaluation_suite(&self) -> &EvaluationSuite {
        &self.evaluation_suite
    }

    /// The environment in which this candidate may be activated.
    #[must_use]
    pub fn environment_scope(&self) -> &EnvironmentScope {
        &self.environment_scope
    }

    /// Builds the live certificate context for `now`.
    #[must_use]
    pub fn evaluation_context(
        &self,
        now: DateTime<Utc>,
        required_level: VerifierLevel,
    ) -> EvaluationContext {
        EvaluationContext::new(
            self.behavior_manifest.digest(),
            self.evaluation_suite.digest(),
            &self.environment_scope,
            now,
            required_level,
        )
    }
}

/// An immutable generated candidate. It carries no authority token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    id: String,
    kind: CandidateKind,
    interface: CandidateInterface,
    implementation_id: String,
    artifact: Artifact,
    certification: CandidateCertificationMaterial,
    subject_digest: Hash,
    state: FoundryState,
}

impl Candidate {
    /// Constructs a draft candidate with a certificate subject digest bound to
    /// its id, kind, and immutable artifact content address.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateError`] when an identity, implementation, interface,
    /// or type declaration is empty.
    pub fn new(
        id: impl Into<String>,
        interface: CandidateInterface,
        implementation_id: impl Into<String>,
        artifact: Artifact,
        certification: CandidateCertificationMaterial,
    ) -> Result<Self, CandidateError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(CandidateError::EmptyCandidateId);
        }

        let implementation_id = implementation_id.into();
        if implementation_id.trim().is_empty() {
            return Err(CandidateError::EmptyImplementationId);
        }

        interface.validate()?;
        let kind = interface.kind();
        let subject_digest = candidate_subject_digest(&id, kind, &artifact);

        Ok(Self {
            id,
            kind,
            interface,
            implementation_id,
            artifact,
            certification,
            subject_digest,
            state: FoundryState::Draft,
        })
    }

    /// Stable candidate identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether this candidate is a tool or workflow.
    #[must_use]
    pub const fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// The typed interface this candidate implements.
    #[must_use]
    pub fn interface(&self) -> &CandidateInterface {
        &self.interface
    }

    /// Stable identifier of the synthesized implementation variant.
    #[must_use]
    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    /// The immutable content-addressed artifact.
    #[must_use]
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// Material used to derive the certificate evaluation context.
    #[must_use]
    pub fn certification(&self) -> &CandidateCertificationMaterial {
        &self.certification
    }

    /// The digest that a certificate must name as its subject.
    #[must_use]
    pub const fn subject_digest(&self) -> Hash {
        self.subject_digest
    }

    /// Lifecycle state controlled by the activation gate.
    #[must_use]
    pub const fn state(&self) -> FoundryState {
        self.state
    }

    pub(crate) fn transition_to(mut self, next: FoundryState) -> Result<Self, FoundryState> {
        if !self.state.can_transition_to(next) {
            return Err(self.state);
        }
        self.state = next;
        Ok(self)
    }
}

fn candidate_subject_digest(id: &str, kind: CandidateKind, artifact: &Artifact) -> Hash {
    let document = json!({
        "candidate_id": id,
        "candidate_kind": kind.as_str(),
        "artifact_id": artifact.id().as_str(),
    });
    // This document contains only strings, which are always canonicalizable.
    let bytes = canonicalize(&document).expect("candidate subject binding is canonicalizable");
    domain_digest(CANDIDATE_SUBJECT_DOMAIN, &bytes)
}

/// One requested tool interface/implementation alternative.
#[derive(Clone, Debug)]
pub struct ToolCandidateSpec {
    /// Stable id to assign to the candidate.
    pub candidate_id: String,
    /// The typed interface the alternative implements.
    pub interface: ToolInterface,
    /// Stable identity of this implementation variant.
    pub implementation_id: String,
    /// The content-addressed artifact for this implementation.
    pub artifact: Artifact,
    /// Live material the activation certificate must bind.
    pub certification: CandidateCertificationMaterial,
}

/// Synthesizes a set of competing tool candidates.
#[derive(Clone, Debug, Default)]
pub struct ToolFoundry;

impl ToolFoundry {
    /// Creates a Tool Foundry.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Turns independently supplied interface/implementation alternatives into
    /// draft candidates. Fewer than two candidates is rejected so a caller
    /// cannot describe a single implementation as a Foundry comparison.
    ///
    /// # Errors
    ///
    /// Returns [`ToolFoundryError`] for fewer than two alternatives, duplicate
    /// ids, or invalid candidate inputs.
    pub fn synthesize<I>(&self, specifications: I) -> Result<Vec<Candidate>, ToolFoundryError>
    where
        I: IntoIterator<Item = ToolCandidateSpec>,
    {
        let specifications: Vec<ToolCandidateSpec> = specifications.into_iter().collect();
        if specifications.len() < 2 {
            return Err(ToolFoundryError::TooFewCandidates {
                actual: specifications.len(),
            });
        }

        let mut ids = BTreeSet::new();
        let mut candidates = Vec::with_capacity(specifications.len());
        for specification in specifications {
            if !ids.insert(specification.candidate_id.clone()) {
                return Err(ToolFoundryError::DuplicateCandidateId {
                    candidate_id: specification.candidate_id,
                });
            }
            candidates.push(Candidate::new(
                specification.candidate_id,
                CandidateInterface::Tool(specification.interface),
                specification.implementation_id,
                specification.artifact,
                specification.certification,
            )?);
        }
        Ok(candidates)
    }

    /// Alias for [`Self::synthesize`] that makes call sites read naturally.
    pub fn synthesize_candidates<I>(
        &self,
        specifications: I,
    ) -> Result<Vec<Candidate>, ToolFoundryError>
    where
        I: IntoIterator<Item = ToolCandidateSpec>,
    {
        self.synthesize(specifications)
    }
}

/// Candidate construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CandidateError {
    /// Candidate ids are audit keys and cannot be blank.
    #[error("candidate id must not be empty")]
    EmptyCandidateId,
    /// Every synthesized implementation needs its own identity.
    #[error("implementation id must not be empty")]
    EmptyImplementationId,
    /// Typed interfaces need a stable name.
    #[error("candidate interface name must not be empty")]
    EmptyInterfaceName,
    /// Typed interfaces need both input and output types.
    #[error("candidate interface types must not be empty")]
    EmptyType,
}

/// Tool Foundry synthesis failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ToolFoundryError {
    /// Foundry comparison needs at least two independent alternatives.
    #[error("Tool Foundry requires at least two candidates, got {actual}")]
    TooFewCandidates {
        /// Number of alternatives supplied.
        actual: usize,
    },
    /// Candidate ids must be unique within one synthesis batch.
    #[error("duplicate candidate id `{candidate_id}`")]
    DuplicateCandidateId {
        /// The duplicate id.
        candidate_id: String,
    },
    /// A candidate could not be constructed.
    #[error(transparent)]
    Candidate(#[from] CandidateError),
}
