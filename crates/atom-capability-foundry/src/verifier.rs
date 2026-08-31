//! Verifier-independence labels for ATOM-FND-003.
//!
//! Labels use the canonical V0--V5 taxonomy from `spec/enums.yaml`. A label at
//! V2 or above is only issued when the evaluator context differs from the
//! candidate-authoring context. This is the local, mechanical part of
//! separated evaluation (ATOM-INV-017).

use thiserror::Error;

pub use atom_claim::VerifierLevel;

/// The evidence mechanism a verifier used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationMethod {
    /// The candidate or its author reports its own result.
    SelfReport,
    /// A model correlated with the candidate evaluates it.
    CorrelatedModel,
    /// A separately run model evaluates the candidate.
    IndependentModel,
    /// A deterministic program or oracle evaluates the candidate.
    ProgrammaticOracle,
    /// A measurement against an external system or real-world observation.
    ExternalReality,
    /// A formal proof checker or cryptographic verifier evaluates it.
    FormalOrCryptographic,
}

impl VerificationMethod {
    /// Canonical taxonomy level for this method.
    #[must_use]
    pub const fn verifier_level(self) -> VerifierLevel {
        match self {
            Self::SelfReport => VerifierLevel::V0,
            Self::CorrelatedModel => VerifierLevel::V1,
            Self::IndependentModel => VerifierLevel::V2,
            Self::ProgrammaticOracle => VerifierLevel::V3,
            Self::ExternalReality => VerifierLevel::V4,
            Self::FormalOrCryptographic => VerifierLevel::V5,
        }
    }
}

/// Auditable input for a verifier-independence label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierInput {
    /// Stable verifier identity.
    pub verifier_id: String,
    /// Context that authored or generated the candidate.
    pub candidate_authoring_context: String,
    /// Context in which evaluation ran.
    pub verifier_context: String,
    /// Evidence mechanism used by the evaluator.
    pub method: VerificationMethod,
    /// Oracle, observation, proof, or cryptographic provenance when required.
    pub provenance_ref: Option<String>,
}

impl VerifierInput {
    /// Creates auditable verifier-label input.
    #[must_use]
    pub fn new(
        verifier_id: impl Into<String>,
        candidate_authoring_context: impl Into<String>,
        verifier_context: impl Into<String>,
        method: VerificationMethod,
        provenance_ref: Option<String>,
    ) -> Self {
        Self {
            verifier_id: verifier_id.into(),
            candidate_authoring_context: candidate_authoring_context.into(),
            verifier_context: verifier_context.into(),
            method,
            provenance_ref,
        }
    }
}

/// A canonical V0--V5 label with the separation evidence that justified it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierLabel {
    verifier_id: String,
    level: VerifierLevel,
    method: VerificationMethod,
    separated_from_candidate: bool,
    provenance_ref: Option<String>,
}

impl VerifierLabel {
    /// Stable evaluator identity.
    #[must_use]
    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    /// Canonical V0--V5 verifier-independence label.
    #[must_use]
    pub const fn level(&self) -> VerifierLevel {
        self.level
    }

    /// Evidence mechanism that determined the label.
    #[must_use]
    pub const fn method(&self) -> VerificationMethod {
        self.method
    }

    /// Whether evaluator execution was separated from candidate authoring.
    #[must_use]
    pub const fn is_separated_from_candidate(&self) -> bool {
        self.separated_from_candidate
    }

    /// Optional auditable oracle, observation, proof, or crypto reference.
    #[must_use]
    pub fn provenance_ref(&self) -> Option<&str> {
        self.provenance_ref.as_deref()
    }
}

/// Labels verifier inputs according to the canonical taxonomy.
#[derive(Clone, Debug, Default)]
pub struct VerifierFoundry;

impl VerifierFoundry {
    /// Creates a Verifier Foundry.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Labels a verifier, rejecting unsupported claims of evaluator
    /// independence or oracle provenance.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError`] when identities are blank, a V2+ method is not
    /// separated from candidate authoring, or an oracle/proof reference needed
    /// by V3--V5 is absent.
    pub fn label(&self, input: VerifierInput) -> Result<VerifierLabel, VerifierError> {
        if input.verifier_id.trim().is_empty() {
            return Err(VerifierError::EmptyVerifierId);
        }
        if input.candidate_authoring_context.trim().is_empty() {
            return Err(VerifierError::EmptyCandidateAuthoringContext);
        }
        if input.verifier_context.trim().is_empty() {
            return Err(VerifierError::EmptyVerifierContext);
        }

        let level = input.method.verifier_level();
        let separated = input.candidate_authoring_context != input.verifier_context;
        if level >= VerifierLevel::V2 && !separated {
            return Err(VerifierError::IndependentLevelRequiresSeparation { level });
        }

        let has_provenance = input
            .provenance_ref
            .as_deref()
            .is_some_and(|reference| !reference.trim().is_empty());
        if level >= VerifierLevel::V3 && !has_provenance {
            return Err(VerifierError::MissingProvenance { level });
        }

        Ok(VerifierLabel {
            verifier_id: input.verifier_id,
            level,
            method: input.method,
            separated_from_candidate: separated,
            provenance_ref: input
                .provenance_ref
                .filter(|reference| !reference.trim().is_empty()),
        })
    }
}

/// Verifier labeling failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VerifierError {
    /// Labels require a stable verifier identity.
    #[error("verifier id must not be empty")]
    EmptyVerifierId,
    /// Separation cannot be audited without the authoring context id.
    #[error("candidate authoring context must not be empty")]
    EmptyCandidateAuthoringContext,
    /// Separation cannot be audited without the verifier context id.
    #[error("verifier context must not be empty")]
    EmptyVerifierContext,
    /// V2--V5 require a context distinct from candidate authoring.
    #[error("verifier level {level} requires a separated evaluator context")]
    IndependentLevelRequiresSeparation {
        /// Level the caller attempted to claim.
        level: VerifierLevel,
    },
    /// Programmatic-oracle, external-reality, and formal/crypto labels require
    /// an auditable evidence reference.
    #[error("verifier level {level} requires an oracle/proof provenance reference")]
    MissingProvenance {
        /// Level the caller attempted to claim.
        level: VerifierLevel,
    },
}
