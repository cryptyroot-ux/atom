//! Certificate-gated activation for ATOM-FND-001 and ATOM-VT-010.
//!
//! The only success output of this gate is an [`ActivatedCandidate`], which
//! contains the original candidate and its independently verified certificate.
//! A missing certificate, a stale/mismatched certificate, a failed generated
//! check, or a failed/non-separated hidden holdout produces a quarantined
//! candidate instead of an active one.

use atom_cert::{CertError, CertVerifier, Certificate};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tool::Candidate;
use crate::verifier::{VerifierLabel, VerifierLevel};

/// Canonical Foundry lifecycle states from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FoundryState {
    /// Candidate exists but has not entered validation.
    Draft,
    /// Candidate is being built in a hermetic environment.
    Building,
    /// Candidate is undergoing generated and independent tests.
    Testing,
    /// Candidate is held pending remediation or re-evaluation.
    Quarantined,
    /// Candidate was permanently rejected.
    Rejected,
    /// Candidate has a valid certificate but is not yet active.
    Certified,
    /// Candidate passed all gates and is eligible for activation.
    Active,
    /// Certified material drifted and needs re-certification.
    Stale,
    /// Candidate is being re-certified after drift.
    Recertifying,
    /// Candidate has been revoked permanently.
    Revoked,
}

impl FoundryState {
    /// Every canonical state in spec order.
    pub const ALL: [Self; 10] = [
        Self::Draft,
        Self::Building,
        Self::Testing,
        Self::Quarantined,
        Self::Rejected,
        Self::Certified,
        Self::Active,
        Self::Stale,
        Self::Recertifying,
        Self::Revoked,
    ];

    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Building => "BUILDING",
            Self::Testing => "TESTING",
            Self::Quarantined => "QUARANTINED",
            Self::Rejected => "REJECTED",
            Self::Certified => "CERTIFIED",
            Self::Active => "ACTIVE",
            Self::Stale => "STALE",
            Self::Recertifying => "RECERTIFYING",
            Self::Revoked => "REVOKED",
        }
    }

    /// Whether this lifecycle transition is allowed by the Foundry state
    /// machine. Terminal states are deliberately omitted as sources.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Draft => matches!(next, Self::Building | Self::Rejected),
            Self::Building => matches!(next, Self::Testing | Self::Quarantined | Self::Rejected),
            Self::Testing => matches!(next, Self::Quarantined | Self::Rejected | Self::Certified),
            Self::Quarantined => matches!(next, Self::Building | Self::Rejected | Self::Revoked),
            Self::Rejected => false,
            Self::Certified => matches!(next, Self::Active | Self::Stale | Self::Revoked),
            Self::Active => matches!(next, Self::Stale | Self::Revoked),
            Self::Stale => matches!(next, Self::Recertifying | Self::Revoked),
            Self::Recertifying => {
                matches!(next, Self::Testing | Self::Quarantined | Self::Rejected)
            }
            Self::Revoked => false,
        }
    }
}

/// Result of one mandatory validation check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// The check completed successfully.
    Passed,
    /// The check completed and found a failure.
    Failed {
        /// Human/audit-readable reason for the failure.
        reason: String,
    },
    /// The gate never accepts an omitted check.
    NotRun,
}

impl CheckStatus {
    /// Creates a failed result with an audit reason.
    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }

    /// Whether this completed check passed.
    #[must_use]
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// The mandatory non-holdout validation results for a candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationEvidence {
    /// Hermetic/reproducible build result.
    pub hermetic_build: CheckStatus,
    /// Generated and ordinary test-suite result.
    pub tests: CheckStatus,
    /// Property-based check result.
    pub property_checks: CheckStatus,
    /// Fuzzing result.
    pub fuzz_checks: CheckStatus,
    /// Adversarial-evaluation result.
    pub adversarial_checks: CheckStatus,
}

impl ValidationEvidence {
    /// Constructs evidence where every required non-holdout check passed.
    #[must_use]
    pub const fn all_passed() -> Self {
        Self {
            hermetic_build: CheckStatus::Passed,
            tests: CheckStatus::Passed,
            property_checks: CheckStatus::Passed,
            fuzz_checks: CheckStatus::Passed,
            adversarial_checks: CheckStatus::Passed,
        }
    }
}

/// A check name used in a gate failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredCheck {
    /// Hermetic build check.
    HermeticBuild,
    /// Generated/ordinary tests.
    Tests,
    /// Property-based checks.
    PropertyChecks,
    /// Fuzz checks.
    FuzzChecks,
    /// Adversarial checks.
    AdversarialChecks,
}

impl RequiredCheck {
    /// Canonical audit name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HermeticBuild => "HERMETIC_BUILD",
            Self::Tests => "TESTS",
            Self::PropertyChecks => "PROPERTY_CHECKS",
            Self::FuzzChecks => "FUZZ_CHECKS",
            Self::AdversarialChecks => "ADVERSARIAL_CHECKS",
        }
    }
}

/// Result of an evaluator-held, hidden test suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenHoldout {
    suite_id: String,
    status: CheckStatus,
    verifier: VerifierLabel,
    hidden_from_candidate: bool,
}

impl HiddenHoldout {
    /// Records a hidden holdout result. The gate additionally checks that the
    /// result passed and that `verifier` meets its independence threshold.
    #[must_use]
    pub fn new(
        suite_id: impl Into<String>,
        status: CheckStatus,
        verifier: VerifierLabel,
        hidden_from_candidate: bool,
    ) -> Self {
        Self {
            suite_id: suite_id.into(),
            status,
            verifier,
            hidden_from_candidate,
        }
    }

    /// Stable hidden-suite identity.
    #[must_use]
    pub fn suite_id(&self) -> &str {
        &self.suite_id
    }

    /// The recorded holdout result.
    #[must_use]
    pub fn status(&self) -> &CheckStatus {
        &self.status
    }

    /// Label of the evaluator that ran the holdout.
    #[must_use]
    pub fn verifier(&self) -> &VerifierLabel {
        &self.verifier
    }

    /// Whether the suite was withheld from candidate authoring/generation.
    #[must_use]
    pub const fn is_hidden_from_candidate(&self) -> bool {
        self.hidden_from_candidate
    }
}

/// All non-certificate evidence the activation gate consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateEvidence {
    /// Hermetic build, tests, property, fuzz, and adversarial evidence.
    pub validation: ValidationEvidence,
    /// Separately evaluated hidden holdout evidence.
    pub holdout: HiddenHoldout,
}

impl GateEvidence {
    /// Packages required validation and holdout evidence.
    #[must_use]
    pub fn new(validation: ValidationEvidence, holdout: HiddenHoldout) -> Self {
        Self {
            validation,
            holdout,
        }
    }
}

/// Minimum verifier strengths required by an activation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationPolicy {
    /// Lowest certificate verifier level accepted by this gate.
    pub minimum_certificate_verifier: VerifierLevel,
    /// Lowest holdout verifier level accepted by this gate.
    pub minimum_holdout_verifier: VerifierLevel,
}

impl ActivationPolicy {
    /// Builds a policy with independently configurable certificate and holdout
    /// thresholds.
    #[must_use]
    pub const fn new(
        minimum_certificate_verifier: VerifierLevel,
        minimum_holdout_verifier: VerifierLevel,
    ) -> Self {
        Self {
            minimum_certificate_verifier,
            minimum_holdout_verifier,
        }
    }
}

impl Default for ActivationPolicy {
    fn default() -> Self {
        // V2 is the lowest canonical level whose evaluator is required to be
        // separated from candidate authoring.
        Self::new(VerifierLevel::V2, VerifierLevel::V2)
    }
}

/// Gate for candidate activation. It owns no authority-issuance operation.
#[derive(Clone, Debug)]
pub struct ActivationGate {
    policy: ActivationPolicy,
}

impl Default for ActivationGate {
    fn default() -> Self {
        Self::new(ActivationPolicy::default())
    }
}

impl ActivationGate {
    /// Creates a gate with an explicit policy.
    #[must_use]
    pub const fn new(policy: ActivationPolicy) -> Self {
        Self { policy }
    }

    /// Returns the gate's verifier thresholds.
    #[must_use]
    pub const fn policy(&self) -> ActivationPolicy {
        self.policy
    }

    /// Reviews a candidate. Failed gates return the candidate in
    /// [`FoundryState::Quarantined`]; only every successful check plus a valid,
    /// subject-bound certificate yields [`ActivationDecision::Activated`].
    ///
    /// # Errors
    ///
    /// Returns [`GateError`] only for an invalid lifecycle transition. Expected
    /// validation/certificate failures are normal `Blocked` decisions so their
    /// complete audit reasons remain available to callers.
    pub fn review(
        &self,
        candidate: Candidate,
        evidence: GateEvidence,
        certificate: Option<Certificate>,
        cert_verifier: &dyn CertVerifier,
        now: DateTime<Utc>,
    ) -> Result<ActivationDecision, GateError> {
        let candidate = enter_testing(candidate)?;
        let mut failures = validation_failures(&evidence.validation);
        holdout_failures(&evidence.holdout, self.policy, &mut failures);

        match certificate.as_ref() {
            None => failures.push(GateFailure::MissingCertificate),
            Some(certificate) => {
                if certificate.binding().subject_digest() != candidate.subject_digest() {
                    failures.push(GateFailure::CertificateSubjectMismatch);
                }
                let context = candidate
                    .certification()
                    .evaluation_context(now, self.policy.minimum_certificate_verifier);
                if let Err(error) = certificate.verify(cert_verifier, &context) {
                    failures.push(GateFailure::InvalidCertificate { error });
                }
            }
        }

        if !failures.is_empty() {
            let candidate = candidate
                .transition_to(FoundryState::Quarantined)
                .map_err(|from| GateError::InvalidTransition {
                    from,
                    to: FoundryState::Quarantined,
                })?;
            return Ok(ActivationDecision::Blocked(Box::new(
                QuarantinedCandidate {
                    candidate,
                    failures,
                },
            )));
        }

        // `None` is handled above, so success always carries the exact
        // certificate that passed verification.
        let certificate = certificate.expect("missing certificate is a gate failure");
        let candidate = candidate
            .transition_to(FoundryState::Certified)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Certified,
            })?
            .transition_to(FoundryState::Active)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Active,
            })?;

        Ok(ActivationDecision::Activated(Box::new(
            ActivatedCandidate {
                candidate,
                certificate,
            },
        )))
    }

    /// Convenience wrapper for callers that only need a successful activation.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Blocked`] for expected gate failures and preserves
    /// all failure categories; it never returns an active candidate without a
    /// valid certificate.
    pub fn activate(
        &self,
        candidate: Candidate,
        evidence: GateEvidence,
        certificate: Option<Certificate>,
        cert_verifier: &dyn CertVerifier,
        now: DateTime<Utc>,
    ) -> Result<ActivatedCandidate, GateError> {
        match self.review(candidate, evidence, certificate, cert_verifier, now)? {
            ActivationDecision::Activated(activated) => Ok(*activated),
            ActivationDecision::Blocked(blocked) => Err(GateError::Blocked {
                failures: blocked.failures,
            }),
        }
    }
}

fn enter_testing(candidate: Candidate) -> Result<Candidate, GateError> {
    match candidate.state() {
        FoundryState::Draft | FoundryState::Quarantined => candidate
            .transition_to(FoundryState::Building)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Building,
            })?
            .transition_to(FoundryState::Testing)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Testing,
            }),
        FoundryState::Building => candidate
            .transition_to(FoundryState::Testing)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Testing,
            }),
        FoundryState::Testing => Ok(candidate),
        FoundryState::Stale => candidate
            .transition_to(FoundryState::Recertifying)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Recertifying,
            })?
            .transition_to(FoundryState::Testing)
            .map_err(|from| GateError::InvalidTransition {
                from,
                to: FoundryState::Testing,
            }),
        FoundryState::Recertifying => {
            candidate
                .transition_to(FoundryState::Testing)
                .map_err(|from| GateError::InvalidTransition {
                    from,
                    to: FoundryState::Testing,
                })
        }
        state => Err(GateError::NotReviewableState { state }),
    }
}

fn validation_failures(evidence: &ValidationEvidence) -> Vec<GateFailure> {
    [
        (RequiredCheck::HermeticBuild, &evidence.hermetic_build),
        (RequiredCheck::Tests, &evidence.tests),
        (RequiredCheck::PropertyChecks, &evidence.property_checks),
        (RequiredCheck::FuzzChecks, &evidence.fuzz_checks),
        (
            RequiredCheck::AdversarialChecks,
            &evidence.adversarial_checks,
        ),
    ]
    .into_iter()
    .filter(|(_, status)| !status.is_passed())
    .map(|(check, status)| GateFailure::CheckNotPassed {
        check,
        status: status.clone(),
    })
    .collect()
}

fn holdout_failures(
    holdout: &HiddenHoldout,
    policy: ActivationPolicy,
    failures: &mut Vec<GateFailure>,
) {
    if holdout.suite_id.trim().is_empty() {
        failures.push(GateFailure::HoldoutSuiteMissing);
    }
    if !holdout.status.is_passed() {
        failures.push(GateFailure::HoldoutNotPassed {
            status: holdout.status.clone(),
        });
    }
    if !holdout.hidden_from_candidate {
        failures.push(GateFailure::HoldoutWasNotHidden);
    }
    if !holdout.verifier.is_separated_from_candidate() {
        failures.push(GateFailure::HoldoutNotSeparated);
    }
    let actual = holdout.verifier.level();
    if actual < policy.minimum_holdout_verifier {
        failures.push(GateFailure::HoldoutVerifierTooWeak {
            required: policy.minimum_holdout_verifier,
            actual,
        });
    }
}

/// Outcome of a non-authority activation review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationDecision {
    /// Every required check, hidden holdout, and certificate check passed.
    Activated(Box<ActivatedCandidate>),
    /// One or more checks failed; the candidate remains quarantined.
    Blocked(Box<QuarantinedCandidate>),
}

impl ActivationDecision {
    /// Whether this decision activated a candidate.
    #[must_use]
    pub const fn is_activated(&self) -> bool {
        matches!(self, Self::Activated(_))
    }
}

/// A candidate that passed the activation gate, paired with its certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedCandidate {
    candidate: Candidate,
    certificate: Certificate,
}

impl ActivatedCandidate {
    /// Candidate whose state is [`FoundryState::Active`].
    #[must_use]
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// The exact certificate verified by this gate.
    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Emits the candidate and its certificate as separate values. This is the
    /// Foundry's complete successful output surface.
    #[must_use]
    pub fn into_parts(self) -> (Candidate, Certificate) {
        (self.candidate, self.certificate)
    }
}

/// A candidate stopped before activation, with every blocking reason retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedCandidate {
    candidate: Candidate,
    failures: Vec<GateFailure>,
}

impl QuarantinedCandidate {
    /// Candidate whose state is [`FoundryState::Quarantined`].
    #[must_use]
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// All failures that blocked promotion.
    #[must_use]
    pub fn failures(&self) -> &[GateFailure] {
        &self.failures
    }

    /// Consumes the outcome to retry the candidate after remediation.
    #[must_use]
    pub fn into_candidate(self) -> Candidate {
        self.candidate
    }
}

/// A concrete reason activation was blocked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateFailure {
    /// A mandatory generated validation check failed or was omitted.
    CheckNotPassed {
        /// Check that did not pass.
        check: RequiredCheck,
        /// Its recorded status.
        status: CheckStatus,
    },
    /// A holdout must have a stable identity.
    HoldoutSuiteMissing,
    /// The hidden suite failed or was not run.
    HoldoutNotPassed {
        /// Its recorded status.
        status: CheckStatus,
    },
    /// A suite visible to generation is not a hidden holdout.
    HoldoutWasNotHidden,
    /// The holdout evaluator shares the candidate authoring context.
    HoldoutNotSeparated,
    /// The holdout label was lower than policy permits.
    HoldoutVerifierTooWeak {
        /// Minimum required verifier level.
        required: VerifierLevel,
        /// Actual evaluator label.
        actual: VerifierLevel,
    },
    /// Active status always requires an independently checked certificate.
    MissingCertificate,
    /// The certificate was issued for a different immutable candidate subject.
    CertificateSubjectMismatch,
    /// The certificate had an invalid signature, was stale/expired, or had too
    /// weak a verifier level.
    InvalidCertificate {
        /// Underlying certificate verification failure.
        error: CertError,
    },
}

/// Gate operation failure, distinct from an expected blocked decision.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GateError {
    /// A candidate in this state cannot enter evaluation.
    #[error("candidate in state {state:?} cannot be reviewed")]
    NotReviewableState {
        /// Current lifecycle state.
        state: FoundryState,
    },
    /// An internal lifecycle path did not match the state machine.
    #[error("invalid Foundry transition {from:?} -> {to:?}")]
    InvalidTransition {
        /// State before the attempted transition.
        from: FoundryState,
        /// Requested next state.
        to: FoundryState,
    },
    /// Convenience activation was requested but a review gate blocked it.
    #[error("candidate activation blocked: {failures:?}")]
    Blocked {
        /// All gate failures retained from review.
        failures: Vec<GateFailure>,
    },
}
