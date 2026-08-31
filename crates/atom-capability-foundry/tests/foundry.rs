//! ATOM-FND-001/002/003 acceptance coverage, including ATOM-VT-010.

use atom_artifact::{Artifact, Provenance, Sbom};
use atom_capability_foundry::{
    ActivationDecision, ActivationGate, Candidate, CandidateCertificationMaterial,
    CandidateInterface, CheckStatus, FoundryState, GateEvidence, GateFailure, HiddenHoldout,
    ToolCandidateSpec, ToolFoundry, ToolInterface, ValidationEvidence, VerificationMethod,
    VerifierFoundry, VerifierInput, VerifierLevel, WorkflowError, WorkflowFoundry,
    WorkflowOutputTypes, WorkflowSpec, WorkflowStep, WorkflowTransition, WorkflowTransitionKind,
};
use atom_cert::{
    BehaviorManifestV2, BindingParams, Certificate, CertificateBinding, EnvironmentScope,
    EvaluationSuite, HmacSha256CertVerifier,
};
use chrono::{DateTime, TimeZone, Utc};
use proptest::prelude::*;
use serde_json::json;

const CERT_KEY: &[u8] = b"foundry-test-cert-key";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap()
}

fn cert_verifier() -> HmacSha256CertVerifier {
    HmacSha256CertVerifier::new("foundry-cert-verifier", CERT_KEY)
}

fn artifact(seed: &str) -> Artifact {
    Artifact::seal(
        format!("generated implementation: {seed}").into_bytes(),
        Provenance::new(
            "capability-foundry",
            &format!("source:{seed}"),
            "hermetic:v1",
        ),
        Sbom::new([]),
        "artifact-test-key",
        b"artifact-test-key",
    )
}

fn manifest(seed: &str) -> BehaviorManifestV2 {
    BehaviorManifestV2::new(json!({
        "schema_version": "2.0.0",
        "cognition_runtime": "atom-native",
        "runtime_version": "0.0.0-alpha.0",
        "provider": "test-provider",
        "model_exact_id": format!("test-model-{seed}"),
        "sampling_parameters": { "temperature": "0" },
        "system_prompt_digest": "system",
        "instruction_bundle_digest": "instructions",
        "context_compiler_version": "1.0.0",
        "context_snapshot_digest": "context",
        "capability_contract_digests": ["contract"],
        "tool_schema_digests": ["tool-schema"],
        "policy_bundle_digest": "policy",
        "grant_semantics_version": "1.0.0",
        "memory_snapshot_digest": "memory",
        "epistemic_policy_version": "1.0.0",
        "verifier_bundle_digest": "verifier",
        "connector_versions": ["connector"],
        "sandbox_runtime": "test-sandbox",
        "worker_image_digests": ["worker"],
        "secret_reference_generations": ["secret-gen"],
        "compatibility_profile_digests": ["compatibility"],
        "environment_fingerprint": "test-env"
    }))
    .unwrap()
}

fn certification(seed: &str) -> CandidateCertificationMaterial {
    CandidateCertificationMaterial::new(
        manifest(seed),
        EvaluationSuite::new(json!({
            "suite": "generated-and-holdout",
            "candidate": seed,
            "holdout": "held-by-evaluator"
        }))
        .unwrap(),
        EnvironmentScope::new(json!({ "os": "linux", "sandbox": "hermetic" })).unwrap(),
    )
}

fn candidate(seed: &str) -> Candidate {
    Candidate::new(
        format!("candidate-{seed}"),
        CandidateInterface::Tool(ToolInterface::new("echo", "Request", "Response")),
        format!("implementation-{seed}"),
        artifact(seed),
        certification(seed),
    )
    .unwrap()
}

fn certificate_for(candidate: &Candidate, level: VerifierLevel) -> Certificate {
    let binding = CertificateBinding::new(BindingParams {
        certificate_id: format!("certificate-for-{}", candidate.id()),
        subject_digest: candidate.subject_digest(),
        behavior_manifest_digest: candidate.certification().behavior_manifest().digest(),
        evaluation_suite_digest: candidate.certification().evaluation_suite().digest(),
        environment_scope: candidate.certification().environment_scope().clone(),
        verifier_level: level,
        verifier_id: "foundry-cert-verifier".into(),
        issued_at: Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap(),
        valid_until: Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap(),
        evidence_refs: vec!["evidence/holdout-vt010".into()],
    });
    Certificate::issue(binding, &cert_verifier()).unwrap()
}

fn independent_holdout(status: CheckStatus) -> HiddenHoldout {
    let label = VerifierFoundry::new()
        .label(VerifierInput::new(
            "holdout-evaluator",
            "candidate-generator-context",
            "isolated-evaluator-context",
            VerificationMethod::IndependentModel,
            None,
        ))
        .unwrap();
    HiddenHoldout::new("VT-010-hidden", status, label, true)
}

fn passing_evidence() -> GateEvidence {
    GateEvidence::new(
        ValidationEvidence::all_passed(),
        independent_holdout(CheckStatus::Passed),
    )
}

#[test]
fn tool_foundry_synthesizes_multiple_draft_candidates() {
    let foundry = ToolFoundry::new();
    let candidates = foundry
        .synthesize([
            ToolCandidateSpec {
                candidate_id: "candidate-a".into(),
                interface: ToolInterface::new("echo", "Request", "Response"),
                implementation_id: "implementation-a".into(),
                artifact: artifact("a"),
                certification: certification("a"),
            },
            ToolCandidateSpec {
                candidate_id: "candidate-b".into(),
                interface: ToolInterface::new("echo-v2", "Request", "Response"),
                implementation_id: "implementation-b".into(),
                artifact: artifact("b"),
                certification: certification("b"),
            },
        ])
        .unwrap();

    assert_eq!(candidates.len(), 2);
    assert!(candidates
        .iter()
        .all(|candidate| candidate.state() == FoundryState::Draft));
}

/// ATOM-VT-010: generated checks can pass while a hidden holdout fails; the
/// candidate must be quarantined rather than promoted.
#[test]
fn vt010_hidden_holdout_failure_blocks_promotion() {
    let candidate = candidate("holdout-fails");
    let certificate = certificate_for(&candidate, VerifierLevel::V2);
    let evidence = GateEvidence::new(
        ValidationEvidence::all_passed(),
        independent_holdout(CheckStatus::failed("hidden boundary input regressed")),
    );

    let decision = ActivationGate::default()
        .review(
            candidate,
            evidence,
            Some(certificate),
            &cert_verifier(),
            now(),
        )
        .unwrap();

    let ActivationDecision::Blocked(blocked) = decision else {
        panic!("a hidden holdout failure must block activation");
    };
    assert_eq!(blocked.candidate().state(), FoundryState::Quarantined);
    assert!(blocked
        .failures()
        .iter()
        .any(|failure| matches!(failure, GateFailure::HoldoutNotPassed { .. })));
}

/// ATOM-INV-008: all non-certificate gates passing is still insufficient for
/// activation; the certificate is mandatory.
#[test]
fn certificate_is_required_for_active() {
    let decision = ActivationGate::default()
        .review(
            candidate("missing-cert"),
            passing_evidence(),
            None,
            &cert_verifier(),
            now(),
        )
        .unwrap();

    let ActivationDecision::Blocked(blocked) = decision else {
        panic!("an uncertified candidate must not become active");
    };
    assert_eq!(blocked.candidate().state(), FoundryState::Quarantined);
    assert!(blocked
        .failures()
        .contains(&GateFailure::MissingCertificate));
}

#[test]
fn valid_subject_bound_certificate_allows_active_candidate() {
    let candidate = candidate("certified");
    let certificate = certificate_for(&candidate, VerifierLevel::V2);

    let activated = ActivationGate::default()
        .activate(
            candidate,
            passing_evidence(),
            Some(certificate),
            &cert_verifier(),
            now(),
        )
        .unwrap();

    assert_eq!(activated.candidate().state(), FoundryState::Active);
    assert_eq!(
        activated.certificate().binding().subject_digest(),
        activated.candidate().subject_digest()
    );
}

#[test]
fn certificate_for_a_different_candidate_is_blocked() {
    let cand_a = candidate("candidate-a");
    let mismatched_certificate = certificate_for(&candidate("candidate-b"), VerifierLevel::V2);

    let decision = ActivationGate::default()
        .review(
            cand_a,
            passing_evidence(),
            Some(mismatched_certificate),
            &cert_verifier(),
            now(),
        )
        .unwrap();

    let ActivationDecision::Blocked(blocked) = decision else {
        panic!("a certificate for another candidate must be blocked");
    };
    assert!(blocked
        .failures()
        .contains(&GateFailure::CertificateSubjectMismatch));
}

#[test]
fn verifier_foundry_uses_v0_to_v5_and_requires_separation() {
    let foundry = VerifierFoundry::new();
    let self_report = foundry
        .label(VerifierInput::new(
            "self",
            "candidate-context",
            "candidate-context",
            VerificationMethod::SelfReport,
            None,
        ))
        .unwrap();
    assert_eq!(self_report.level(), VerifierLevel::V0);

    let formal = foundry
        .label(VerifierInput::new(
            "proof-checker",
            "candidate-context",
            "proof-context",
            VerificationMethod::FormalOrCryptographic,
            Some("proof:sha256:abc".into()),
        ))
        .unwrap();
    assert_eq!(formal.level(), VerifierLevel::V5);
    assert!(formal.is_separated_from_candidate());

    assert!(foundry
        .label(VerifierInput::new(
            "not-independent",
            "same-context",
            "same-context",
            VerificationMethod::IndependentModel,
            None,
        ))
        .is_err());
}

fn complete_workflow_spec() -> WorkflowSpec {
    let outcomes = WorkflowOutputTypes::new(
        "Response",
        "Failure",
        "Timeout",
        "Retry",
        "Reconcile",
        "Compensate",
    );
    WorkflowSpec {
        workflow_id: "durable-echo".into(),
        start_step: "execute".into(),
        input_type: "Request".into(),
        output_type: "Response".into(),
        steps: vec![
            WorkflowStep::activity("execute", "Request", outcomes),
            WorkflowStep::terminal("succeeded", "Response"),
            WorkflowStep::terminal("failed", "Failure"),
            WorkflowStep::terminal("timed-out", "Timeout"),
            WorkflowStep::terminal("retrying", "Retry"),
            WorkflowStep::terminal("reconciling", "Reconcile"),
            WorkflowStep::terminal("compensating", "Compensate"),
        ],
        transitions: vec![
            WorkflowTransition::new(
                "execute",
                WorkflowTransitionKind::Success,
                "succeeded",
                "Response",
            ),
            WorkflowTransition::new(
                "execute",
                WorkflowTransitionKind::Failure,
                "failed",
                "Failure",
            ),
            WorkflowTransition::new(
                "execute",
                WorkflowTransitionKind::Timeout,
                "timed-out",
                "Timeout",
            ),
            WorkflowTransition::new(
                "execute",
                WorkflowTransitionKind::Retry,
                "retrying",
                "Retry",
            ),
            WorkflowTransition::new(
                "execute",
                WorkflowTransitionKind::Reconciliation,
                "reconciling",
                "Reconcile",
            ),
            WorkflowTransition::new(
                "execute",
                WorkflowTransitionKind::Compensation,
                "compensating",
                "Compensate",
            ),
        ],
    }
}

#[test]
fn workflow_foundry_requires_explicit_typed_recovery_transitions() {
    let workflow = WorkflowFoundry::new()
        .synthesize(complete_workflow_spec())
        .unwrap();
    assert!(workflow.is_durable());
    assert_eq!(
        workflow.transitions().len(),
        WorkflowTransitionKind::ALL.len()
    );

    let mut missing_compensation = complete_workflow_spec();
    missing_compensation.transitions.pop();
    assert!(matches!(
        WorkflowFoundry::new().synthesize(missing_compensation),
        Err(WorkflowError::MissingTransition {
            kind: WorkflowTransitionKind::Compensation,
            ..
        })
    ));
}

proptest! {
    /// The gate is all-of: any one required generated check failing blocks
    /// promotion even with a valid certificate and passing hidden holdout.
    #[test]
    fn property_any_required_check_failure_blocks_promotion(failing_check in 0usize..5) {
        let candidate = candidate("property");
        let certificate = certificate_for(&candidate, VerifierLevel::V2);
        let mut validation = ValidationEvidence::all_passed();
        match failing_check {
            0 => validation.hermetic_build = CheckStatus::failed("build"),
            1 => validation.tests = CheckStatus::failed("tests"),
            2 => validation.property_checks = CheckStatus::failed("property"),
            3 => validation.fuzz_checks = CheckStatus::failed("fuzz"),
            4 => validation.adversarial_checks = CheckStatus::failed("adversarial"),
            _ => unreachable!("strategy is bounded"),
        }

        let decision = ActivationGate::default()
            .review(
                candidate,
                GateEvidence::new(validation, independent_holdout(CheckStatus::Passed)),
                Some(certificate),
                &cert_verifier(),
                now(),
            )
            .unwrap();
        prop_assert!(matches!(decision, ActivationDecision::Blocked(_)));
    }
}
