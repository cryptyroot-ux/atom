//! CER-001 certificate invariants (RED → GREEN).
//!
//! A certificate binds an *exact* BehaviorManifestV2 digest, evaluation-suite
//! digest, environment scope and verifier. A material change to any of the
//! bound artifacts makes the certificate STALE and therefore unusable, and a
//! certificate presented against the wrong verifier is denied.

use atom_cert::{
    BehaviorManifestV2, BindingParams, CertError, Certificate, CertificateBinding,
    EnvironmentScope, EvaluationContext, EvaluationSuite, HmacSha256CertVerifier, StaleReason,
    VerifierLevel,
};
use chrono::{TimeZone, Utc};
use serde_json::json;

fn manifest_value() -> serde_json::Value {
    json!({
        "schema_version": "2.0.0",
        "cognition_runtime": "atom-native",
        "runtime_version": "0.0.0-alpha.0",
        "provider": "anthropic",
        "model_exact_id": "claude-opus-4-8-thinking",
        "sampling_parameters": { "temperature": "0", "top_p": "1" },
        "system_prompt_digest": "aa",
        "instruction_bundle_digest": "bb",
        "context_compiler_version": "1.0.0",
        "context_snapshot_digest": "cc",
        "capability_contract_digests": ["c1"],
        "tool_schema_digests": ["t1"],
        "policy_bundle_digest": "dd",
        "grant_semantics_version": "1.0.0",
        "memory_snapshot_digest": "ee",
        "epistemic_policy_version": "1.0.0",
        "verifier_bundle_digest": "ff",
        "connector_versions": ["conn-1"],
        "sandbox_runtime": "native",
        "worker_image_digests": ["img-1"],
        "secret_reference_generations": ["gen-1"],
        "compatibility_profile_digests": ["prof-1"],
        "environment_fingerprint": "fp-1"
    })
}

fn manifest() -> BehaviorManifestV2 {
    BehaviorManifestV2::new(manifest_value()).unwrap()
}

fn eval_suite() -> EvaluationSuite {
    EvaluationSuite::new(json!({ "suite": "smoke", "cases": ["c1", "c2"] })).unwrap()
}

fn env_scope() -> EnvironmentScope {
    EnvironmentScope::new(json!({ "os": "linux", "arch": "x86_64" })).unwrap()
}

fn verifier() -> HmacSha256CertVerifier {
    HmacSha256CertVerifier::new("verifier-A", b"seal-key-A")
}

fn binding(level: VerifierLevel) -> CertificateBinding {
    let issued_at = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
    let valid_until = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
    CertificateBinding::new(BindingParams {
        certificate_id: "cert-1".into(),
        subject_digest: atom_ledger::domain_digest("TEST-SUBJECT:", b"workload-A"),
        behavior_manifest_digest: manifest().digest(),
        evaluation_suite_digest: eval_suite().digest(),
        environment_scope: env_scope(),
        verifier_level: level,
        verifier_id: "verifier-A".into(),
        issued_at,
        valid_until,
        evidence_refs: vec!["ev-1".into()],
    })
}

/// The moment, manifest, eval and env the cert is evaluated against.
fn context_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap()
}

fn matching_context(required: VerifierLevel) -> EvaluationContext {
    EvaluationContext::new(
        manifest().digest(),
        eval_suite().digest(),
        &env_scope(),
        context_now(),
        required,
    )
}

#[test]
fn manifest_requires_all_bmv2_fields() {
    // full manifest is accepted
    assert!(BehaviorManifestV2::new(manifest_value()).is_ok());

    // drop one required field → rejected
    let mut broken = manifest_value();
    broken
        .as_object_mut()
        .unwrap()
        .remove("environment_fingerprint");
    assert!(matches!(
        BehaviorManifestV2::new(broken),
        Err(CertError::MissingManifestField { .. })
    ));

    // a non-object is rejected
    assert!(matches!(
        BehaviorManifestV2::new(json!("not-an-object")),
        Err(CertError::NotAnObject)
    ));
}

#[test]
fn valid_certificate_verifies() {
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();
    assert!(cert
        .verify(&verifier(), &matching_context(VerifierLevel::V0))
        .is_ok());
    assert!(cert
        .stale_reason(&matching_context(VerifierLevel::V0))
        .is_none());
}

#[test]
fn binding_digest_binds_every_field() {
    let base = binding(VerifierLevel::V3).digest();

    // a different verifier level yields a different signed digest
    assert_ne!(base, binding(VerifierLevel::V4).digest());

    // a different manifest yields a different digest
    let mut other_manifest = manifest_value();
    other_manifest["model_exact_id"] = json!("some-other-model");
    let other = CertificateBinding::new(BindingParams {
        certificate_id: "cert-1".into(),
        subject_digest: atom_ledger::domain_digest("TEST-SUBJECT:", b"workload-A"),
        behavior_manifest_digest: BehaviorManifestV2::new(other_manifest).unwrap().digest(),
        evaluation_suite_digest: eval_suite().digest(),
        environment_scope: env_scope(),
        verifier_level: VerifierLevel::V3,
        verifier_id: "verifier-A".into(),
        issued_at: Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap(),
        valid_until: Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap(),
        evidence_refs: vec!["ev-1".into()],
    });
    assert_ne!(base, other.digest());
}

#[test]
fn wrong_verifier_is_denied() {
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();

    // a different verifier identity
    let other = HmacSha256CertVerifier::new("verifier-B", b"seal-key-B");
    assert!(matches!(
        cert.verify(&other, &matching_context(VerifierLevel::V0)),
        Err(CertError::WrongVerifier)
    ));

    // an impostor reusing the verifier id but not the key material
    let impostor = HmacSha256CertVerifier::new("verifier-A", b"forged-key");
    assert!(matches!(
        cert.verify(&impostor, &matching_context(VerifierLevel::V0)),
        Err(CertError::WrongVerifier)
    ));
}

#[test]
fn issuing_with_a_mismatched_verifier_is_rejected() {
    let wrong = HmacSha256CertVerifier::new("verifier-B", b"seal-key-B");
    assert!(matches!(
        Certificate::issue(binding(VerifierLevel::V3), &wrong),
        Err(CertError::VerifierMismatch { .. })
    ));
}

#[test]
fn manifest_material_change_makes_cert_stale() {
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();

    let mut changed = manifest_value();
    changed["model_exact_id"] = json!("upgraded-model");
    let ctx = EvaluationContext::new(
        BehaviorManifestV2::new(changed).unwrap().digest(),
        eval_suite().digest(),
        &env_scope(),
        context_now(),
        VerifierLevel::V0,
    );

    assert_eq!(cert.stale_reason(&ctx), Some(StaleReason::ManifestChanged));
    assert!(matches!(
        cert.verify(&verifier(), &ctx),
        Err(CertError::Stale {
            reason: StaleReason::ManifestChanged
        })
    ));
}

#[test]
fn eval_suite_material_change_makes_cert_stale() {
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();

    let changed_eval = EvaluationSuite::new(json!({ "suite": "smoke", "cases": ["c1"] })).unwrap();
    let ctx = EvaluationContext::new(
        manifest().digest(),
        changed_eval.digest(),
        &env_scope(),
        context_now(),
        VerifierLevel::V0,
    );

    assert_eq!(
        cert.stale_reason(&ctx),
        Some(StaleReason::EvaluationSuiteChanged)
    );
    assert!(matches!(
        cert.verify(&verifier(), &ctx),
        Err(CertError::Stale {
            reason: StaleReason::EvaluationSuiteChanged
        })
    ));
}

#[test]
fn environment_drift_makes_cert_stale() {
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();

    let drifted = EnvironmentScope::new(json!({ "os": "linux", "arch": "arm64" })).unwrap();
    let ctx = EvaluationContext::new(
        manifest().digest(),
        eval_suite().digest(),
        &drifted,
        context_now(),
        VerifierLevel::V0,
    );

    assert_eq!(cert.stale_reason(&ctx), Some(StaleReason::EnvironmentDrift));
    assert!(matches!(
        cert.verify(&verifier(), &ctx),
        Err(CertError::Stale {
            reason: StaleReason::EnvironmentDrift
        })
    ));
}

#[test]
fn insufficient_verifier_level_is_denied() {
    // cert certified at V1, consumer requires V3
    let cert = Certificate::issue(binding(VerifierLevel::V1), &verifier()).unwrap();
    assert!(matches!(
        cert.verify(&verifier(), &matching_context(VerifierLevel::V3)),
        Err(CertError::InsufficientVerifier { .. })
    ));
}

#[test]
fn expired_certificate_is_denied() {
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();
    let after_expiry = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    let ctx = EvaluationContext::new(
        manifest().digest(),
        eval_suite().digest(),
        &env_scope(),
        after_expiry,
        VerifierLevel::V0,
    );
    assert!(matches!(
        cert.verify(&verifier(), &ctx),
        Err(CertError::Expired)
    ));
}

#[test]
fn certificate_verifies_without_the_issuer_instance() {
    // Issue with one signer instance; verify with an independently-built verifier
    // holding the same published key. Determinism: cert = signature(message).
    let cert = Certificate::issue(binding(VerifierLevel::V3), &verifier()).unwrap();
    let independent = HmacSha256CertVerifier::new("verifier-A", b"seal-key-A");
    assert!(cert
        .verify(&independent, &matching_context(VerifierLevel::V0))
        .is_ok());
}
