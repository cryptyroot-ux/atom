//! atom-cert: behavior certificate binding (CER-001 / CRT-001, SUP-001).
//!
//! Normative source: `spec/` (precedence 1).
//!
//! A [`Certificate`] seals an *exact* binding: the digest of a
//! [`BehaviorManifestV2`], the digest of the [`EvaluationSuite`] it was
//! certified against, the [`EnvironmentScope`] it is scoped to, and the
//! verifier ([`VerifierLevel`] + verifier id) that vouched for it. The seal is a
//! deterministic signature over the binding digest, so a certificate is
//! `signature(message)` and can be checked by anyone holding the verification
//! key — the issuer instance need not be trusted or even present.
//!
//! *Material change ⇒ stale.* Verification is always relative to an
//! [`EvaluationContext`] describing what is true *now*. If the live manifest,
//! evaluation suite or environment no longer matches what the certificate
//! bound, the certificate is stale ([`StaleReason`]) and unusable — a
//! certificate cannot outlive the artifacts it vouches for.

#![forbid(unsafe_code)]

use atom_ledger::{canonicalize, domain_digest, Hash};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::fmt;
use thiserror::Error;

pub use atom_evidence::VerifierLevel;

/// Domain tag for a [`BehaviorManifestV2`] digest.
pub const MANIFEST_DOMAIN: &str = "ATOM-BMANIFEST-v2:";
/// Domain tag for an [`EvaluationSuite`] digest.
pub const EVAL_SUITE_DOMAIN: &str = "ATOM-EVALSUITE-v1:";
/// Domain tag for an [`EnvironmentScope`] digest.
pub const ENV_SCOPE_DOMAIN: &str = "ATOM-ENVSCOPE-v1:";
/// Domain tag for a [`CertificateBinding`] digest — the signed message.
pub const BINDING_DOMAIN: &str = "ATOM-CERT-BINDING-v1:";
/// Domain tag mixed into the HMAC seal so a cert signature can never collide
/// with any other MAC in the system.
pub const CERT_SEAL_DOMAIN: &str = "ATOM-CERT-SEAL-v1:";

/// The embedded BehaviorManifestV2 schema (normative required-field set).
const MANIFEST_SCHEMA: &str =
    include_str!("../../../spec/schemas/behavior-manifest-v2.schema.json");

/// Errors from constructing, issuing or verifying a certificate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertError {
    /// A wrapped artifact value was not a JSON object.
    #[error("value is not a JSON object")]
    NotAnObject,

    /// The manifest is missing a field the schema marks required.
    #[error("manifest is missing required field `{field}`")]
    MissingManifestField {
        /// The absent required field.
        field: String,
    },

    /// A value could not be canonicalized under RFC 8785.
    #[error("value is not canonicalizable (RFC 8785): {0}")]
    Canonicalization(String),

    /// The presented verifier is not the one bound by the certificate, or its
    /// signature does not check out.
    #[error("verifier identity or seal does not match the certificate")]
    WrongVerifier,

    /// Issuing was attempted with a signer whose id differs from the binding.
    #[error("signer `{signer}` does not match the binding verifier `{binding}`")]
    VerifierMismatch {
        /// The signer that attempted to issue.
        signer: String,
        /// The verifier id the binding names.
        binding: String,
    },

    /// The evaluation moment is past the certificate's validity window.
    #[error("certificate has expired")]
    Expired,

    /// The evaluation moment precedes the certificate's validity window.
    #[error("certificate is not yet valid")]
    NotYetValid,

    /// A bound artifact changed materially; the certificate is stale.
    #[error("certificate is stale: {reason}")]
    Stale {
        /// Which bound artifact drifted.
        reason: StaleReason,
    },

    /// The certificate's verifier level is below what the consumer requires.
    #[error("insufficient verifier level: certified {actual}, required {required}")]
    InsufficientVerifier {
        /// Level the consumer demands.
        required: VerifierLevel,
        /// Level the certificate actually carries.
        actual: VerifierLevel,
    },
}

/// Why a certificate is stale: the one bound artifact that drifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason {
    /// The live BehaviorManifestV2 digest differs from the bound one.
    ManifestChanged,
    /// The live evaluation-suite digest differs from the bound one.
    EvaluationSuiteChanged,
    /// The live environment scope differs from the bound one.
    EnvironmentDrift,
}

impl StaleReason {
    /// Canonical string form (stored in a binding's `stale_conditions`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManifestChanged => "BEHAVIOR_MANIFEST_DIGEST_CHANGED",
            Self::EvaluationSuiteChanged => "EVALUATION_SUITE_DIGEST_CHANGED",
            Self::EnvironmentDrift => "ENVIRONMENT_DRIFT",
        }
    }
}

impl fmt::Display for StaleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Bound artifacts: each wraps a JSON value and precomputes its domain digest so
// the binding digest is cheap and infallible.
// ---------------------------------------------------------------------------

/// A behavior manifest (schema v2). Its digest is what a certificate binds; a
/// single changed field changes the digest and so invalidates the certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BehaviorManifestV2 {
    value: serde_json::Value,
    digest: Hash,
}

impl BehaviorManifestV2 {
    /// Validate that `value` is an object carrying every schema-required field,
    /// then bind its content-address.
    ///
    /// # Errors
    ///
    /// * [`CertError::NotAnObject`] if `value` is not a JSON object.
    /// * [`CertError::MissingManifestField`] if a required field is absent.
    /// * [`CertError::Canonicalization`] if the value cannot be canonicalized.
    pub fn new(value: serde_json::Value) -> Result<Self, CertError> {
        let object = value.as_object().ok_or(CertError::NotAnObject)?;
        for field in required_manifest_fields() {
            if !object.contains_key(&field) {
                return Err(CertError::MissingManifestField { field });
            }
        }
        let bytes = canonicalize(&value).map_err(|e| CertError::Canonicalization(e.to_string()))?;
        Ok(Self {
            digest: domain_digest(MANIFEST_DOMAIN, &bytes),
            value,
        })
    }

    /// The manifest's content-address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        self.digest
    }

    /// The underlying manifest value.
    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// Required-field set, read from the embedded schema.
fn required_manifest_fields() -> Vec<String> {
    let schema: serde_json::Value =
        serde_json::from_str(MANIFEST_SCHEMA).expect("embedded manifest schema is valid JSON");
    schema["required"]
        .as_array()
        .expect("manifest schema has a `required` array")
        .iter()
        .map(|field| field.as_str().expect("`required` entries are strings").to_owned())
        .collect()
}

/// The evaluation suite a certificate was certified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationSuite {
    value: serde_json::Value,
    digest: Hash,
}

impl EvaluationSuite {
    /// Bind an evaluation suite by its content-address.
    ///
    /// # Errors
    ///
    /// [`CertError::NotAnObject`] / [`CertError::Canonicalization`].
    pub fn new(value: serde_json::Value) -> Result<Self, CertError> {
        let digest = object_digest(&value, EVAL_SUITE_DOMAIN)?;
        Ok(Self { value, digest })
    }

    /// The suite's content-address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        self.digest
    }

    /// The underlying suite value.
    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// The environment scope a certificate is valid within.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentScope {
    value: serde_json::Value,
    digest: Hash,
}

impl EnvironmentScope {
    /// Bind an environment scope by its content-address.
    ///
    /// # Errors
    ///
    /// [`CertError::NotAnObject`] / [`CertError::Canonicalization`].
    pub fn new(value: serde_json::Value) -> Result<Self, CertError> {
        let digest = object_digest(&value, ENV_SCOPE_DOMAIN)?;
        Ok(Self { value, digest })
    }

    /// The scope's content-address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        self.digest
    }

    /// The underlying scope value.
    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// Validate an object value and return its domain digest.
fn object_digest(value: &serde_json::Value, domain: &str) -> Result<Hash, CertError> {
    if !value.is_object() {
        return Err(CertError::NotAnObject);
    }
    let bytes = canonicalize(value).map_err(|e| CertError::Canonicalization(e.to_string()))?;
    Ok(domain_digest(domain, &bytes))
}

// ---------------------------------------------------------------------------
// Verifier seal (deterministic signature). Mirrors atom-ledger's signer.
// ---------------------------------------------------------------------------

/// A certificate seal: which key signed, and the signature bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    key_id: String,
    bytes: Vec<u8>,
}

impl Signature {
    /// The id of the key that produced this seal.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The raw signature bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Never render seal bytes.
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Seals certificate bindings and verifies seals it did not create.
///
/// Symmetric by default ([`HmacSha256CertVerifier`]); an asymmetric verifier is
/// just another implementation of this trait.
pub trait CertVerifier: Send + Sync {
    /// Identifier of the verifier key.
    fn key_id(&self) -> &str;

    /// Sign a binding digest.
    fn sign(&self, digest: &Hash) -> Vec<u8>;

    /// Verify a signature claiming to come from `key_id`. Must reject an unknown
    /// key id and compare the signature in constant time.
    fn verify(&self, key_id: &str, digest: &Hash, signature: &[u8]) -> bool;
}

/// HMAC-SHA256 seal over `ATOM-CERT-SEAL-v1: || digest`.
pub struct HmacSha256CertVerifier {
    key_id: String,
    key: Vec<u8>,
}

impl HmacSha256CertVerifier {
    /// Build a verifier from a key id and key material.
    pub fn new(key_id: impl Into<String>, key: impl AsRef<[u8]>) -> Self {
        Self {
            key_id: key_id.into(),
            key: key.as_ref().to_vec(),
        }
    }

    fn mac(&self, digest: &Hash) -> hmac::Hmac<sha2::Sha256> {
        use hmac::Mac as _;
        let mut mac = <hmac::Hmac<sha2::Sha256>>::new_from_slice(&self.key)
            .expect("HMAC accepts a key of any length");
        mac.update(CERT_SEAL_DOMAIN.as_bytes());
        mac.update(digest.as_bytes());
        mac
    }
}

/// Never render the key material.
impl fmt::Debug for HmacSha256CertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSha256CertVerifier")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl CertVerifier for HmacSha256CertVerifier {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, digest: &Hash) -> Vec<u8> {
        use hmac::Mac as _;
        self.mac(digest).finalize().into_bytes().to_vec()
    }

    fn verify(&self, key_id: &str, digest: &Hash, signature: &[u8]) -> bool {
        use hmac::Mac as _;
        key_id == self.key_id && self.mac(digest).verify_slice(signature).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Binding + certificate.
// ---------------------------------------------------------------------------

/// Inputs to a [`CertificateBinding`]. A struct keeps the constructor readable
/// and the bound field set explicit.
pub struct BindingParams {
    /// Stable id of this certificate.
    pub certificate_id: String,
    /// Content-address of the certified subject/workload.
    pub subject_digest: Hash,
    /// Digest of the certified [`BehaviorManifestV2`].
    pub behavior_manifest_digest: Hash,
    /// Digest of the [`EvaluationSuite`] used to certify.
    pub evaluation_suite_digest: Hash,
    /// Environment scope the certificate is valid within.
    pub environment_scope: EnvironmentScope,
    /// Verifier independence level attained.
    pub verifier_level: VerifierLevel,
    /// Id of the verifier that must seal and check this certificate.
    pub verifier_id: String,
    /// Start of the validity window.
    pub issued_at: DateTime<Utc>,
    /// End of the validity window.
    pub valid_until: DateTime<Utc>,
    /// Evidence records backing the certification.
    pub evidence_refs: Vec<String>,
}

/// The exact set of artifacts a certificate binds. Its [`digest`](Self::digest)
/// is the signed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateBinding {
    certificate_id: String,
    subject_digest: Hash,
    behavior_manifest_digest: Hash,
    evaluation_suite_digest: Hash,
    environment_scope: EnvironmentScope,
    environment_scope_digest: Hash,
    verifier_level: VerifierLevel,
    verifier_id: String,
    issued_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    stale_conditions: Vec<String>,
    evidence_refs: Vec<String>,
    digest: Hash,
}

impl CertificateBinding {
    /// Assemble a binding and compute its (infallible) content-address.
    #[must_use]
    pub fn new(params: BindingParams) -> Self {
        let environment_scope_digest = params.environment_scope.digest();
        let stale_conditions = vec![
            StaleReason::ManifestChanged.as_str().to_owned(),
            StaleReason::EvaluationSuiteChanged.as_str().to_owned(),
            StaleReason::EnvironmentDrift.as_str().to_owned(),
        ];
        let mut binding = Self {
            certificate_id: params.certificate_id,
            subject_digest: params.subject_digest,
            behavior_manifest_digest: params.behavior_manifest_digest,
            evaluation_suite_digest: params.evaluation_suite_digest,
            environment_scope: params.environment_scope,
            environment_scope_digest,
            verifier_level: params.verifier_level,
            verifier_id: params.verifier_id,
            issued_at: params.issued_at,
            valid_until: params.valid_until,
            stale_conditions,
            evidence_refs: params.evidence_refs,
            digest: Hash::GENESIS,
        };
        binding.digest = binding.compute_digest();
        binding
    }

    /// The signed message: `SHA-256(BINDING_DOMAIN || JCS(binding))`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        self.digest
    }

    /// Id of the verifier bound to this certificate.
    #[must_use]
    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    /// The verifier level this binding attained.
    #[must_use]
    pub fn verifier_level(&self) -> VerifierLevel {
        self.verifier_level
    }

    /// The environment scope this binding is valid within.
    #[must_use]
    pub fn environment_scope(&self) -> &EnvironmentScope {
        &self.environment_scope
    }

    /// The conditions that make this certificate stale, in canonical form.
    #[must_use]
    pub fn stale_conditions(&self) -> &[String] {
        &self.stale_conditions
    }

    fn compute_digest(&self) -> Hash {
        let document = json!({
            "certificate_id": self.certificate_id,
            "subject_digest": self.subject_digest.to_hex(),
            "behavior_manifest_digest": self.behavior_manifest_digest.to_hex(),
            "evaluation_suite_digest": self.evaluation_suite_digest.to_hex(),
            "environment_scope_digest": self.environment_scope_digest.to_hex(),
            "verifier_level": self.verifier_level.as_str(),
            "verifier_id": self.verifier_id,
            "issued_at": self.issued_at.to_rfc3339(),
            "valid_until": self.valid_until.to_rfc3339(),
            "stale_conditions": self.stale_conditions,
            "evidence_refs": self.evidence_refs,
        });
        // Strings and string arrays only: RFC 8785 canonicalization cannot fail.
        let bytes = canonicalize(&document).expect("string-only document is canonicalizable");
        domain_digest(BINDING_DOMAIN, &bytes)
    }
}

/// What is true *now*, against which a certificate is judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationContext {
    behavior_manifest_digest: Hash,
    evaluation_suite_digest: Hash,
    environment_scope_digest: Hash,
    now: DateTime<Utc>,
    required_level: VerifierLevel,
}

impl EvaluationContext {
    /// The live manifest/eval/env, the moment of evaluation, and the verifier
    /// level the consumer requires.
    #[must_use]
    pub fn new(
        behavior_manifest_digest: Hash,
        evaluation_suite_digest: Hash,
        environment_scope: &EnvironmentScope,
        now: DateTime<Utc>,
        required_level: VerifierLevel,
    ) -> Self {
        Self {
            behavior_manifest_digest,
            evaluation_suite_digest,
            environment_scope_digest: environment_scope.digest(),
            now,
            required_level,
        }
    }
}

/// A sealed certificate: a binding plus a verifier's signature over its digest.
///
/// Because the seal is a deterministic function of the binding digest, the
/// certificate is verifiable by anyone holding the verification key; the issuer
/// need not be trusted or present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    binding: CertificateBinding,
    signature: Signature,
}

impl Certificate {
    /// Seal a binding. The `verifier` must be the one the binding names.
    ///
    /// # Errors
    ///
    /// [`CertError::VerifierMismatch`] if `verifier.key_id()` differs from the
    /// binding's `verifier_id`.
    pub fn issue(
        binding: CertificateBinding,
        verifier: &dyn CertVerifier,
    ) -> Result<Self, CertError> {
        if verifier.key_id() != binding.verifier_id {
            return Err(CertError::VerifierMismatch {
                signer: verifier.key_id().to_owned(),
                binding: binding.verifier_id.clone(),
            });
        }
        let bytes = verifier.sign(&binding.digest());
        let signature = Signature {
            key_id: verifier.key_id().to_owned(),
            bytes,
        };
        Ok(Self { binding, signature })
    }

    /// The bound artifacts.
    #[must_use]
    pub fn binding(&self) -> &CertificateBinding {
        &self.binding
    }

    /// The seal.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The reason this certificate is stale in `context`, if any. A material
    /// change to any bound artifact yields `Some`.
    #[must_use]
    pub fn stale_reason(&self, context: &EvaluationContext) -> Option<StaleReason> {
        if context.behavior_manifest_digest != self.binding.behavior_manifest_digest {
            return Some(StaleReason::ManifestChanged);
        }
        if context.evaluation_suite_digest != self.binding.evaluation_suite_digest {
            return Some(StaleReason::EvaluationSuiteChanged);
        }
        if context.environment_scope_digest != self.binding.environment_scope_digest {
            return Some(StaleReason::EnvironmentDrift);
        }
        None
    }

    /// Verify the certificate against `verifier` and the live `context`.
    ///
    /// Checks, in order: verifier identity + seal, temporal validity, staleness
    /// (material change), then verifier-level sufficiency.
    ///
    /// # Errors
    ///
    /// [`CertError::WrongVerifier`], [`CertError::NotYetValid`],
    /// [`CertError::Expired`], [`CertError::Stale`] or
    /// [`CertError::InsufficientVerifier`].
    pub fn verify(
        &self,
        verifier: &dyn CertVerifier,
        context: &EvaluationContext,
    ) -> Result<(), CertError> {
        // Authenticate the seal before trusting any bound claim.
        if verifier.key_id() != self.binding.verifier_id
            || self.signature.key_id != self.binding.verifier_id
            || !verifier.verify(
                &self.signature.key_id,
                &self.binding.digest(),
                &self.signature.bytes,
            )
        {
            return Err(CertError::WrongVerifier);
        }
        if context.now < self.binding.issued_at {
            return Err(CertError::NotYetValid);
        }
        if context.now > self.binding.valid_until {
            return Err(CertError::Expired);
        }
        if let Some(reason) = self.stale_reason(context) {
            return Err(CertError::Stale { reason });
        }
        if context.required_level > self.binding.verifier_level {
            return Err(CertError::InsufficientVerifier {
                required: context.required_level,
                actual: self.binding.verifier_level,
            });
        }
        Ok(())
    }
}

/// Stage marker: this crate is the Phase 5a certificate core, not the skeleton.
pub const CRATE_STAGE: &str = "F5a-cert-core";

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn env() -> EnvironmentScope {
        EnvironmentScope::new(json!({ "os": "linux" })).unwrap()
    }

    fn sample_binding() -> CertificateBinding {
        CertificateBinding::new(BindingParams {
            certificate_id: "c".into(),
            subject_digest: domain_digest("T:", b"s"),
            behavior_manifest_digest: domain_digest("T:", b"m"),
            evaluation_suite_digest: domain_digest("T:", b"e"),
            environment_scope: env(),
            verifier_level: VerifierLevel::V3,
            verifier_id: "k1".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap(),
            evidence_refs: vec!["ev".into()],
        })
    }

    #[test]
    fn domains_are_all_distinct() {
        let bytes = b"x";
        let all = [
            domain_digest(MANIFEST_DOMAIN, bytes),
            domain_digest(EVAL_SUITE_DOMAIN, bytes),
            domain_digest(ENV_SCOPE_DOMAIN, bytes),
            domain_digest(BINDING_DOMAIN, bytes),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn binding_digest_is_deterministic() {
        assert_eq!(sample_binding().digest(), sample_binding().digest());
    }

    #[test]
    fn seal_round_trips_and_rejects_tampering() {
        let signer = HmacSha256CertVerifier::new("k1", b"key");
        let digest = sample_binding().digest();
        let sig = signer.sign(&digest);
        assert!(signer.verify("k1", &digest, &sig));
        assert!(!signer.verify("other", &digest, &sig));
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!signer.verify("k1", &digest, &flipped));
        let wrong_key = HmacSha256CertVerifier::new("k1", b"different");
        assert!(!wrong_key.verify("k1", &digest, &sig));
    }

    #[test]
    fn debug_never_prints_key_material() {
        let rendered = format!("{:?}", HmacSha256CertVerifier::new("k1", b"top-secret"));
        assert!(rendered.contains("k1"));
        assert!(!rendered.contains("top-secret"));
    }
}
