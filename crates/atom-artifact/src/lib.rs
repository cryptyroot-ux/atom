//! atom-artifact: a content-addressed executable artifact whose identity *is*
//! the SHA-256 of its bytes, bundled with provenance, an SBOM and a signature,
//! and verifiable so that any tamper is detected.
//!
//! Normative source is `spec/` (precedence 1):
//!
//! * **SUP-001** (`requirements.yaml`, verification "Tamper/install
//!   verification"): official and Foundry executable artifacts MUST be
//!   content-addressed and include provenance, SBOM, signatures/attestations
//!   and immutable identity.
//! * **ATOM-VT-012** (`acceptance/catalog.yaml`): a regressed artifact must be
//!   detectable so a prior certified route can be restored — which requires the
//!   identity to be a stable, forgery-resistant hash of the content.
//!
//! Immutability is enforced structurally: the [`ArtifactId`] is derived from the
//! bytes and there is no setter for it. [`Artifact::verify`] recomputes the hash
//! and checks the whole bundle, so editing a single byte — of the content, the
//! provenance, the SBOM or the signature — makes the artifact invalid.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A content address: the lowercase hex SHA-256 of the artifact bytes.
///
/// There is deliberately no public constructor from a raw string other than the
/// wire deserialization; the intended way to obtain one is [`ArtifactId::of`],
/// which hashes bytes. This is what makes the identity *of the content* rather
/// than an arbitrary label.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// The content address of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(format!("sha256:{:x}", hasher.finalize()))
    }

    /// Borrows the canonical `sha256:...` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where an artifact came from and how it was built (SUP-001).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The builder that produced the artifact (e.g. `official` or `foundry`).
    pub builder: String,
    /// The source identity the build was driven from (a commit, a manifest).
    pub source_ref: String,
    /// A free-form build recipe identifier, so the build can be reproduced.
    pub build_recipe: String,
}

impl Provenance {
    /// Provenance naming the `builder`, `source_ref` and `build_recipe`.
    #[must_use]
    pub fn new(builder: &str, source_ref: &str, build_recipe: &str) -> Self {
        Self {
            builder: builder.to_owned(),
            source_ref: source_ref.to_owned(),
            build_recipe: build_recipe.to_owned(),
        }
    }
}

/// One dependency recorded in the SBOM.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SbomComponent {
    /// The component name.
    pub name: String,
    /// Its pinned version.
    pub version: String,
}

impl SbomComponent {
    /// A component `name` pinned at `version`.
    #[must_use]
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_owned(),
            version: version.to_owned(),
        }
    }
}

/// The software bill of materials: every component the artifact was built from.
///
/// Components are kept sorted and de-duplicated so the SBOM has one canonical
/// form, which the artifact's binding digest depends on.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Sbom(Vec<SbomComponent>);

impl Sbom {
    /// An SBOM from a set of components, canonicalized (sorted, de-duplicated).
    #[must_use]
    pub fn new(components: impl IntoIterator<Item = SbomComponent>) -> Self {
        let mut components: Vec<SbomComponent> = components.into_iter().collect();
        components.sort();
        components.dedup();
        Self(components)
    }

    /// The components, in canonical order.
    #[must_use]
    pub fn components(&self) -> &[SbomComponent] {
        &self.0
    }

    /// Whether the SBOM is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A detached signature over the artifact's binding digest.
///
/// The alpha models signing as an HMAC-style keyed digest: [`Signature::sign`]
/// hashes the binding digest together with a key id and secret, and
/// verification recomputes it. This is enough to make the acceptance property —
/// tamper is detected, a forged bundle does not verify — mechanically true,
/// without pulling in an asymmetric-crypto dependency at this layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Which key signed it, so a verifier knows which secret to use.
    pub key_id: String,
    /// The signature value over the binding digest.
    pub value: String,
}

impl Signature {
    /// Signs `binding_digest` with `key_id` and `secret`.
    #[must_use]
    pub fn sign(binding_digest: &str, key_id: &str, secret: &[u8]) -> Self {
        Self {
            key_id: key_id.to_owned(),
            value: Self::compute(binding_digest, key_id, secret),
        }
    }

    /// Whether this signature is valid for `binding_digest` under `secret`.
    #[must_use]
    pub fn verify(&self, binding_digest: &str, secret: &[u8]) -> bool {
        self.value == Self::compute(binding_digest, &self.key_id, secret)
    }

    fn compute(binding_digest: &str, key_id: &str, secret: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"atom-artifact-sig-v1");
        hasher.update(key_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(secret);
        hasher.update([0u8]);
        hasher.update(binding_digest.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Why an artifact failed verification (SUP-001, ATOM-VT-012).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ArtifactError {
    /// The stored id is not the hash of the stored content — content-address
    /// broken, so this is not the artifact it claims to be.
    #[error("content address mismatch: id is {declared}, but content hashes to {actual}")]
    ContentAddressMismatch {
        /// The id recorded in the artifact.
        declared: String,
        /// The hash the content actually produces.
        actual: String,
    },
    /// The signature does not verify against the recomputed binding digest —
    /// something in the bundle (content, provenance or SBOM) was altered, or
    /// the signature itself was.
    #[error("signature does not verify for key `{key_id}`")]
    SignatureInvalid {
        /// The key the signature named.
        key_id: String,
    },
}

/// A content-addressed, provenance- and SBOM-bearing, signed artifact (SUP-001).
///
/// Its [`Artifact::id`] is the hash of [`Artifact::content`]; the two cannot be
/// set independently because [`Artifact::seal`] derives the id and the caller
/// never supplies it. That is the immutable-identity guarantee.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    id: ArtifactId,
    content: Vec<u8>,
    provenance: Provenance,
    sbom: Sbom,
    signature: Signature,
}

impl Artifact {
    /// Seals `content` into an immutable, signed artifact (SUP-001).
    ///
    /// The id is computed from the content — never supplied — and the signature
    /// is taken over a binding digest that folds in the content id, the
    /// provenance and the SBOM, so none of them can be swapped afterwards
    /// without invalidating the signature.
    #[must_use]
    pub fn seal(
        content: Vec<u8>,
        provenance: Provenance,
        sbom: Sbom,
        key_id: &str,
        secret: &[u8],
    ) -> Self {
        let id = ArtifactId::of(&content);
        let binding = Self::binding_digest(&id, &provenance, &sbom);
        let signature = Signature::sign(&binding, key_id, secret);
        Self {
            id,
            content,
            provenance,
            sbom,
            signature,
        }
    }

    /// The content address / immutable identity.
    #[must_use]
    pub fn id(&self) -> &ArtifactId {
        &self.id
    }

    /// The artifact bytes.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// The build provenance.
    #[must_use]
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// The SBOM.
    #[must_use]
    pub fn sbom(&self) -> &Sbom {
        &self.sbom
    }

    /// The detached signature.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The digest the signature is taken over: content id + provenance + SBOM.
    ///
    /// Folding all three in is what makes a tamper anywhere in the bundle — not
    /// just in the bytes — detectable at [`Artifact::verify`].
    fn binding_digest(id: &ArtifactId, provenance: &Provenance, sbom: &Sbom) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"atom-artifact-binding-v1");
        hasher.update(id.as_str().as_bytes());
        hasher.update([0u8]);
        hasher.update(provenance.builder.as_bytes());
        hasher.update([0u8]);
        hasher.update(provenance.source_ref.as_bytes());
        hasher.update([0u8]);
        hasher.update(provenance.build_recipe.as_bytes());
        hasher.update([0u8]);
        for component in sbom.components() {
            hasher.update(component.name.as_bytes());
            hasher.update([0u8]);
            hasher.update(component.version.as_bytes());
            hasher.update([0u8]);
        }
        format!("{:x}", hasher.finalize())
    }

    /// Verifies the artifact end to end (SUP-001, tamper detection).
    ///
    /// Two checks:
    ///
    /// 1. The content still hashes to the recorded id (content-address holds).
    /// 2. The signature verifies against the recomputed binding digest, which
    ///    covers the id, provenance and SBOM.
    ///
    /// Any single-byte change to content, provenance, SBOM or signature makes
    /// one of these fail.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::ContentAddressMismatch`] if the bytes were altered, or
    /// [`ArtifactError::SignatureInvalid`] if the bundle or signature was.
    pub fn verify(&self, secret: &[u8]) -> Result<(), ArtifactError> {
        let actual = ArtifactId::of(&self.content);
        if actual != self.id {
            return Err(ArtifactError::ContentAddressMismatch {
                declared: self.id.as_str().to_owned(),
                actual: actual.as_str().to_owned(),
            });
        }
        let binding = Self::binding_digest(&self.id, &self.provenance, &self.sbom);
        if !self.signature.verify(&binding, secret) {
            return Err(ArtifactError::SignatureInvalid {
                key_id: self.signature.key_id.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"official-signing-key-secret";

    fn sample() -> Artifact {
        Artifact::seal(
            b"#!/bin/sh\necho hello\n".to_vec(),
            Provenance::new("official", "git:abc123", "recipe:v1"),
            Sbom::new([
                SbomComponent::new("libc", "2.39"),
                SbomComponent::new("openssl", "3.3.0"),
            ]),
            "key-official",
            SECRET,
        )
    }

    // ─── SUP-001: content-addressed identity is the hash of the content ──────
    #[test]
    fn id_is_content_hash() {
        let artifact = sample();
        assert_eq!(artifact.id(), &ArtifactId::of(artifact.content()));
        assert!(artifact.id().as_str().starts_with("sha256:"));
    }

    #[test]
    fn identical_content_yields_identical_id() {
        let a = sample();
        let b = sample();
        assert_eq!(a.id(), b.id(), "content address is deterministic");
    }

    #[test]
    fn different_content_yields_different_id() {
        let a = sample();
        let b = Artifact::seal(
            b"#!/bin/sh\necho goodbye\n".to_vec(),
            Provenance::new("official", "git:abc123", "recipe:v1"),
            Sbom::new([]),
            "key-official",
            SECRET,
        );
        assert_ne!(a.id(), b.id());
    }

    // ─── SUP-001: a well-formed artifact verifies ────────────────────────────
    #[test]
    fn sealed_artifact_verifies() {
        let artifact = sample();
        assert!(artifact.verify(SECRET).is_ok());
    }

    // ─── SUP-001 / VT-012: tamper is detected ────────────────────────────────
    #[test]
    fn tampered_content_is_invalid() {
        let mut artifact = sample();
        // Flip a byte in the content without touching the recorded id.
        artifact.content[0] ^= 0xff;
        let err = artifact.verify(SECRET).unwrap_err();
        assert!(matches!(err, ArtifactError::ContentAddressMismatch { .. }));
    }

    #[test]
    fn tampered_provenance_breaks_signature() {
        let mut artifact = sample();
        // Content id still matches, but provenance changed → signature fails.
        artifact.provenance.source_ref = "git:evil".into();
        let err = artifact.verify(SECRET).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureInvalid { .. }));
    }

    #[test]
    fn tampered_sbom_breaks_signature() {
        let mut artifact = sample();
        artifact.sbom = Sbom::new([SbomComponent::new("backdoor", "1.0")]);
        let err = artifact.verify(SECRET).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureInvalid { .. }));
    }

    #[test]
    fn forged_signature_is_invalid() {
        let mut artifact = sample();
        artifact.signature.value = "deadbeef".into();
        let err = artifact.verify(SECRET).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureInvalid { .. }));
    }

    #[test]
    fn wrong_secret_does_not_verify() {
        let artifact = sample();
        let err = artifact.verify(b"attacker-secret").unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureInvalid { .. }));
    }

    #[test]
    fn provenance_and_sbom_are_carried() {
        let artifact = sample();
        assert_eq!(artifact.provenance().builder, "official");
        assert_eq!(artifact.sbom().components().len(), 2);
        // SBOM is canonicalized (sorted): libc before openssl.
        assert_eq!(artifact.sbom().components()[0].name, "libc");
    }

    #[test]
    fn round_trips_through_json_and_still_verifies() {
        let artifact = sample();
        let json = serde_json::to_string(&artifact).expect("serializes");
        let restored: Artifact = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(restored.id(), artifact.id());
        assert!(restored.verify(SECRET).is_ok());
    }
}
