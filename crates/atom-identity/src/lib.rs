//! atom-identity: content-addressed principal & workload identity (AUT-001, SUP-001).
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **AUT-001** — a [`CapabilityGrant`] binds subject/workload identity. Here a
//!   grant is *bound* only when its `subject_id` / `workload_id` equal the
//!   content-address of a valid [`WorkloadIdentity`].
//! * **SUP-001** — artifacts carry an *immutable, content-addressed identity*.
//!   A [`WorkloadIdentity`] id is `SHA-256(domain || JCS{public_key, attestation})`
//!   via [`atom_ledger`]; it is derived from the material, never chosen freely.
//!
//! Tamper resistance is structural: change the public key or the attestation and
//! the content-address changes, so every grant that named the honest identity's
//! address stops binding. A wire identity whose stored id no longer matches its
//! material is rejected by [`WorkloadIdentity::verify`], which the grant-binding
//! paths always call first.

#![forbid(unsafe_code)]

use atom_capability::CapabilityGrant;
use atom_evidence::Evidence;
use atom_ledger::{canonicalize, domain_digest, Hash};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain tag for a workload/subject content-address. Domain separation keeps an
/// identity digest from ever colliding with a payload, event or cert digest.
pub const IDENTITY_DOMAIN: &str = "ATOM-IDENTITY-v1:";

/// Domain tag for the attestation digest an identity is anchored to.
pub const ATTESTATION_DOMAIN: &str = "ATOM-ATTESTATION-v1:";

/// Errors produced while deriving, verifying, or binding an identity.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A stored identity's content-address does not match its material: the
    /// public key or attestation was altered after the id was published.
    #[error("tampered identity: material hashes to {expected} but document claims {found}")]
    TamperedIdentity {
        /// Content-address recomputed from the material (the truth).
        expected: String,
        /// Content-address the document claims.
        found: String,
    },

    /// A grant field does not name the provided identity's content-address, so
    /// the grant is not bound to a valid identity (AUT-001).
    #[error("grant {field} `{grant_value}` is not bound to identity `{identity_id}`")]
    UnboundIdentity {
        /// Which grant field failed (`subject_id` or `workload_id`).
        field: &'static str,
        /// The value carried by the grant.
        grant_value: String,
        /// The content-address of the identity that was expected.
        identity_id: String,
    },

    /// The attestation material could not be canonicalized (RFC 8785).
    #[error("attestation is not canonicalizable: {0}")]
    Attestation(String),
}

/// A content-addressed identity: the `SHA-256` of a workload's material.
///
/// It is a hash, not a name. Two identities are equal iff their material is
/// byte-for-byte identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(Hash);

impl IdentityId {
    /// Borrow the underlying digest.
    #[must_use]
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }

    /// Lowercase hex, the only textual form of an identity.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl std::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A workload/subject identity, content-addressed by its material.
///
/// The id is bound to `(public_key, attestation)`. The only safe constructors
/// ([`WorkloadIdentity::derive`], [`WorkloadIdentity::from_attestation`]) compute
/// the id, so they can never produce a mismatch. A tampered id can only arrive
/// over the wire; [`WorkloadIdentity::verify`] is the gate that rejects it, and
/// every grant-binding path calls it before trusting the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadIdentity {
    public_key: Vec<u8>,
    attestation: Hash,
    id: IdentityId,
}

impl WorkloadIdentity {
    /// Derive an identity from raw public-key bytes and an attestation digest.
    ///
    /// The content-address is computed here, so the result is always internally
    /// consistent.
    #[must_use]
    pub fn derive(public_key: impl Into<Vec<u8>>, attestation: Hash) -> Self {
        let public_key = public_key.into();
        let id = compute_id(&public_key, &attestation);
        Self {
            public_key,
            attestation,
            id,
        }
    }

    /// Anchor an identity to an [`Evidence`] attestation.
    ///
    /// The attestation digest is `SHA-256(domain || JCS(evidence))`, so mutating
    /// the attestation record changes the identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Attestation`] if the evidence cannot be
    /// canonicalized under RFC 8785.
    pub fn from_attestation(
        public_key: impl Into<Vec<u8>>,
        evidence: &Evidence,
    ) -> Result<Self, IdentityError> {
        let value = serde_json::to_value(evidence)
            .map_err(|e| IdentityError::Attestation(e.to_string()))?;
        let bytes = canonicalize(&value).map_err(|e| IdentityError::Attestation(e.to_string()))?;
        let attestation = domain_digest(ATTESTATION_DOMAIN, &bytes);
        Ok(Self::derive(public_key, attestation))
    }

    /// The content-address of this identity.
    #[must_use]
    pub fn id(&self) -> &IdentityId {
        &self.id
    }

    /// The public-key material this identity is derived from.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The attestation digest this identity is anchored to.
    #[must_use]
    pub fn attestation(&self) -> &Hash {
        &self.attestation
    }

    /// Recompute the content-address from the material and compare it to the
    /// stored id.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::TamperedIdentity`] when the material no longer
    /// hashes to the stored id.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let recomputed = compute_id(&self.public_key, &self.attestation);
        if recomputed != self.id {
            return Err(IdentityError::TamperedIdentity {
                expected: recomputed.to_hex(),
                found: self.id.to_hex(),
            });
        }
        Ok(())
    }
}

/// `IdentityId = SHA-256(IDENTITY_DOMAIN || JCS{attestation, public_key})`.
fn compute_id(public_key: &[u8], attestation: &Hash) -> IdentityId {
    let document = serde_json::json!({
        "attestation": attestation.to_hex(),
        "public_key": hex::encode(public_key),
    });
    // The document is all strings, so RFC 8785 canonicalization cannot fail.
    let bytes = canonicalize(&document).expect("string-only document is canonicalizable");
    IdentityId(domain_digest(IDENTITY_DOMAIN, &bytes))
}

// ---------------------------------------------------------------------------
// Wire form: an identity may be tampered in transit; `verify` is the gate.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct IdentityWire {
    public_key: String,
    attestation: Hash,
    id: IdentityId,
}

impl Serialize for WorkloadIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        IdentityWire {
            public_key: hex::encode(&self.public_key),
            attestation: self.attestation,
            id: self.id,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WorkloadIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = IdentityWire::deserialize(deserializer)?;
        let public_key = hex::decode(&wire.public_key).map_err(serde::de::Error::custom)?;
        // Stored as-is (no recompute): a mismatch is a tamper that `verify` catches.
        Ok(Self {
            public_key,
            attestation: wire.attestation,
            id: wire.id,
        })
    }
}

// ---------------------------------------------------------------------------
// Grant binding (AUT-001)
// ---------------------------------------------------------------------------

/// Stamp a grant so it is bound to the given valid identities.
///
/// Both identities are verified first, then the grant's `subject_id` /
/// `workload_id` are set to their content-addresses. A grant produced this way
/// always passes [`verify_binding`].
///
/// # Errors
///
/// Returns [`IdentityError::TamperedIdentity`] if either identity fails its
/// content-address check.
pub fn stamp_grant(
    subject: &WorkloadIdentity,
    workload: &WorkloadIdentity,
    mut grant: CapabilityGrant,
) -> Result<CapabilityGrant, IdentityError> {
    subject.verify()?;
    workload.verify()?;
    grant.subject_id = subject.id().to_hex();
    grant.workload_id = workload.id().to_hex();
    Ok(grant)
}

/// Verify that a grant is bound to valid subject and workload identities.
///
/// Enforces AUT-001's identity binding: the grant must name the *content-address*
/// of each provided identity, and each identity must pass its content-address
/// check. A grant naming a free string, or one bound to an identity whose
/// material was tampered, is denied.
///
/// # Errors
///
/// * [`IdentityError::TamperedIdentity`] if an identity fails verification.
/// * [`IdentityError::UnboundIdentity`] if a grant field does not equal the
///   identity's content-address.
pub fn verify_binding(
    grant: &CapabilityGrant,
    subject: &WorkloadIdentity,
    workload: &WorkloadIdentity,
) -> Result<(), IdentityError> {
    subject.verify()?;
    workload.verify()?;

    let subject_id = subject.id().to_hex();
    if grant.subject_id != subject_id {
        return Err(IdentityError::UnboundIdentity {
            field: "subject_id",
            grant_value: grant.subject_id.clone(),
            identity_id: subject_id,
        });
    }

    let workload_id = workload.id().to_hex();
    if grant.workload_id != workload_id {
        return Err(IdentityError::UnboundIdentity {
            field: "workload_id",
            grant_value: grant.workload_id.clone(),
            identity_id: workload_id,
        });
    }

    Ok(())
}

/// Stage marker: this crate is the Phase 5a identity core, not the old skeleton.
pub const CRATE_STAGE: &str = "F5a-identity-core";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_distinguishes_identity_from_attestation() {
        let bytes = b"same-bytes";
        assert_ne!(
            domain_digest(IDENTITY_DOMAIN, bytes),
            domain_digest(ATTESTATION_DOMAIN, bytes)
        );
    }

    #[test]
    fn roundtrip_serialize_preserves_id() {
        let id = WorkloadIdentity::derive(b"pk".to_vec(), Hash::GENESIS);
        let json = serde_json::to_string(&id).unwrap();
        let back: WorkloadIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        assert!(back.verify().is_ok());
    }
}
