//! AUT-001 / SUP-001 identity invariants (RED → GREEN).
//!
//! * A workload identity is content-addressed: its id is `SHA-256` over its
//!   material (public key + attestation), never a free-chosen name.
//! * A grant is only bound when its `subject_id` / `workload_id` equal the
//!   content-address of a *valid* identity — a grant naming a free string is
//!   denied.
//! * Tampering the material of an identity changes its content-address, so any
//!   grant derived from the untampered identity no longer binds.

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_evidence::{Evidence, JsonObject, SourceAuthority, TaintLabels, VerifierLevel};
use atom_identity::{stamp_grant, verify_binding, IdentityError, WorkloadIdentity};
use chrono::{TimeZone, Utc};

fn sample_identity(pk: &[u8], attestation_seed: &str) -> WorkloadIdentity {
    let attestation = atom_ledger::domain_digest("TEST-ATTESTATION:", attestation_seed.as_bytes());
    WorkloadIdentity::derive(pk.to_vec(), attestation)
}

/// A grant whose subject/workload id is a raw string chosen by the caller.
fn free_named_grant(subject: &str, workload: &str) -> CapabilityGrant {
    let not_before = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let expires_at = Utc.with_ymd_and_hms(2026, 1, 1, 1, 0, 0).unwrap();
    CapabilityGrant {
        grant_id: "g-test".into(),
        subject_id: subject.into(),
        workload_id: workload.into(),
        operations: vec!["read".into()],
        resources: vec![ResourceSelector {
            resource_type: "*".into(),
            resource_id: "*".into(),
        }],
        purpose: "test".into(),
        not_before,
        expires_at,
        budget: Budget {
            max_cost: 1,
            max_seconds: 1,
        },
        delegation_depth: 1,
        audience: "test".into(),
        generation: 0,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
    }
}

fn content_address_binds_material_not_names() {
    let a = sample_identity(b"public-key-A", "att-1");
    let a_again = sample_identity(b"public-key-A", "att-1");
    let diff_key = sample_identity(b"public-key-B", "att-1");
    let diff_att = sample_identity(b"public-key-A", "att-2");

    // deterministic: identical material → identical content address
    assert_eq!(a.id(), a_again.id());
    // the id changes if the public key changes
    assert_ne!(a.id(), diff_key.id());
    // the id changes if the attestation changes
    assert_ne!(a.id(), diff_att.id());
    // the id is a 32-byte SHA-256 rendered as 64 hex chars, not the caller's text
    assert_eq!(a.id().to_hex().len(), 64);
}

#[test]
fn derived_identity_verifies() {
    let id = sample_identity(b"pk", "att");
    assert!(id.verify().is_ok());
}

#[test]
fn grant_without_valid_identity_is_denied() {
    let subject = sample_identity(b"subject-pk", "att-s");
    let workload = sample_identity(b"workload-pk", "att-w");
    // A grant that names free strings, not the identities' content addresses.
    let grant = free_named_grant("alice", "worker-1");

    let err = verify_binding(&grant, &subject, &workload).unwrap_err();
    assert!(matches!(err, IdentityError::UnboundIdentity { .. }));
}

#[test]
fn stamped_grant_binds_the_identity_content_address() {
    let subject = sample_identity(b"subject-pk", "att-s");
    let workload = sample_identity(b"workload-pk", "att-w");
    let grant = free_named_grant("alice", "worker-1");

    let bound = stamp_grant(&subject, &workload, grant).unwrap();
    // the stamped grant now carries the content addresses, not the free names
    assert_eq!(bound.subject_id, subject.id().to_hex());
    assert_eq!(bound.workload_id, workload.id().to_hex());
    assert!(verify_binding(&bound, &subject, &workload).is_ok());
}

#[test]
fn tampered_identity_invalidates_derived_grant() {
    let subject = sample_identity(b"subject-pk", "att-s");
    let workload = sample_identity(b"workload-pk", "att-w");
    let bound = stamp_grant(&subject, &workload, free_named_grant("x", "y")).unwrap();

    // Tamper: keep the published id, swap the underlying public key material.
    let mut doc: serde_json::Value = serde_json::to_value(&subject).unwrap();
    doc["public_key"] = serde_json::Value::String(hex::encode(b"attacker-pk"));
    let tampered: WorkloadIdentity = serde_json::from_value(doc).unwrap();

    // The tampered identity fails its own content-address check.
    assert!(matches!(
        tampered.verify().unwrap_err(),
        IdentityError::TamperedIdentity { .. }
    ));
    // And a grant that was bound to the honest identity no longer binds to it.
    assert!(verify_binding(&bound, &tampered, &workload).is_err());
}

#[test]
fn identity_can_be_anchored_to_an_attestation() {
    let evidence = |seed: &str| {
        let mut payload = JsonObject::empty();
        payload.insert("attested", serde_json::json!(seed));
        Evidence::new(
            "ev-1",
            VerifierLevel::V3,
            SourceAuthority::Verified,
            TaintLabels::default(),
            vec![],
            payload,
        )
        .unwrap()
    };

    let id1 = WorkloadIdentity::from_attestation(b"pk".to_vec(), &evidence("claim-a")).unwrap();
    let id1_again =
        WorkloadIdentity::from_attestation(b"pk".to_vec(), &evidence("claim-a")).unwrap();
    let id2 = WorkloadIdentity::from_attestation(b"pk".to_vec(), &evidence("claim-b")).unwrap();

    assert_eq!(id1.id(), id1_again.id());
    // a different attestation ⇒ a different identity
    assert_ne!(id1.id(), id2.id());
    assert!(id1.verify().is_ok());
}
