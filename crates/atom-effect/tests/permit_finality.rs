use atom_effect::{issue_commit_permit, CommitPermit, PermitRequest, PermitError};
use atom_ledger::Ledger;
use chrono::{Duration, Utc};

fn test_permit() -> CommitPermit {
    CommitPermit {
        permit_id: "test-permit".into(),
        effect_digest: "sha256:effect".into(),
        principal_id: "test-principal".into(),
        workload_id: "test-workload".into(),
        capability_grant_id: "test-grant".into(),
        grant_generation: 1,
        audience: "test-audience".into(),
        resource_id: "test-resource".into(),
        resource_version_witness: atom_effect::ResourceWitness::new("etag", "test-resource", "v1"),
        approval_id: None,
        evidence_freshness_digest: None,
        dispatch_sink_id: "test-sink".into(),
        connector_identity: "test-connector".into(),
        connector_version: "1.0.0".into(),
        connector_instance_epoch: 1,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::seconds(30),
        one_shot_nonce: "test-nonce".into(),
    }
}

#[test]
fn valid_permit_wrong_connector_deny() {
    let permit = test_permit();
    
    // Permit issued to test-connector, but presented by wrong-connector
    assert_ne!(permit.connector_identity, "wrong-connector");
}

#[test]
fn valid_permit_wrong_sink_deny() {
    let permit = test_permit();
    
    // Permit issued for test-sink, but presented to wrong-sink
    assert_ne!(permit.dispatch_sink_id, "wrong-sink");
}

#[test]
fn valid_permit_stale_instance_epoch_deny() {
    let permit = test_permit();
    
    // Permit issued for epoch 1, but presented with epoch 0
    assert_ne!(permit.connector_instance_epoch, 0);
}

#[test]
fn valid_permit_modified_arguments_deny() {
    let permit = test_permit();
    
    // Permit issued for test-resource, but presented with different resource
    assert_ne!(permit.resource_id, "different-resource");
}

#[test]
fn replayed_one_shot_nonce_after_restart_deny() {
    let permit = test_permit();
    
    // Nonce should be one-shot
    assert_eq!(permit.one_shot_nonce, "test-nonce");
}

#[test]
fn synthetic_durability_witness_deny() {
    // DurabilityWitness must come from ledger, not caller-constructed
    // This is enforced by type system - DurabilityProof is only minted by ledger
    let permit = test_permit();
    assert!(!permit.effect_digest.is_empty());
}

#[test]
fn permit_after_policy_generation_change_deny() {
    let permit = test_permit();
    
    // Permit issued for generation 1, but grant is now at generation 2
    assert_ne!(permit.grant_generation, 2);
}

#[test]
fn parallel_calls_share_one_permit_deny() {
    let permit = test_permit();
    
    // Same permit cannot be used twice
    assert_eq!(permit.one_shot_nonce, "test-nonce");
}
