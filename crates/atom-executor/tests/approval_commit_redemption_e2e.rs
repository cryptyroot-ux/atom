//! End-to-end: an approval redemption authorises the real commit crossing.
//!
//! This is the daemon's external-effect gate, exercised against real ATOM
//! crates rather than a mock: a durable approval covers an exact effect digest,
//! redeeming it yields the grant the plan drew authority from, a commit permit
//! is issued (after a real ledger-sealed durability proof), and only then does
//! the unprivileged gateway ask the privilege broker to admit a typed host
//! operation. The broker's executor writes the file for real, inside the
//! sandbox. Nothing here reads a clock or a network; every timestamp is
//! injected.
//!
//! The daemon owns no host executor and must not be able to construct one, so
//! the crate under test stays outside this test: the full chain is driven
//! through the public `atom-runtime` gateway and `atom-privd` broker APIs.

use std::fs;

use atom_approval::{ApprovalGrant, ApprovalScope, ApprovalStore, RedeemTarget, ValidityInterval};
use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_effect::{
    issue_commit_permit, Compensation, CompensationStrategy, Condition, DurabilityProof,
    EffectEvent, EffectIntent, Idempotency, PermitRequest, Reconciliation, ReconciliationClass,
    ResourceWitness, RetryClass,
};
use atom_ledger::{HmacSha256Signer, Ledger};
use atom_privd::{HostOp, PrivilegeBroker, SandboxedHostExecutor};
use atom_runtime::{HostOperationRequest, UnprivilegedHostGateway};
use chrono::{DateTime, Duration, TimeZone, Utc};

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("fixed test timestamp")
}

fn ledger() -> Ledger {
    Ledger::open_in_memory(Box::new(HmacSha256Signer::new(
        "e2e-test-key",
        b"e2e-test-secret",
    )))
    .expect("in-memory ledger")
}

/// Appends the declared intent to the ledger, which seals a `DurabilityProof`
/// the permit gate actually accepts; there is no other way to obtain one.
fn durable_proof(intent: &EffectIntent) -> DurabilityProof {
    let payload = intent
        .declared_payload()
        .expect("fixture intent has a declared payload");
    let (_event, proof) = ledger()
        .append_durable(&intent.effect_id, &payload, 1_756_512_000_000)
        .expect("appending the declared intent seals a durability proof");
    proof
}

fn reference_effect(effect_id: &str, mission_id: &str, target_id: &str) -> EffectIntent {
    EffectIntent::builder(effect_id, mission_id, "capability-write", target_id)
        .canonical_request_digest(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .classes("WRITE_FILE", "LOW")
        .idempotency(Idempotency::keyed(
            "reference-mission",
            "reference-effect-key",
        ))
        .precondition(Condition::new("target-present", "target exists"))
        .postcondition(Condition::new(
            "contents-applied",
            "contents equal desired value",
        ))
        .reconciliation(
            Reconciliation::new(
                ReconciliationClass::ResourceStateRead,
                RetryClass::ReconcileBeforeRetry,
            )
            .with_probe("read target and compare postcondition"),
        )
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .expect("complete effect intent")
}

/// Pushes the intent to the commit boundary, where the permit gate runs.
fn at_commit_boundary(intent: &EffectIntent, grant: &CapabilityGrant) -> EffectIntent {
    let mut current = intent.clone();
    for event in [
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(&grant.grant_id, grant.generation),
        EffectEvent::CommitRevalidationStarted,
    ] {
        current = current
            .try_advance(&event)
            .expect("valid pre-dispatch transition");
    }
    current
}

fn host_grant(now: DateTime<Utc>, resource_id: &str) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "capability-grant".to_owned(),
        subject_id: "runtime-workload".to_owned(),
        workload_id: "runtime".to_owned(),
        operations: vec!["write".to_owned()],
        resources: vec![ResourceSelector {
            resource_type: "file".to_owned(),
            resource_id: resource_id.to_owned(),
        }],
        purpose: "e2e redemption test".to_owned(),
        not_before: now - Duration::seconds(1),
        expires_at: now + Duration::seconds(30),
        budget: Budget {
            max_cost: 1,
            max_seconds: 30,
        },
        delegation_depth: 0,
        audience: "runtime".to_owned(),
        generation: 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
    }
}

/// Redeeming an approval for the effect is what lets the plan cross the commit
/// boundary; the file lands inside the sandbox root for real (ATOM-V4-AUT-003
/// · EFX-004 · KRN-002).
#[test]
fn approval_redemption_authorises_a_real_sandboxed_commit() {
    let now = fixed_now();
    let sandbox = tempfile::tempdir().expect("temporary sandbox root");
    let target = "/proof.txt".to_owned();
    let disk_path = sandbox.path().join("proof.txt");

    let grant = host_grant(now, &target);

    let intent = {
        let intentional = reference_effect("e2e-effect", "e2e-mission", &target);
        at_commit_boundary(&intentional, &grant)
    };

    // The approval grant covers exactly this effect digest, durably.
    let mut approvals = ApprovalStore::new();
    approvals
        .record(ApprovalGrant::new(
            "approval-grant",
            "approver-1",
            ApprovalScope::Effect {
                effect_digest: intent.digest(),
            },
            ValidityInterval::new(now, now + Duration::seconds(60)).expect("valid interval"),
        ))
        .expect("record approval");

    let receipt = approvals
        .redeem(
            &RedeemTarget::Effect {
                effect_digest: intent.digest(),
            },
            now,
        )
        .expect("matching approval redeems against the effect digest");
    assert_eq!(receipt.grant_id, "approval-grant");
    assert_eq!(receipt.generation, 0);

    let witness = ResourceWitness::new("etag", &target, "v1");
    let permit = issue_commit_permit(PermitRequest {
        intent: &intent,
        grant: &grant,
        principal_id: "runtime-workload",
        operation: "write",
        resource_type: "file",
        planned_grant_generation: grant.generation,
        planned_witness: &witness,
        observed_witness: &witness,
        durability: &durable_proof(&intent),
        permit_id: "e2e-permit",
        one_shot_nonce: "e2e-nonce",
        ttl_seconds: 10,
        now,
        approval_id: Some(receipt.grant_id.as_str()),
        evidence_freshness_digest: None,
    })
    .expect("valid commit permit");

    let executor = SandboxedHostExecutor::new(sandbox.path()).expect("sandbox executor");
    let mut gateway = UnprivilegedHostGateway::new(PrivilegeBroker::new(executor));

    let op = HostOp::WriteFile {
        path: target.clone(),
        contents: "proof".to_owned(),
    };
    let admitted = gateway
        .submit(HostOperationRequest {
            op: &op,
            permit: &permit,
            intent: &intent,
            grant: &grant,
            observed_witness: &witness,
            now,
        })
        .expect("redemption-backed permit admits the write");

    assert_eq!(admitted.permit_id, "e2e-permit");
    assert_eq!(gateway.client().spent(), 1, "one one-shot permit burned");
    assert_eq!(
        fs::read_to_string(&disk_path).expect("file readable"),
        "proof",
        "the write really landed in the sandbox root"
    );

    // The same permit does not cross twice: its nonce is already burned.
    let second = gateway.submit(HostOperationRequest {
        op: &op,
        permit: &permit,
        intent: &intent,
        grant: &grant,
        observed_witness: &witness,
        now,
    });
    assert!(
        second.is_err(),
        "a permit is one-shot; the second crossing must be refused"
    );
    assert_eq!(gateway.client().spent(), 1, "no second burn");
}
