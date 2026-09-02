//! KRN-001 verification: architecture path test + adversarial bypass suite.
//!
//! These tests link `atom-kernel` as an EXTERNAL crate, so they can only touch
//! its public API. That is the point: if the double gate could be bypassed from
//! outside, it would show up here. `Authorization` and `CommitToken` have no
//! public constructor, so the *only* way to obtain a committed mutation in this
//! file is to traverse `authorize` and then `commit`, in that order.

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_effect::{
    Compensation, CompensationStrategy, DurabilityProof, EffectEvent, EffectIntent, EffectState,
    Idempotency, PermitError, Reconciliation, ReconciliationClass, ResourceWitness, RetryClass,
};
use atom_kernel::{AuthorizeRequest, CommitRequest, Kernel, KernelError};
use atom_ledger::{HmacSha256Signer, Ledger};
use chrono::{DateTime, Duration, Utc};

const PRINCIPAL: &str = "principal-1";
const GRANT_ID: &str = "grant-1";
const EFFECT_ID: &str = "effect-1";
const TARGET_ID: &str = "orders-42";
const OPERATION: &str = "write";
const RESOURCE_TYPE: &str = "database";

fn base_grant(now: DateTime<Utc>, generation: u64) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: GRANT_ID.into(),
        subject_id: PRINCIPAL.into(),
        workload_id: "workload-1".into(),
        operations: vec!["read".into(), "write".into()],
        resources: vec![ResourceSelector {
            resource_type: RESOURCE_TYPE.into(),
            resource_id: TARGET_ID.into(),
        }],
        purpose: "ops".into(),
        not_before: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
        budget: Budget {
            max_cost: 1_000,
            max_seconds: 3_600,
        },
        delegation_depth: 3,
        audience: "ops".into(),
        generation,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
    }
}

fn base_intent() -> EffectIntent {
    EffectIntent::builder(EFFECT_ID, "mission-1", GRANT_ID, TARGET_ID)
        .canonical_request_digest(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .classes("db.write", "high")
        .idempotency(Idempotency::keyed("orders", "idem-key-1"))
        .reconciliation(Reconciliation::new(
            ReconciliationClass::LedgerReplay,
            RetryClass::ReconcileBeforeRetry,
        ))
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .expect("base intent is well formed")
}

fn pending_intent() -> EffectIntent {
    base_intent()
        .try_advance(&EffectEvent::AuthorizationRequested)
        .expect("INTENT_DURABLE -> AUTHORIZATION_PENDING")
}

fn witness(value: &str) -> ResourceWitness {
    ResourceWitness::new("etag", TARGET_ID, value)
}

/// A real durability proof for the base intent's effect, minted the only way a
/// proof can be: by actually appending the declared intent to a ledger stream
/// named for the effect. The endurance->revalidating advance does not change the
/// declared payload, so this proof binds at the commit boundary too.
fn durability() -> DurabilityProof {
    durability_for(&base_intent())
}

/// A real durability proof for exactly `intent`: the declared payload (the
/// caller's declaration, stable across lifecycle transitions) is appended to the
/// effect's own stream. The proof binds to that exact declaration and no other
/// (ATOM-INV-004, EFX-001).
///
/// There is no `DurabilityProof` constructor a caller can invoke, so a forged
/// proof is inexpressible. The adversarial tests hand it an intent whose
/// identity differs from the one being committed.
fn durability_for(intent: &EffectIntent) -> DurabilityProof {
    let signer = Box::new(HmacSha256Signer::new(
        "atom-kernel-test-seal",
        b"atom-kernel-test-key-not-for-production",
    ));
    let mut ledger = Ledger::open_in_memory(signer).expect("in-memory ledger opens");
    let payload = intent
        .declared_payload()
        .expect("fixture intent has a declared payload");
    let (_event, proof) = ledger
        .append_durable(&intent.effect_id, &payload, 1_756_512_000_000)
        .expect("appending the declared intent seals a durability proof");
    proof
}

/// Drive an intent through Phase A (authorize) and the administrative
/// `CommitRevalidationStarted` transition, leaving it standing at the commit
/// boundary with a fresh [`atom_kernel::Authorization`].
fn authorized_at_boundary(
    kernel: &Kernel,
    grant: &CapabilityGrant,
    planned: &ResourceWitness,
    now: DateTime<Utc>,
) -> (atom_kernel::Authorization, EffectIntent) {
    let pending = pending_intent();
    let (auth, authorized) = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: planned,
            now,
        })
        .expect("capability authorization must pass for a valid grant");
    assert_eq!(authorized.state, EffectState::Authorized);
    let revalidating = authorized
        .try_advance(&EffectEvent::CommitRevalidationStarted)
        .expect("AUTHORIZED -> COMMIT_REVALIDATING");
    (auth, revalidating)
}

// ---------------------------------------------------------------------------
// ARCHITECTURE PATH TEST — success is reachable ONLY through both gates in order
// ---------------------------------------------------------------------------

#[test]
fn architecture_path_success_requires_both_gates_in_order() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 7);
    let planned = witness("v1");

    let (auth, revalidating) = authorized_at_boundary(&kernel, &grant, &planned, now);
    assert_eq!(auth.grant_generation(), 7);
    assert_eq!(auth.effect_digest(), base_intent().digest());

    let observed = witness("v1"); // resource has not moved since planning
    let durable = durability();
    let (token, dispatching) = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &revalidating,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .expect("commit revalidation must pass when nothing drifted");

    assert_eq!(dispatching.state, EffectState::Dispatching);
    assert_eq!(token.effect_id(), EFFECT_ID);
    assert_eq!(token.grant_id(), GRANT_ID);
    assert_eq!(token.grant_generation(), 7);
    assert_eq!(token.resource_id(), TARGET_ID);
    assert_eq!(token.one_shot_nonce(), "nonce-1");
    assert_eq!(kernel.nonces_spent(), 1);
}

// ---------------------------------------------------------------------------
// ADVERSARIAL BYPASS SUITE — every shortcut is denied
// ---------------------------------------------------------------------------

// ── no grant = deny ────────────────────────────────────────────────────────
// A revoked grant yields NO Authorization; without an Authorization there is no
// way to reach `commit` (it is a required, unforgeable argument).
#[test]
fn no_grant_revoked_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let mut grant = base_grant(now, 1);
    grant.revocation_state = RevocationState::Revoked;
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::GrantNotActive { .. }));
}

#[test]
fn no_grant_expired_window_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let mut grant = base_grant(now, 1);
    grant.expires_at = now - Duration::minutes(1); // already expired
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::GrantOutsideValidity { .. }));
}

// ── no permit = deny ───────────────────────────────────────────────────────
// Phase A passed, but the commit boundary cannot mint/consume a permit, so no
// CommitToken is produced.
#[test]
fn no_permit_non_durable_intent_denies_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    let (auth, revalidating) = authorized_at_boundary(&kernel, &grant, &planned, now);

    let observed = witness("v1");
    // A real proof, but minted for a DIFFERENT effect's stream: it does not
    // prove durability of this effect, so the commit boundary refuses it
    // (EFX-001). A proof for THIS effect cannot be hand-built.
    let never_written = EffectIntent {
        effect_id: "effect-never-written".into(),
        ..revalidating.clone()
    };
    let not_durable = durability_for(&never_written);
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &revalidating,
            grant: &grant,
            observed_witness: &observed,
            durability: &not_durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::EffectNotDurable { .. })
    ));
    assert_eq!(kernel.nonces_spent(), 0, "a refused commit burns nothing");
}

#[test]
fn no_permit_wrong_state_denies_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");

    // Authorize, but present the AUTHORIZED intent to commit WITHOUT the
    // CommitRevalidationStarted transition — the boundary is not open.
    let pending = pending_intent();
    let (auth, authorized) = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap();

    let observed = witness("v1");
    let durable = durability();
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &authorized, // still AUTHORIZED, not COMMIT_REVALIDATING
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::WrongState { .. }));
}

#[test]
fn no_permit_ttl_out_of_range_denies_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    let (auth, revalidating) = authorized_at_boundary(&kernel, &grant, &planned, now);

    let observed = witness("v1");
    let durable = durability();
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &revalidating,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 0, // not short-lived: invalid
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::TtlOutOfRange { .. })
    ));
}

// ── stale permit = deny ────────────────────────────────────────────────────
// Replay: the same one-shot nonce cannot be spent twice.
#[test]
fn stale_permit_replayed_nonce_denies_second_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 5);
    let planned = witness("v1");
    let observed = witness("v1");
    let durable = durability();

    let (auth1, reval1) = authorized_at_boundary(&kernel, &grant, &planned, now);
    kernel
        .commit(CommitRequest {
            authorization: &auth1,
            intent: &reval1,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-shared",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .expect("first commit succeeds");

    // A second, independently authorized effect attempt reusing the burned nonce.
    let (auth2, reval2) = authorized_at_boundary(&kernel, &grant, &planned, now);
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth2,
            intent: &reval2,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-2",
            one_shot_nonce: "nonce-shared", // replay
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::NonceAlreadyUsed { .. })
    ));
    assert_eq!(kernel.nonces_spent(), 1);
}

// Durable one-shot memory: a cold start rehydrates the registry from the ledger's
// nonce-burn stream, so a permit burned in a prior process life is refused again
// on restart instead of being re-served (ATOM-V4-EFX-004 · durable nonce).
#[test]
fn restarted_kernel_seeded_from_durable_burns_denies_replay() {
    let now = Utc::now();
    let grant = base_grant(now, 5);
    let planned = witness("v1");
    let observed = witness("v1");
    let durable = durability();

    // First process: commits and durably burns `nonce-persisted` (the runtime
    // writes it to the ledger's nonce-burn stream; here we hand the same value
    // to the restarted kernel's seeding constructor).
    let mut first = Kernel::new();
    let (auth1, reval1) = authorized_at_boundary(&first, &grant, &planned, now);
    first
        .commit(CommitRequest {
            authorization: &auth1,
            intent: &reval1,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-persisted",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .expect("first process commit succeeds");

    // Restart: a fresh kernel seeded with the durably-burned nonce. No state was
    // carried over except what the ledger recorded.
    let mut rebooted = Kernel::with_burned_nonces(["nonce-persisted".to_owned()]);
    let (auth2, reval2) = authorized_at_boundary(&rebooted, &grant, &planned, now);
    let err = rebooted
        .commit(CommitRequest {
            authorization: &auth2,
            intent: &reval2,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-2",
            one_shot_nonce: "nonce-persisted", // replay across the restart
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::NonceAlreadyUsed { .. })
    ));
    assert_eq!(rebooted.nonces_spent(), 1);
}

// The seeding constructor is additive: an unseeded kernel still starts empty.
#[test]
fn fresh_kernel_starts_with_zero_spent_nonces() {
    let kernel = Kernel::new();
    assert_eq!(kernel.nonces_spent(), 0);
}
#[test]
fn stale_permit_generation_drift_denies_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant_at_authorize = base_grant(now, 7);
    let planned = witness("v1");
    let (auth, revalidating) = authorized_at_boundary(&kernel, &grant_at_authorize, &planned, now);

    // Grant re-issued: generation moved from 7 to 8 in the window.
    let grant_now = base_grant(now, 8);
    let observed = witness("v1");
    let durable = durability();
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &revalidating,
            grant: &grant_now,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::GrantGenerationDrift { .. })
    ));
    assert_eq!(kernel.nonces_spent(), 0);
}

// Stale authority: the grant was revoked between authorize and commit.
#[test]
fn stale_permit_grant_revoked_after_authorize_denies_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 3);
    let planned = witness("v1");
    let (auth, revalidating) = authorized_at_boundary(&kernel, &grant, &planned, now);

    let mut grant_now = base_grant(now, 3);
    grant_now.revocation_state = RevocationState::Revoked;
    let observed = witness("v1");
    let durable = durability();
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &revalidating,
            grant: &grant_now,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::GrantNotActive { .. })
    ));
}

// ── wrong resource = deny ──────────────────────────────────────────────────
// Grant scoped to a different resource id than the intent targets.
#[test]
fn wrong_resource_not_covered_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let mut grant = base_grant(now, 1);
    grant.resources = vec![ResourceSelector {
        resource_type: RESOURCE_TYPE.into(),
        resource_id: "some-other-row".into(),
    }];
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::ResourceNotGranted { .. }));
}

// Wrong resource type, even with the right id.
#[test]
fn wrong_resource_type_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: "blobstore", // grant covers "database"
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::ResourceNotGranted { .. }));
}

// Resource moved after planning: witness drift at the commit boundary.
#[test]
fn wrong_resource_witness_drift_denies_commit() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    let (auth, revalidating) = authorized_at_boundary(&kernel, &grant, &planned, now);

    let observed = witness("v2"); // someone else wrote the row
    let durable = durability();
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth,
            intent: &revalidating,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-1",
            one_shot_nonce: "nonce-1",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::Permit(PermitError::ResourceWitnessDrift { .. })
    ));
    assert_eq!(kernel.nonces_spent(), 0);
}

// ── further escalation attempts ────────────────────────────────────────────

#[test]
fn wrong_operation_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: "admin", // not in grant.operations
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::OperationNotGranted { .. }));
}

#[test]
fn wrong_principal_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: "attacker", // grant belongs to principal-1
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::PrincipalMismatch { .. }));
}

#[test]
fn capability_id_mismatch_denies_authorization() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let mut grant = base_grant(now, 1);
    grant.grant_id = "a-different-grant".into(); // intent.capability_id is "grant-1"
    let planned = witness("v1");
    let pending = pending_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::CapabilityMismatch { .. }));
}

#[test]
fn authorize_out_of_order_state_denied() {
    let now = Utc::now();
    let kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");
    // Present an intent still in INTENT_DURABLE (AuthorizationRequested skipped).
    let intent = base_intent();

    let err = kernel
        .authorize(AuthorizeRequest {
            intent: &intent,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap_err();
    assert!(matches!(err, KernelError::WrongState { .. }));
}

// An Authorization minted for effect A cannot be used to commit effect B.
#[test]
fn cross_effect_authorization_reuse_denied() {
    let now = Utc::now();
    let mut kernel = Kernel::new();
    let grant = base_grant(now, 1);
    let planned = witness("v1");

    // Authorize effect A.
    let (auth_a, _reval_a) = authorized_at_boundary(&kernel, &grant, &planned, now);

    // Build a DIFFERENT effect B and stand it at the boundary, but try to use
    // effect A's authorization to commit it.
    let intent_b = EffectIntent::builder("effect-2", "mission-1", GRANT_ID, TARGET_ID)
        .canonical_request_digest(
            "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )
        .classes("db.write", "high")
        .idempotency(Idempotency::keyed("orders", "idem-key-2"))
        .reconciliation(Reconciliation::new(
            ReconciliationClass::LedgerReplay,
            RetryClass::ReconcileBeforeRetry,
        ))
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .unwrap();
    let pending_b = intent_b
        .try_advance(&EffectEvent::AuthorizationRequested)
        .unwrap();
    let (_auth_b, authorized_b) = kernel
        .authorize(AuthorizeRequest {
            intent: &pending_b,
            grant: &grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .unwrap();
    let reval_b = authorized_b
        .try_advance(&EffectEvent::CommitRevalidationStarted)
        .unwrap();

    let observed = witness("v1");
    let durable = durability_for(&reval_b); // real proof on effect-2's stream
    let err = kernel
        .commit(CommitRequest {
            authorization: &auth_a, // wrong effect's authorization
            intent: &reval_b,
            grant: &grant,
            observed_witness: &observed,
            durability: &durable,
            permit_id: "permit-2",
            one_shot_nonce: "nonce-2",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KernelError::AuthorizationEffectMismatch { .. }
    ));
    assert_eq!(kernel.nonces_spent(), 0);
}
