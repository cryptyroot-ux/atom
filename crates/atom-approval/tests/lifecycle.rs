//! AUT-003 acceptance suite for the durable ApprovalGrant lifecycle store.
//!
//! These tests are written before the implementation (TDD, RED first). They pin
//! the four normative behaviours from `TASK.md` / `spec/` AUT-003:
//!
//! * changed-payload  → deny  (approval bound to effect digest A never redeems B)
//! * expiry           → deny  (grant redeemed outside its validity interval)
//! * revocation       → deny  (revoked grant, even before expiry)
//! * happy path       → ok    (valid digest, inside interval, not revoked)
//! * deny-by-default  → deny  (no matching grant at all)
//!
//! The store reads no clock: `now` is always injected so identical inputs give
//! identical decisions.

use atom_approval::{
    ApprovalGrant, ApprovalScope, ApprovalStore, CapabilityEnvelope, RedeemError, RedeemTarget,
    ValidityInterval,
};
use atom_capability::{Budget, ResourceSelector};
use atom_effect::{
    Compensation, CompensationStrategy, Condition, EffectIntent, Idempotency, Reconciliation,
    ReconciliationClass, RetryClass,
};
use chrono::{DateTime, TimeZone, Utc};

const APPROVER: &str = "principal/security-officer";
const OPERATION: &str = "write";
const RESOURCE_TYPE: &str = "db";
const RESOURCE_ID: &str = "db/orders";

fn at(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, hour, minute, 0)
        .single()
        .expect("fixture timestamp is unambiguous")
}

/// Commit-time "now" used across the suite, inside the fixture interval.
fn now() -> DateTime<Utc> {
    at(12, 0)
}

fn interval() -> ValidityInterval {
    ValidityInterval::new(at(11, 0), at(13, 0)).expect("valid interval")
}

/// A canonical effect intent whose digest binds to the request payload.
fn intent_with_request(request_digest: &str) -> EffectIntent {
    EffectIntent::builder(
        "effect/01J8ZPEFFECTORDERS",
        "mission/01J8Z0MISSIONORDERS",
        "grant/orders-writer",
        RESOURCE_ID,
    )
    .request_digest(request_digest)
    .classes("RESOURCE_MUTATION", "HIGH")
    .idempotency(Idempotency::keyed(RESOURCE_ID, "idem-8842"))
    .reconciliation(
        Reconciliation::new(
            ReconciliationClass::ExternalOperationLookup,
            RetryClass::ReconcileBeforeRetry,
        )
        .with_probe("GET /orders/8842"),
    )
    .precondition(Condition::new("pre/row-exists", "orders.id == 8842"))
    .postcondition(Condition::new(
        "post/row-archived",
        "orders.state == 'ARCHIVED'",
    ))
    .compensation(
        Compensation::new(CompensationStrategy::InverseOperation)
            .with_operation("POST /orders/8842/restore"),
    )
    .build()
    .expect("fixture intent satisfies EFX-002")
}

fn effect_grant(effect_digest: &str) -> ApprovalGrant {
    ApprovalGrant::new(
        "approval/effect-1",
        APPROVER,
        ApprovalScope::Effect {
            effect_digest: effect_digest.to_owned(),
        },
        interval(),
    )
}

fn resources() -> Vec<ResourceSelector> {
    vec![ResourceSelector {
        resource_type: RESOURCE_TYPE.into(),
        resource_id: RESOURCE_ID.into(),
    }]
}

fn effect_target(effect_digest: &str) -> RedeemTarget {
    RedeemTarget::Effect {
        effect_digest: effect_digest.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// AUT-003: changed-payload → deny
// ---------------------------------------------------------------------------

#[test]
fn changed_payload_is_denied() {
    let approved = intent_with_request("sha256:aaaa");
    let mutated = intent_with_request("sha256:bbbb");
    assert_ne!(
        approved.digest(),
        mutated.digest(),
        "a changed request payload must change the effect digest"
    );

    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&approved.digest()))
        .expect("record durable grant");

    // Redeeming for the digest that was approved works.
    assert!(store
        .redeem(&effect_target(&approved.digest()), now())
        .is_ok());

    // Redeeming for the mutated payload's digest is denied: the approval was
    // bound to exactly one effect identity.
    let denied = store.redeem(&effect_target(&mutated.digest()), now());
    assert!(matches!(denied, Err(RedeemError::NoMatchingGrant)));
}

// ---------------------------------------------------------------------------
// AUT-003: expiry → deny
// ---------------------------------------------------------------------------

#[test]
fn expired_grant_is_denied() {
    let intent = intent_with_request("sha256:aaaa");
    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&intent.digest()))
        .expect("record durable grant");

    let after_expiry = at(13, 1);
    let denied = store.redeem(&effect_target(&intent.digest()), after_expiry);
    assert!(matches!(denied, Err(RedeemError::Expired { .. })));
}

#[test]
fn not_yet_valid_grant_is_denied() {
    let intent = intent_with_request("sha256:aaaa");
    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&intent.digest()))
        .expect("record durable grant");

    let before_start = at(10, 59);
    let denied = store.redeem(&effect_target(&intent.digest()), before_start);
    assert!(matches!(denied, Err(RedeemError::NotYetValid { .. })));
}

// ---------------------------------------------------------------------------
// AUT-003: revocation → deny (even before expiry)
// ---------------------------------------------------------------------------

#[test]
fn revoked_grant_is_denied_before_expiry() {
    let intent = intent_with_request("sha256:aaaa");
    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&intent.digest()))
        .expect("record durable grant");

    // Valid before revocation.
    assert!(store
        .redeem(&effect_target(&intent.digest()), now())
        .is_ok());

    store.revoke("approval/effect-1").expect("revoke grant");

    // Denied after revocation despite still being inside the validity interval.
    let denied = store.redeem(&effect_target(&intent.digest()), now());
    assert!(matches!(denied, Err(RedeemError::Revoked { .. })));
}

// ---------------------------------------------------------------------------
// AUT-003: happy path → ok
// ---------------------------------------------------------------------------

#[test]
fn valid_matching_grant_redeems() {
    let intent = intent_with_request("sha256:aaaa");
    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&intent.digest()))
        .expect("record durable grant");

    let receipt = store
        .redeem(&effect_target(&intent.digest()), now())
        .expect("valid grant redeems");
    assert_eq!(receipt.grant_id, "approval/effect-1");
    assert_eq!(receipt.redeemed_at, now());
}

// ---------------------------------------------------------------------------
// Deny-by-default
// ---------------------------------------------------------------------------

#[test]
fn empty_store_denies_by_default() {
    let intent = intent_with_request("sha256:aaaa");
    let store = ApprovalStore::new();
    let denied = store.redeem(&effect_target(&intent.digest()), now());
    assert!(matches!(denied, Err(RedeemError::NoMatchingGrant)));
}

// ---------------------------------------------------------------------------
// Capability-envelope scope (AUT-003: exact effect OR bounded envelope)
// ---------------------------------------------------------------------------

fn capability_grant() -> ApprovalGrant {
    ApprovalGrant::new(
        "approval/envelope-1",
        APPROVER,
        ApprovalScope::Capability(CapabilityEnvelope {
            operations: vec!["read".into(), OPERATION.into()],
            resources: resources(),
            budget: Some(Budget {
                max_cost: 1_000,
                max_seconds: 7_200,
            }),
        }),
        interval(),
    )
}

#[test]
fn capability_envelope_covers_matching_effect() {
    let mut store = ApprovalStore::new();
    store.record(capability_grant()).expect("record");

    let target = RedeemTarget::Capability {
        operation: OPERATION.into(),
        resources: resources(),
        budget: Some(Budget {
            max_cost: 500,
            max_seconds: 60,
        }),
    };
    assert!(store.redeem(&target, now()).is_ok());
}

#[test]
fn capability_envelope_denies_operation_outside_envelope() {
    let mut store = ApprovalStore::new();
    store.record(capability_grant()).expect("record");

    let target = RedeemTarget::Capability {
        operation: "delete".into(),
        resources: resources(),
        budget: None,
    };
    assert!(matches!(
        store.redeem(&target, now()),
        Err(RedeemError::NoMatchingGrant)
    ));
}

#[test]
fn capability_envelope_denies_resource_outside_envelope() {
    let mut store = ApprovalStore::new();
    store.record(capability_grant()).expect("record");

    let target = RedeemTarget::Capability {
        operation: OPERATION.into(),
        resources: vec![ResourceSelector {
            resource_type: RESOURCE_TYPE.into(),
            resource_id: "db/secrets".into(),
        }],
        budget: None,
    };
    assert!(matches!(
        store.redeem(&target, now()),
        Err(RedeemError::NoMatchingGrant)
    ));
}

#[test]
fn capability_envelope_denies_budget_over_envelope() {
    let mut store = ApprovalStore::new();
    store.record(capability_grant()).expect("record");

    let target = RedeemTarget::Capability {
        operation: OPERATION.into(),
        resources: resources(),
        budget: Some(Budget {
            max_cost: 10_000,
            max_seconds: 60,
        }),
    };
    assert!(matches!(
        store.redeem(&target, now()),
        Err(RedeemError::NoMatchingGrant)
    ));
}

#[test]
fn effect_target_never_matches_capability_scope_and_vice_versa() {
    let mut store = ApprovalStore::new();
    store.record(capability_grant()).expect("record");

    // An exact-effect redemption cannot be satisfied by an envelope grant that
    // was never bound to that precise digest.
    let denied = store.redeem(&effect_target("sha256:whatever"), now());
    assert!(matches!(denied, Err(RedeemError::NoMatchingGrant)));
}

// ---------------------------------------------------------------------------
// Durability: the store and its grants survive a serialization round-trip.
// ---------------------------------------------------------------------------

#[test]
fn store_round_trips_through_serialization() {
    let intent = intent_with_request("sha256:aaaa");
    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&intent.digest()))
        .expect("record");
    store.revoke("approval/effect-1").expect("revoke");

    let json = serde_json::to_string(&store).expect("serialize");
    let restored: ApprovalStore = serde_json::from_str(&json).expect("deserialize");

    // Revocation state is durable across the round-trip.
    let denied = restored.redeem(&effect_target(&intent.digest()), now());
    assert!(matches!(denied, Err(RedeemError::Revoked { .. })));
}

// ---------------------------------------------------------------------------
// Store integrity guards
// ---------------------------------------------------------------------------

#[test]
fn recording_duplicate_grant_id_is_rejected() {
    let intent = intent_with_request("sha256:aaaa");
    let mut store = ApprovalStore::new();
    store
        .record(effect_grant(&intent.digest()))
        .expect("record");
    let dup = store.record(effect_grant(&intent.digest()));
    assert!(dup.is_err());
}

#[test]
fn revoking_unknown_grant_is_rejected() {
    let mut store = ApprovalStore::new();
    assert!(store.revoke("approval/missing").is_err());
}

#[test]
fn interval_rejects_inverted_bounds() {
    assert!(ValidityInterval::new(at(13, 0), at(11, 0)).is_err());
}
