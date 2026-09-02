//! Shared deterministic fixtures for the atom-effect acceptance tests
//! (ATOM-VT-002 unknown external effect, ATOM-VT-003 TOCTOU authority drift)
//! and the state-machine/schema conformance suites.
//!
//! Every timestamp is a literal. The crate under test never reads a clock, so
//! neither do its tests: identical event logs must produce identical digests.

#![allow(dead_code)]

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_effect::{
    CommitPermitted, Compensation, CompensationStrategy, Condition, DurabilityProof, EffectEvent,
    EffectIntent, EffectState, Idempotency, ObservedOutcome, ReconciledOutcome, Reconciliation,
    ReconciliationClass, ResourceWitness, RetryClass,
};
use atom_ledger::{HmacSha256Signer, Ledger};
use chrono::{DateTime, TimeZone, Utc};

pub const PRINCIPAL: &str = "principal/atom-operator";
pub const GRANT_ID: &str = "grant/orders-writer";
pub const OPERATION: &str = "write";
pub const RESOURCE_TYPE: &str = "db";
pub const RESOURCE_ID: &str = "db/orders";
pub const EFFECT_ID: &str = "effect/01J8ZPEFFECTORDERS";
pub const UPSTREAM_EFFECT_ID: &str = "effect/01J8ZPUPSTREAMWRITE";
pub const GRANT_GENERATION: u64 = 7;
pub const EXTERNAL_OPERATION_ID: &str = "ext-op-8842";

/// A fixed instant on 2026-08-30, inside the fixture grant's validity window.
pub fn at(hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, hour, minute, second)
        .single()
        .expect("fixture timestamp is unambiguous")
}

/// Commit-time "now" used by permit issuance and consumption.
pub fn now() -> DateTime<Utc> {
    at(12, 0, 0)
}

/// An active grant that authorises `write` on the fixture resource.
pub fn grant() -> CapabilityGrant {
    CapabilityGrant {
        grant_id: GRANT_ID.into(),
        subject_id: PRINCIPAL.into(),
        workload_id: "workload/atomd".into(),
        operations: vec!["read".into(), OPERATION.into()],
        resources: vec![ResourceSelector {
            resource_type: RESOURCE_TYPE.into(),
            resource_id: RESOURCE_ID.into(),
        }],
        purpose: "order maintenance".into(),
        not_before: at(11, 0, 0),
        expires_at: at(13, 0, 0),
        budget: Budget {
            max_cost: 1_000,
            max_seconds: 7_200,
        },
        delegation_depth: 3,
        audience: "atom:orders".into(),
        generation: GRANT_GENERATION,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        parent_authority_digest: None,
        holder_binding: None,
        authority_digest: None,
        nonce: None,
        constraints: None,
    }

/// The same grant after the owner revoked it (ATOM-VT-003).
pub fn revoked_grant() -> CapabilityGrant {
    CapabilityGrant {
        revocation_state: RevocationState::Revoked,
        ..grant()
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
}

/// The same grant after a re-issue bumped its generation (ATOM-VT-003).
pub fn regenerated_grant() -> CapabilityGrant {
    CapabilityGrant {
        generation: GRANT_GENERATION + 1,
        ..grant()
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
}

pub fn witness(value: &str) -> ResourceWitness {
    ResourceWitness::new("etag", RESOURCE_ID, value)
}

/// The resource version observed while the effect was planned.
pub fn planned_witness() -> ResourceWitness {
    witness("W/\"17\"")
}

/// The resource version after somebody else wrote to the target.
pub fn drifted_witness() -> ResourceWitness {
    witness("W/\"18\"")
}

/// Proof that the EffectIntent was persisted before dispatch (EFX-001).
///
/// Minted the only way a real proof can be: by actually appending the declared
/// intent (the identity payload, stable across lifecycle transitions) to a ledger
/// stream named for the effect. There is no `DurabilityProof` constructor a test
/// could call directly, which is the point — a forged proof is inexpressible, so
/// the tests exercise the same durability path production does.
pub fn durability() -> DurabilityProof {
    durability_for(&intent_in(EffectState::CommitRevalidating))
}

/// Proof bound to exactly `intent`: the declared payload is appended to the
/// effect's own stream, so `proof.proves_intent(effect_id, declared_digest)`
/// holds for this intent and no other.
///
/// There is no `DurabilityProof` constructor a caller can invoke, so a forged
/// proof is inexpressible. The only adversarial moves left — a *real* proof
/// belonging to another effect, or one whose stream matches but whose payload
/// differs — are exercised by the callers (ATOM-INV-004, EFX-001).
pub fn durability_for(intent: &EffectIntent) -> DurabilityProof {
    let signer = Box::new(HmacSha256Signer::new(
        "atom-effect-test-seal",
        b"atom-effect-test-key-not-for-production",
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

/// A real durable proof over an arbitrary `payload` on `stream_id`.
///
/// Used to mount an ATOM-INV-004 payload-swap attack: a genuine ledger-sealed
/// proof on the *right* stream whose payload is not the intent's declaration.
pub fn proof_over(stream_id: &str, payload: &serde_json::Value) -> DurabilityProof {
    let signer = Box::new(HmacSha256Signer::new(
        "atom-effect-test-seal",
        b"atom-effect-test-key-not-for-production",
    ));
    let mut ledger = Ledger::open_in_memory(signer).expect("in-memory ledger opens");
    let (_event, proof) = ledger
        .append_durable(stream_id, payload, 1_756_512_000_000)
        .expect("appending seals a durability proof");
    proof
}

/// A complete EffectIntent carrying every EFX-002 field, in INTENT_DURABLE.
pub fn intent() -> EffectIntent {
    EffectIntent::builder(
        EFFECT_ID,
        "mission/01J8Z0MISSIONORDERS",
        GRANT_ID,
        RESOURCE_ID,
    )
    .canonical_request_digest(
        "sha256:5f2c9e1d8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
    )
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
    .dependency(UPSTREAM_EFFECT_ID)
    .build()
    .expect("fixture intent satisfies EFX-002")
}

/// The dependency of [`intent`]: same shape, no dependencies of its own.
pub fn upstream_intent() -> EffectIntent {
    EffectIntent::builder(
        UPSTREAM_EFFECT_ID,
        "mission/01J8Z0MISSIONORDERS",
        GRANT_ID,
        RESOURCE_ID,
    )
    .canonical_request_digest(
        "sha256:0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff0",
    )
    .classes("RESOURCE_MUTATION", "HIGH")
    .idempotency(Idempotency::keyed(RESOURCE_ID, "idem-8841"))
    .reconciliation(
        Reconciliation::new(
            ReconciliationClass::ExternalOperationLookup,
            RetryClass::ReconcileBeforeRetry,
        )
        .with_probe("GET /orders/8841"),
    )
    .compensation(Compensation::new(CompensationStrategy::NotCompensable))
    .build()
    .expect("upstream fixture satisfies EFX-002")
}

/// `subject` driven to `state` through durable events only.
pub fn advanced(subject: EffectIntent, state: EffectState) -> EffectIntent {
    let mut current = subject;
    for event in path_to(state) {
        current = current
            .try_advance(&event)
            .expect("fixture path follows spec/state-machines/effect.yaml");
    }
    assert_eq!(current.state, state, "fixture path must reach {state}");
    current
}

/// The fixture intent driven to `state` through durable events only.
pub fn intent_in(state: EffectState) -> EffectIntent {
    advanced(intent(), state)
}

/// The CommitPermitted event a real commit gate emits after consuming a permit.
pub fn sample_commit_permitted() -> EffectEvent {
    EffectEvent::CommitPermitted(CommitPermitted {
        permit_id: "permit/01J8ZPCOMMITORDERS".into(),
        one_shot_nonce: "nonce/01J8ZPCOMMITORDERS".into(),
        effect_digest: intent().digest(),
    })
}

/// The shortest durable-event path from INTENT_DURABLE to `state`.
///
/// Only edges present in `spec/state-machines/effect.yaml` are used, so a path
/// that stops being legal is a spec/code disagreement, not a fixture bug.
pub fn path_to(state: EffectState) -> Vec<EffectEvent> {
    use EffectState as S;

    let mut events = Vec::new();
    if state == S::IntentDurable {
        return events;
    }
    if state == S::CancelledBeforeEffect {
        events.push(EffectEvent::cancelled("operator cancelled before dispatch"));
        return events;
    }

    events.push(EffectEvent::AuthorizationRequested);
    if state == S::AuthorizationPending {
        return events;
    }
    events.push(EffectEvent::authorization_granted(
        GRANT_ID,
        GRANT_GENERATION,
    ));
    if state == S::Authorized {
        return events;
    }
    events.push(EffectEvent::CommitRevalidationStarted);
    if state == S::CommitRevalidating {
        return events;
    }
    if state == S::ConfirmedFailure {
        events.push(sample_commit_permitted());
        events.push(EffectEvent::dispatch_rejected(
            "target rejected the request",
        ));
        return events;
    }
    events.push(sample_commit_permitted());
    if state == S::Dispatching {
        return events;
    }
    events.push(EffectEvent::dispatched(Some(EXTERNAL_OPERATION_ID)));
    if state == S::Dispatched {
        return events;
    }
    if state == S::UnknownOutcome || state == S::Reconciling {
        events.push(EffectEvent::observation_lost("remote dropped the response"));
        if state == S::Reconciling {
            events.push(EffectEvent::ReconciliationStarted);
        }
        return events;
    }
    events.push(EffectEvent::ObservationStarted);
    if state == S::Observing {
        return events;
    }
    match state {
        S::ConfirmedSuccess => events.push(EffectEvent::observed(ObservedOutcome::Success)),
        S::Partial => events.push(EffectEvent::observed(ObservedOutcome::Partial)),
        S::Compensating | S::Compensated | S::CompensationFailed => {
            events.push(EffectEvent::observed(ObservedOutcome::Partial));
            events.push(EffectEvent::CompensationStarted);
            if state == S::Compensated {
                events.push(EffectEvent::Compensated);
            } else if state == S::CompensationFailed {
                events.push(EffectEvent::compensation_failed("undo was rejected"));
            }
        }
        other => panic!("no fixture path defined for {other}"),
    }
    events
}

/// One event of every variant, for exhaustive (state x event) reducer sweeps.
pub fn sample_events() -> Vec<EffectEvent> {
    vec![
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(GRANT_ID, GRANT_GENERATION),
        EffectEvent::CommitRevalidationStarted,
        sample_commit_permitted(),
        EffectEvent::commit_revalidation_failed("grant generation drifted"),
        EffectEvent::cancelled("operator cancelled before dispatch"),
        EffectEvent::dispatched(Some(EXTERNAL_OPERATION_ID)),
        EffectEvent::dispatch_rejected("target rejected the request"),
        EffectEvent::dispatch_ambiguous("connection reset while sending"),
        EffectEvent::ObservationStarted,
        EffectEvent::observation_lost("remote dropped the response"),
        EffectEvent::observed(ObservedOutcome::Success),
        EffectEvent::observed(ObservedOutcome::Failure),
        EffectEvent::observed(ObservedOutcome::Partial),
        EffectEvent::observed(ObservedOutcome::Ambiguous),
        EffectEvent::ReconciliationStarted,
        EffectEvent::reconciled(ReconciledOutcome::Success),
        EffectEvent::reconciled(ReconciledOutcome::Failure),
        EffectEvent::reconciled(ReconciledOutcome::Partial),
        EffectEvent::reconciled(ReconciledOutcome::Inconclusive),
        EffectEvent::CompensationStarted,
        EffectEvent::Compensated,
        EffectEvent::compensation_failed("undo was rejected"),
        EffectEvent::compensation_ambiguous("undo response was lost"),
    ]
}
