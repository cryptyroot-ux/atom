//! ATOM-VT (KRN-002) — the privilege boundary.
//!
//! A host operation reaches the recording executor only behind a valid,
//! one-shot [`atom_effect::CommitPermit`]. Everything the commit gate would
//! refuse — an expired, premature, revoked, drifted, replayed, or foreign
//! permit — is refused here too, and never touches the host.

mod support;

use atom_effect::PermitError;
use atom_privd::{AdmissionRequest, DenyReason};
use support::{
    at, broker, drifted_witness, foreign_intent_for, regenerated, revoked, Scenario, RecordingExecutor,
    all_ops, NONCE, PERMIT_ID,
};
use atom_privd::PrivilegeBroker;

#[test]
fn a_valid_permit_admits_the_op_and_reaches_the_executor_once() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let mut broker = broker();

    let admitted = broker
        .admit(scenario.request())
        .expect("a valid, unspent permit admits the op");

    assert_eq!(admitted.permit_id, PERMIT_ID);
    assert_eq!(admitted.one_shot_nonce, NONCE);
    assert_eq!(admitted.outcome.op_kind, scenario.op.kind());
    assert_eq!(
        broker.executor().executed(),
        std::slice::from_ref(&scenario.op),
        "exactly the admitted op reached the host"
    );
    assert_eq!(broker.spent(), 1, "the permit was consumed exactly once");
}

#[test]
fn a_valid_permit_admits_every_typed_op() {
    for op in all_ops() {
        let scenario = Scenario::new(op.clone());
        let mut broker = broker();
        broker
            .admit(scenario.request())
            .unwrap_or_else(|error| panic!("{}: {error:?}", op.kind()));
        assert_eq!(broker.executor().count(), 1, "{}", op.kind());
        assert_eq!(broker.spent(), 1, "{}", op.kind());
    }
}

#[test]
fn a_replayed_permit_is_denied_and_runs_the_op_only_once() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let mut broker = broker();

    broker.admit(scenario.request()).expect("the first crossing");
    let denied = broker
        .admit(scenario.request())
        .expect_err("EFX-004: a commit permit is one-shot");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::NonceAlreadyUsed { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 1, "the op ran once, not twice");
    assert_eq!(broker.spent(), 1);
}

#[test]
fn an_expired_permit_is_denied_and_never_reaches_the_executor() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            now: at(12, 0, 16),
            ..scenario.request()
        })
        .expect_err("a permit past its TTL is dead");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::PermitExpired { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
    assert_eq!(broker.spent(), 0);
}

#[test]
fn a_premature_permit_is_denied() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            now: at(11, 59, 59),
            ..scenario.request()
        })
        .expect_err("a permit before it was issued is not yet valid");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::PermitNotYetValid { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
}

#[test]
fn a_revoked_grant_is_denied_and_never_reaches_the_executor() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let revoked_grant = revoked(&scenario.grant);
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            grant: &revoked_grant,
            ..scenario.request()
        })
        .expect_err("VT: a revoked grant must not cross the boundary");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::GrantNotActive { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
    assert_eq!(broker.spent(), 0);
}

#[test]
fn a_regenerated_grant_is_denied() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let regenerated_grant = regenerated(&scenario.grant);
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            grant: &regenerated_grant,
            ..scenario.request()
        })
        .expect_err("VT-003: authority drift must not cross the boundary");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::GrantGenerationDrift { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
}

#[test]
fn a_drifted_resource_is_denied() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let drifted = drifted_witness(&scenario.op);
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            observed_witness: &drifted,
            ..scenario.request()
        })
        .expect_err("VT-003: a changed resource must not cross the boundary");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::ResourceWitnessDrift { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
}

#[test]
fn a_permit_bound_to_another_effect_is_denied() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let other = foreign_intent_for(&scenario.op);
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            intent: &other,
            ..scenario.request()
        })
        .expect_err("EFX-004: a permit is bound to one effect digest");

    assert!(
        matches!(
            denied,
            DenyReason::PermitRejected(PermitError::DigestMismatch { .. })
        ),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
}

/// A host-side failure is not a boundary denial: the permit was validly spent
/// before the executor ran, so the crossing cannot be retried.
#[test]
fn a_host_failure_after_a_valid_crossing_still_burns_the_permit() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let mut broker = PrivilegeBroker::new(RecordingExecutor::failing());

    let denied = broker
        .admit(scenario.request())
        .expect_err("the host refused the op");
    assert!(matches!(denied, DenyReason::ExecutionFailed(_)), "{denied:?}");
    assert_eq!(broker.spent(), 1, "the permit was consumed before dispatch");

    let retried = broker
        .admit(scenario.request())
        .expect_err("the permit is one-shot even when the host fails");
    assert!(
        matches!(
            retried,
            DenyReason::PermitRejected(PermitError::NonceAlreadyUsed { .. })
        ),
        "{retried:?}"
    );
}
