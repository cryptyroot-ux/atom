//! The load-bearing property of KRN-002: no path admits a host op without a
//! valid, unspent [`atom_effect::CommitPermit`], and a refused crossing burns
//! nothing — the permit is still good if the drift that caused the refusal was
//! transient.
//!
//! The type system carries half the proof: [`atom_privd::PrivilegeBroker`] owns
//! its executor privately and exposes it only as `&E`, so the sole path that
//! can call `execute` is `admit`, and `admit` executes only after the permit is
//! consumed. These tests carry the other half at runtime.

mod support;

use atom_effect::PermitError;
use atom_privd::{AdmissionRequest, DenyReason};
use support::{
    all_ops, at, broker, drifted_witness, foreign_intent_for, regenerated, revoked, Scenario,
};

#[test]
fn no_tampered_crossing_ever_reaches_the_executor_or_spends_the_permit() {
    for op in all_ops() {
        let scenario = Scenario::new(op.clone());

        // These are the values a valid permit was frozen against; each variant
        // below drifts exactly one and must be refused on that ground.
        let revoked_grant = revoked(&scenario.grant);
        let regenerated_grant = regenerated(&scenario.grant);
        let drifted = drifted_witness(&scenario.op);
        let foreign = foreign_intent_for(&scenario.op);

        let tampered: [(&str, AdmissionRequest); 6] = [
            (
                "expired",
                AdmissionRequest {
                    now: at(12, 0, 16),
                    ..scenario.request()
                },
            ),
            (
                "premature",
                AdmissionRequest {
                    now: at(11, 59, 59),
                    ..scenario.request()
                },
            ),
            (
                "revoked",
                AdmissionRequest {
                    grant: &revoked_grant,
                    ..scenario.request()
                },
            ),
            (
                "regenerated",
                AdmissionRequest {
                    grant: &regenerated_grant,
                    ..scenario.request()
                },
            ),
            (
                "witness-drift",
                AdmissionRequest {
                    observed_witness: &drifted,
                    ..scenario.request()
                },
            ),
            (
                "foreign-effect",
                AdmissionRequest {
                    intent: &foreign,
                    ..scenario.request()
                },
            ),
        ];

        // One broker sees every tampered crossing in turn. Because no refusal
        // may burn the nonce, the untouched permit must still be good at the
        // end — proving none of the refusals silently spent it.
        let mut broker = broker();
        for (label, request) in tampered {
            match broker.admit(request) {
                Ok(_) => panic!("{}/{label}: a tampered crossing must be refused", op.kind()),
                Err(denied) => assert!(
                    matches!(denied, DenyReason::PermitRejected(_)),
                    "{}/{label}: expected a permit refusal, got {denied:?}",
                    op.kind()
                ),
            }
            assert_eq!(broker.executor().count(), 0, "{}/{label}", op.kind());
            assert_eq!(
                broker.spent(),
                0,
                "{}/{label} must not burn the permit",
                op.kind()
            );
        }

        broker.admit(scenario.request()).unwrap_or_else(|error| {
            panic!(
                "{}: the undrifted permit is still good: {error:?}",
                op.kind()
            )
        });
        assert_eq!(broker.executor().count(), 1, "{}", op.kind());
        assert_eq!(broker.spent(), 1, "{}", op.kind());
    }
}

/// A permit refused at the boundary can be retried once the transient drift
/// clears — the refusal genuinely burned nothing.
#[test]
fn a_transiently_refused_permit_is_still_consumable_once() {
    let scenario = Scenario::new(all_ops()[0].clone());
    let revoked_grant = revoked(&scenario.grant);
    let mut broker = broker();

    broker
        .admit(AdmissionRequest {
            grant: &revoked_grant,
            ..scenario.request()
        })
        .expect_err("refused while the grant was revoked");
    assert_eq!(broker.spent(), 0);

    // The revocation is lifted; the same permit crosses exactly once.
    broker
        .admit(scenario.request())
        .expect("the permit outlived a transient refusal");
    assert_eq!(broker.executor().count(), 1);

    let replay = broker.admit(scenario.request()).expect_err("but only once");
    assert!(
        matches!(
            replay,
            DenyReason::PermitRejected(PermitError::NonceAlreadyUsed { .. })
        ),
        "{replay:?}"
    );
}
