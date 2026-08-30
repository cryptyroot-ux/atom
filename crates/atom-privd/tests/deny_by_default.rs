//! Deny-by-default (KRN-002): host administration is a closed, typed enum with
//! a validated schema, and the grant's allowlist is re-checked at the boundary.
//!
//! There is no "run arbitrary command": an unknown operation is rejected before
//! it can name itself, a malformed operation is rejected before any permit is
//! spent, and a valid permit authorises only the exact operation and resource
//! its grant covers.

mod support;

use atom_privd::{AdmissionRequest, DenyReason, HostOp, OpError};
use support::{
    broker, grant_covering, intent_for, now, permit_for, planned_witness, Scenario,
};

#[test]
fn an_unknown_operation_tag_is_rejected_at_the_type_boundary() {
    // No variant names this, so it can never be constructed — only attempted
    // over the wire, where the closed enum refuses it.
    let unknown = r#"{"op":"run_arbitrary","program":"/bin/sh","args":["-c","rm -rf /"]}"#;
    let error = serde_json::from_str::<HostOp>(unknown)
        .expect_err("deny-by-default: an unknown op is not a HostOp");
    assert!(
        error.to_string().contains("unknown variant"),
        "{error}"
    );
}

#[test]
fn every_known_operation_round_trips_through_its_own_tag() {
    for op in support::all_ops() {
        let json = serde_json::to_string(&op).expect("a HostOp serialises");
        let back: HostOp = serde_json::from_str(&json).expect("and deserialises");
        assert_eq!(back, op);
        assert!(json.contains(op.kind()), "{json} carries tag {}", op.kind());
    }
}

#[test]
fn a_malformed_operation_is_denied_before_any_permit_is_spent() {
    let scenario = Scenario::new(HostOp::WriteFile {
        path: "/etc/atom/app.conf".into(),
        contents: "key = value\n".into(),
    });

    let malformed = [
        HostOp::WriteFile {
            path: "   ".into(),
            contents: "x".into(),
        },
        HostOp::RemoveFile {
            path: "relative/path".into(),
        },
        HostOp::SpawnProcess {
            program: "systemctl".into(),
            args: vec!["restart".into()],
        },
        HostOp::ConfigureNetwork {
            interface: "eth0".into(),
            allow_cidr: "not-a-cidr".into(),
        },
    ];

    for op in malformed {
        let mut broker = broker();
        let denied = broker
            .admit(AdmissionRequest {
                op: &op,
                ..scenario.request()
            })
            .expect_err("a malformed op must be refused");
        assert!(matches!(denied, DenyReason::InvalidOp(_)), "{op:?}: {denied:?}");
        assert_eq!(broker.executor().count(), 0, "{op:?}");
        assert_eq!(broker.spent(), 0, "{op:?} must not spend a permit");
    }
}

#[test]
fn a_blank_field_names_itself() {
    let error = HostOp::RemoveFile { path: String::new() }
        .validate()
        .expect_err("an empty path is not a resource");
    assert!(matches!(error, OpError::BlankField { .. }), "{error:?}");
}

/// The permit carries no operation, so the broker — not the permit — enforces
/// the allowlist: a permit issued to *write* a file cannot *delete* it.
#[test]
fn a_write_permit_cannot_authorize_a_delete_on_the_same_file() {
    let path = "/etc/atom/app.conf";
    let scenario = Scenario::new(HostOp::WriteFile {
        path: path.into(),
        contents: "key = value\n".into(),
    });
    let delete = HostOp::RemoveFile { path: path.into() };
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            op: &delete,
            ..scenario.request()
        })
        .expect_err("the grant allows write, not delete");

    assert!(
        matches!(denied, DenyReason::OperationNotGranted { .. }),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
    assert_eq!(broker.spent(), 0, "a mismatched op must not burn a valid permit");
}

#[test]
fn a_permit_for_one_resource_cannot_reach_a_resource_outside_its_grant() {
    let scenario = Scenario::new(HostOp::WriteFile {
        path: "/etc/atom/app.conf".into(),
        contents: "x".into(),
    });
    let elsewhere = HostOp::WriteFile {
        path: "/etc/atom/other.conf".into(),
        contents: "x".into(),
    };
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            op: &elsewhere,
            ..scenario.request()
        })
        .expect_err("the grant covers only the one file");

    assert!(
        matches!(denied, DenyReason::ResourceNotGranted { .. }),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
    assert_eq!(broker.spent(), 0);
}

/// Even when the grant covers two files, a permit is bound to exactly one: the
/// permit for file A cannot be redirected to file B.
#[test]
fn a_permit_is_bound_to_one_resource_within_a_multi_resource_grant() {
    let file_a = "/etc/atom/a.conf";
    let file_b = "/etc/atom/b.conf";
    let op_a = HostOp::WriteFile {
        path: file_a.into(),
        contents: "x".into(),
    };
    let grant = grant_covering(&[file_a, file_b]);
    let intent = intent_for(&op_a);
    let witness = planned_witness(&op_a);
    let permit = permit_for(&op_a, &grant, &intent, &witness);

    let op_b = HostOp::WriteFile {
        path: file_b.into(),
        contents: "x".into(),
    };
    let mut broker = broker();

    let denied = broker
        .admit(AdmissionRequest {
            op: &op_b,
            permit: &permit,
            intent: &intent,
            grant: &grant,
            observed_witness: &witness,
            now: now(),
        })
        .expect_err("the permit is bound to file A, not file B");

    assert!(
        matches!(denied, DenyReason::PermitResourceMismatch { .. }),
        "{denied:?}"
    );
    assert_eq!(broker.executor().count(), 0);
    assert_eq!(broker.spent(), 0);
}
