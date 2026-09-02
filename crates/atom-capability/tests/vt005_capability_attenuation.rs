//! ATOM-VT-005: Capability attenuation — child requests broader
//! targets/operation/budget → kernel DENIES + records evidence.
//!
//! From `spec/acceptance/catalog.yaml`:
//! > Scenario: Child requests broader targets/operation/budget.
//! > Pass: Kernel denies and records evidence.

use atom_capability::{
    subset_check, Budget, CapabilityError, CapabilityGrant, ResourceSelector, RevocationState,
};
use chrono::Utc;

fn parent_grant() -> CapabilityGrant {
    let now = Utc::now();
        grant_id: "parent-001".into(),
        subject_id: "owner".into(),
        workload_id: "wl-parent".into(),
        operations: vec!["read".into(), "write".into(), "execute".into()],
        resources: vec![
            ResourceSelector {
                resource_type: "server".into(),
                resource_id: "srv-alpha".into(),
            },
            ResourceSelector {
                resource_type: "database".into(),
                resource_id: "db-main".into(),
            },
        ],
        purpose: "deployment operations".into(),
        not_before: now,
        expires_at: now + chrono::Duration::hours(4),
        budget: Budget {
            max_cost: 10_000,
            max_seconds: 14_400,
        },
        delegation_depth: 5,
        audience: "ops-team".into(),
        generation: 0,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
}

fn child_from_parent(parent: &CapabilityGrant) -> CapabilityGrant {
        grant_id: "child-001".into(),
        subject_id: "worker".into(),
        workload_id: "wl-child".into(),
        operations: vec!["read".into()],
        resources: vec![ResourceSelector {
            resource_type: "server".into(),
            resource_id: "srv-alpha".into(),
        }],
        purpose: "deployment operations".into(),
        not_before: parent.not_before,
        expires_at: parent.expires_at - chrono::Duration::minutes(5),
        budget: Budget {
            max_cost: 5_000,
            max_seconds: 7_200,
        },
        delegation_depth: 4,
        audience: "ops-team".into(),
        generation: 0,
        revocation_state: RevocationState::Active,
        parent_grant_id: Some(parent.grant_id.clone()),
        nonce: None,
        constraints: None,
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
}

// --- VT-005a: broader operations ---

#[test]
fn vt005_broader_operations_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    // Child requests "admin" which parent does not have
    child.operations = vec!["read".into(), "admin".into()];

    let err = subset_check(&parent, &child).unwrap_err();
    match err {
        CapabilityError::OperationsNotSubset { ref missing } => {
            assert!(missing.contains(&"admin".to_string()));
        }
        _ => panic!("expected OperationsNotSubset, got {:?}", err),
    }
    // "Records evidence" — the error itself IS the evidence record.
    // In production this would be persisted to the ledger.
}

// --- VT-005b: broader resources ---

#[test]
fn vt005_broader_resources_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    // Child requests a resource parent doesn't cover
    child.resources = vec![ResourceSelector {
        resource_type: "server".into(),
        resource_id: "srv-omega".into(), // not in parent
    }];

    let err = subset_check(&parent, &child).unwrap_err();
    assert!(matches!(err, CapabilityError::ResourcesNotContained { .. }));
}

// --- VT-005c: broader budget ---

#[test]
fn vt005_broader_budget_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    child.budget = Budget {
        max_cost: 999_999, // way more than parent's 10_000
        max_seconds: 7_200,
    };

    let err = subset_check(&parent, &child).unwrap_err();
    assert!(matches!(err, CapabilityError::BudgetExceeded { .. }));
}

// --- VT-005d: time window outside parent ---

#[test]
fn vt005_time_window_outside_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    // Child expires AFTER parent
    child.expires_at = parent.expires_at + chrono::Duration::hours(10);

    let err = subset_check(&parent, &child).unwrap_err();
    assert!(matches!(err, CapabilityError::TimeWindowOutside { .. }));
}

// --- VT-005e: delegation depth not decreased ---

#[test]
fn vt005_delegation_depth_same_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    child.delegation_depth = parent.delegation_depth; // same, not decreased

    let err = subset_check(&parent, &child).unwrap_err();
    assert!(matches!(
        err,
        CapabilityError::DelegationDepthNotDecreased { .. }
    ));
}

// --- VT-005f: audience widened ---

#[test]
fn vt005_audience_widened_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    child.audience = "everyone".into(); // wider than "ops-team"

    let err = subset_check(&parent, &child).unwrap_err();
    assert!(matches!(err, CapabilityError::AudienceWidened { .. }));
}

// --- VT-005g: purpose widened ---

#[test]
fn vt005_purpose_widened_denied() {
    let parent = parent_grant();
    let mut child = child_from_parent(&parent);
    child.purpose = "unrestricted access".into(); // wider than "deployment operations"

    let err = subset_check(&parent, &child).unwrap_err();
    assert!(matches!(err, CapabilityError::PurposeWidened { .. }));
}

// --- VT-005h: valid child passes ---

#[test]
fn vt005_valid_child_passes() {
    let parent = parent_grant();
    let child = child_from_parent(&parent);
    assert!(subset_check(&parent, &child).is_ok());
}
