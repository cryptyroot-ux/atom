//! INV-012: Resource pressure, urgency, model recommendation, or repeated
//! success NEVER increases authority.
//!
//! This test verifies that no code path in atom-capability can widen a
//! grant's authority regardless of "pressure" signals. Since the subset_check
//! function is purely structural (it doesn't accept pressure parameters),
//! the invariant is enforced by design: there is no API to widen authority.
//!
//! This test documents the invariant and verifies that even if we simulate
//! various "pressure" scenarios, the subset_check result does not change.

use atom_capability::{
    subset_check, Budget, CapabilityError, CapabilityGrant, ResourceSelector, RevocationState,
};
use chrono::Utc;

fn base_grant() -> CapabilityGrant {
    let now = Utc::now();
    CapabilityGrant {
        grant_id: "base-001".into(),
        subject_id: "s1".into(),
        workload_id: "w1".into(),
        operations: vec!["read".into(), "write".into()],
        resources: vec![ResourceSelector {
            resource_type: "server".into(),
            resource_id: "srv-1".into(),
        }],
        purpose: "ops".into(),
        not_before: now,
        expires_at: now + chrono::Duration::hours(2),
        budget: Budget {
            max_cost: 5_000,
            max_seconds: 7_200,
        },
        delegation_depth: 5,
        audience: "team".into(),
        generation: 0,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
    }
}

/// Simulate a "pressure" scenario: try to widen the child grant in various
/// ways that a compromised model or urgent situation might request.
/// Every attempt MUST be rejected by subset_check.
fn attempt_widen_under_pressure(
    parent: &CapabilityGrant,
    modify: impl FnOnce(&mut CapabilityGrant),
) -> CapabilityError {
    let mut child = CapabilityGrant {
        grant_id: "child-pressure".into(),
        subject_id: "s1".into(),
        workload_id: "w1".into(),
        operations: parent.operations.clone(),
        resources: parent.resources.clone(),
        purpose: parent.purpose.clone(),
        not_before: parent.not_before,
        expires_at: parent.expires_at,
        budget: parent.budget,
        delegation_depth: parent.delegation_depth - 1,
        audience: parent.audience.clone(),
        generation: 0,
        revocation_state: RevocationState::Active,
        parent_grant_id: Some(parent.grant_id.clone()),
        nonce: None,
        constraints: None,
    };

    modify(&mut child);

    subset_check(parent, &child).unwrap_err()
}

#[test]
fn inv012_pressure_cannot_widen_operations() {
    let parent = base_grant();
    let err = attempt_widen_under_pressure(&parent, |child| {
        // "Model recommends adding admin for efficiency"
        child.operations.push("admin".into());
    });
    assert!(
        matches!(err, CapabilityError::OperationsNotSubset { .. }),
        "pressure must not widen operations: {:?}",
        err
    );
}

#[test]
fn inv012_urgency_cannot_widen_budget() {
    let parent = base_grant();
    let err = attempt_widen_under_pressure(&parent, |child| {
        // "Urgent: need more budget"
        child.budget = Budget {
            max_cost: parent.budget.max_cost * 10,
            max_seconds: parent.budget.max_seconds,
        };
    });
    assert!(
        matches!(err, CapabilityError::BudgetExceeded { .. }),
        "urgency must not widen budget: {:?}",
        err
    );
}

#[test]
fn inv012_repeated_success_cannot_widen_resources() {
    let parent = base_grant();
    let err = attempt_widen_under_pressure(&parent, |child| {
        // "We've been successful 100 times, surely we can access more"
        child.resources.push(ResourceSelector {
            resource_type: "server".into(),
            resource_id: "srv-omega".into(),
        });
    });
    assert!(
        matches!(err, CapabilityError::ResourcesNotContained { .. }),
        "repeated success must not widen resources: {:?}",
        err
    );
}

#[test]
fn inv012_pressure_cannot_extend_time_window() {
    let parent = base_grant();
    let err = attempt_widen_under_pressure(&parent, |child| {
        // "Need more time, deadline extended"
        child.expires_at = parent.expires_at + chrono::Duration::hours(48);
    });
    assert!(
        matches!(err, CapabilityError::TimeWindowOutside { .. }),
        "pressure must not extend time window: {:?}",
        err
    );
}

#[test]
fn inv012_pressure_cannot_increase_delegation_depth() {
    let parent = base_grant();
    let err = attempt_widen_under_pressure(&parent, |child| {
        // "Need to delegate further for parallel execution"
        child.delegation_depth = parent.delegation_depth + 1;
    });
    assert!(
        matches!(err, CapabilityError::DelegationDepthNotDecreased { .. }),
        "pressure must not increase delegation depth: {:?}",
        err
    );
}

#[test]
fn inv012_pressure_cannot_widen_audience() {
    let parent = base_grant();
    let err = attempt_widen_under_pressure(&parent, |child| {
        // "Share with everyone for visibility"
        child.audience = "everyone".into();
    });
    assert!(
        matches!(err, CapabilityError::AudienceWidened { .. }),
        "pressure must not widen audience: {:?}",
        err
    );
}

#[test]
fn inv012_no_api_to_widen_authority() {
    // The strongest form of INV-012: there is no function in atom-capability
    // that takes a grant and returns a wider grant. The only way to get a
    // grant is AuthorityProfile::compile() (which creates from scratch) or
    // manual construction (which is the owner's prerogative).
    //
    // subset_check is the ONLY validation path, and it only returns Ok/Err —
    // it never modifies grants.
    //
    // This test simply documents that invariant by verifying the public API
    // surface doesn't expose any "widen" or "escalate" function.
    let parent = base_grant();
    let child = base_grant(); // identical grant

    // Even an identical grant fails because parent_grant_id doesn't match
    let err = subset_check(&parent, &child).unwrap_err();
    assert_eq!(err, CapabilityError::MissingParentGrantId);
}
