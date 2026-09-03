use atom_capability::{subset_check, Budget, CapabilityError, CapabilityGrant, ResourceSelector};
use chrono::{Duration, Utc};

fn parent_grant() -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "parent-001".into(),
        subject_id: "owner".into(),
        workload_id: "wl-parent".into(),
        operations: vec!["read".into(), "write".into(), "execute".into()],
        resources: vec![ResourceSelector {
            resource_type: "*".into(),
            resource_id: "*".into(),
        }],
        purpose: "deployment".into(),
        not_before: Utc::now(),
        expires_at: Utc::now() + Duration::hours(4),
        budget: Budget {
            max_cost: 10_000,
            max_seconds: 14_400,
        },
        delegation_depth: 5,
        audience: "ops-team".into(),
        generation: 1,
        revocation_state: atom_capability::RevocationState::Active,
        parent_grant_id: None,
        parent_authority_digest: None,
        holder_binding: None,
        authority_digest: None,
        nonce: None,
        constraints: None,
    }
}

#[test]
fn delegation_chain_parent_substitution_deny() {
    let parent = parent_grant();
    
    // Create a child that references a different parent
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some("different-parent".into());
    child.delegation_depth = 4;
    
    // Should fail because parent_grant_id doesn't match
    let result = subset_check(&parent, &child);
    assert!(matches!(result, Err(CapabilityError::MissingParentGrantId)));
}

#[test]
fn child_operation_wider_than_parent_deny() {
    let parent = parent_grant();
    
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.operations = vec!["read".into(), "write".into(), "execute".into(), "admin".into()];
    child.delegation_depth = 4;
    
    // Should fail because child has 'admin' which parent doesn't have
    let result = subset_check(&parent, &child);
    assert!(matches!(result, Err(CapabilityError::OperationsNotSubset { .. })));
}

#[test]
fn child_resource_wider_than_parent_deny() {
    let parent = parent_grant();
    
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.resources = vec![
        ResourceSelector { resource_type: "*".into(), resource_id: "*".into() },
        ResourceSelector { resource_type: "secret".into(), resource_id: "*".into() },
    ];
    child.delegation_depth = 4;
    
    // Should fail because child has 'secret' resource which parent doesn't cover
    let result = subset_check(&parent, &child);
    assert!(matches!(result, Err(CapabilityError::ResourcesNotContained { .. })));
}

#[test]
fn child_budget_greater_than_parent_deny() {
    let parent = parent_grant();
    
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.budget = Budget {
        max_cost: 20_000, // Greater than parent's 10_000
        max_seconds: 14_400,
    };
    child.delegation_depth = 4;
    
    // Should fail because child budget > parent budget
    let result = subset_check(&parent, &child);
    assert!(matches!(result, Err(CapabilityError::BudgetExceeded { .. })));
}

#[test]
fn child_expiry_longer_than_parent_deny() {
    let parent = parent_grant();
    
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.expires_at = parent.expires_at + Duration::hours(1);
    child.delegation_depth = 4;
    
    // Should fail because child expires after parent
    let result = subset_check(&parent, &child);
    assert!(matches!(result, Err(CapabilityError::TimeWindowOutside { .. })));
}

#[test]
fn parent_revoked_after_child_created_child_unusable() {
    let mut parent = parent_grant();
    
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.delegation_depth = 4;
    
    // First, child should be valid
    assert!(subset_check(&parent, &child).is_ok());
    
    // Revoke parent
    parent.revocation_state = atom_capability::RevocationState::Revoked;
    
    // Now child should be unusable
    let result = subset_check(&parent, &child);
    assert!(matches!(result, Err(CapabilityError::ParentRevoked { .. })));
}

#[test]
fn offline_chain_verification_pass() {
    let parent = parent_grant();
    
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.delegation_depth = 4;
    
    // Valid chain should pass
    assert!(subset_check(&parent, &child).is_ok());
}
