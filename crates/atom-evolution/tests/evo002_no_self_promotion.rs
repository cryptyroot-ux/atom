//! ATOM-EVO-002 + INV-003/012: trusted-core / authority-policy changes must
//! not self-promote from production cognition, and no evolution may expand
//! authority (enforced via atom_capability::subset_check).

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_evolution::{
    ChangeClass, ChangeOrigin, EvolutionError, ProposedChange, Stage,
};
use chrono::{Duration, Utc};

/// Build a parent grant with broad authority.
fn parent_grant() -> CapabilityGrant {
    let now = Utc::now();
    CapabilityGrant {
        grant_id: "parent".into(),
        subject_id: "s".into(),
        workload_id: "w".into(),
        operations: vec!["read".into(), "write".into(), "execute".into()],
        resources: vec![ResourceSelector {
            resource_type: "*".into(),
            resource_id: "*".into(),
        }],
        purpose: "owner".into(),
        not_before: now,
        expires_at: now + Duration::hours(4),
        budget: Budget {
            max_cost: 100_000,
            max_seconds: 14_400,
        },
        delegation_depth: 10,
        audience: "team".into(),
        generation: 0,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
    }
}

/// A strict *subset* of the parent (valid attenuation).
fn child_subset(parent: &CapabilityGrant) -> CapabilityGrant {
    let mut c = parent.clone();
    c.grant_id = "child".into();
    c.parent_grant_id = Some(parent.grant_id.clone()); // attest lineage (subset_check req #1)
    c.operations = vec!["read".into(), "write".into()]; // ⊆ parent
    c.budget = Budget {
        max_cost: 5_000, // ≤ parent
        max_seconds: 7_200,
    };
    c.delegation_depth = parent.delegation_depth - 1; // < parent
    c.expires_at = parent.expires_at - Duration::minutes(5); // within parent
    c
}

/// A *broader* than parent grant (invalid — authority expansion).
fn child_expansion(parent: &CapabilityGrant) -> CapabilityGrant {
    let mut c = parent.clone();
    c.grant_id = "child".into();
    c.operations = vec!["read".into(), "write".into(), "execute".into(), "admin".into()]; // ⊃ parent
    c.budget = Budget {
        max_cost: 999_999, // > parent
        max_seconds: 100_000,
    };
    c.delegation_depth = parent.delegation_depth + 1; // > parent
    c
}

#[test]
fn trusted_core_from_production_cognition_is_rejected() {
    let change = ProposedChange {
        class: ChangeClass::TrustedCore,
        origin: ChangeOrigin::ProductionCognition,
        parent_grant: None,
        child_grant: None,
    };
    assert_eq!(
        change.assert_no_self_promotion(),
        Err(EvolutionError::SelfPromotionForbidden {
            class: ChangeClass::TrustedCore,
            origin: ChangeOrigin::ProductionCognition,
        })
    );
}

#[test]
fn authority_policy_from_production_cognition_is_rejected() {
    let change = ProposedChange {
        class: ChangeClass::AuthorityPolicy,
        origin: ChangeOrigin::ProductionCognition,
        parent_grant: None,
        child_grant: None,
    };
    assert!(change.assert_no_self_promotion().is_err());
}

#[test]
fn trusted_core_from_reviewed_human_is_allowed() {
    let change = ProposedChange {
        class: ChangeClass::TrustedCore,
        origin: ChangeOrigin::ReviewedHuman,
        parent_grant: None,
        child_grant: None,
    };
    assert!(change.assert_no_self_promotion().is_ok());
}

#[test]
fn capability_from_production_cognition_allowed_when_subset() {
    let parent = parent_grant();
    let change = ProposedChange {
        class: ChangeClass::Capability,
        origin: ChangeOrigin::ProductionCognition,
        parent_grant: Some(parent.clone()),
        child_grant: Some(child_subset(&parent)),
    };
    assert!(change.assert_no_self_promotion().is_ok());
}

#[test]
fn authority_expansion_is_rejected_inv_003_012() {
    let parent = parent_grant();
    let change = ProposedChange {
        class: ChangeClass::Capability,
        origin: ChangeOrigin::ReviewedHuman,
        parent_grant: Some(parent.clone()),
        child_grant: Some(child_expansion(&parent)),
    };
    match change.assert_no_self_promotion() {
        Err(EvolutionError::AuthorityExpansion(_)) => {}
        other => panic!("expected AuthorityExpansion, got {other:?}"),
    }
}

#[test]
fn repeated_success_does_not_expand_authority() {
    // INV-012: resource pressure, urgency, model recommendation, or repeated
    // success never increases authority. Here we simulate "repeated success"
    // by attempting the same expansion many times — the outcome must not flip.
    let parent = parent_grant();
    let expansion = child_expansion(&parent);
    for success_count in 1..=10u32 {
        let change = ProposedChange {
            class: ChangeClass::Capability,
            origin: ChangeOrigin::ReviewedHuman,
            parent_grant: Some(parent.clone()),
            child_grant: Some(expansion.clone()),
        };
        // Even after `success_count` prior successes, the expansion is refused.
        assert!(
            change.assert_no_self_promotion().is_err(),
            "repeated success ({success_count}) must not grant broader authority"
        );
    }
}

// Keep `Stage` referenced so the import is meaningful for readers of this file.
#[test]
fn stage_ordinals_are_ordered() {
    assert!(Stage::Lab < Stage::Simulation);
    assert!(Stage::Simulation < Stage::Shadow);
    assert!(Stage::Shadow < Stage::Canary);
    assert!(Stage::Canary < Stage::Active);
}
