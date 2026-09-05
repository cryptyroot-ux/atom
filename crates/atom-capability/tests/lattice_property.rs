//! Lattice property test (AUT-002): for any valid parent/child pair where
//! subset_check returns OK, the child's authority MUST be ⊆ parent across
//! every dimension.

use atom_capability::{subset_check, Budget, CapabilityGrant, ResourceSelector, RevocationState};
use chrono::{Duration, Utc};
use proptest::prelude::*;

fn arb_resource() -> impl Strategy<Value = ResourceSelector> {
    ("[a-z]{1,8}", "[a-z0-9]{1,12}").prop_map(|(t, id)| ResourceSelector {
        resource_type: t,
        resource_id: id,
    })
}

/// Generate a parent grant at a given delegation depth.
fn arb_parent(depth: u32) -> impl Strategy<Value = CapabilityGrant> {
    (
        prop::collection::vec("[a-z]{1,8}", 1..5),
        prop::collection::vec(arb_resource(), 1..3),
        1u64..100_000u64,
    )
        .prop_map(move |(ops, resources, max_cost)| {
            let now = Utc::now();
            CapabilityGrant {
                grant_id: "parent".into(),
                subject_id: "s".into(),
                workload_id: "w".into(),
                operations: ops,
                resources,
                purpose: "test".into(),
                not_before: now,
                expires_at: now + Duration::hours(4),
                budget: Budget {
                    max_cost,
                    max_seconds: 14_400,
                },
                delegation_depth: depth,
                audience: "team".into(),
                generation: 0,
                revocation_state: RevocationState::Active,
                parent_grant_id: None,
                nonce: None,
                constraints: None,
                authority_digest: None,
                holder_binding: None,
                parent_authority_digest: None,
            }
        })
}

proptest! {
    /// If subset_check(parent, child) == Ok, then child ops ⊆ parent ops,
    /// child budget ≤ parent budget, child time inside parent, child depth < parent.
    #[test]
    fn lattice_subset_implies_containment(
        parent in arb_parent(5),
        child_ops in prop::collection::vec("[a-z]{1,8}", 0..6),
        child_max_cost in 0u64..200_000u64,
        child_depth in 0u32..10u32,
    ) {
        let child = CapabilityGrant {
            grant_id: "child".into(),
            subject_id: "s".into(),
            workload_id: "w".into(),
            operations: child_ops.clone(),
            resources: parent.resources.clone(),
            purpose: parent.purpose.clone(),
            not_before: parent.not_before,
            expires_at: parent.expires_at - Duration::minutes(1),
            budget: Budget { max_cost: child_max_cost, max_seconds: 7200 },
            delegation_depth: child_depth,
            audience: parent.audience.clone(),
            generation: 0,
            revocation_state: RevocationState::Active,
            parent_grant_id: Some(parent.grant_id.clone()),
            nonce: None,
            constraints: None,
            authority_digest: None,
            holder_binding: None,
            parent_authority_digest: None,
        };

        let result = subset_check(&parent, &child);

        if result.is_ok() {
            // subset_check passed — verify lattice invariants hold
            let parent_ops: std::collections::HashSet<&str> =
                parent.operations.iter().map(|s| s.as_str()).collect();
            for op in &child.operations {
                prop_assert!(parent_ops.contains(op.as_str()),
                    "subset_check ok but child op '{}' not in parent {:?}", op, parent.operations);
            }
            prop_assert!(child.budget.max_cost <= parent.budget.max_cost);
            prop_assert!(child.not_before >= parent.not_before);
            prop_assert!(child.expires_at <= parent.expires_at);
            prop_assert!(child.delegation_depth < parent.delegation_depth);
        }
    }

    /// Adding an operation the parent doesn't have always causes rejection.
    #[test]
    fn extra_op_always_rejected(
        parent in arb_parent(5),
        extra_op in "[A-Z]{3,10}"
    ) {
        if parent.operations.contains(&extra_op) {
            return Ok(()); // skip if parent already has this op
        }
        let child = CapabilityGrant {
            grant_id: "child".into(),
            subject_id: "s".into(),
            workload_id: "w".into(),
            operations: vec![extra_op],
            resources: parent.resources.clone(),
            purpose: parent.purpose.clone(),
            not_before: parent.not_before,
            expires_at: parent.expires_at - Duration::minutes(1),
            budget: Budget { max_cost: 1, max_seconds: 100 },
            delegation_depth: parent.delegation_depth.saturating_sub(1),
            audience: parent.audience.clone(),
            generation: 0,
            revocation_state: RevocationState::Active,
            parent_grant_id: Some(parent.grant_id.clone()),
            nonce: None,
            constraints: None,
            authority_digest: None,
            holder_binding: None,
            parent_authority_digest: None,
        };
        let result = subset_check(&parent, &child);
        prop_assert!(result.is_err(),
            "child with extra op '{}' should be rejected", child.operations[0]);
    }
}
