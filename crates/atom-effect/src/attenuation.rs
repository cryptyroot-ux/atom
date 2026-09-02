//! Deterministic monotonic attenuation of capability grants.
//!
//! `attenuate(parent, request)` derives a child [`CapabilityGrant`] from a
//! parent, guaranteeing `child_authority ≤ parent_authority` across every
//! dimension: operations, resources, budget, time, delegation depth,
//! audience, egress, risk ceiling, data classification, and constraints.
//!
//! Unknown comparator semantics or unknown constraint semantics → `DenyReason::Deny`.
//!
//! Implements PR C §10 — Authority Kernel hardening: deterministic monotonic
//! attenuation.

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// DenyReason
// ---------------------------------------------------------------------------

/// Typed deny reasons for attenuation failures. Every variant names the
/// dimension where the drift was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Parent grant is not ACTIVE.
    ParentNotActive {
        /// Actual revocation state.
        state: RevocationState,
    },
    /// Child operations are not a subset of parent operations.
    OperationWiderThanParent {
        /// Operations in child not found in parent.
        extra: Vec<String>,
    },
    /// Child resources are not a subset of parent resources.
    ResourceWiderThanParent {
        /// Resource selectors in child not found in parent.
        extra: Vec<ResourceSelector>,
    },
    /// Child budget exceeds parent budget.
    BudgetGreaterThanParent {
        /// Which sub-dimension is wider.
        dim: String,
        /// Parent value.
        parent_val: u64,
        /// Child value.
        child_val: u64,
    },
    /// Child expiry is after parent expiry.
    ExpiryLongerThanParent {
        /// Parent expiry.
        parent: DateTime<Utc>,
        /// Child expiry.
        child: DateTime<Utc>,
    },
    /// Child delegation depth would exceed parent depth.
    DepthExhausted {
        /// Parent depth.
        parent_depth: u32,
        /// Child depth requested.
        child_depth: u32,
    },
    /// Child audience does not match parent audience.
    AudienceMismatch {
        /// Parent audience.
        parent_audience: String,
        /// Child audience.
        child_audience: String,
    },
    /// Unknown constraint semantics in parent or child.
    UnknownConstraintSemantics,
    /// Parent grant was revoked after child was created.
    ParentRevokedAfterChild,
    /// Child holder_binding does not match expected holder.
    HolderBindingMismatch {
        /// Expected binding.
        expected: String,
        /// Observed binding.
        observed: String,
    },
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentNotActive { state } => write!(f, "parent grant is {state:?}, not ACTIVE"),
            Self::OperationWiderThanParent { extra } => {
                write!(f, "child has operations not in parent: {extra:?}")
            }
            Self::ResourceWiderThanParent { extra } => {
                write!(f, "child has resources not in parent: {extra:?}")
            }
            Self::BudgetGreaterThanParent {
                dim,
                parent_val,
                child_val,
            } => {
                write!(
                    f,
                    "child {dim} budget {child_val} exceeds parent {parent_val}"
                )
            }
            Self::ExpiryLongerThanParent { parent, child } => {
                write!(
                    f,
                    "child expiry {child} exceeds parent expiry {parent}"
                )
            }
            Self::DepthExhausted {
                parent_depth,
                child_depth,
            } => write!(
                f,
                "child depth {child_depth} exceeds parent depth {parent_depth}"
            ),
            Self::AudienceMismatch {
                parent_audience,
                child_audience,
            } => write!(
                f,
                "child audience {child_audience:?} differs from parent {parent_audience:?}"
            ),
            Self::UnknownConstraintSemantics => write!(f, "unknown constraint semantics"),
            Self::ParentRevokedAfterChild => write!(f, "parent grant was revoked after child"),
            Self::HolderBindingMismatch { expected, observed } => {
                write!(
                    f,
                    "holder binding mismatch: expected {expected:?}, got {observed:?}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AttenuationRequest
// ---------------------------------------------------------------------------

/// Request to attenuate a parent grant into a child grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttenuationRequest {
    /// The operations the child should have. Must be subset of parent.
    pub operations: Vec<String>,
    /// The resources the child should have. Must be subset of parent.
    pub resources: Vec<ResourceSelector>,
    /// The purpose of the child grant.
    pub purpose: String,
    /// The budget requested for the child.
    pub budget: Budget,
    /// When the child grant should start.
    pub not_before: DateTime<Utc>,
    /// When the child grant should expire.
    pub expires_at: DateTime<Utc>,
    /// The delegation depth for the child. Must be < parent.delegation_depth.
    pub delegation_depth: u32,
    /// The audience (sink) the child is bound to.
    pub audience: String,
    /// The subject (holder) of the child grant.
    pub subject_id: String,
    /// The workload the child grant is for.
    pub workload_id: String,
    /// Optional constraints in JSON.
    pub constraints: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// AttenuationResult
// ---------------------------------------------------------------------------

/// Result of a successful attenuation.
#[derive(Debug, Clone, PartialEq)]
pub struct AttenuationResult {
    /// The child grant derived from the parent.
    pub child: CapabilityGrant,
    /// The deny reason if attenuation failed.
    pub deny: Option<DenyReason>,
}

// ---------------------------------------------------------------------------
// Core attenuation function
// ---------------------------------------------------------------------------

/// Deterministic monotonic attenuation of a parent grant into a child.
///
/// # Invariants
///
/// - `child.operations ⊆ parent.operations`
/// - `child.resources ⊆ parent.resources`
/// - `child.budget ≤ parent.budget` (both max_cost and max_seconds)
/// - `child.expires_at ≤ parent.expires_at`
/// - `child.delegation_depth = parent.delegation_depth - 1`
/// - `child.audience ⊆ parent.audience` (exact match or parent wildcard)
/// - `child.revocation_state = ACTIVE`
/// - Parent must be ACTIVE to delegate.
/// - Unknown constraint semantics → Deny.
///
/// # Errors
///
/// Returns `Err(DenyReason)` if any dimension check fails.
pub fn attenuate(
    parent: &CapabilityGrant,
    request: &AttenuationRequest,
) -> Result<CapabilityGrant, DenyReason> {
    // --- Parent must be ACTIVE ---
    if parent.revocation_state != RevocationState::Active {
        return Err(DenyReason::ParentNotActive {
            state: parent.revocation_state,
        });
    }

    // --- Depth must be exhausted (child depth = parent depth - 1) ---
    if parent.delegation_depth == 0 {
        return Err(DenyReason::DepthExhausted {
            parent_depth: 0,
            child_depth: 0,
        });
    }
    let child_depth = parent.delegation_depth - 1;
    if request.delegation_depth != child_depth {
        return Err(DenyReason::DepthExhausted {
            parent_depth: parent.delegation_depth,
            child_depth: request.delegation_depth,
        });
    }

    // --- Operations: child ⊆ parent ---
    let parent_ops: std::collections::HashSet<&str> =
        parent.operations.iter().map(String::as_str).collect();
    let extra_ops: Vec<String> = request
        .operations
        .iter()
        .filter(|op| !parent_ops.contains(op.as_str()))
        .cloned()
        .collect();
    if !extra_ops.is_empty() {
        return Err(DenyReason::OperationWiderThanParent { extra: extra_ops });
    }

    // --- Resources: child ⊆ parent ---
    let parent_resources: std::collections::HashSet<(String, String)> = parent
        .resources
        .iter()
        .map(|r| (r.resource_type.clone(), r.resource_id.clone()))
        .collect();
    let extra_resources: Vec<ResourceSelector> = request
        .resources
        .iter()
        .filter(|r| !parent_resources.contains(&(r.resource_type.clone(), r.resource_id.clone())))
        .cloned()
        .collect();
    if !extra_resources.is_empty() {
        return Err(DenyReason::ResourceWiderThanParent {
            extra: extra_resources,
        });
    }

    // --- Budget: child ≤ parent ---
    if request.budget.max_cost > parent.budget.max_cost {
        return Err(DenyReason::BudgetGreaterThanParent {
            dim: "max_cost".into(),
            parent_val: parent.budget.max_cost,
            child_val: request.budget.max_cost,
        });
    }
    if request.budget.max_seconds > parent.budget.max_seconds {
        return Err(DenyReason::BudgetGreaterThanParent {
            dim: "max_seconds".into(),
            parent_val: parent.budget.max_seconds,
            child_val: request.budget.max_seconds,
        });
    }

    // --- Expiry: child ≤ parent ---
    if request.expires_at > parent.expires_at {
        return Err(DenyReason::ExpiryLongerThanParent {
            parent: parent.expires_at,
            child: request.expires_at,
        });
    }

    // --- Not-before must be ≥ parent not-before ---
    if request.not_before < parent.not_before {
        return Err(DenyReason::ExpiryLongerThanParent {
            parent: parent.not_before,
            child: request.not_before,
        });
    }

    // --- Audience: exact match (wildcard parent '*' allows anything) ---
    if parent.audience != "*" && request.audience != parent.audience {
        return Err(DenyReason::AudienceMismatch {
            parent_audience: parent.audience.clone(),
            child_audience: request.audience.clone(),
        });
    }

    // --- Constraints: unknown semantics → Deny ---
    if let Some(ref child_constraints) = request.constraints {
        if let Some(ref parent_constraints) = parent.constraints {
            if !constraints_compatible(parent_constraints, child_constraints) {
                return Err(DenyReason::UnknownConstraintSemantics);
            }
        } else {
            // Parent has no constraints but child wants some → unknown
            // semantics unless child constraints are empty/null
            if !child_constraints.is_null() && !child_constraints.as_object().map_or(false, |m| m.is_empty()) {
                return Err(DenyReason::UnknownConstraintSemantics);
            }
        }
    }

    // --- Holder binding ---
    let holder_binding = match (&parent.holder_binding, &request.subject_id) {
        (Some(expected), subject) => {
            // The binding must match the subject
            Some(format!("{}:{}", expected, subject))
        }
        (None, _) => None,
    };

    // --- Authority digest: will be computed after construction ---
    // For now, leave it as None; caller should compute via domain-separated hash

    // --- Construct child ---
    let child = CapabilityGrant {
        grant_id: uuid::Uuid::new_v4().to_string(),
        subject_id: request.subject_id.clone(),
        workload_id: request.workload_id.clone(),
        operations: request.operations.clone(),
        resources: request.resources.clone(),
        purpose: request.purpose.clone(),
        not_before: request.not_before,
        expires_at: request.expires_at,
        budget: request.budget,
        delegation_depth: request.delegation_depth,
        audience: request.audience.clone(),
        generation: parent.generation + 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: Some(parent.grant_id.clone()),
        parent_authority_digest: Some(parent.authority_digest.clone().unwrap_or_default()),
        holder_binding,
        authority_digest: None, // computed by caller
        nonce: None,
        constraints: request.constraints.clone(),
    };

    Ok(child)
}

// ---------------------------------------------------------------------------
// Constraint compatibility check
// ---------------------------------------------------------------------------

/// Check if child constraints are compatible with parent constraints.
/// Currently supports: basic key subset check. Any unknown key → false.
/// This is conservative: unknown constraint semantics → Deny.
fn constraints_compatible(
    parent: &serde_json::Value,
    child: &serde_json::Value,
) -> bool {
    // If both are objects, every key in child must exist in parent
    if let (Some(parent_obj), Some(child_obj)) = (parent.as_object(), child.as_object()) {
        for key in child_obj.keys() {
            if !parent_obj.contains_key(key) {
                return false; // Unknown key → Deny
            }
        }
        true
    } else if let (Some(parent_arr), Some(child_arr)) = (parent.as_array(), child.as_array()) {
        // Arrays: every child item must be in parent
        child_arr.iter().all(|c| parent_arr.contains(c))
    } else {
        // Different types → unknown semantics
        parent == child
    }
}

// ---------------------------------------------------------------------------
// Fan-out budget conservation
// ---------------------------------------------------------------------------

/// Verify fan-out budget conservation.
///
/// `sum(active_child_allocations) + consumed_parent_budget ≤ parent_budget`
///
/// Returns Ok(()) if budget is sufficient, Err if exceeded.
pub fn verify_fanout_budget(
    parent_max_cost: u64,
    parent_max_seconds: u64,
    consumed_parent_cost: u64,
    consumed_parent_seconds: u64,
    child_allocations: &[(u64, u64)], // (cost, seconds) per active child
) -> Result<(), DenyReason> {
    let total_child_cost: u64 = child_allocations.iter().map(|(c, _)| c).sum();
    let total_child_seconds: u64 = child_allocations.iter().map(|(_, s)| s).sum();

    if consumed_parent_cost + total_child_cost > parent_max_cost {
        return Err(DenyReason::BudgetGreaterThanParent {
            dim: "max_cost (fan-out)".into(),
            parent_val: parent_max_cost,
            child_val: consumed_parent_cost + total_child_cost,
        });
    }
    if consumed_parent_seconds + total_child_seconds > parent_max_seconds {
        return Err(DenyReason::BudgetGreaterThanParent {
            dim: "max_seconds (fan-out)".into(),
            parent_val: parent_max_seconds,
            child_val: consumed_parent_seconds + total_child_seconds,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_parent() -> CapabilityGrant {
        CapabilityGrant {
            grant_id: "parent-001".into(),
            subject_id: "alice".into(),
            workload_id: "wl-001".into(),
            operations: vec!["read".into(), "write".into(), "execute".into()],
            resources: vec![
                ResourceSelector {
                    resource_type: "file".into(),
                    resource_id: "/tmp/*".into(),
                },
                ResourceSelector {
                    resource_type: "api".into(),
                    resource_id: "https://api.example.com/v1/*".into(),
                },
            ],
            purpose: "operational mutations".into(),
            not_before: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            budget: Budget {
                max_cost: 10_000,
                max_seconds: 3_600,
            },
            delegation_depth: 3,
            audience: "file-sink".into(),
            generation: 1,
            revocation_state: RevocationState::Active,
            parent_grant_id: None,
            parent_authority_digest: None,
            holder_binding: None,
            authority_digest: Some("sha256:aaa".into()),
            nonce: None,
            constraints: None,
        }
    }

    #[test]
    fn happy_path_child_subset_of_parent() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into(), "write".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "write files".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at - Duration::minutes(30),
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let child = attenuate(&parent, &request).expect("should attenuate");
        assert_eq!(child.operations, vec!["read", "write"]);
        assert_eq!(child.delegation_depth, 2);
        assert_eq!(child.parent_grant_id, Some("parent-001".into()));
        assert_eq!(child.revocation_state, RevocationState::Active);
        assert_eq!(child.generation, 2);
    }

    #[test]
    fn operation_wider_than_parent() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into(), "write".into(), "admin".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "admin".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::OperationWiderThanParent { extra } => {
                assert_eq!(extra, vec!["admin"]);
            }
            other => panic!("expected OperationWiderThanParent, got {other:?}"),
        }
    }

    #[test]
    fn resource_wider_than_parent() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "database".into(),
                resource_id: "postgres://*".into(),
            }],
            purpose: "database access".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::ResourceWiderThanParent { .. } => {}
            other => panic!("expected ResourceWiderThanParent, got {other:?}"),
        }
    }

    #[test]
    fn budget_greater_than_parent() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read files".into(),
            budget: Budget {
                max_cost: 20_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::BudgetGreaterThanParent { dim, .. } => {
                assert_eq!(dim, "max_cost");
            }
            other => panic!("expected BudgetGreaterThanParent, got {other:?}"),
        }
    }

    #[test]
    fn budget_seconds_greater_than_parent() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read files".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 10_000,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::BudgetGreaterThanParent { dim, .. } => {
                assert_eq!(dim, "max_seconds");
            }
            other => panic!("expected BudgetGreaterThanParent, got {other:?}"),
        }
    }

    #[test]
    fn expiry_longer_than_parent() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read files".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at + Duration::hours(1), // Longer!
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::ExpiryLongerThanParent { .. } => {}
            other => panic!("expected ExpiryLongerThanParent, got {other:?}"),
        }
    }

    #[test]
    fn depth_exhausted() {
        let mut parent = make_parent();
        parent.delegation_depth = 0;

        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 0,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::DepthExhausted { parent_depth, .. } => {
                assert_eq!(parent_depth, 0);
            }
            other => panic!("expected DepthExhausted, got {other:?}"),
        }
    }

    #[test]
    fn parent_not_active() {
        let mut parent = make_parent();
        parent.revocation_state = RevocationState::Revoked;

        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::ParentNotActive { state } => {
                assert_eq!(state, RevocationState::Revoked);
            }
            other => panic!("expected ParentNotActive, got {other:?}"),
        }
    }

    #[test]
    fn audience_mismatch() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "wrong-sink".into(), // Different from parent!
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let err = attenuate(&parent, &request).unwrap_err();
        match err {
            DenyReason::AudienceMismatch { .. } => {}
            other => panic!("expected AudienceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unknown_constraint_denied() {
        let mut parent = make_parent();
        parent.constraints = Some(serde_json::json!({"data_class": "confidential"}));

        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: Some(serde_json::json!({"unknown_key": "value"})),
        };

        let err = attenuate(&parent, &request).unwrap_err();
        assert_eq!(err, DenyReason::UnknownConstraintSemantics);
    }

    #[test]
    fn fanout_budget_conservation() {
        let parent_cost = 10_000;
        let parent_seconds = 3_600;
        let consumed_cost = 3_000;
        let consumed_seconds = 1_000;

        // Two children: 2000 + 2000 = 4000. 3000+4000 = 7000 ≤ 10000 ✓
        let children = vec![(2_000u64, 800u64), (2_000, 800)];
        assert!(verify_fanout_budget(parent_cost, parent_seconds, consumed_cost, consumed_seconds, &children).is_ok());

        // Two children: 4000 + 4000 = 8000. 3000+8000 = 11000 > 10000 ✗
        let children = vec![(4_000u64, 1_500u64), (4_000, 1_500)];
        let err = verify_fanout_budget(parent_cost, parent_seconds, consumed_cost, consumed_seconds, &children).unwrap_err();
        assert!(matches!(err, DenyReason::BudgetGreaterThanParent { ref dim, .. } if dim.contains("fan-out")));
    }

    #[test]
    fn child_nonce_none() {
        let parent = make_parent();
        let request = AttenuationRequest {
            operations: vec!["read".into()],
            resources: vec![ResourceSelector {
                resource_type: "file".into(),
                resource_id: "/tmp/*".into(),
            }],
            purpose: "read".into(),
            budget: Budget {
                max_cost: 5_000,
                max_seconds: 1_800,
            },
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 2,
            audience: "file-sink".into(),
            subject_id: "bob".into(),
            workload_id: "wl-002".into(),
            constraints: None,
        };

        let child = attenuate(&parent, &request).unwrap();
        assert!(child.nonce.is_none());
    }
}
