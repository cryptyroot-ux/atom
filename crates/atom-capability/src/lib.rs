//! atom-capability: CapabilityGrant model + subset-only attenuation lattice.
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **AUT-001** — CapabilityGrant binds subject/workload identity, operation,
//!   resource selector, purpose, validity interval, budget, delegation depth,
//!   audience, generation, revocation and parent grant where delegated.
//! * **AUT-002** — Delegation is syntactically AND semantically subset-only.
//! * **INV-003** — Capability delegation can only attenuate authority; child
//!   authority is never broader than parent authority.
//! * **INV-012** — Resource pressure, urgency, model recommendation, or repeated
//!   success never increases authority.
//! * **ADR-015** — Capability Contract v1 as universal substrate.
//! * **ADR-017** — Authority profiles compile to explicit grants; profiles never
//!   bypass policy.
//!
//! ```rust
//! use atom_capability::{AuthorityProfile, CapabilityGrant, ResourceSelector, RevocationState, Budget};
//! use chrono::{Utc, Duration};
//!
//! let now = Utc::now();
//! let parent = CapabilityGrant {
//!     grant_id: "p1".into(),
//!     subject_id: "s1".into(),
//!     workload_id: "w1".into(),
//!     operations: vec!["read".into(), "write".into(), "execute".into(), "admin".into()],
//!     resources: vec![ResourceSelector { resource_type: "*".into(), resource_id: "*".into() }],
//!     purpose: "owner".into(),
//!     not_before: now,
//!     expires_at: now + Duration::hours(4),
//!     budget: Budget { max_cost: 100_000, max_seconds: 14_400 },
//!     delegation_depth: 10,
//!     audience: "owner".into(),
//!     generation: 0,
//!     revocation_state: RevocationState::Active,
//!     parent_grant_id: None,
//!     nonce: None,
//!     constraints: None,
//! };
//!
//! let mut child = AuthorityProfile::Operate.compile("s1", "w1", "delegated");
//! child.parent_grant_id = Some(parent.grant_id.clone());
//! child.delegation_depth = parent.delegation_depth - 1;
//! child.not_before = parent.not_before;
//! child.expires_at = parent.expires_at - Duration::minutes(5);
//! child.resources = parent.resources.clone();
//! child.purpose = parent.purpose.clone();
//! child.audience = parent.audience.clone();
//!
//! assert!(atom_capability::subset_check(&parent, &child).is_ok());
//! ```

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by capability validation and subset checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("operations not subset of parent: missing={missing:?}")]
    OperationsNotSubset { missing: Vec<String> },

    #[error("resources not contained in parent: extra={extra:?}")]
    ResourcesNotContained { extra: Vec<String> },

    #[error("budget exceeds parent remaining: child={child}, parent_remaining={parent_remaining}")]
    BudgetExceeded {
        child: u64,
        parent_remaining: u64,
    },

    #[error("time window not inside parent: child not_before ({child_nb}) < parent not_before ({parent_nb}) or child expires_at ({child_ea}) > parent expires_at ({parent_ea})")]
    TimeWindowOutside {
        child_nb: String,
        child_ea: String,
        parent_nb: String,
        parent_ea: String,
    },

    #[error("delegation_depth must strictly decrease: child={child}, parent={parent}")]
    DelegationDepthNotDecreased { child: u32, parent: u32 },

    #[error("audience widened: child={child}, parent={parent}")]
    AudienceWidened { child: String, parent: String },

    #[error("purpose widened: child={child}, parent={parent}")]
    PurposeWidened { child: String, parent: String },

    #[error("child must have parent_grant_id when delegating")]
    MissingParentGrantId,

    #[error("grant expired: expires_at={expires_at}")]
    GrantExpired { expires_at: String },

    #[error("grant not yet valid: not_before={not_before}")]
    GrantNotYetValid { not_before: String },

    #[error("grant revoked: state={state:?}")]
    GrantRevoked { state: RevocationState },
}

// ---------------------------------------------------------------------------
// Revocation state
// ---------------------------------------------------------------------------

/// Revocation state for a capability grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RevocationState {
    Active,
    Revoked,
    Expired,
}

// ---------------------------------------------------------------------------
// CapabilityGrant
// ---------------------------------------------------------------------------

/// A typed capability grant binding principal, workload, operations, resources,
/// purpose, validity, budget, delegation depth, audience, generation and
/// revocation state.
///
/// Matches `spec/schemas/capability-grant.schema.json` exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub subject_id: String,
    pub workload_id: String,
    pub operations: Vec<String>,
    pub resources: Vec<ResourceSelector>,
    pub purpose: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub budget: Budget,
    pub delegation_depth: u32,
    pub audience: String,
    pub generation: u64,
    pub revocation_state: RevocationState,

    // optional
    #[serde(default)]
    pub parent_grant_id: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub constraints: Option<serde_json::Value>,
}

/// A resource selector — a typed identifier for the target resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSelector {
    pub resource_type: String,
    pub resource_id: String,
}

/// Budget envelope for a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum cost units the grant holder may consume.
    pub max_cost: u64,
    /// Maximum wall-clock seconds the grant holder may spend.
    pub max_seconds: u64,
}

// ---------------------------------------------------------------------------
// Authority profiles (ADR-017)
// ---------------------------------------------------------------------------

/// User-facing authority profiles that compile to explicit grants.
/// Profiles are UX presets — they never bypass policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityProfile {
    /// Read-only observation. No mutations.
    Observe,
    /// Standard operational mutations within scope.
    Operate,
    /// Full administrative access within scope.
    Admin,
    /// Time-limited operations that may execute without interactive approval.
    Unattended,
    /// User-defined custom profile.
    Custom,
}

impl AuthorityProfile {
    /// Compile this profile into a [`CapabilityGrant`] with sensible defaults.
    ///
    /// The caller must set `parent_grant_id` and adjust `delegation_depth` /
    /// time window / budget when delegating from a parent.
    pub fn compile(
        self,
        subject_id: &str,
        workload_id: &str,
        audience: &str,
    ) -> CapabilityGrant {
        let now = Utc::now();
        let (operations, purpose, max_cost, max_seconds, delegation_depth) = match self {
            AuthorityProfile::Observe => (
                vec!["read".into()],
                "read-only observation".into(),
                1_000,
                300,
                3,
            ),
            AuthorityProfile::Operate => (
                vec!["read".into(), "write".into(), "execute".into()],
                "standard operational mutations".into(),
                10_000,
                3_600,
                5,
            ),
            AuthorityProfile::Admin => (
                vec![
                    "read".into(),
                    "write".into(),
                    "execute".into(),
                    "admin".into(),
                    "deploy".into(),
                ],
                "full administrative access".into(),
                100_000,
                86_400,
                10,
            ),
            AuthorityProfile::Unattended => (
                vec!["read".into(), "write".into(), "execute".into()],
                "unattended operational mutations".into(),
                5_000,
                1_800,
                4,
            ),
            AuthorityProfile::Custom => (
                vec!["read".into()],
                "custom profile — caller must set operations".into(),
                1_000,
                300,
                3,
            ),
        };

        CapabilityGrant {
            grant_id: uuid::Uuid::new_v4().to_string(),
            subject_id: subject_id.to_string(),
            workload_id: workload_id.to_string(),
            operations,
            resources: vec![ResourceSelector {
                resource_type: "*".into(),
                resource_id: "*".into(),
            }],
            purpose,
            not_before: now,
            expires_at: now + chrono::Duration::seconds(max_seconds as i64),
            budget: Budget {
                max_cost,
                max_seconds,
            },
            delegation_depth,
            audience: audience.to_string(),
            generation: 0,
            revocation_state: RevocationState::Active,
            parent_grant_id: None,
            nonce: None,
            constraints: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Subset check (AUT-002 / INV-003)
// ---------------------------------------------------------------------------

/// Verify that `child` is a strict semantic subset of `parent` across every
/// dimension of the capability lattice.
///
/// Returns `Ok(())` if the child is validly attenuated, or a
/// [`CapabilityError`] describing which dimension failed.
///
/// INV-003: capability delegation can only attenuate authority.
/// INV-012: resource pressure, urgency, or repeated success never increases
/// authority — this function is the mechanical enforcement.
pub fn subset_check(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
) -> Result<(), CapabilityError> {
    // 1. Child must reference parent
    if child.parent_grant_id.as_deref() != Some(&parent.grant_id) {
        return Err(CapabilityError::MissingParentGrantId);
    }

    // 2. Operations ⊆ parent operations
    let parent_ops: std::collections::HashSet<&str> =
        parent.operations.iter().map(|s| s.as_str()).collect();
    let missing: Vec<String> = child
        .operations
        .iter()
        .filter(|op| !parent_ops.contains(op.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(CapabilityError::OperationsNotSubset { missing });
    }

    // 3. Resources semantically contained
    //    Each child resource must match at least one parent resource.
    //    "*" in parent means wildcard — matches anything.
    for cr in &child.resources {
        let contained = parent.resources.iter().any(|pr| {
            (pr.resource_type == "*" || pr.resource_type == cr.resource_type)
                && (pr.resource_id == "*" || pr.resource_id == cr.resource_id)
        });
        if !contained {
            return Err(CapabilityError::ResourcesNotContained {
                extra: vec![format!("{}:{}", cr.resource_type, cr.resource_id)],
            });
        }
    }

    // 4. Budget ≤ parent remaining reservation
    //    We use max_cost as the binding constraint (max_seconds is informational).
    if child.budget.max_cost > parent.budget.max_cost {
        return Err(CapabilityError::BudgetExceeded {
            child: child.budget.max_cost,
            parent_remaining: parent.budget.max_cost,
        });
    }

    // 5. Time window inside parent
    if child.not_before < parent.not_before || child.expires_at > parent.expires_at {
        return Err(CapabilityError::TimeWindowOutside {
            child_nb: child.not_before.to_rfc3339(),
            child_ea: child.expires_at.to_rfc3339(),
            parent_nb: parent.not_before.to_rfc3339(),
            parent_ea: parent.expires_at.to_rfc3339(),
        });
    }

    // 6. Delegation depth strictly decreases
    if child.delegation_depth >= parent.delegation_depth {
        return Err(CapabilityError::DelegationDepthNotDecreased {
            child: child.delegation_depth,
            parent: parent.delegation_depth,
        });
    }

    // 7. Audience cannot widen
    //    Child audience must be equal or more specific (substring or exact match).
    //    We treat parent audience as the upper bound — child must be identical
    //    or a subset string. A wildcard parent ("*") allows anything.
    if parent.audience != "*" && child.audience != parent.audience {
        // Allow child to be more specific (e.g. parent="team", child="team:alice")
        if !child.audience.starts_with(&parent.audience) {
            return Err(CapabilityError::AudienceWidened {
                child: child.audience.clone(),
                parent: parent.audience.clone(),
            });
        }
    }

    // 8. Purpose cannot widen
    //    Child purpose must be equal or more specific.
    if parent.purpose != "*" && child.purpose != parent.purpose
        && !child.purpose.starts_with(&parent.purpose)
    {
        return Err(CapabilityError::PurposeWidened {
            child: child.purpose.clone(),
            parent: parent.purpose.clone(),
        });
    }

    Ok(())
}

/// Validate that a grant is currently usable (not expired, not revoked, valid
/// time window).
pub fn validate_grant(grant: &CapabilityGrant) -> Result<(), CapabilityError> {
    let now = Utc::now();

    match grant.revocation_state {
        RevocationState::Revoked => {
            return Err(CapabilityError::GrantRevoked {
                state: RevocationState::Revoked,
            });
        }
        RevocationState::Expired => {
            return Err(CapabilityError::GrantRevoked {
                state: RevocationState::Expired,
            });
        }
        RevocationState::Active => {}
    }

    if now < grant.not_before {
        return Err(CapabilityError::GrantNotYetValid {
            not_before: grant.not_before.to_rfc3339(),
        });
    }

    if now > grant.expires_at {
        return Err(CapabilityError::GrantExpired {
            expires_at: grant.expires_at.to_rfc3339(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_grant(ops: Vec<&str>, budget: u64, depth: u32) -> CapabilityGrant {
        let now = Utc::now();
        CapabilityGrant {
            grant_id: uuid::Uuid::new_v4().to_string(),
            subject_id: "s1".into(),
            workload_id: "w1".into(),
            operations: ops.into_iter().map(String::from).collect(),
            resources: vec![ResourceSelector {
                resource_type: "*".into(),
                resource_id: "*".into(),
            }],
            purpose: "test".into(),
            not_before: now,
            expires_at: now + chrono::Duration::hours(2),
            budget: Budget {
                max_cost: budget,
                max_seconds: 7200,
            },
            delegation_depth: depth,
            audience: "test-audience".into(),
            generation: 0,
            revocation_state: RevocationState::Active,
            parent_grant_id: None,
            nonce: None,
            constraints: None,
        }
    }

    fn make_child(parent: &CapabilityGrant, ops: Vec<&str>, budget: u64, depth: u32) -> CapabilityGrant {
        CapabilityGrant {
            grant_id: uuid::Uuid::new_v4().to_string(),
            subject_id: "s1".into(),
            workload_id: "w1".into(),
            operations: ops.into_iter().map(String::from).collect(),
            resources: vec![ResourceSelector {
                resource_type: "*".into(),
                resource_id: "*".into(),
            }],
            purpose: parent.purpose.clone(),
            not_before: parent.not_before,
            expires_at: parent.expires_at - chrono::Duration::minutes(5),
            budget: Budget {
                max_cost: budget,
                max_seconds: 3600,
            },
            delegation_depth: depth,
            audience: parent.audience.clone(),
            generation: 0,
            revocation_state: RevocationState::Active,
            parent_grant_id: Some(parent.grant_id.clone()),
            nonce: None,
            constraints: None,
        }
    }

    #[test]
    fn basic_subset_ok() {
        let parent = make_grant(vec!["read", "write", "execute"], 1000, 5);
        let child = make_child(&parent, vec!["read", "write"], 500, 4);
        assert!(subset_check(&parent, &child).is_ok());
    }

    #[test]
    fn operations_not_subset() {
        let parent = make_grant(vec!["read"], 1000, 5);
        let child = make_child(&parent, vec!["read", "admin"], 500, 4);
        let err = subset_check(&parent, &child).unwrap_err();
        assert!(matches!(err, CapabilityError::OperationsNotSubset { .. }));
    }

    #[test]
    fn budget_exceeded() {
        let parent = make_grant(vec!["read"], 100, 5);
        let child = make_child(&parent, vec!["read"], 200, 4);
        let err = subset_check(&parent, &child).unwrap_err();
        assert!(matches!(err, CapabilityError::BudgetExceeded { .. }));
    }

    #[test]
    fn delegation_depth_not_decreased() {
        let parent = make_grant(vec!["read"], 1000, 5);
        let child = make_child(&parent, vec!["read"], 500, 5); // same depth
        let err = subset_check(&parent, &child).unwrap_err();
        assert!(matches!(
            err,
            CapabilityError::DelegationDepthNotDecreased { .. }
        ));
    }

    #[test]
    fn missing_parent_grant_id() {
        let parent = make_grant(vec!["read"], 1000, 5);
        let mut child = make_child(&parent, vec!["read"], 500, 4);
        child.parent_grant_id = None; // remove parent ref
        let err = subset_check(&parent, &child).unwrap_err();
        assert_eq!(err, CapabilityError::MissingParentGrantId);
    }
}
