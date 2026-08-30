//! Policy evaluation for effect-scoped approvals.
//!
//! This crate deliberately keeps authorization evaluation deterministic: callers
//! supply the intent, capability, approval grants, and evaluation time. The
//! evaluator performs no I/O, reads no clock, and creates no identifiers.
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **AUT-003** — approvals are durable grants bound to an exact effect or a
//!   bounded capability/resource envelope.
//! * **INV-003** — an approval cannot widen a grantee's capability.
//! * **INV-012** — pressure signals cannot create authority.
//! * **ADR-017** — authority profiles compile to explicit capability grants;
//!   profiles do not bypass this evaluator.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};

/// A consequential effect considered by the policy evaluator.
///
/// `effect_intent_digest` and `resource_witness` are caller-provided durable
/// identities. An exact-effect approval requires both to match exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectIntent {
    /// Canonical digest of the durable effect intent.
    pub effect_intent_digest: String,
    /// Requested capability operation.
    pub operation: String,
    /// Concrete resources targeted by the effect.
    pub resources: Vec<ResourceSelector>,
    /// Version / generation witness for the resources observed while planning.
    pub resource_witness: Value,
    /// Maximum resources this one effect may consume.
    pub budget: Budget,
    /// Digest identifying the evidence freshness evaluated for this effect.
    pub evidence_freshness_digest: String,
}

impl EffectIntent {
    /// Construct an effect intent without reading time, randomness, or external state.
    pub fn new(
        effect_intent_digest: impl Into<String>,
        operation: impl Into<String>,
        resources: Vec<ResourceSelector>,
        resource_witness: Value,
        budget: Budget,
        evidence_freshness_digest: impl Into<String>,
    ) -> Self {
        Self {
            effect_intent_digest: effect_intent_digest.into(),
            operation: operation.into(),
            resources,
            resource_witness,
            budget,
            evidence_freshness_digest: evidence_freshness_digest.into(),
        }
    }
}

/// Compatibility name for an [`EffectIntent`] used as policy input.
pub type PolicyIntent = EffectIntent;

/// An approval bound to one precise effect identity and its resource witness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectScope {
    /// Digest of the one effect that this approval can authorize.
    pub effect_intent_digest: String,
    /// Resource witness that must still match at evaluation time.
    pub resource_witness: Value,
}

/// An approval bounded to a subset of a capability's operation, resource, and
/// budget envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    /// Operations the approval can cover.
    pub operations: Vec<String>,
    /// Resources the approval can cover.
    pub resources: Vec<ResourceSelector>,
    /// Upper bounds for each authorized effect.
    pub budget: Budget,
}

/// The mutually exclusive scopes permitted by AUT-003.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ApprovalScope {
    /// One exact effect and resource witness.
    Effect(EffectScope),
    /// A bounded envelope which may cover more than one effect.
    Capability(CapabilityScope),
}

/// Alias used where an approval scope is returned as a request hint.
pub type ApprovalScopeHint = ApprovalScope;

/// Alias for integrations that refer to a scope hint generically.
pub type ScopeHint = ApprovalScope;

/// Compatibility name for an approval scope.
pub type Scope = ApprovalScope;

/// Persisted lifecycle state of an approval grant.
///
/// A grant can be granted only from `Pending`; consumption keeps it `Granted`
/// while uses remain and makes it `Consumed` when exhausted. `Expired` and
/// `Revoked` are terminal states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Consumed,
    Expired,
    Revoked,
}

/// Compatibility name for the approval lifecycle state.
pub type ApprovalLifecycle = ApprovalStatus;

/// Compatibility name for the approval lifecycle state.
pub type ApprovalState = ApprovalStatus;

/// A durable approval grant.
///
/// The type is serializable so its creation and every lifecycle transition can
/// be stored as an append-only ledger event. Evaluation only inspects a
/// snapshot and never mutates `uses_remaining` itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalGrant {
    /// Stable durable identity for this approval.
    pub grant_id: String,
    /// Identity of the human or authority that approved the scope.
    pub approver_id: String,
    /// Exact-effect or bounded capability scope.
    pub scope: ApprovalScope,
    /// Timestamp after which the grant is unusable.
    pub expires_at: DateTime<Utc>,
    /// Total number of uses authorized when granted.
    pub max_uses: u32,
    /// Uses left according to the durable lifecycle projection.
    pub uses_remaining: u32,
    /// Freshness evidence that must equal the intent's evidence digest.
    pub evidence_freshness_digest: String,
    /// Durable approval lifecycle state.
    pub status: ApprovalStatus,
}

/// A lifecycle event suitable for recording in an append-only ledger.
///
/// Store the event alongside its `grant_id`, then replay it with
/// [`ApprovalGrant::apply`] to rebuild the durable projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalLifecycleEvent {
    Granted,
    Consumed,
    Expired,
    Revoked,
}

/// Errors returned by lifecycle reduction. They are deterministic and can be
/// persisted as the reason an attempted transition was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalLifecycleError {
    #[error("invalid approval lifecycle transition: {event:?} from {status:?}")]
    InvalidTransition {
        /// Persisted status before the transition.
        status: ApprovalStatus,
        /// Requested lifecycle event.
        event: ApprovalLifecycleEvent,
    },

    #[error(
        "approval use counters are invalid: uses_remaining={uses_remaining}, max_uses={max_uses}"
    )]
    InvalidUseCounters {
        /// Remaining count found in the durable grant.
        uses_remaining: u32,
        /// Maximum count found in the durable grant.
        max_uses: u32,
    },

    #[error("approval grant has no uses remaining")]
    NoUsesRemaining,
}

impl ApprovalGrant {
    /// Apply one durable lifecycle event without I/O or a clock read.
    pub fn apply(&self, event: ApprovalLifecycleEvent) -> Result<Self, ApprovalLifecycleError> {
        self.validate_use_counters()?;

        let mut next = self.clone();
        match event {
            ApprovalLifecycleEvent::Granted => {
                if self.status != ApprovalStatus::Pending {
                    return Err(ApprovalLifecycleError::InvalidTransition {
                        status: self.status,
                        event,
                    });
                }
                next.status = ApprovalStatus::Granted;
            }
            ApprovalLifecycleEvent::Consumed => {
                if self.status != ApprovalStatus::Granted {
                    return Err(ApprovalLifecycleError::InvalidTransition {
                        status: self.status,
                        event,
                    });
                }
                if self.uses_remaining == 0 {
                    return Err(ApprovalLifecycleError::NoUsesRemaining);
                }
                next.uses_remaining -= 1;
                if next.uses_remaining == 0 {
                    next.status = ApprovalStatus::Consumed;
                }
            }
            ApprovalLifecycleEvent::Expired => {
                if !matches!(
                    self.status,
                    ApprovalStatus::Pending | ApprovalStatus::Granted
                ) {
                    return Err(ApprovalLifecycleError::InvalidTransition {
                        status: self.status,
                        event,
                    });
                }
                next.status = ApprovalStatus::Expired;
            }
            ApprovalLifecycleEvent::Revoked => {
                if !matches!(
                    self.status,
                    ApprovalStatus::Pending | ApprovalStatus::Granted
                ) {
                    return Err(ApprovalLifecycleError::InvalidTransition {
                        status: self.status,
                        event,
                    });
                }
                next.status = ApprovalStatus::Revoked;
            }
        }
        Ok(next)
    }

    /// Transition a pending approval to granted.
    pub fn grant(&self) -> Result<Self, ApprovalLifecycleError> {
        self.apply(ApprovalLifecycleEvent::Granted)
    }

    /// Record one consumed use. The last permitted use transitions to
    /// [`ApprovalStatus::Consumed`].
    pub fn consume(&self) -> Result<Self, ApprovalLifecycleError> {
        self.apply(ApprovalLifecycleEvent::Consumed)
    }

    /// Record an expiry event after the caller's durable clock/policy has found
    /// that the grant is no longer valid.
    pub fn expire(&self) -> Result<Self, ApprovalLifecycleError> {
        self.apply(ApprovalLifecycleEvent::Expired)
    }

    /// Record a revocation event.
    pub fn revoke(&self) -> Result<Self, ApprovalLifecycleError> {
        self.apply(ApprovalLifecycleEvent::Revoked)
    }

    fn validate_use_counters(&self) -> Result<(), ApprovalLifecycleError> {
        if self.max_uses == 0 || self.uses_remaining > self.max_uses {
            return Err(ApprovalLifecycleError::InvalidUseCounters {
                uses_remaining: self.uses_remaining,
                max_uses: self.max_uses,
            });
        }
        Ok(())
    }

    fn usable_at(&self, now: DateTime<Utc>) -> Result<(), String> {
        match self.status {
            ApprovalStatus::Pending => return Err("approval grant is pending".into()),
            ApprovalStatus::Consumed => return Err("approval grant is consumed".into()),
            ApprovalStatus::Expired => return Err("approval grant is expired".into()),
            ApprovalStatus::Revoked => return Err("approval grant is revoked".into()),
            ApprovalStatus::Granted => {}
        }

        if self.max_uses == 0 || self.uses_remaining > self.max_uses {
            return Err("approval grant has invalid use counters".into());
        }
        if self.uses_remaining == 0 {
            return Err("approval grant is consumed".into());
        }
        if now >= self.expires_at {
            return Err("approval grant is expired".into());
        }
        Ok(())
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// The matching approval and capability authorize the exact intent.
    Allow(String),
    /// A capability or candidate approval makes the requested action invalid.
    Deny(String),
    /// Capability exists, but no usable matching approval exists.
    RequireApproval(ApprovalScopeHint),
}

/// Deterministic evaluator for capabilities and durable approval grants.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluate one effect against capability and approval snapshots.
    ///
    /// `now` is injected explicitly. This method does not read a clock, touch a
    /// ledger, generate values, or otherwise perform I/O. It also never
    /// modifies a grant; callers must durably consume an allowed grant through
    /// [`ApprovalGrant::consume`] at their transaction boundary.
    pub fn evaluate(
        intent: &EffectIntent,
        grants: &[ApprovalGrant],
        capability: &CapabilityGrant,
        now: DateTime<Utc>,
    ) -> PolicyDecision {
        if let Err(reason) = capability_authorizes_intent(capability, intent, now) {
            return PolicyDecision::Deny(reason);
        }

        let mut rejected_candidate = None;
        for grant in grants {
            if !scope_matches_intent(&grant.scope, intent) {
                continue;
            }

            if let Err(reason) = grant.usable_at(now) {
                rejected_candidate.get_or_insert_with(|| {
                    format!("approval grant {} rejected: {reason}", grant.grant_id)
                });
                continue;
            }

            if grant.evidence_freshness_digest != intent.evidence_freshness_digest {
                rejected_candidate.get_or_insert_with(|| {
                    format!(
                        "approval grant {} rejected: evidence freshness digest does not match intent",
                        grant.grant_id
                    )
                });
                continue;
            }

            if !scope_within_capability(&grant.scope, capability) {
                rejected_candidate.get_or_insert_with(|| {
                    format!(
                        "approval grant {} rejected: approval scope exceeds grantee capability",
                        grant.grant_id
                    )
                });
                continue;
            }

            return PolicyDecision::Allow(format!(
                "effect {} allowed by approval grant {} within capability {}",
                intent.effect_intent_digest, grant.grant_id, capability.grant_id
            ));
        }

        if let Some(reason) = rejected_candidate {
            PolicyDecision::Deny(reason)
        } else {
            PolicyDecision::RequireApproval(ApprovalScope::Effect(EffectScope {
                effect_intent_digest: intent.effect_intent_digest.clone(),
                resource_witness: intent.resource_witness.clone(),
            }))
        }
    }
}

/// Convenience free function for callers that do not need the marker type.
pub fn evaluate(
    intent: &EffectIntent,
    grants: &[ApprovalGrant],
    capability: &CapabilityGrant,
    now: DateTime<Utc>,
) -> PolicyDecision {
    PolicyEngine::evaluate(intent, grants, capability, now)
}

fn capability_authorizes_intent(
    capability: &CapabilityGrant,
    intent: &EffectIntent,
    now: DateTime<Utc>,
) -> Result<(), String> {
    match capability.revocation_state {
        RevocationState::Active => {}
        RevocationState::Revoked => return Err("capability grant is revoked".into()),
        RevocationState::Expired => return Err("capability grant is expired".into()),
    }

    if now < capability.not_before {
        return Err("capability grant is not yet valid".into());
    }
    if now >= capability.expires_at {
        return Err("capability grant is expired".into());
    }
    if !capability
        .operations
        .iter()
        .any(|op| op == &intent.operation)
    {
        return Err(format!(
            "capability grant does not authorize operation {}",
            intent.operation
        ));
    }
    if intent.resources.is_empty() {
        return Err("effect intent has no concrete resources".into());
    }
    if intent
        .resources
        .iter()
        .any(|resource| resource.resource_type == "*" || resource.resource_id == "*")
    {
        return Err("effect intent resources must be concrete".into());
    }
    if !intent.resources.iter().all(|resource| {
        capability
            .resources
            .iter()
            .any(|allowed| resource_contains(allowed, resource))
    }) {
        return Err("capability grant does not authorize one or more resources".into());
    }
    if intent.budget.max_cost > capability.budget.max_cost
        || intent.budget.max_seconds > capability.budget.max_seconds
    {
        return Err("effect budget exceeds capability bounds".into());
    }
    Ok(())
}

fn scope_matches_intent(scope: &ApprovalScope, intent: &EffectIntent) -> bool {
    match scope {
        ApprovalScope::Effect(effect) => {
            effect.effect_intent_digest == intent.effect_intent_digest
                && effect.resource_witness == intent.resource_witness
        }
        ApprovalScope::Capability(capability) => {
            !capability.operations.is_empty()
                && !capability.resources.is_empty()
                && capability
                    .operations
                    .iter()
                    .any(|op| op == &intent.operation)
                && intent.resources.iter().all(|resource| {
                    capability
                        .resources
                        .iter()
                        .any(|allowed| resource_contains(allowed, resource))
                })
                && intent.budget.max_cost <= capability.budget.max_cost
                && intent.budget.max_seconds <= capability.budget.max_seconds
        }
    }
}

fn scope_within_capability(scope: &ApprovalScope, capability: &CapabilityGrant) -> bool {
    match scope {
        // An exact effect scope is necessarily bounded by the capability after
        // `capability_authorizes_intent` and exact scope matching have passed.
        ApprovalScope::Effect(_) => true,
        ApprovalScope::Capability(scope) => {
            !scope.operations.is_empty()
                && !scope.resources.is_empty()
                && scope.operations.iter().all(|operation| {
                    capability
                        .operations
                        .iter()
                        .any(|allowed| allowed == operation)
                })
                && scope.resources.iter().all(|resource| {
                    capability
                        .resources
                        .iter()
                        .any(|allowed| resource_contains(allowed, resource))
                })
                && scope.budget.max_cost <= capability.budget.max_cost
                && scope.budget.max_seconds <= capability.budget.max_seconds
        }
    }
}

/// Whether `container` semantically contains `candidate`, using the same
/// wildcard semantics as `atom-capability`'s attenuation check.
fn resource_contains(container: &ResourceSelector, candidate: &ResourceSelector) -> bool {
    (container.resource_type == "*" || container.resource_type == candidate.resource_type)
        && (container.resource_id == "*" || container.resource_id == candidate.resource_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use serde_json::json;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
            .single()
            .expect("valid fixed timestamp")
    }

    #[test]
    fn exact_scope_requires_the_same_resource_witness() {
        let scope = ApprovalScope::Effect(EffectScope {
            effect_intent_digest: "effect-a".into(),
            resource_witness: json!({"version": 1}),
        });
        let intent = EffectIntent::new(
            "effect-a",
            "read",
            vec![ResourceSelector {
                resource_type: "db".into(),
                resource_id: "one".into(),
            }],
            json!({"version": 2}),
            Budget {
                max_cost: 1,
                max_seconds: 1,
            },
            "evidence",
        );

        assert!(!scope_matches_intent(&scope, &intent));
    }

    #[test]
    fn lifecycle_rejects_regranting_a_consumed_approval() {
        let grant = ApprovalGrant {
            grant_id: "approval".into(),
            approver_id: "approver".into(),
            scope: ApprovalScope::Effect(EffectScope {
                effect_intent_digest: "effect".into(),
                resource_witness: json!({}),
            }),
            expires_at: fixed_now() + Duration::minutes(1),
            max_uses: 1,
            uses_remaining: 1,
            evidence_freshness_digest: "evidence".into(),
            status: ApprovalStatus::Pending,
        };

        let consumed = grant.grant().unwrap().consume().unwrap();
        assert!(matches!(
            consumed.grant(),
            Err(ApprovalLifecycleError::InvalidTransition {
                status: ApprovalStatus::Consumed,
                event: ApprovalLifecycleEvent::Granted,
            })
        ));
    }
}
