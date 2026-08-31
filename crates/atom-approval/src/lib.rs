//! atom-approval: durable [`ApprovalGrant`] lifecycle store (AUT-003).
//!
//! ATOM — normative source is `spec/` (precedence 1).
//!
//! This crate owns the **persistence and lifecycle** of approvals: it records
//! durable grants, tracks their validity interval and revocation state, and
//! redeems a grant against a concrete redemption target. It deliberately does
//! **not** re-implement the authorization *decision* — that belongs to
//! `atom-policy`. The division of labour is:
//!
//! * `atom-policy`   — evaluates an effect against capability + approvals.
//! * `atom-approval` — stores approvals durably and validates their lifecycle
//!   (bound scope, validity interval, revocation) at redemption time.
//!
//! AUT-003 requires an approval to be a durable grant scoped to **either** an
//! exact effect digest **or** a bounded capability/resource envelope. The four
//! failure modes it must enforce are all lifecycle facts, not policy opinions:
//!
//! * **changed-payload** — a grant bound to effect digest `A` never redeems `B`
//!   (a mutated request has a different [`atom_effect::EffectIntent::digest`]).
//! * **expiry** — a grant redeemed outside its [`ValidityInterval`] is denied.
//! * **revocation** — a revoked grant is denied even before it expires.
//! * **deny-by-default** — no matching grant means denied.
//!
//! The store reads no clock: `now` is injected into [`ApprovalStore::redeem`]
//! so identical inputs always produce identical decisions.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use atom_capability::{Budget, ResourceSelector};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Validity interval
// ---------------------------------------------------------------------------

/// A half-open validity interval `[not_before, expires_at)`.
///
/// A grant is only usable when `not_before <= now < expires_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityInterval {
    /// The instant at which the grant becomes usable.
    pub not_before: DateTime<Utc>,
    /// The instant at and after which the grant is expired.
    pub expires_at: DateTime<Utc>,
}

impl ValidityInterval {
    /// Construct an interval, rejecting a non-positive window.
    ///
    /// # Errors
    ///
    /// [`IntervalError::NotBeforeAfterExpiry`] when `not_before >= expires_at`;
    /// an interval that is empty or inverted could never authorize anything and
    /// is therefore a construction bug rather than a runtime denial.
    pub fn new(
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, IntervalError> {
        if not_before >= expires_at {
            return Err(IntervalError::NotBeforeAfterExpiry {
                not_before,
                expires_at,
            });
        }
        Ok(Self {
            not_before,
            expires_at,
        })
    }

    /// Whether `now` falls inside the half-open interval.
    #[must_use]
    pub fn contains(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_before && now < self.expires_at
    }
}

/// The interval could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IntervalError {
    /// `not_before` was at or after `expires_at`.
    #[error("validity interval is empty or inverted: not_before={not_before}, expires_at={expires_at}")]
    NotBeforeAfterExpiry {
        /// The requested lower bound.
        not_before: DateTime<Utc>,
        /// The requested upper bound.
        expires_at: DateTime<Utc>,
    },
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// A bounded capability/resource envelope an approval may cover.
///
/// An envelope can authorize more than one effect, but only ones whose
/// operation, resources and budget all fall inside the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEnvelope {
    /// Operations the envelope authorizes.
    pub operations: Vec<String>,
    /// Resources the envelope authorizes.
    pub resources: Vec<ResourceSelector>,
    /// Optional upper bound each covered effect must stay within. `None`
    /// declares the envelope imposes no budget ceiling of its own.
    #[serde(default)]
    pub budget: Option<Budget>,
}

/// The mutually exclusive scopes AUT-003 permits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalScope {
    /// One exact effect identity, addressed by its
    /// [`atom_effect::EffectIntent::digest`].
    Effect {
        /// The single effect digest this approval can redeem.
        effect_digest: String,
    },
    /// A bounded envelope which may cover more than one effect.
    Capability(CapabilityEnvelope),
}

// ---------------------------------------------------------------------------
// Redemption target
// ---------------------------------------------------------------------------

/// A concrete thing a caller wants to redeem an approval against.
///
/// This is the caller's *request*, not the stored grant. An [`ApprovalScope`]
/// matches a [`RedeemTarget`] only when the scope's kind matches and every
/// bound is satisfied. Effect and capability targets never cross-match: an
/// exact-effect target requires an exact-effect grant for the same digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RedeemTarget {
    /// Redeem against one exact effect digest.
    Effect {
        /// The effect digest being redeemed.
        effect_digest: String,
    },
    /// Redeem an effect described by operation, resources and budget.
    Capability {
        /// The operation the effect performs.
        operation: String,
        /// The concrete resources the effect touches.
        resources: Vec<ResourceSelector>,
        /// The budget the effect will consume, if known.
        #[serde(default)]
        budget: Option<Budget>,
    },
}

impl ApprovalScope {
    /// Whether this scope covers `target`.
    ///
    /// Matching is scope-kind exact: an [`ApprovalScope::Effect`] only covers a
    /// [`RedeemTarget::Effect`] with an identical digest, and an
    /// [`ApprovalScope::Capability`] only covers a [`RedeemTarget::Capability`]
    /// whose operation, resources and budget all fall inside the envelope.
    #[must_use]
    pub fn covers(&self, target: &RedeemTarget) -> bool {
        match (self, target) {
            (
                ApprovalScope::Effect { effect_digest },
                RedeemTarget::Effect {
                    effect_digest: wanted,
                },
            ) => effect_digest == wanted,
            (
                ApprovalScope::Capability(envelope),
                RedeemTarget::Capability {
                    operation,
                    resources,
                    budget,
                },
            ) => envelope_covers(envelope, operation, resources, budget.as_ref()),
            _ => false,
        }
    }
}

fn envelope_covers(
    envelope: &CapabilityEnvelope,
    operation: &str,
    resources: &[ResourceSelector],
    budget: Option<&Budget>,
) -> bool {
    if envelope.operations.is_empty() || envelope.resources.is_empty() {
        return false;
    }
    if resources.is_empty() {
        return false;
    }
    if !envelope.operations.iter().any(|op| op == operation) {
        return false;
    }
    if !resources
        .iter()
        .all(|resource| envelope.resources.iter().any(|allowed| resource_contains(allowed, resource)))
    {
        return false;
    }
    if let Some(ceiling) = envelope.budget {
        match budget {
            Some(requested) => {
                if requested.max_cost > ceiling.max_cost
                    || requested.max_seconds > ceiling.max_seconds
                {
                    return false;
                }
            }
            // The envelope declares a budget ceiling but the caller declared no
            // budget: it cannot be proven to stay within, so deny.
            None => return false,
        }
    }
    true
}

/// Whether `container` semantically contains `candidate`, using the same
/// wildcard semantics as `atom-capability`'s attenuation check.
fn resource_contains(container: &ResourceSelector, candidate: &ResourceSelector) -> bool {
    (container.resource_type == "*" || container.resource_type == candidate.resource_type)
        && (container.resource_id == "*" || container.resource_id == candidate.resource_id)
}

// ---------------------------------------------------------------------------
// Revocation state + grant
// ---------------------------------------------------------------------------

/// Durable revocation state of an approval grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RevocationState {
    /// The grant has not been revoked.
    #[default]
    Active,
    /// The grant has been revoked and can never be redeemed again.
    Revoked,
}

/// A durable approval grant.
///
/// It is serializable so its creation and every lifecycle transition can be
/// persisted (e.g. as an append-only ledger event) and replayed. `generation`
/// increments on each durable state change so a stale copy can be detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGrant {
    /// Stable durable identity for this approval.
    pub grant_id: String,
    /// Identity of the human or authority that approved the scope.
    pub approver_id: String,
    /// Exact-effect or bounded capability scope.
    pub scope: ApprovalScope,
    /// The interval during which the grant is usable.
    pub validity: ValidityInterval,
    /// Durable revocation state.
    #[serde(default)]
    pub revocation_state: RevocationState,
    /// Monotonic generation, bumped on each durable transition.
    #[serde(default)]
    pub generation: u64,
}

impl ApprovalGrant {
    /// Construct a fresh, active grant at generation 0.
    #[must_use]
    pub fn new(
        grant_id: impl Into<String>,
        approver_id: impl Into<String>,
        scope: ApprovalScope,
        validity: ValidityInterval,
    ) -> Self {
        Self {
            grant_id: grant_id.into(),
            approver_id: approver_id.into(),
            scope,
            validity,
            revocation_state: RevocationState::Active,
            generation: 0,
        }
    }

    /// Whether the grant is revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revocation_state == RevocationState::Revoked
    }

    /// Validate this grant against `target` and `now` without mutating it.
    ///
    /// # Errors
    ///
    /// * [`RedeemError::NoMatchingGrant`] if the scope does not cover `target`.
    /// * [`RedeemError::Revoked`] if the grant is revoked.
    /// * [`RedeemError::NotYetValid`] / [`RedeemError::Expired`] if `now` is
    ///   outside the validity interval.
    fn check(&self, target: &RedeemTarget, now: DateTime<Utc>) -> Result<(), RedeemError> {
        if !self.scope.covers(target) {
            return Err(RedeemError::NoMatchingGrant);
        }
        if self.is_revoked() {
            return Err(RedeemError::Revoked {
                grant_id: self.grant_id.clone(),
            });
        }
        if now < self.validity.not_before {
            return Err(RedeemError::NotYetValid {
                grant_id: self.grant_id.clone(),
                not_before: self.validity.not_before,
            });
        }
        if now >= self.validity.expires_at {
            return Err(RedeemError::Expired {
                grant_id: self.grant_id.clone(),
                expires_at: self.validity.expires_at,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Redemption outcome + errors
// ---------------------------------------------------------------------------

/// Proof that a specific grant authorized a specific redemption at `now`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemReceipt {
    /// The grant that authorized the redemption.
    pub grant_id: String,
    /// The instant the caller supplied as `now`.
    pub redeemed_at: DateTime<Utc>,
    /// The grant's generation at the time of redemption.
    pub generation: u64,
}

/// Why a redemption was denied. Deny-by-default is [`RedeemError::NoMatchingGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RedeemError {
    /// No stored grant covered the target: the deny-by-default outcome.
    #[error("no durable approval grant matches the redemption target")]
    NoMatchingGrant,

    /// A grant covered the target but has been revoked.
    #[error("approval grant {grant_id} is revoked")]
    Revoked {
        /// The revoked grant.
        grant_id: String,
    },

    /// A grant covered the target but `now` is before its validity interval.
    #[error("approval grant {grant_id} is not yet valid (not_before={not_before})")]
    NotYetValid {
        /// The grant that is not yet valid.
        grant_id: String,
        /// The instant the grant becomes valid.
        not_before: DateTime<Utc>,
    },

    /// A grant covered the target but `now` is at or after `expires_at`.
    #[error("approval grant {grant_id} is expired (expires_at={expires_at})")]
    Expired {
        /// The expired grant.
        grant_id: String,
        /// The instant the grant expired.
        expires_at: DateTime<Utc>,
    },
}

/// Why a grant could not be recorded or transitioned.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    /// A grant with this id is already present.
    #[error("approval grant {grant_id} already exists")]
    DuplicateGrant {
        /// The conflicting id.
        grant_id: String,
    },

    /// No grant with this id is present.
    #[error("approval grant {grant_id} not found")]
    UnknownGrant {
        /// The missing id.
        grant_id: String,
    },
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// A durable, replayable store of [`ApprovalGrant`]s keyed by `grant_id`.
///
/// The store is serializable in full so it can be persisted and restored. It
/// performs no I/O and reads no clock; `now` is always supplied by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalStore {
    grants: BTreeMap<String, ApprovalGrant>,
}

impl ApprovalStore {
    /// An empty store, which denies every redemption by default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            grants: BTreeMap::new(),
        }
    }

    /// Record a durable grant.
    ///
    /// # Errors
    ///
    /// [`StoreError::DuplicateGrant`] if a grant with the same id already
    /// exists; grant ids are durable identities and must not be reused.
    pub fn record(&mut self, grant: ApprovalGrant) -> Result<(), StoreError> {
        if self.grants.contains_key(&grant.grant_id) {
            return Err(StoreError::DuplicateGrant {
                grant_id: grant.grant_id,
            });
        }
        self.grants.insert(grant.grant_id.clone(), grant);
        Ok(())
    }

    /// Durably revoke a stored grant. Revocation is terminal and idempotent-safe
    /// only in that re-revoking bumps the generation again.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownGrant`] if no grant with `grant_id` is present.
    pub fn revoke(&mut self, grant_id: &str) -> Result<(), StoreError> {
        let grant = self
            .grants
            .get_mut(grant_id)
            .ok_or_else(|| StoreError::UnknownGrant {
                grant_id: grant_id.to_owned(),
            })?;
        grant.revocation_state = RevocationState::Revoked;
        grant.generation += 1;
        Ok(())
    }

    /// Fetch a stored grant by id.
    #[must_use]
    pub fn get(&self, grant_id: &str) -> Option<&ApprovalGrant> {
        self.grants.get(grant_id)
    }

    /// Number of grants held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether the store holds no grants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Redeem an approval for `target` at `now`.
    ///
    /// Returns the first stored grant that both covers the target and passes
    /// its lifecycle checks. When one grant covers the target but is unusable
    /// (revoked / not-yet-valid / expired) and no other usable grant covers it,
    /// the specific lifecycle error is returned so callers can distinguish it
    /// from the deny-by-default [`RedeemError::NoMatchingGrant`].
    ///
    /// This never mutates the store: consumption/attenuation decisions belong to
    /// the caller's transaction boundary and to `atom-policy`.
    ///
    /// # Errors
    ///
    /// [`RedeemError`] describing why no usable grant authorized the target.
    pub fn redeem(
        &self,
        target: &RedeemTarget,
        now: DateTime<Utc>,
    ) -> Result<RedeemReceipt, RedeemError> {
        // BTreeMap iteration is ordered by grant_id, so the decision is
        // deterministic for a given store snapshot.
        let mut rejection: Option<RedeemError> = None;
        for grant in self.grants.values() {
            match grant.check(target, now) {
                Ok(()) => {
                    return Ok(RedeemReceipt {
                        grant_id: grant.grant_id.clone(),
                        redeemed_at: now,
                        generation: grant.generation,
                    })
                }
                // A grant that does not cover the target is not a reason to
                // surface a lifecycle error; keep looking.
                Err(RedeemError::NoMatchingGrant) => {}
                // A covering-but-unusable grant is a candidate rejection. Keep
                // the first one so the reason is deterministic.
                Err(other) => {
                    rejection.get_or_insert(other);
                }
            }
        }
        Err(rejection.unwrap_or(RedeemError::NoMatchingGrant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, hour, 0, 0)
            .single()
            .expect("unambiguous")
    }

    fn interval() -> ValidityInterval {
        ValidityInterval::new(ts(11), ts(13)).expect("valid")
    }

    #[test]
    fn effect_scope_covers_only_exact_digest() {
        let scope = ApprovalScope::Effect {
            effect_digest: "sha256:aaaa".into(),
        };
        assert!(scope.covers(&RedeemTarget::Effect {
            effect_digest: "sha256:aaaa".into(),
        }));
        assert!(!scope.covers(&RedeemTarget::Effect {
            effect_digest: "sha256:bbbb".into(),
        }));
    }

    #[test]
    fn interval_contains_is_half_open() {
        let iv = interval();
        assert!(!iv.contains(ts(11) - chrono::Duration::seconds(1)));
        assert!(iv.contains(ts(11)));
        assert!(iv.contains(ts(12)));
        assert!(!iv.contains(ts(13)));
    }

    #[test]
    fn envelope_with_ceiling_denies_unbounded_budget() {
        let envelope = CapabilityEnvelope {
            operations: vec!["write".into()],
            resources: vec![ResourceSelector {
                resource_type: "db".into(),
                resource_id: "db/orders".into(),
            }],
            budget: Some(Budget {
                max_cost: 10,
                max_seconds: 10,
            }),
        };
        assert!(!envelope_covers(&envelope, "write", &envelope.resources, None));
    }
}
