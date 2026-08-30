//! atom-target: the typed [`Target`] an effect acts on, and the idempotency key
//! that makes a duplicate dispatch a no-op rather than a second effect.
//!
//! Normative source is `spec/` (precedence 1):
//!
//! * **TGT-001 / EFX-002** (`requirements.yaml`): an `EffectIntent` MUST carry a
//!   canonical request digest, its **target**, idempotency semantics and the
//!   external operation identity when known.
//! * **ATOM-VT-013** (`acceptance/catalog.yaml`): an imported capability stays
//!   bounded by the ATOM grant/effect path — a repeat of the same request must
//!   not become a second effect on the world.
//!
//! This crate does not re-implement [`atom_effect::Idempotency`]; it reads it.
//! The target is a *typed* identity so an effect planned for a resource can
//! never be dispatched at an agent or an external system by accident, and the
//! idempotency key is derived deterministically so the same request always
//! collapses onto the same ledger row.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use atom_effect::{EffectIntent, Idempotency, IdempotencyMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The kind of thing an effect can act on.
///
/// The kind is checked against the operation before dispatch, so a plan built
/// for one kind of target is refused when handed a different one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetKind {
    /// A resource inside a system ATOM governs (a row, a file, a record).
    Resource,
    /// Another agent ATOM can address.
    Agent,
    /// An operation performed at an external system boundary.
    External,
}

impl TargetKind {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "RESOURCE",
            Self::Agent => "AGENT",
            Self::External => "EXTERNAL",
        }
    }
}

/// The typed identity of the thing an effect acts on (TGT-001).
///
/// Every variant reduces to a single canonical [`Target::target_id`] string,
/// which is exactly the `target_id` an [`EffectIntent`] carries: an effect and
/// its target are bound by that string, and the binding is checked before a
/// dispatch is ever keyed.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Target {
    /// A resource, addressed by its type and id.
    Resource {
        /// The resource's type, in the target system's vocabulary.
        resource_type: String,
        /// The resource's id within that type.
        resource_id: String,
    },
    /// An agent, addressed by its id.
    Agent {
        /// The agent's stable id.
        agent_id: String,
    },
    /// An external system operation, addressed by system and operation id.
    External {
        /// The external system's stable id.
        system: String,
        /// The operation's id within that system.
        external_id: String,
    },
}

impl Target {
    /// A resource target.
    #[must_use]
    pub fn resource(resource_type: &str, resource_id: &str) -> Self {
        Self::Resource {
            resource_type: resource_type.to_owned(),
            resource_id: resource_id.to_owned(),
        }
    }

    /// An agent target.
    #[must_use]
    pub fn agent(agent_id: &str) -> Self {
        Self::Agent {
            agent_id: agent_id.to_owned(),
        }
    }

    /// An external-system target.
    #[must_use]
    pub fn external(system: &str, external_id: &str) -> Self {
        Self::External {
            system: system.to_owned(),
            external_id: external_id.to_owned(),
        }
    }

    /// The typed kind of this target.
    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        match self {
            Self::Resource { .. } => TargetKind::Resource,
            Self::Agent { .. } => TargetKind::Agent,
            Self::External { .. } => TargetKind::External,
        }
    }

    /// The canonical target identity string.
    ///
    /// This is the value an [`EffectIntent::target_id`](atom_effect::EffectIntent)
    /// is expected to equal, so the effect and its target cannot drift apart.
    #[must_use]
    pub fn target_id(&self) -> String {
        match self {
            Self::Resource {
                resource_type,
                resource_id,
            } => format!("RESOURCE:{resource_type}:{resource_id}"),
            Self::Agent { agent_id } => format!("AGENT:{agent_id}"),
            Self::External {
                system,
                external_id,
            } => format!("EXTERNAL:{system}:{external_id}"),
        }
    }
}

/// The deterministic identity a dispatch is deduplicated on (ATOM-VT-013).
///
/// Two dispatches share a key exactly when they are the same request against
/// the same target under the same idempotency contract. The ledger keys its
/// rows on this, so a repeat collapses onto the row the first dispatch created
/// instead of touching the world a second time.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Borrows the canonical key string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derives the key from a target and an idempotency contract.
    ///
    /// The discriminator depends on the mode, because "the same request" means
    /// different things under each contract:
    ///
    /// * `KEYED` — the caller's deduplication key is authoritative.
    /// * `NATURAL` — applying twice equals applying once, so the request digest
    ///   (its content identity) is the natural key.
    /// * `NON_IDEMPOTENT` — a repeat *would* be a second effect, so only a
    ///   literal re-dispatch of the very same effect id is caught; a different
    ///   effect id is, correctly, a different effect.
    fn derive(target: &Target, idempotency: &Idempotency, effect: &EffectIntent) -> Self {
        let discriminator = match idempotency.mode {
            IdempotencyMode::Keyed => idempotency
                .key
                .clone()
                .unwrap_or_else(|| effect.request_digest.clone()),
            IdempotencyMode::Natural => effect.request_digest.clone(),
            IdempotencyMode::NonIdempotent => effect.effect_id.clone(),
        };
        Self(format!(
            "{}|{}|{}|{}",
            target.target_id(),
            idempotency.mode.as_str(),
            idempotency.scope,
            discriminator
        ))
    }
}

/// Why a target could not be bound to an effect for dispatch.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TargetError {
    /// The target is not the kind the operation expects (TGT-001).
    #[error("operation expects a {expected} target, not a {observed} one")]
    KindMismatch {
        /// The kind the operation was planned for.
        expected: TargetKind,
        /// The kind of the target actually supplied.
        observed: TargetKind,
    },
    /// The target's identity is not the one the effect was written against.
    #[error("effect targets `{effect_target}`, not `{target}`")]
    TargetBindingMismatch {
        /// The `target_id` the effect carries.
        effect_target: String,
        /// The canonical id of the target supplied.
        target: String,
    },
}

impl std::fmt::Display for TargetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated pairing of an effect with the typed target it will act on.
///
/// Producing one proves the kind matched and the identity bound; it also
/// carries the derived [`IdempotencyKey`], so nothing downstream re-derives it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dispatch {
    target: Target,
    idempotency_key: IdempotencyKey,
    effect_id: String,
}

impl Dispatch {
    /// The target this dispatch acts on.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// The deduplication key.
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// The effect being dispatched.
    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }
}

/// Binds `effect` to `target`, refusing a wrong kind or identity (TGT-001).
///
/// `expected_kind` is what the operation was planned for; a target of any other
/// kind is denied rather than dispatched. The target identity must also equal
/// the `target_id` the effect was written against, so the two cannot diverge.
///
/// # Errors
///
/// [`TargetError::KindMismatch`] when the target is the wrong kind, or
/// [`TargetError::TargetBindingMismatch`] when its identity is not the effect's.
pub fn bind(
    effect: &EffectIntent,
    target: Target,
    expected_kind: TargetKind,
) -> Result<Dispatch, TargetError> {
    if target.kind() != expected_kind {
        return Err(TargetError::KindMismatch {
            expected: expected_kind,
            observed: target.kind(),
        });
    }
    if target.target_id() != effect.target_id {
        return Err(TargetError::TargetBindingMismatch {
            effect_target: effect.target_id.clone(),
            target: target.target_id(),
        });
    }
    let idempotency_key = IdempotencyKey::derive(&target, &effect.idempotency, effect);
    Ok(Dispatch {
        target,
        idempotency_key,
        effect_id: effect.effect_id.clone(),
    })
}

/// What happened when a dispatch was offered to the ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchOutcome {
    /// True only on the first dispatch of a key: the effect touches the world.
    ///
    /// A duplicate returns `false`, which is the whole point (ATOM-VT-013).
    pub applied: bool,
    /// The external operation identity recorded for this key, if any.
    pub external_operation_id: Option<String>,
}

/// A recorded dispatch, keyed by its [`IdempotencyKey`].
#[derive(Clone, Debug, Eq, PartialEq)]
struct DispatchRecord {
    effect_id: String,
    external_operation_id: Option<String>,
}

/// The memory that makes idempotency real: the set of keys already dispatched.
///
/// Without something that remembers a key was used, "duplicate dispatch is a
/// no-op" is only a wish. This is that memory — in-process, ordered, holding
/// one row per distinct request.
#[derive(Clone, Debug, Default)]
pub struct DispatchLedger {
    seen: BTreeMap<IdempotencyKey, DispatchRecord>,
}

impl DispatchLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct effects have actually been applied.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing has been dispatched yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Whether `key` has already been dispatched.
    #[must_use]
    pub fn contains(&self, key: &IdempotencyKey) -> bool {
        self.seen.contains_key(key)
    }

    /// Offers `dispatch` to the ledger, applying it at most once.
    ///
    /// The first offer of a key records it and reports `applied: true`. Every
    /// later offer of the same key is a no-op that reports `applied: false` and
    /// replays the external operation identity recorded the first time — so a
    /// retried request observes the original outcome, not a second one.
    pub fn dispatch(
        &mut self,
        dispatch: &Dispatch,
        external_operation_id: Option<&str>,
    ) -> DispatchOutcome {
        if let Some(existing) = self.seen.get(&dispatch.idempotency_key) {
            return DispatchOutcome {
                applied: false,
                external_operation_id: existing.external_operation_id.clone(),
            };
        }
        let external_operation_id = external_operation_id.map(str::to_owned);
        self.seen.insert(
            dispatch.idempotency_key.clone(),
            DispatchRecord {
                effect_id: dispatch.effect_id.clone(),
                external_operation_id: external_operation_id.clone(),
            },
        );
        DispatchOutcome {
            applied: true,
            external_operation_id,
        }
    }

    /// The external operation identity recorded for `key`, if it was dispatched.
    #[must_use]
    pub fn external_operation_id(&self, key: &IdempotencyKey) -> Option<&str> {
        self.seen
            .get(key)
            .and_then(|record| record.external_operation_id.as_deref())
    }

    /// The effect id that first claimed `key`, if any.
    #[must_use]
    pub fn effect_id_for(&self, key: &IdempotencyKey) -> Option<&str> {
        self.seen.get(key).map(|record| record.effect_id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_effect::{
        Compensation, CompensationStrategy, EffectIntent, Idempotency, Reconciliation,
        ReconciliationClass, RetryClass,
    };

    fn intent_for(target: &Target, idempotency: Idempotency, effect_id: &str) -> EffectIntent {
        EffectIntent::builder(effect_id, "mission-1", "cap-1", &target.target_id())
            .request_digest("req-digest-abc")
            .classes("mutate", "medium")
            .idempotency(idempotency)
            .reconciliation(Reconciliation::new(
                ReconciliationClass::LedgerReplay,
                RetryClass::Transient,
            ))
            .compensation(Compensation::new(CompensationStrategy::NotCompensable))
            .build()
            .expect("intent builds")
    }

    // ─── TGT-001: target is typed; wrong kind is denied ──────────────────────
    #[test]
    fn wrong_target_kind_is_denied() {
        let target = Target::resource("db", "row-1");
        let effect = intent_for(&target, Idempotency::keyed("scope", "k1"), "e1");
        // The operation was planned for an AGENT, but a RESOURCE was supplied.
        let err = bind(&effect, target, TargetKind::Agent).unwrap_err();
        assert!(matches!(
            err,
            TargetError::KindMismatch {
                expected: TargetKind::Agent,
                observed: TargetKind::Resource
            }
        ));
    }

    #[test]
    fn target_identity_must_match_effect() {
        let planned = Target::resource("db", "row-1");
        let effect = intent_for(&planned, Idempotency::keyed("scope", "k1"), "e1");
        // A different resource id — same kind, different identity.
        let other = Target::resource("db", "row-2");
        let err = bind(&effect, other, TargetKind::Resource).unwrap_err();
        assert!(matches!(err, TargetError::TargetBindingMismatch { .. }));
    }

    #[test]
    fn correct_kind_and_identity_binds() {
        let target = Target::external("stripe", "charge-1");
        let effect = intent_for(&target, Idempotency::keyed("scope", "k1"), "e1");
        let dispatch = bind(&effect, target.clone(), TargetKind::External).expect("binds");
        assert_eq!(dispatch.target(), &target);
        assert_eq!(dispatch.effect_id(), "e1");
    }

    // ─── ATOM-VT-013: duplicate idempotency → exactly one effect ─────────────
    #[test]
    fn duplicate_keyed_dispatch_applies_once() {
        let target = Target::external("stripe", "charge-1");
        let effect = intent_for(&target, Idempotency::keyed("payments", "idem-key-42"), "e1");
        let dispatch = bind(&effect, target, TargetKind::External).expect("binds");

        let mut ledger = DispatchLedger::new();
        let first = ledger.dispatch(&dispatch, Some("ext-op-1"));
        let second = ledger.dispatch(&dispatch, Some("ext-op-2"));
        let third = ledger.dispatch(&dispatch, Some("ext-op-3"));

        assert!(first.applied, "first dispatch must apply");
        assert!(!second.applied, "duplicate must NOT apply");
        assert!(!third.applied, "duplicate must NOT apply");
        assert_eq!(ledger.applied_count(), 1, "exactly one effect on the world");
        // The retry observes the original outcome, not a fresh one.
        assert_eq!(second.external_operation_id.as_deref(), Some("ext-op-1"));
        assert_eq!(third.external_operation_id.as_deref(), Some("ext-op-1"));
    }

    #[test]
    fn natural_idempotency_dedups_on_request_digest() {
        let target = Target::resource("kv", "config");
        // Two distinct effect ids, same natural request → one effect.
        let e1 = intent_for(&target, Idempotency::natural("kv"), "effect-A");
        let e2 = intent_for(&target, Idempotency::natural("kv"), "effect-B");
        let d1 = bind(&e1, target.clone(), TargetKind::Resource).expect("binds");
        let d2 = bind(&e2, target, TargetKind::Resource).expect("binds");
        assert_eq!(
            d1.idempotency_key(),
            d2.idempotency_key(),
            "natural key ignores effect id"
        );

        let mut ledger = DispatchLedger::new();
        assert!(ledger.dispatch(&d1, None).applied);
        assert!(!ledger.dispatch(&d2, None).applied);
        assert_eq!(ledger.applied_count(), 1);
    }

    #[test]
    fn distinct_requests_are_two_effects() {
        let target = Target::external("stripe", "charge-1");
        let e1 = intent_for(&target, Idempotency::keyed("payments", "key-1"), "e1");
        let e2 = intent_for(&target, Idempotency::keyed("payments", "key-2"), "e2");
        let d1 = bind(&e1, target.clone(), TargetKind::External).expect("binds");
        let d2 = bind(&e2, target, TargetKind::External).expect("binds");
        assert_ne!(d1.idempotency_key(), d2.idempotency_key());

        let mut ledger = DispatchLedger::new();
        assert!(ledger.dispatch(&d1, Some("op-1")).applied);
        assert!(ledger.dispatch(&d2, Some("op-2")).applied);
        assert_eq!(ledger.applied_count(), 2);
    }

    #[test]
    fn non_idempotent_repeat_of_same_effect_id_is_still_caught() {
        let target = Target::resource("queue", "jobs");
        let effect = intent_for(&target, Idempotency::non_idempotent("queue"), "job-1");
        let dispatch = bind(&effect, target, TargetKind::Resource).expect("binds");

        let mut ledger = DispatchLedger::new();
        assert!(ledger.dispatch(&dispatch, None).applied);
        // A literal re-dispatch of the same effect id must not double-fire.
        assert!(!ledger.dispatch(&dispatch, None).applied);
        assert_eq!(ledger.applied_count(), 1);
    }

    #[test]
    fn target_id_round_trips_through_kinds() {
        assert_eq!(Target::resource("db", "r1").target_id(), "RESOURCE:db:r1");
        assert_eq!(Target::agent("agent-7").target_id(), "AGENT:agent-7");
        assert_eq!(
            Target::external("sys", "op-3").target_id(),
            "EXTERNAL:sys:op-3"
        );
    }
}
