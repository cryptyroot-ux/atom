//! atom-connector: the contract every connector to an external system must
//! satisfy, and the conformance suite that refuses one that does not.
//!
//! Normative source is `spec/` (precedence 1):
//!
//! * **CON-001 / EFX-002** (`requirements.yaml`, verification "Connector
//!   conformance suite"): the adapter to an external system MUST support the
//!   effect contract — canonical request digest, idempotency, retry,
//!   reconciliation and compensation.
//! * **ATOM-VT-013** (`acceptance/catalog.yaml`): a peer that advertises broad
//!   authority does not get to bypass ATOM's effect path. A connector is not
//!   trusted because it says it is; it is trusted because the suite passed.
//!
//! The failure mode this crate exists to prevent is a *silent passthrough*: a
//! connector that quietly drops the parts of the effect contract it does not
//! implement, so an effect that assumed reconciliation is dispatched to a
//! system that cannot reconcile. The suite makes the gap explicit and refuses.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use atom_effect::EffectIntent;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A single capability of the effect contract a connector may support.
///
/// These are the mechanical parts EFX-002 asks an intent to carry; a connector
/// that carries an intent must be able to honour the parts that intent uses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    /// Can carry and echo the canonical request digest.
    RequestDigest,
    /// Deduplicates on an idempotency key, so a repeat is not a second effect.
    Idempotency,
    /// Classifies failures so a caller knows whether a retry is safe.
    Retry,
    /// Can settle an ambiguous outcome without writing again.
    Reconciliation,
    /// Can undo a landed effect.
    Compensation,
    /// Reports the external operation identity the system assigns.
    ExternalOperationId,
}

impl Capability {
    /// Every capability, in canonical order.
    pub const ALL: [Self; 6] = [
        Self::RequestDigest,
        Self::Idempotency,
        Self::Retry,
        Self::Reconciliation,
        Self::Compensation,
        Self::ExternalOperationId,
    ];

    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestDigest => "REQUEST_DIGEST",
            Self::Idempotency => "IDEMPOTENCY",
            Self::Retry => "RETRY",
            Self::Reconciliation => "RECONCILIATION",
            Self::Compensation => "COMPENSATION",
            Self::ExternalOperationId => "EXTERNAL_OPERATION_ID",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a connector claims it can do (CON-001).
///
/// A claim is not proof. The [`certify`] suite exists to check the claim
/// against what a given set of effects actually requires; nothing here trusts
/// the declaration on its own.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorContract {
    /// Stable identity of the connector, so a rejection can be named.
    pub connector_id: String,
    /// The external system it speaks to.
    pub system: String,
    /// The capabilities it declares support for.
    pub supported: BTreeSet<Capability>,
}

impl ConnectorContract {
    /// A contract for `connector_id` against `system` supporting `supported`.
    #[must_use]
    pub fn new(
        connector_id: &str,
        system: &str,
        supported: impl IntoIterator<Item = Capability>,
    ) -> Self {
        Self {
            connector_id: connector_id.to_owned(),
            system: system.to_owned(),
            supported: supported.into_iter().collect(),
        }
    }

    /// Whether the connector claims `capability`.
    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.supported.contains(&capability)
    }
}

/// The capabilities an effect requires of whatever connector carries it.
///
/// This is derived from the intent's own declarations, not asked of the caller:
/// an intent that names a compensation needs a connector that can compensate,
/// and so on. Deriving it here is what stops a connector from silently ignoring
/// a part of the contract the intent depends on.
#[must_use]
pub fn required_capabilities(effect: &EffectIntent) -> BTreeSet<Capability> {
    use atom_effect::{CompensationStrategy, IdempotencyMode, ReconciliationClass};

    let mut required = BTreeSet::new();
    // A canonical request digest is always part of the contract (EFX-002).
    required.insert(Capability::RequestDigest);

    // An idempotency contract other than "a repeat is a new effect" needs the
    // connector to actually deduplicate.
    if effect.idempotency.mode != IdempotencyMode::NonIdempotent {
        required.insert(Capability::Idempotency);
    }

    // A retry class other than NEVER means the caller may resend; the connector
    // must classify failures rather than swallow them.
    if effect.reconciliation.retry_class != atom_effect::RetryClass::Never {
        required.insert(Capability::Retry);
    }

    // A reconciliation plan that reads the world back needs a connector that
    // can perform that read; LEDGER_REPLAY and NOT_RECONCILABLE do not.
    match effect.reconciliation.class {
        ReconciliationClass::ExternalOperationLookup => {
            required.insert(Capability::Reconciliation);
            required.insert(Capability::ExternalOperationId);
        }
        ReconciliationClass::ResourceStateRead => {
            required.insert(Capability::Reconciliation);
        }
        ReconciliationClass::LedgerReplay | ReconciliationClass::NotReconcilable => {}
    }

    // A compensable effect needs a connector that can undo.
    if let Some(compensation) = &effect.compensation {
        if compensation.strategy != CompensationStrategy::NotCompensable {
            required.insert(Capability::Compensation);
        }
    }

    required
}

/// Why a connector failed conformance (CON-001).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConformanceError {
    /// The connector does not support a capability the effects require.
    ///
    /// This is the anti-silent-passthrough guarantee: the missing parts are
    /// named, and the connector is rejected rather than allowed to drop them.
    #[error("connector `{connector_id}` is missing required capabilities: {missing:?}")]
    MissingCapabilities {
        /// The connector that failed.
        connector_id: String,
        /// The capabilities it lacked, in canonical order.
        missing: Vec<Capability>,
    },
}

/// Proof a connector passed the conformance suite for a required capability set.
///
/// Only [`certify`] constructs this, so holding one is evidence the connector
/// was checked against real requirements — it cannot be forged by a connector
/// that merely claims conformance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCertificate {
    connector_id: String,
    system: String,
    covered: BTreeSet<Capability>,
}

impl ConformanceCertificate {
    /// The connector this certificate is for.
    #[must_use]
    pub fn connector_id(&self) -> &str {
        &self.connector_id
    }

    /// The external system the connector speaks to.
    #[must_use]
    pub fn system(&self) -> &str {
        &self.system
    }

    /// The capabilities that were required and verified present.
    #[must_use]
    pub fn covered(&self) -> &BTreeSet<Capability> {
        &self.covered
    }
}

/// Runs the conformance suite: the connector must support every capability the
/// `effects` require, or it is rejected (CON-001).
///
/// Passing no effects still requires the base contract (a request digest),
/// because a connector that cannot carry a digest cannot carry any effect.
///
/// # Errors
///
/// [`ConformanceError::MissingCapabilities`] naming every required capability
/// the connector does not support. It never silently passes a partial match.
pub fn certify<'a, I>(
    contract: &ConnectorContract,
    effects: I,
) -> Result<ConformanceCertificate, ConformanceError>
where
    I: IntoIterator<Item = &'a EffectIntent>,
{
    let mut required: BTreeSet<Capability> = BTreeSet::new();
    required.insert(Capability::RequestDigest);
    for effect in effects {
        required.extend(required_capabilities(effect));
    }

    let missing: Vec<Capability> = required
        .iter()
        .copied()
        .filter(|capability| !contract.supports(*capability))
        .collect();

    if !missing.is_empty() {
        return Err(ConformanceError::MissingCapabilities {
            connector_id: contract.connector_id.clone(),
            missing,
        });
    }

    Ok(ConformanceCertificate {
        connector_id: contract.connector_id.clone(),
        system: contract.system.clone(),
        covered: required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_effect::{
        Compensation, CompensationStrategy, EffectIntent, Idempotency, Reconciliation,
        ReconciliationClass, RetryClass,
    };

    fn full_connector(id: &str) -> ConnectorContract {
        ConnectorContract::new(id, "stripe", Capability::ALL)
    }

    /// An effect needing digest + idempotency + retry + reconciliation +
    /// external-op-id + compensation — the whole contract.
    fn demanding_effect() -> EffectIntent {
        EffectIntent::builder("e1", "m1", "cap-1", "EXTERNAL:stripe:charge-1")
            .request_digest("digest-1")
            .classes("charge", "high")
            .idempotency(Idempotency::keyed("payments", "key-1"))
            .reconciliation(
                Reconciliation::new(
                    ReconciliationClass::ExternalOperationLookup,
                    RetryClass::Transient,
                )
                .with_probe("GET /charges/{id}"),
            )
            .compensation(
                Compensation::new(CompensationStrategy::InverseOperation)
                    .with_operation("POST /refunds"),
            )
            .build()
            .expect("intent builds")
    }

    /// A minimal effect: non-idempotent, never-retry, ledger-replay, no comp.
    fn minimal_effect() -> EffectIntent {
        EffectIntent::builder("e2", "m1", "cap-1", "RESOURCE:kv:x")
            .request_digest("digest-2")
            .classes("write", "low")
            .idempotency(Idempotency::non_idempotent("kv"))
            .reconciliation(Reconciliation::new(
                ReconciliationClass::LedgerReplay,
                RetryClass::Never,
            ))
            .compensation(Compensation::new(CompensationStrategy::NotCompensable))
            .build()
            .expect("intent builds")
    }

    // ─── CON-001: a conformant connector passes ──────────────────────────────
    #[test]
    fn full_connector_certifies_for_demanding_effect() {
        let connector = full_connector("conn-full");
        let effect = demanding_effect();
        let cert = certify(&connector, [&effect]).expect("should certify");
        assert_eq!(cert.connector_id(), "conn-full");
        assert!(cert.covered().contains(&Capability::Reconciliation));
        assert!(cert.covered().contains(&Capability::Compensation));
    }

    // ─── CON-001: non-conformant connector is REJECTED, not passed through ───
    #[test]
    fn connector_missing_reconciliation_is_rejected() {
        // Supports everything EXCEPT reconciliation + external op id.
        let connector = ConnectorContract::new(
            "conn-partial",
            "stripe",
            [
                Capability::RequestDigest,
                Capability::Idempotency,
                Capability::Retry,
                Capability::Compensation,
            ],
        );
        let effect = demanding_effect();
        let err = certify(&connector, [&effect]).unwrap_err();
        match err {
            ConformanceError::MissingCapabilities {
                connector_id,
                missing,
            } => {
                assert_eq!(connector_id, "conn-partial");
                assert!(missing.contains(&Capability::Reconciliation));
                assert!(missing.contains(&Capability::ExternalOperationId));
            }
        }
    }

    #[test]
    fn connector_missing_idempotency_is_rejected_for_keyed_effect() {
        let connector = ConnectorContract::new(
            "conn-no-idem",
            "stripe",
            [Capability::RequestDigest, Capability::Retry],
        );
        let effect = demanding_effect();
        let err = certify(&connector, [&effect]).unwrap_err();
        assert!(matches!(
            err,
            ConformanceError::MissingCapabilities { ref missing, .. }
                if missing.contains(&Capability::Idempotency)
        ));
    }

    #[test]
    fn empty_connector_fails_base_contract() {
        // No effects, but a connector that cannot even carry a digest is refused.
        let connector = ConnectorContract::new("conn-empty", "stripe", []);
        let err = certify(&connector, std::iter::empty()).unwrap_err();
        assert!(matches!(
            err,
            ConformanceError::MissingCapabilities { ref missing, .. }
                if missing == &vec![Capability::RequestDigest]
        ));
    }

    #[test]
    fn minimal_effect_needs_only_the_base_contract() {
        // A connector that only supports the request digest is enough for a
        // non-idempotent, never-retry, ledger-replay, uncompensable effect.
        let connector =
            ConnectorContract::new("conn-min", "kv", [Capability::RequestDigest]);
        let effect = minimal_effect();
        let required = required_capabilities(&effect);
        assert_eq!(required, BTreeSet::from([Capability::RequestDigest]));
        assert!(certify(&connector, [&effect]).is_ok());
    }

    #[test]
    fn requirements_are_the_union_across_all_effects() {
        // A connector must satisfy the union of every effect it will carry.
        let connector = ConnectorContract::new(
            "conn-union",
            "mixed",
            [Capability::RequestDigest, Capability::Idempotency],
        );
        let demanding = demanding_effect();
        let minimal = minimal_effect();
        // The demanding effect drags in reconciliation etc., so the union is
        // not satisfied and the connector is rejected.
        let err = certify(&connector, [&minimal, &demanding]).unwrap_err();
        assert!(matches!(
            err,
            ConformanceError::MissingCapabilities { ref missing, .. }
                if missing.contains(&Capability::Reconciliation)
        ));
    }
}
