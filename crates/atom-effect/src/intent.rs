//! [`EffectIntent`]: the durable record that must exist before anything is
//! dispatched (EFX-001), carrying every field EFX-002 asks for.
//!
//! An intent authorises nothing by itself. It is the written-down request, its
//! declared semantics, and its position in the lifecycle — nothing more.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical::{to_canonical_bytes, CanonicalizationError};
use crate::digest::{digest_component, digest_optional, finish};
use crate::event::EffectEvent;
use crate::reducer::{try_reduce, ReduceError};
use crate::semantics::{Compensation, Condition, Idempotency, Reconciliation};
use crate::state::EffectState;

/// The builder refused to produce an intent.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntentError {
    /// EFX-002 requires the field and it was never declared.
    #[error("EFX-002 requires `{field}`")]
    MissingField {
        /// The absent field.
        field: &'static str,
    },
    /// The field carries only whitespace, which is not an identifier.
    #[error("`{field}` must not be blank")]
    EmptyField {
        /// Path of the blank field.
        field: String,
    },
    /// The declaration contradicts itself, so it could never be replayed.
    #[error("`{field}` contradicts itself: {reason}")]
    Inconsistent {
        /// The self-contradicting field.
        field: &'static str,
        /// Why the declaration cannot hold.
        reason: &'static str,
    },
    /// An effect cannot wait for itself.
    #[error("effect `{effect_id}` cannot depend on itself")]
    SelfDependency {
        /// The effect that named itself.
        effect_id: String,
    },
    /// Dependency edges form a set: each is declared once.
    #[error("dependency `{effect_id}` is declared more than once")]
    DuplicateDependency {
        /// The repeated edge.
        effect_id: String,
    },
    /// The request digest is not a canonical `sha256:<64 hex>` identity.
    ///
    /// EFX-005 / ATOM-SEM-003 accept only `canonical_request_digest`, and a
    /// canonical digest is the SHA-256 of the RFC 8785 request bytes. A
    /// free-form string here would defeat the point of a canonical identity.
    #[error("`canonical_request_digest` must be `sha256:<64 hex>`, got `{value}`")]
    NotCanonicalDigest {
        /// The rejected value.
        value: String,
    },
}
/// Fails unless `value` is `sha256:` followed by exactly 64 lower-case hex.
pub(crate) fn require_canonical_digest(value: &str) -> Result<(), IntentError> {
    let is_canonical = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    });
    if is_canonical {
        Ok(())
    } else {
        Err(IntentError::NotCanonicalDigest {
            value: value.to_owned(),
        })
    }
}
/// Fails unless `value` carries something other than whitespace.
pub(crate) fn require_text(value: &str, field: &str) -> Result<(), IntentError> {
    if value.trim().is_empty() {
        return Err(IntentError::EmptyField {
            field: field.to_owned(),
        });
    }
    Ok(())
}

/// A written-down request, its declared semantics, and where it has got to.
///
/// The field set is exactly `spec/schemas/effect-intent.schema.json`, and
/// `deny_unknown_fields` mirrors its `additionalProperties: false`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntent {
    /// Identity of this effect.
    pub effect_id: String,
    /// The mission the effect serves.
    pub mission_id: String,
    /// The capability the effect will be authorised against.
    pub capability_id: String,
    /// The resource the effect acts on.
    pub target_id: String,
    /// Canonical (RFC 8785) digest of the request body: `sha256:<64 hex>`. A
    /// reordered or reformatted request keeps this identity; a mutated one earns
    /// a new one. The sole accepted request-digest field (EFX-005).
    pub canonical_request_digest: String,
    /// The target's own handle, discovered at dispatch and not before.
    pub external_operation_id: Option<String>,
    /// What kind of effect this is, in the caller's vocabulary.
    pub effect_class: String,
    /// How much a wrong outcome would cost.
    pub risk_class: String,
    /// The idempotency contract of the request.
    pub idempotency: Idempotency,
    /// What must hold before the effect is applied.
    pub preconditions: Vec<Condition>,
    /// What must hold after it has been applied.
    pub postconditions: Vec<Condition>,
    /// How an unknown outcome would be settled.
    pub reconciliation: Reconciliation,
    /// How a landed effect would be undone.
    pub compensation: Option<Compensation>,
    /// Effects that must settle before this one may be dispatched (EFX-003).
    pub dependencies: Vec<String>,
    /// Where the effect has got to in `spec/state-machines/effect.yaml`.
    pub state: EffectState,
}
impl EffectIntent {
    /// Starts a builder for an effect on `target_id`.
    #[must_use]
    pub fn builder(
        effect_id: &str,
        mission_id: &str,
        capability_id: &str,
        target_id: &str,
    ) -> EffectIntentBuilder {
        EffectIntentBuilder {
            effect_id: effect_id.to_owned(),
            mission_id: mission_id.to_owned(),
            capability_id: capability_id.to_owned(),
            target_id: target_id.to_owned(),
            canonical_request_digest: None,
            classes: None,
            idempotency: None,
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            reconciliation: None,
            compensation: None,
            dependencies: Vec::new(),
        }
    }

    /// The identity digest: everything the caller declared, and nothing the
    /// lifecycle later discovers.
    ///
    /// A [`crate::CommitPermit`] binds to this, so an effect that moves through
    /// its states keeps the identity its permit was issued against (EFX-004).
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        self.digest_into(&mut hasher);
        finish(hasher)
    }

    /// The intent's declared payload: every field the caller wrote down, and
    /// nothing the lifecycle later discovers (`state`, `external_operation_id`).
    ///
    /// This is the JSON the ledger persists on the effect's own stream, so the
    /// bytes are byte-for-byte stable as the intent advances through its states.
    /// A whole-struct serialization would change with `state`, so nothing else
    /// can be re-derived at the commit gate (ATOM-INV-004).
    ///
    /// # Errors
    ///
    /// [`CanonicalizationError`] if serializing the declared fields fails.
    pub fn declared_payload(&self) -> Result<serde_json::Value, CanonicalizationError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| CanonicalizationError::Serialization(error.to_string()))?;
        let fields = value.as_object_mut().ok_or_else(|| {
            CanonicalizationError::Serialization("intent must serialize to an object".into())
        })?;
        fields.remove("external_operation_id");
        fields.remove("state");
        Ok(value)
    }

    /// The RFC 8785 payload digest of the declared intent, computed exactly as
    /// the ledger computes it over the persisted declared payload.
    ///
    /// A `DurabilityProof` seals this digest, so the two bind: the proof attests
    /// that *this exact declaration* was durably persisted, not merely something
    /// on the effect's stream (EFX-001, ATOM-INV-004).
    ///
    /// # Errors
    ///
    /// [`CanonicalizationError`] if serializing or canonicalizing the declared
    /// payload fails.
    pub fn declared_payload_digest(&self) -> Result<atom_ledger::Hash, CanonicalizationError> {
        let value = self.declared_payload()?;
        let bytes = to_canonical_bytes(&value)?;
        Ok(atom_ledger::payload_digest_bytes(&bytes))
    }

    /// The identity digest extended with the lifecycle position.
    #[must_use]
    pub fn state_digest(&self) -> String {
        let mut hasher = Sha256::new();
        self.digest_into(&mut hasher);
        digest_component(&mut hasher, "state");
        digest_component(&mut hasher, self.state.as_str());
        digest_optional(&mut hasher, self.external_operation_id.as_deref());
        finish(hasher)
    }
    /// Feeds the declared identity into `hasher`, list lengths included so no
    /// two different declarations can hash the same way.
    fn digest_into(&self, hasher: &mut Sha256) {
        for value in [
            &self.effect_id,
            &self.mission_id,
            &self.capability_id,
            &self.target_id,
            &self.canonical_request_digest,
            &self.effect_class,
            &self.risk_class,
        ] {
            digest_component(hasher, value);
        }
        self.idempotency.digest_into(hasher);
        for (label, conditions) in [
            ("preconditions", &self.preconditions),
            ("postconditions", &self.postconditions),
        ] {
            digest_component(hasher, label);
            digest_component(hasher, &conditions.len().to_string());
            for condition in conditions {
                condition.digest_into(hasher);
            }
        }
        self.reconciliation.digest_into(hasher);
        match &self.compensation {
            Some(compensation) => {
                digest_component(hasher, "some");
                compensation.digest_into(hasher);
            }
            None => digest_component(hasher, "none"),
        }
        digest_component(hasher, "dependencies");
        digest_component(hasher, &self.dependencies.len().to_string());
        for dependency in &self.dependencies {
            digest_component(hasher, dependency);
        }
    }
    /// The intent after applying one durable event.
    ///
    /// The only field an event may write, besides the state, is the external
    /// operation identity the target hands back at dispatch (EFX-002).
    ///
    /// # Errors
    ///
    /// [`ReduceError::EventNotAccepted`] when `spec/state-machines/effect.yaml`
    /// has no edge for this state and event.
    pub fn try_advance(&self, event: &EffectEvent) -> Result<Self, ReduceError> {
        let state = try_reduce(self.state, event)?;
        let mut next = self.clone();
        next.state = state;
        if let EffectEvent::Dispatched(payload) = event {
            next.external_operation_id = payload.external_operation_id.clone();
        }
        Ok(next)
    }
}
/// Accumulates an [`EffectIntent`] and refuses to produce an invalid one.
///
/// Every EFX-002 field is mandatory, and a field whose parts contradict each
/// other is rejected: a stored contradiction would be replayed as if true.
#[derive(Clone, Debug)]
pub struct EffectIntentBuilder {
    effect_id: String,
    mission_id: String,
    capability_id: String,
    target_id: String,
    canonical_request_digest: Option<String>,
    classes: Option<(String, String)>,
    idempotency: Option<Idempotency>,
    preconditions: Vec<Condition>,
    postconditions: Vec<Condition>,
    reconciliation: Option<Reconciliation>,
    compensation: Option<Compensation>,
    dependencies: Vec<String>,
}

impl EffectIntentBuilder {
    /// Sets the canonical request digest directly (`sha256:<64 hex>`).
    ///
    /// Prefer [`Self::canonical_request`] to compute it from the request body;
    /// use this only when the RFC 8785 digest was minted elsewhere.
    #[must_use]
    pub fn canonical_request_digest(mut self, canonical_request_digest: &str) -> Self {
        self.canonical_request_digest = Some(canonical_request_digest.to_owned());
        self
    }

    /// Computes and sets the canonical request digest from the request body,
    /// canonicalizing `request` under RFC 8785 (JCS) before hashing.
    ///
    /// # Errors
    ///
    /// [`CanonicalizationError`] if `request` carries a non-integer number.
    pub fn canonical_request(
        mut self,
        request: &serde_json::Value,
    ) -> Result<Self, CanonicalizationError> {
        self.canonical_request_digest = Some(crate::canonical::canonical_request_digest(request)?);
        Ok(self)
    }

    /// Sets the effect and risk classes.
    #[must_use]
    pub fn classes(mut self, effect_class: &str, risk_class: &str) -> Self {
        self.classes = Some((effect_class.to_owned(), risk_class.to_owned()));
        self
    }

    /// Sets the idempotency contract.
    #[must_use]
    pub fn idempotency(mut self, idempotency: Idempotency) -> Self {
        self.idempotency = Some(idempotency);
        self
    }
    /// Adds a precondition, keeping declaration order.
    #[must_use]
    pub fn precondition(mut self, condition: Condition) -> Self {
        self.preconditions.push(condition);
        self
    }

    /// Adds a postcondition, keeping declaration order.
    #[must_use]
    pub fn postcondition(mut self, condition: Condition) -> Self {
        self.postconditions.push(condition);
        self
    }

    /// Sets how an unknown outcome would be settled.
    #[must_use]
    pub fn reconciliation(mut self, reconciliation: Reconciliation) -> Self {
        self.reconciliation = Some(reconciliation);
        self
    }

    /// Sets how a landed effect would be undone.
    #[must_use]
    pub fn compensation(mut self, compensation: Compensation) -> Self {
        self.compensation = Some(compensation);
        self
    }

    /// Adds an effect this one waits for, keeping declaration order.
    #[must_use]
    pub fn dependency(mut self, effect_id: &str) -> Self {
        self.dependencies.push(effect_id.to_owned());
        self
    }
    /// Validates every EFX-002 field and produces the intent.
    ///
    /// The result always starts in `INTENT_DURABLE`: an intent that has just
    /// been written down has been authorised by nobody.
    ///
    /// # Errors
    ///
    /// [`IntentError`] naming the first field that is absent, blank,
    /// self-contradicting, or a broken dependency edge.
    pub fn build(self) -> Result<EffectIntent, IntentError> {
        for (value, field) in [
            (&self.effect_id, "effect_id"),
            (&self.mission_id, "mission_id"),
            (&self.capability_id, "capability_id"),
            (&self.target_id, "target_id"),
        ] {
            require_text(value, field)?;
        }

        let canonical_request_digest =
            self.canonical_request_digest
                .ok_or(IntentError::MissingField {
                    field: "canonical_request_digest",
                })?;
        require_canonical_digest(&canonical_request_digest)?;

        let (effect_class, risk_class) = self.classes.ok_or(IntentError::MissingField {
            field: "effect_class",
        })?;
        require_text(&effect_class, "effect_class")?;
        require_text(&risk_class, "risk_class")?;

        let idempotency = self.idempotency.ok_or(IntentError::MissingField {
            field: "idempotency",
        })?;
        idempotency.validate()?;

        let reconciliation = self.reconciliation.ok_or(IntentError::MissingField {
            field: "reconciliation",
        })?;
        reconciliation.validate()?;

        let compensation = self.compensation.ok_or(IntentError::MissingField {
            field: "compensation",
        })?;
        compensation.validate()?;
        for (kind, conditions) in [
            ("preconditions", &self.preconditions),
            ("postconditions", &self.postconditions),
        ] {
            for (index, condition) in conditions.iter().enumerate() {
                condition.validate(kind, index)?;
            }
        }

        {
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for (index, dependency) in self.dependencies.iter().enumerate() {
                if dependency.trim().is_empty() {
                    return Err(IntentError::EmptyField {
                        field: format!("dependencies[{index}]"),
                    });
                }
                if *dependency == self.effect_id {
                    return Err(IntentError::SelfDependency {
                        effect_id: dependency.clone(),
                    });
                }
                if !seen.insert(dependency.as_str()) {
                    return Err(IntentError::DuplicateDependency {
                        effect_id: dependency.clone(),
                    });
                }
            }
        }

        Ok(EffectIntent {
            effect_id: self.effect_id,
            mission_id: self.mission_id,
            capability_id: self.capability_id,
            target_id: self.target_id,
            canonical_request_digest,
            external_operation_id: None,
            effect_class,
            risk_class,
            idempotency,
            preconditions: self.preconditions,
            postconditions: self.postconditions,
            reconciliation,
            compensation: Some(compensation),
            dependencies: self.dependencies,
            state: EffectState::IntentDurable,
        })
    }
}
