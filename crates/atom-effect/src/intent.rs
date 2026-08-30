//! [`EffectIntent`]: the durable record that must exist before anything is
//! dispatched (EFX-001), carrying every field EFX-002 asks for.
//!
//! An intent authorises nothing by itself. It is the written-down request, its
//! declared semantics, and its position in the lifecycle — nothing more.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
    /// Digest of the canonical request body, so a mutated request is a new one.
    pub request_digest: String,
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
            request_digest: None,
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
            &self.request_digest,
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
    request_digest: Option<String>,
    classes: Option<(String, String)>,
    idempotency: Option<Idempotency>,
    preconditions: Vec<Condition>,
    postconditions: Vec<Condition>,
    reconciliation: Option<Reconciliation>,
    compensation: Option<Compensation>,
    dependencies: Vec<String>,
}

impl EffectIntentBuilder {
    /// Sets the digest of the canonical request body.
    #[must_use]
    pub fn request_digest(mut self, request_digest: &str) -> Self {
        self.request_digest = Some(request_digest.to_owned());
        self
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

        let request_digest = self.request_digest.ok_or(IntentError::MissingField {
            field: "request_digest",
        })?;
        require_text(&request_digest, "request_digest")?;

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
            request_digest,
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
