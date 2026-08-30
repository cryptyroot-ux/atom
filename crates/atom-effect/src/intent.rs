//! [`EffectIntent`]: the durable record that must exist before anything is
//! dispatched (EFX-001), carrying every field EFX-002 asks for.
//!
//! An intent authorises nothing by itself. It is the written-down request, its
//! declared semantics, and its position in the lifecycle — nothing more.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::digest::{digest_component, finish};
use crate::event::EffectEvent;
use crate::reducer::{try_reduce, ReduceError};
use crate::semantics::{
    Compensation, CompensationStrategy, Condition, Idempotency, IdempotencyMode, Reconciliation,
    ReconciliationClass,
};
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
// INTENT-CONTINUES-HERE

impl EffectIntent {
    /// Canonical digest over stable identity + semantics. A mutated request is a
    /// new effect, so `request_digest`, `target_id` and `capability_id` are in.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_component(&mut hasher, &self.effect_id);
        digest_component(&mut hasher, &self.mission_id);
        digest_component(&mut hasher, &self.capability_id);
        digest_component(&mut hasher, &self.target_id);
        digest_component(&mut hasher, &self.request_digest);
        digest_component(&mut hasher, &self.effect_class);
        digest_component(&mut hasher, &self.risk_class);
        for dep in &self.dependencies {
            digest_component(&mut hasher, dep);
        }
        finish(hasher)
    }

    /// Apply `event` via the pure reducer, returning a new intent in the next
    /// state. Refusals (anything not in `spec/state-machines/effect.yaml`) are
    /// surfaced as an error rather than silently ignored. Durable event payloads
    /// (e.g. the external operation id discovered at dispatch) are recorded.
    #[must_use]
    pub fn try_advance(&self, event: &EffectEvent) -> Result<EffectIntent, ReduceError> {
        let next = try_reduce(self.state, event)?;
        let mut advanced = self.clone();
        advanced.state = next;
        // Record the external operation identity when the target returns one.
        if let EffectEvent::Dispatched(payload) = event {
            advanced.external_operation_id = payload.external_operation_id.clone();
        }
        Ok(advanced)
    }

    /// Start building an intent. `EffectIntentBuilder` enforces every EFX-002
    /// mandatory field and rejects self-contradicting semantics.
    #[must_use]
    pub fn builder(
        effect_id: &str,
        mission_id: &str,
        capability_id: &str,
        target_id: &str,
    ) -> EffectIntentBuilder {
        EffectIntentBuilder::new(effect_id, mission_id, capability_id, target_id)
    }

    /// Digest over the current state only — distinct from [`Self::digest`],
    /// which is identity-stable. Used by tests to assert each state digests
    /// differently.
    #[must_use]
    pub fn state_digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_component(&mut hasher, &self.effect_id);
        digest_component(&mut hasher, self.state.as_str());
        finish(hasher)
    }
}

/// A fluent builder that refuses to produce an [`EffectIntent`] missing any
/// EFX-002 field or carrying self-contradicting semantics.
#[derive(Clone, Debug)]
pub struct EffectIntentBuilder {
    effect_id: String,
    mission_id: String,
    capability_id: String,
    target_id: String,
    request_digest: Option<String>,
    effect_class: Option<String>,
    risk_class: Option<String>,
    idempotency: Option<Idempotency>,
    preconditions: Vec<Condition>,
    postconditions: Vec<Condition>,
    reconciliation: Option<Reconciliation>,
    compensation: Option<Compensation>,
    dependencies: Vec<String>,
}

impl EffectIntentBuilder {
    /// Create a builder for the given durable identity.
    #[must_use]
    pub fn new(
        effect_id: &str,
        mission_id: &str,
        capability_id: &str,
        target_id: &str,
    ) -> Self {
        Self {
            effect_id: effect_id.to_owned(),
            mission_id: mission_id.to_owned(),
            capability_id: capability_id.to_owned(),
            target_id: target_id.to_owned(),
            request_digest: None,
            effect_class: None,
            risk_class: None,
            idempotency: None,
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            reconciliation: None,
            compensation: None,
            dependencies: Vec::new(),
        }
    }

    /// Set `request_digest`.
    pub fn request_digest(mut self, value: &str) -> Self {
        self.request_digest = Some(value.to_owned());
        self
    }

    /// Set effect and risk classes.
    pub fn classes(mut self, effect_class: &str, risk_class: &str) -> Self {
        self.effect_class = Some(effect_class.to_owned());
        self.risk_class = Some(risk_class.to_owned());
        self
    }

    /// Set idempotency semantics.
    pub fn idempotency(mut self, value: Idempotency) -> Self {
        self.idempotency = Some(value);
        self
    }

    /// Set reconciliation semantics.
    pub fn reconciliation(mut self, value: Reconciliation) -> Self {
        self.reconciliation = Some(value);
        self
    }

    /// Set compensation semantics.
    pub fn compensation(mut self, value: Compensation) -> Self {
        self.compensation = Some(value);
        self
    }

    /// Add a dependency edge (EFX-003).
    pub fn dependency(mut self, effect_id: &str) -> Self {
        self.dependencies.push(effect_id.to_owned());
        self
    }

    /// Add a precondition edge (EFX-002).
    pub fn precondition(mut self, condition: Condition) -> Self {
        self.preconditions.push(condition);
        self
    }

    /// Add a postcondition edge (EFX-002).
    pub fn postcondition(mut self, condition: Condition) -> Self {
        self.postconditions.push(condition);
        self
    }

    /// Build, enforcing every EFX-002 requirement.
    pub fn build(self) -> Result<EffectIntent, IntentError> {
        require_text(&self.effect_id, "effect_id")?;
        require_text(&self.mission_id, "mission_id")?;
        require_text(&self.capability_id, "capability_id")?;
        require_text(&self.target_id, "target_id")?;

        let request_digest = self
            .request_digest
            .ok_or(IntentError::MissingField { field: "request_digest" })?;
        require_text(&request_digest, "request_digest")?;

        let effect_class = self
            .effect_class
            .ok_or(IntentError::MissingField { field: "effect_class" })?;
        require_text(&effect_class, "effect_class")?;

        let risk_class = self
            .risk_class
            .ok_or(IntentError::MissingField { field: "risk_class" })?;
        require_text(&risk_class, "risk_class")?;

        let idempotency = self
            .idempotency
            .ok_or(IntentError::MissingField { field: "idempotency" })?;
        if idempotency.mode == IdempotencyMode::Keyed && idempotency.key.is_none() {
            return Err(IntentError::Inconsistent {
                field: "idempotency",
                reason: "keyed scope requires a key",
            });
        }
        if idempotency.mode == IdempotencyMode::Natural && idempotency.key.is_some() {
            return Err(IntentError::Inconsistent {
                field: "idempotency",
                reason: "natural scope carries no key",
            });
        }

        let reconciliation = self
            .reconciliation
            .ok_or(IntentError::MissingField {
                field: "reconciliation",
            })?;
        if reconciliation.class == ReconciliationClass::ExternalOperationLookup
            && reconciliation.probe.is_none()
        {
            return Err(IntentError::Inconsistent {
                field: "reconciliation",
                reason: "external lookup requires a probe",
            });
        }
        if reconciliation.class == ReconciliationClass::NotReconcilable
            && reconciliation.probe.is_some()
        {
            return Err(IntentError::Inconsistent {
                field: "reconciliation",
                reason: "unreconcilable effects carry no probe",
            });
        }

        let compensation = self
            .compensation
            .ok_or(IntentError::MissingField { field: "compensation" })?;
        if compensation.strategy == CompensationStrategy::InverseOperation
            && compensation.operation.is_none()
        {
            return Err(IntentError::Inconsistent {
                field: "compensation",
                reason: "inverse operation requires an operation",
            });
        }
        if compensation.strategy == CompensationStrategy::NotCompensable
            && compensation.operation.is_some()
        {
            return Err(IntentError::Inconsistent {
                field: "compensation",
                reason: "not-compensable effects carry no operation",
            });
        }

        // Conditions must carry a non-blank id and expression.
        for (i, cond) in self.preconditions.iter().enumerate() {
            cond.validate("preconditions", i)?;
        }
        for (i, cond) in self.postconditions.iter().enumerate() {
            cond.validate("postconditions", i)?;
        }

        // Dependency edges: no blank, no self-dependency, no duplicates.
        let mut seen = std::collections::HashSet::new();
        for dep in &self.dependencies {
            require_text(dep, "dependencies[...]")?;
            if dep == &self.effect_id {
                return Err(IntentError::SelfDependency {
                    effect_id: dep.clone(),
                });
            }
            if !seen.insert(dep.clone()) {
                return Err(IntentError::DuplicateDependency {
                    effect_id: dep.clone(),
                });
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

