//! The declared semantics an [`crate::EffectIntent`] carries (EFX-002).
//!
//! Each value object validates itself, and a declaration that contradicts
//! itself is rejected rather than stored: a contradiction would otherwise be
//! replayed later as if it were true.

use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::digest::{digest_component, digest_optional};
use crate::intent::{require_text, IntentError};

/// A pre- or postcondition the effect asserts about its target.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// Stable identity, so a violation can be named in the ledger.
    pub condition_id: String,
    /// The assertion itself, in the target's own vocabulary.
    pub expression: String,
}

impl Condition {
    /// A condition named `condition_id` asserting `expression`.
    #[must_use]
    pub fn new(condition_id: &str, expression: &str) -> Self {
        Self {
            condition_id: condition_id.to_owned(),
            expression: expression.to_owned(),
        }
    }

    pub(crate) fn validate(&self, kind: &str, index: usize) -> Result<(), IntentError> {
        for (value, name) in [
            (&self.condition_id, "condition_id"),
            (&self.expression, "expression"),
        ] {
            if value.trim().is_empty() {
                return Err(IntentError::EmptyField {
                    field: format!("{kind}[{index}].{name}"),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn digest_into(&self, hasher: &mut Sha256) {
        digest_component(hasher, &self.condition_id);
        digest_component(hasher, &self.expression);
    }
}
/// How the target behaves when the same request arrives twice.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdempotencyMode {
    /// Applying the request twice is indistinguishable from applying it once.
    Natural,
    /// The target deduplicates on a caller-supplied key.
    Keyed,
    /// A repeat is a second, distinct effect on the world.
    NonIdempotent,
}

impl IdempotencyMode {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Natural => "NATURAL",
            Self::Keyed => "KEYED",
            Self::NonIdempotent => "NON_IDEMPOTENT",
        }
    }
}

/// The idempotency contract of the request (EFX-002).
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Idempotency {
    /// How a repeat is treated.
    pub mode: IdempotencyMode,
    /// The scope within which the key, or the natural identity, is unique.
    pub scope: String,
    /// The deduplication key, present exactly when `mode` is `KEYED`.
    pub key: Option<String>,
}
impl Idempotency {
    /// A request that is safe to repeat by construction.
    #[must_use]
    pub fn natural(scope: &str) -> Self {
        Self {
            mode: IdempotencyMode::Natural,
            scope: scope.to_owned(),
            key: None,
        }
    }

    /// A request the target deduplicates on `key`.
    #[must_use]
    pub fn keyed(scope: &str, key: &str) -> Self {
        Self {
            mode: IdempotencyMode::Keyed,
            scope: scope.to_owned(),
            key: Some(key.to_owned()),
        }
    }

    /// A request whose repeat would be a second effect.
    #[must_use]
    pub fn non_idempotent(scope: &str) -> Self {
        Self {
            mode: IdempotencyMode::NonIdempotent,
            scope: scope.to_owned(),
            key: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), IntentError> {
        require_text(&self.scope, "idempotency.scope")?;
        match (self.mode, &self.key) {
            (IdempotencyMode::Keyed, Some(key)) => require_text(key, "idempotency.key"),
            (IdempotencyMode::Keyed, None) => Err(IntentError::Inconsistent {
                field: "idempotency",
                reason: "a KEYED mode deduplicates on a key, so one is required",
            }),
            (_, Some(_)) => Err(IntentError::Inconsistent {
                field: "idempotency",
                reason: "only a KEYED mode carries a deduplication key",
            }),
            (_, None) => Ok(()),
        }
    }

    pub(crate) fn digest_into(&self, hasher: &mut Sha256) {
        digest_component(hasher, self.mode.as_str());
        digest_component(hasher, &self.scope);
        digest_optional(hasher, self.key.as_deref());
    }
}
/// What a caller is allowed to do after a failure, from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryClass {
    /// Never retry: a repeat would be a second effect.
    Never,
    /// A transient fault; the same request may be sent again.
    Transient,
    /// The target asked for a slower caller.
    RateLimited,
    /// Another provider may serve the same request.
    ProviderFailoverAllowed,
    /// Observe again before deciding anything.
    ReobserveThenRetry,
    /// Authority must be re-established first.
    ReauthorizeThenRetry,
    /// The outcome must be reconciled before any retry (INV-002).
    ReconcileBeforeRetry,
}

impl RetryClass {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "NEVER",
            Self::Transient => "TRANSIENT",
            Self::RateLimited => "RATE_LIMITED",
            Self::ProviderFailoverAllowed => "PROVIDER_FAILOVER_ALLOWED",
            Self::ReobserveThenRetry => "REOBSERVE_THEN_RETRY",
            Self::ReauthorizeThenRetry => "REAUTHORIZE_THEN_RETRY",
            Self::ReconcileBeforeRetry => "RECONCILE_BEFORE_RETRY",
        }
    }
}
/// How an ambiguous outcome is to be settled, without writing again (EFX-003).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationClass {
    /// Ask the target about the operation it named at dispatch.
    ExternalOperationLookup,
    /// Read the resource back and compare it with the postconditions.
    ResourceStateRead,
    /// Replay our own ledger: the answer is already written down.
    LedgerReplay,
    /// Nothing can settle it; the ambiguity is permanent.
    NotReconcilable,
}

impl ReconciliationClass {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalOperationLookup => "EXTERNAL_OPERATION_LOOKUP",
            Self::ResourceStateRead => "RESOURCE_STATE_READ",
            Self::LedgerReplay => "LEDGER_REPLAY",
            Self::NotReconcilable => "NOT_RECONCILABLE",
        }
    }

    /// Whether this class needs a probe to name what it would read.
    const fn needs_probe(self) -> bool {
        matches!(self, Self::ExternalOperationLookup | Self::ResourceStateRead)
    }
}

/// The declared plan for resolving an unknown outcome (EFX-002).
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    /// How the outcome would be settled.
    pub class: ReconciliationClass,
    /// What the caller may do once it is settled.
    pub retry_class: RetryClass,
    /// The read the probe performs, required by the lookup classes.
    pub probe: Option<String>,
}
impl Reconciliation {
    /// A reconciliation plan of `class`, retryable per `retry_class`.
    #[must_use]
    pub fn new(class: ReconciliationClass, retry_class: RetryClass) -> Self {
        Self {
            class,
            retry_class,
            probe: None,
        }
    }

    /// The same plan, naming the read the probe performs.
    #[must_use]
    pub fn with_probe(mut self, probe: &str) -> Self {
        self.probe = Some(probe.to_owned());
        self
    }

    pub(crate) fn validate(&self) -> Result<(), IntentError> {
        match (self.class.needs_probe(), &self.probe) {
            (true, Some(probe)) => require_text(probe, "reconciliation.probe"),
            (true, None) => Err(IntentError::Inconsistent {
                field: "reconciliation",
                reason: "this class reconciles by reading, so it needs a probe",
            }),
            (false, Some(_)) => Err(IntentError::Inconsistent {
                field: "reconciliation",
                reason: "this class has nothing to probe",
            }),
            (false, None) => Ok(()),
        }
    }

    pub(crate) fn digest_into(&self, hasher: &mut Sha256) {
        digest_component(hasher, self.class.as_str());
        digest_component(hasher, self.retry_class.as_str());
        digest_optional(hasher, self.probe.as_deref());
    }
}
/// How a landed effect would be undone.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompensationStrategy {
    /// A single inverse call undoes it.
    InverseOperation,
    /// A separate transaction restores the invariant.
    CompensatingTransaction,
    /// Nothing can undo it; a partial landing is permanent.
    NotCompensable,
}

impl CompensationStrategy {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InverseOperation => "INVERSE_OPERATION",
            Self::CompensatingTransaction => "COMPENSATING_TRANSACTION",
            Self::NotCompensable => "NOT_COMPENSABLE",
        }
    }

    /// Whether this strategy must name the action it would perform.
    const fn needs_operation(self) -> bool {
        !matches!(self, Self::NotCompensable)
    }
}

/// The declared compensation semantics of the effect (EFX-002).
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compensation {
    /// How the effect would be undone.
    pub strategy: CompensationStrategy,
    /// The undo action itself, required by every strategy that has one.
    pub operation: Option<String>,
}
impl Compensation {
    /// A compensation plan following `strategy`.
    #[must_use]
    pub fn new(strategy: CompensationStrategy) -> Self {
        Self {
            strategy,
            operation: None,
        }
    }

    /// The same plan, naming the undo action.
    #[must_use]
    pub fn with_operation(mut self, operation: &str) -> Self {
        self.operation = Some(operation.to_owned());
        self
    }

    pub(crate) fn validate(&self) -> Result<(), IntentError> {
        match (self.strategy.needs_operation(), &self.operation) {
            (true, Some(operation)) => require_text(operation, "compensation.operation"),
            (true, None) => Err(IntentError::Inconsistent {
                field: "compensation",
                reason: "this strategy undoes the effect by acting, so it needs an operation",
            }),
            (false, Some(_)) => Err(IntentError::Inconsistent {
                field: "compensation",
                reason: "an uncompensable effect has no undo to perform",
            }),
            (false, None) => Ok(()),
        }
    }

    pub(crate) fn digest_into(&self, hasher: &mut Sha256) {
        digest_component(hasher, self.strategy.as_str());
        digest_optional(hasher, self.operation.as_deref());
    }
}
