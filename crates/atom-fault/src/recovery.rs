//! The recovery mapping: [`FaultClass`] -> [`RetryClass`] and the mission-level
//! [`RecoveryDirective`] that wraps it.
//!
//! [`RetryClass`] is `atom-effect`'s enum, reused verbatim (it is the
//! authoritative `spec/enums.yaml` `retry_class`). This crate does **not**
//! redefine it. `replan` and `stop` are mission-level actions, not retry
//! classes, so they are added only by [`RecoveryDirective`].

use atom_effect::RetryClass;

use crate::class::FaultClass;

/// The "plain retry" classes: recovery that re-sends the request with no
/// interposed step.
///
/// This is the set ATOM-INV-002 forbids for an ambiguous effect: an
/// `UNKNOWN_OUTCOME` must never be resolved by any of these. Everything else
/// (`Never`, `ReobserveThenRetry`, `ReauthorizeThenRetry`,
/// `ReconcileBeforeRetry`) interposes a step or refuses outright.
#[must_use]
pub fn is_plain_retry(retry_class: RetryClass) -> bool {
    matches!(
        retry_class,
        RetryClass::Transient | RetryClass::RateLimited | RetryClass::ProviderFailoverAllowed
    )
}

/// Map a [`FaultClass`] to the recovery [`RetryClass`] it warrants.
///
/// Total and pure. Every binding is grounded below in one line, citing the
/// recovery taxonomy of the ATOM Technical Blueprint v3.1 (SRC-ATOM-BP31), the
/// Architecture Decision Pack v0.1 (SRC-ADR01), the machine enum
/// `spec/enums.yaml` `retry_class`, and the invariants of
/// `spec/invariants.yaml`.
///
/// Non-negotiable bindings (from the task boundary and ATOM-INV-002):
/// `EFFECT_UNKNOWN -> ReconcileBeforeRetry`, `STALE_EVIDENCE ->
/// ReobserveThenRetry`, `AUTHORITY_DRIFT -> ReauthorizeThenRetry`,
/// `POLICY_DENIAL -> Never`, `PROVIDER_TRANSIENT -> Transient`, `RATE_LIMIT ->
/// RateLimited`, `CONNECTOR_FAILURE -> ProviderFailoverAllowed`.
#[must_use]
pub fn recovery_for(class: FaultClass) -> RetryClass {
    match class {
        // ATOM-INV-002: an ambiguous outcome is never safe-to-retry; it must be
        // reconciled first. This is the whole point of the crate.
        FaultClass::EffectUnknown => RetryClass::ReconcileBeforeRetry,

        // Task binding + FLT-001 "reobserve": the action ran on stale facts, so
        // renew the observation before proceeding, never resend blindly.
        FaultClass::StaleEvidence => RetryClass::ReobserveThenRetry,

        // Task binding + FLT-001 "reauthorize" + INV-018: a stale/drifted grant
        // generation cannot commit, so re-establish authority before retrying.
        FaultClass::AuthorityDrift => RetryClass::ReauthorizeThenRetry,

        // Task binding + INV-019 (policy is a separate, supreme gate) + INV-012
        // (no pressure raises authority): a denied action is not retryable.
        FaultClass::PolicyDenial => RetryClass::Never,

        // Task binding: a transient provider/transport fault clears on resend.
        FaultClass::ProviderTransient => RetryClass::Transient,

        // Task binding: honor the provider's explicit back-pressure signal.
        FaultClass::RateLimit => RetryClass::RateLimited,

        // Task binding (BP failover taxonomy): a peer may serve the same
        // request. The class asserts failover is the recovery mode; whether a
        // concrete peer exists is a downstream dispatch concern.
        FaultClass::ConnectorFailure => RetryClass::ProviderFailoverAllowed,

        // Derived — BP fault taxonomy: a schema/contract violation is
        // deterministic for the same request, so an identical resend reproduces
        // it. Not retryable at this layer; a corrected call is a new plan.
        FaultClass::ToolContractError => RetryClass::Never,

        // Derived — INV-012 + ADR-015 (capability substrate): a missing grant
        // cannot be conjured by resending under pressure, so retry is futile.
        FaultClass::CapabilityMissing => RetryClass::Never,

        // Derived — BP fault taxonomy: an isolated contention/lock clash (with
        // no ambiguous effect, which would classify as EFFECT_UNKNOWN first)
        // clears on a bounded backoff-and-retry.
        FaultClass::ResourceConflict => RetryClass::Transient,

        // Derived — BP recovery taxonomy + INV-015: the cached world-model is
        // stale, so re-observe the environment before proceeding (mirrors the
        // reobserve semantics of STALE_EVIDENCE).
        FaultClass::EnvironmentDrift => RetryClass::ReobserveThenRetry,

        // Derived — INV-001 (cognition cannot mutate authoritative state): a
        // mis-planned step re-run repeats the mistake. It is not retryable; the
        // mission-level directive is Replan (see `directive_for`).
        FaultClass::SemanticMisplan => RetryClass::Never,

        // Derived — verifier_level taxonomy + INV-017 (separated evaluation
        // evidence): disagreement is resolved by gathering stronger, more
        // independent observation, not by resending the effect.
        FaultClass::VerifierDisagreement => RetryClass::ReobserveThenRetry,

        // Derived — BP sandbox/isolation taxonomy: a sandbox provisioning/run
        // failure is infrastructure, independent of the request; a fresh
        // sandbox on retry typically succeeds.
        FaultClass::SandboxFailure => RetryClass::Transient,
    }
}

/// A mission-level recovery action: a [`RetryClass`], or an action that retry
/// cannot express.
///
/// The machine retry vocabulary ([`RetryClass`], `spec/enums.yaml`
/// `retry_class`) has no `replan` or `stop`: those are mission-level, per the
/// task boundary. This enum keeps [`RetryClass`] as the single source of retry
/// truth and layers the two mission actions on top, only for the classes retry
/// cannot help.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecoveryDirective {
    /// Recover by retrying per the wrapped [`RetryClass`].
    Retry(RetryClass),
    /// The plan itself is wrong; discard it and plan anew (`SEMANTIC_MISPLAN`).
    Replan,
    /// Unrecoverable at this level; halt and escalate (`POLICY_DENIAL`).
    Stop,
}

/// Map a [`FaultClass`] to its mission-level [`RecoveryDirective`].
///
/// Only the two classes retry cannot help get a mission action, exactly as the
/// task boundary fixes it:
///
/// * `SEMANTIC_MISPLAN -> Replan` — the approach was wrong (INV-001); make a
///   new plan rather than re-run the same step.
/// * `POLICY_DENIAL -> Stop` — policy forbids the action; replanning to route
///   around a denial would violate INV-012/INV-016, so the mission halts and
///   escalates instead.
///
/// Every other class carries its [`recovery_for`] retry class unchanged.
#[must_use]
pub fn directive_for(class: FaultClass) -> RecoveryDirective {
    match class {
        FaultClass::SemanticMisplan => RecoveryDirective::Replan,
        FaultClass::PolicyDenial => RecoveryDirective::Stop,
        other => RecoveryDirective::Retry(recovery_for(other)),
    }
}
