//! [`classify`]: the pure, total, deterministic fault classifier.

use crate::class::FaultClass;
use crate::signal::{
    AuthorityStatus, CapabilityStatus, ConnectorStatus, EnvironmentStatus, EvidenceStatus,
    FaultSignal, PlanStatus, PolicyDecision, ResourceStatus, SandboxStatus, ToolStatus,
    TransportStatus, VerifierStatus,
};

/// Classify a [`FaultSignal`] into exactly one [`FaultClass`].
///
/// Pure, total, deterministic: no clock, no I/O, no interior mutability. The
/// same signal always yields the same class, and every possible signal yields
/// one.
///
/// # The priority ladder
///
/// A single failure can trip several facets at once, so classification is a
/// fixed priority ladder, ordered **most safety-constraining first**. The first
/// rung that matches wins; this ordering is what makes the result well-defined
/// and is itself the classifier's policy:
///
/// 1. **`EFFECT_UNKNOWN`** — the effect outcome is ambiguous
///    ([`EffectState::UnknownOutcome`]/[`EffectState::Reconciling`]). ATOM-INV-002
///    makes this absolute: it dominates *every* other facet, so an ambiguous
///    effect is never coerced to safe-to-retry (and, via INV-013, never
///    abandoned) whatever else is true.
/// 2. **`POLICY_DENIAL`** — policy denied the action. An authoritative refusal
///    outranks every operational fault; no reauth/reobserve/retry may override
///    a denial (INV-019, INV-012).
/// 3. **`AUTHORITY_DRIFT`** — the grant drifted. A stale grant cannot commit
///    (INV-018), so authority is re-established before anything operational.
/// 4. **`CAPABILITY_MISSING`** — a required capability is absent: structural,
///    and not conjurable under pressure (INV-012).
/// 5. **`SEMANTIC_MISPLAN`** — the plan step is wrong; its low-level errors are
///    symptoms, so fix the plan before trusting them.
/// 6. **`TOOL_CONTRACT_ERROR`** — a hard, attributable contract violation at the
///    tool boundary.
/// 7. **`STALE_EVIDENCE`** — the action ran on a stale observation; a direct,
///    measurable freshness fact.
/// 8. **`VERIFIER_DISAGREEMENT`** — verifiers split on the (settled) outcome.
/// 9. **`ENVIRONMENT_DRIFT`** — the world/topology changed under the plan.
/// 10. **`RESOURCE_CONFLICT`** — a resource is contended or locked.
/// 11. **`SANDBOX_FAILURE`** — the local execution sandbox failed.
/// 12. **`CONNECTOR_FAILURE`** — an external connector failed.
/// 13. **`RATE_LIMIT`** — the provider asked for a slower caller (specific
///     back-pressure outranks a generic transient error).
/// 14. **`PROVIDER_TRANSIENT`** — a generic transient transport error.
/// 15. **fail-safe** — a reported fault that matches no facet is classified as
///     `EFFECT_UNKNOWN`, so an unexplained fault is never assumed safe-to-retry
///     (ATOM-INV-002 as the default posture).
#[must_use]
pub fn classify(signal: FaultSignal) -> FaultClass {
    // 1. ATOM-INV-002 — ambiguity dominates everything.
    if signal.is_effect_ambiguous() {
        return FaultClass::EffectUnknown;
    }

    // A settled effect state (e.g. CONFIRMED_FAILURE) is not itself a fault
    // kind: only ambiguity, handled above, is decided by the effect state. Any
    // genuine failure is attributed by the operational facets below.

    // 2. Policy denial: authoritative refusal outranks operational faults.
    if signal.policy == PolicyDecision::Denied {
        return FaultClass::PolicyDenial;
    }

    // 3. Authority drift: a stale grant cannot commit (INV-018).
    if signal.authority == AuthorityStatus::Drifted {
        return FaultClass::AuthorityDrift;
    }

    // 4. Missing capability: structural, not conjurable under pressure.
    if signal.capability == CapabilityStatus::Missing {
        return FaultClass::CapabilityMissing;
    }

    // 5. Semantic misplan: fix the plan before trusting its symptoms.
    if signal.plan == PlanStatus::Misplanned {
        return FaultClass::SemanticMisplan;
    }

    // 6. Tool contract error: a hard, attributable boundary violation.
    if signal.tool == ToolStatus::ContractError {
        return FaultClass::ToolContractError;
    }

    // 7. Stale evidence: a direct freshness fact.
    if signal.evidence == EvidenceStatus::Stale {
        return FaultClass::StaleEvidence;
    }

    // 8. Verifier disagreement about a settled outcome.
    if signal.verifier == VerifierStatus::Disagreement {
        return FaultClass::VerifierDisagreement;
    }

    // 9. Environment drift.
    if signal.environment == EnvironmentStatus::Drifted {
        return FaultClass::EnvironmentDrift;
    }

    // 10. Resource contention.
    if signal.resource == ResourceStatus::Conflict {
        return FaultClass::ResourceConflict;
    }

    // 11. Sandbox failure (local infrastructure).
    if signal.sandbox == SandboxStatus::Failed {
        return FaultClass::SandboxFailure;
    }

    // 12. Connector failure (external).
    if signal.connector == ConnectorStatus::Failed {
        return FaultClass::ConnectorFailure;
    }

    // 13. + 14. Transport: specific back-pressure before generic transient.
    match signal.transport {
        TransportStatus::RateLimited => return FaultClass::RateLimit,
        TransportStatus::Transient => return FaultClass::ProviderTransient,
        TransportStatus::Ok => {}
    }

    // 15. Fail-safe: an unexplained fault is never assumed safe-to-retry.
    FaultClass::EffectUnknown
}
