//! Commit boundary: `CommitPermit`, `issue_commit_permit`, one-shot consumption.
//!
//! Implements EFX-004: a short-lived, one-shot permit bound to the effect
//! digest, resource witness, principal and grant generation. The permit is the
//! only thing that opens the dispatch window, and the `NonceRegistry` ensures it
//! can be consumed exactly once.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::event::CommitPermitted;
use crate::intent::{EffectIntent, IntentError};
use crate::state::EffectState;

/// Hard upper bound on a commit permit's lifetime, per EFX-004.
pub const MAX_PERMIT_TTL_SECONDS: u32 = 300;

/// Proof that `EffectIntent` was persisted into the authoritative ledger before
/// any dispatch was attempted (EFX-001). Fields: effect identity, sequence at
/// which it was written, and the ledger hash that seals the stream head.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DurabilityWitness {
    /// The effect whose durability is being attested.
    pub effect_id: String,
    /// The ledger sequence at which the intent was sealed.
    pub sequence: u64,
    /// The hash of the sealed ledger head at that sequence.
    pub ledger_hash: String,
}

impl DurabilityWitness {
    /// Build a witness. Empty `effect_id` / `ledger_hash` or zero `sequence`
    /// are rejected by `issue_commit_permit` as "not durable".
    #[must_use]
    pub fn new(effect_id: &str, sequence: u64, ledger_hash: &str) -> Self {
        Self {
            effect_id: effect_id.to_owned(),
            sequence,
            ledger_hash: ledger_hash.to_owned(),
        }
    }

    /// True only when every field is present and non-empty.
    fn is_meaningful(&self) -> bool {
        !self.effect_id.trim().is_empty()
            && self.sequence > 0
            && !self.ledger_hash.trim().is_empty()
    }
}

/// A claim about the resource's state at a point in time, used to detect drift.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceWitness {
    /// The resource type (e.g. "db", "server").
    pub resource_type: String,
    /// The resource id.
    pub resource_id: String,
    /// A version/etag/git-sha/hash snapshot of the resource state.
    pub version: String,
}

impl ResourceWitness {
    /// Build a witness for `resource_type`/`resource_id` at `version`.
    #[must_use]
    pub fn new(resource_type: &str, resource_id: &str, version: &str) -> Self {
        Self {
            resource_type: resource_type.to_owned(),
            resource_id: resource_id.to_owned(),
            version: version.to_owned(),
        }
    }
}

/// Why `issue_commit_permit` refused.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PermitError {
    /// The grant's `revocation_state` is not Active.
    #[error("grant is not active: {state:?}")]
    GrantNotActive { state: String },

    /// The grant's generation no longer matches what the plan pinned.
    #[error("grant generation drift: planned {planned}, observed {observed}")]
    GrantGenerationDrift { planned: u64, observed: u64 },

    /// The observed resource witness differs from the planned one (TOCTOU).
    #[error("resource witness drift")]
    ResourceWitnessDrift {},

    /// `now` falls outside the grant's validity window.
    #[error("grant outside validity window")]
    GrantOutsideValidity {},

    /// The grant does not grant `operation` on `resource_type`.
    #[error("operation not granted: {operation}")]
    OperationNotGranted { operation: String },

    /// The grant does not cover `resource_type`.
    #[error("resource not granted: {resource_type}")]
    ResourceNotGranted { resource_type: String },

    /// The permit principal does not match the grant subject.
    #[error("principal mismatch")]
    PrincipalMismatch {},

    /// EFX-001: the intent was never made durable.
    #[error("effect not durable")]
    EffectNotDurable {},

    /// The effect is not in `COMMIT_REVALIDATING` (EFX-004 timing).
    #[error("effect not revalidating")]
    EffectNotRevalidating {},

    /// The requested TTL is 0 or above [`MAX_PERMIT_TTL_SECONDS`].
    #[error("TTL out of range")]
    TtlOutOfRange {},
    /// The one-shot nonce was already consumed.
    #[error("nonce already used")]
    NonceAlreadyUsed {},
    /// The permit's expiry is in the past at consume time.
    #[error("permit expired")]
    PermitExpired {},
    /// The permit is not yet valid at consume time.
    #[error("permit not yet valid")]
    PermitNotYetValid {},
    /// The effect digest on the permit no longer matches the intent.
    #[error("digest mismatch")]
    DigestMismatch {},
}

/// A request to the commit boundary to mint a one-shot permit.
#[derive(Clone, Debug)]
pub struct PermitRequest<'a> {
    /// The plan being revalidated.
    pub intent: &'a EffectIntent,
    /// The current grant as seen by the kernel.
    pub grant: &'a atom_capability::CapabilityGrant,
    /// The principal requesting dispatch.
    pub principal_id: &'a str,
    /// The operation being performed (e.g. "read", "write").
    pub operation: &'a str,
    /// The resource type being targeted.
    pub resource_type: &'a str,
    /// The grant generation the plan was pinned against.
    pub planned_grant_generation: u64,
    /// The planned resource witness (from planning time).
    pub planned_witness: &'a ResourceWitness,
    /// The observed resource witness (from revalidation time).
    pub observed_witness: &'a ResourceWitness,
    /// Durability attestation for EFX-001.
    pub durability: &'a DurabilityWitness,
    /// Caller-chosen permit id (one-shot, never reused).
    pub permit_id: &'a str,
    /// Caller-chosen one-shot nonce.
    pub one_shot_nonce: &'a str,
    /// Requested TTL in seconds (bounded by [`MAX_PERMIT_TTL_SECONDS`]).
    pub ttl_seconds: u32,
    /// The instant of revalidation.
    pub now: DateTime<Utc>,
    /// Optional approval binding (AUT-003).
    pub approval_id: Option<&'a str>,
    /// Optional evidence-freshness digest.
    pub evidence_freshness_digest: Option<&'a str>,
}

/// A short-lived, one-shot dispatch authorization (EFX-004).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CommitPermit {
    pub permit_id: String,
    pub effect_digest: String,
    pub principal_id: String,
    pub capability_grant_id: String,
    pub grant_generation: u64,
    pub resource_id: String,
    pub resource_version_witness: ResourceWitness,
    pub approval_id: Option<String>,
    pub evidence_freshness_digest: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub one_shot_nonce: String,
}

impl CommitPermit {
    /// The TTL in seconds between issue and expiry.
    #[must_use]
    pub fn ttl_seconds(&self) -> i64 {
        (self.expires_at - self.issued_at).num_seconds()
    }

    /// True while `instant` is within `[issued_at, expires_at]`.
    #[must_use]
    pub fn is_valid_at(&self, instant: DateTime<Utc>) -> bool {
        instant >= self.issued_at && instant <= self.expires_at
    }
}

/// A request to consume a permit exactly once.
#[derive(Clone, Debug)]
pub struct ConsumeRequest<'a> {
    pub permit: &'a CommitPermit,
    pub intent: &'a EffectIntent,
    pub grant: &'a atom_capability::CapabilityGrant,
    pub observed_witness: &'a ResourceWitness,
    pub now: DateTime<Utc>,
}

/// A registry that burns a one-shot nonce on first use.
#[derive(Clone, Debug, Default)]
pub struct NonceRegistry {
    burned: std::collections::HashSet<String>,
}

impl NonceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the permit's nonce. Returns `CommitPermitted` on first use; on
    /// any reuse or expired permit, returns `Err` and the permit stays unused.
    pub fn consume(&mut self, req: ConsumeRequest<'_>) -> Result<CommitPermitted, PermitError> {
        // EFX-004: the permit is only valid inside its own TTL window.
        if req.now < req.permit.issued_at {
            return Err(PermitError::PermitNotYetValid {});
        }
        if !req.permit.is_valid_at(req.now) {
            return Err(PermitError::PermitExpired {});
        }

        // One-shot: a reused nonce is rejected.
        if self.burned.contains(&req.permit.one_shot_nonce) {
            return Err(PermitError::NonceAlreadyUsed {});
        }

        // The permit is bound to one effect identity; a different intent cannot
        // present it (EFX-004).
        if req.permit.effect_digest != req.intent.digest() {
            return Err(PermitError::DigestMismatch {});
        }

        // The effect must still be at the commit boundary — once it has left
        // COMMIT_REVALIDATING, the permit is spent or stale.
        if req.intent.state != EffectState::CommitRevalidating {
            return Err(PermitError::EffectNotRevalidating {});
        }

        // Authority may not have escalated between issuance and consumption.
        if !matches!(
            req.grant.revocation_state,
            atom_capability::RevocationState::Active
        ) {
            return Err(PermitError::GrantNotActive {
                state: format!("{:?}", req.grant.revocation_state),
            });
        }

        // The grant generation pinned at issuance must still be current: a
        // re-issue (generation bump) invalidates the permit (VT-003).
        if req.grant.generation != req.permit.grant_generation {
            return Err(PermitError::GrantGenerationDrift {
                planned: req.permit.grant_generation,
                observed: req.grant.generation,
            });
        }

        // Witness must still match at consume time.
        if req.observed_witness.resource_type != req.permit.resource_version_witness.resource_type
            || req.observed_witness.resource_id != req.permit.resource_version_witness.resource_id
            || req.observed_witness.version != req.permit.resource_version_witness.version
        {
            return Err(PermitError::ResourceWitnessDrift {});
        }

        self.burned.insert(req.permit.one_shot_nonce.to_owned());
        Ok(CommitPermitted {
            permit_id: req.permit.permit_id.clone(),
            one_shot_nonce: req.permit.one_shot_nonce.clone(),
            effect_digest: req.permit.effect_digest.clone(),
        })
    }

    /// True if `nonce` has already been consumed.
    #[must_use]
    pub fn is_used(&self, nonce: &str) -> bool {
        self.burned.contains(nonce)
    }

    /// Number of consumed nonces (for assertions in tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.burned.len()
    }

    /// True when no nonce has been consumed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.burned.is_empty()
    }
}

/// The commit boundary. Mint a one-shot permit after revalidating authority,
/// durability and resource state (EFX-001 + EFX-004).
pub fn issue_commit_permit(req: PermitRequest<'_>) -> Result<CommitPermit, PermitError> {
    // Timing: only COMMIT_REVALIDATING may mint a permit.
    if req.intent.state != EffectState::CommitRevalidating {
        return Err(PermitError::EffectNotRevalidating {});
    }

    // EFX-001: the intent must be durable first.
    if !req.durability.is_meaningful() {
        return Err(PermitError::EffectNotDurable {});
    }

    // Authority: grant must be Active.
    if !matches!(req.grant.revocation_state, atom_capability::RevocationState::Active) {
        return Err(PermitError::GrantNotActive {
            state: format!("{:?}", req.grant.revocation_state),
        });
    }

    // Authority: generation must not have drifted.
    if req.grant.generation != req.planned_grant_generation {
        return Err(PermitError::GrantGenerationDrift {
            planned: req.planned_grant_generation,
            observed: req.grant.generation,
        });
    }

    // Authority: validity window.
    if req.now < req.grant.not_before || req.now > req.grant.expires_at {
        return Err(PermitError::GrantOutsideValidity {});
    }

    // Authority: principal must match subject.
    if req.principal_id != req.grant.subject_id {
        return Err(PermitError::PrincipalMismatch {});
    }

    // Authority: operation must be in the grant's operations.
    if !req
        .grant
        .operations
        .iter()
        .any(|op| op == req.operation)
    {
        return Err(PermitError::OperationNotGranted {
            operation: req.operation.to_owned(),
        });
    }

    // Authority: resource type must be covered by the grant.
    if !req
        .grant
        .resources
        .iter()
        .any(|r| r.resource_type == req.resource_type || r.resource_type == "*")
    {
        return Err(PermitError::ResourceNotGranted {
            resource_type: req.resource_type.to_owned(),
        });
    }

    // TOCTOU: planned witness must equal observed witness.
    if req.planned_witness.resource_type != req.observed_witness.resource_type
        || req.planned_witness.resource_id != req.observed_witness.resource_id
        || req.planned_witness.version != req.observed_witness.version
    {
        return Err(PermitError::ResourceWitnessDrift {});
    }

    // EFX-004: TTL bounded.
    if req.ttl_seconds == 0 || req.ttl_seconds > MAX_PERMIT_TTL_SECONDS {
        return Err(PermitError::TtlOutOfRange {});
    }

    let expires_at = req.now + Duration::seconds(i64::from(req.ttl_seconds));
    let effect_digest = req.intent.digest();

    Ok(CommitPermit {
        permit_id: req.permit_id.to_owned(),
        effect_digest,
        principal_id: req.principal_id.to_owned(),
        capability_grant_id: req.grant.grant_id.clone(),
        grant_generation: req.grant.generation,
        resource_id: req.intent.target_id.clone(),
        resource_version_witness: req.observed_witness.clone(),
        approval_id: req.approval_id.map(str::to_owned),
        evidence_freshness_digest: req.evidence_freshness_digest.map(str::to_owned),
        issued_at: req.now,
        expires_at,
        one_shot_nonce: req.one_shot_nonce.to_owned(),
    })
}

/// Admission to dispatch. Returns `Ok(())` only when the effect is in a state
/// that may dispatch and no blocking dependency is unresolved (EFX-003).
pub fn admit_dispatch(
    effect: &EffectIntent,
    upstream: &[&EffectIntent],
) -> Result<(), AdmissionError> {
    use std::collections::HashSet;

    // Only DISPATCHING effects are admissible (post-permit). An effect still in
    // an ambiguous state must reconcile before it may dispatch again.
    if effect.state != EffectState::Dispatching {
        return Err(if effect.state.blocks_dependents() {
            AdmissionError::AmbiguousOutcome {
                effect_id: effect.effect_id.clone(),
            }
        } else {
            AdmissionError::NotDispatchable {
                state: effect.state,
            }
        });
    }

    // EFX-003: every dependency must be resolved (not UnknownOutcome).
    let resolved: HashSet<&str> = upstream
        .iter()
        .map(|e| (e.effect_id.as_str(), e.state))
        .filter(|(_, s)| *s != EffectState::UnknownOutcome)
        .map(|(id, _)| id)
        .collect();

    for dep in &effect.dependencies {
        // Only an upstream effect we were actually given can block us. If it was
        // not supplied, we simply have not verified it yet — not a blocker.
        let dependency_state = match upstream.iter().find(|e| e.effect_id == *dep) {
            Some(up) => up.state,
            None => continue,
        };

        match dependency_state {
            EffectState::UnknownOutcome => {
                return Err(AdmissionError::DependencyAmbiguous {
                    effect_id: dep.clone(),
                });
            }
            _ if resolved.contains(dep.as_str()) => continue,
            _ => {
                return Err(AdmissionError::BlockedOnDependency {
                    effect_id: dep.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Why `admit_dispatch` refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// The effect is not in a dispatchable state.
    NotDispatchable { state: EffectState },
    /// A dependency is unresolved (still UnknownOutcome or absent).
    BlockedOnDependency { effect_id: String },
    /// A dependency is in UNKNOWN_OUTCOME (ambiguous, must reconcile first).
    DependencyAmbiguous { effect_id: String },
    /// The effect itself is ambiguous and must reconcile before dispatch.
    AmbiguousOutcome { effect_id: String },
}

/// JSON Schema constants for cross-checking against `spec/schemas/`.
pub const COMMIT_PERMIT_SCHEMA: &str = r#"{
  "title": "CommitPermit",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "permit_id", "effect_digest", "principal_id", "capability_grant_id",
    "grant_generation", "resource_id", "resource_version_witness",
    "issued_at", "expires_at", "one_shot_nonce"
  ],
  "properties": {
    "permit_id": { "type": "string" },
    "effect_digest": { "type": "string" },
    "principal_id": { "type": "string" },
    "capability_grant_id": { "type": "string" },
    "grant_generation": { "type": "integer", "minimum": 0 },
    "resource_id": { "type": "string" },
    "resource_version_witness": { "type": "object" },
    "approval_id": { "type": ["string", "null"] },
    "evidence_freshness_digest": { "type": ["string", "null"] },
    "issued_at": { "type": "string", "format": "date-time" },
    "expires_at": { "type": "string", "format": "date-time" },
    "one_shot_nonce": { "type": "string" }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema"
}"#;

/// JSON Schema constant for `EffectIntent`.
pub const EFFECT_INTENT_SCHEMA: &str = r#"{
  "title": "EffectIntent",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "effect_id", "mission_id", "capability_id", "target_id", "request_digest",
    "effect_class", "risk_class", "idempotency", "preconditions",
    "postconditions", "reconciliation", "dependencies", "state"
  ],
  "properties": {
    "effect_id": { "type": "string" },
    "mission_id": { "type": "string" },
    "capability_id": { "type": "string" },
    "target_id": { "type": "string" },
    "request_digest": { "type": "string" },
    "external_operation_id": { "type": ["string", "null"] },
    "effect_class": { "type": "string" },
    "risk_class": { "type": "string" },
    "idempotency": { "type": "object" },
    "preconditions": { "type": "array" },
    "postconditions": { "type": "array" },
    "reconciliation": { "type": "object" },
    "compensation": { "type": ["object", "null"] },
    "dependencies": { "type": "array", "items": { "type": "string" } },
    "state": { "type": "string" }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema"
}"#;

// Keep `IntentError` and digest helpers referenced for downstream consumers.
#[allow(unused_imports, dead_code)]
use IntentError as _IntentErrorMarker;
#[allow(unused_imports, dead_code)]
use Sha256 as _Sha256Marker;
