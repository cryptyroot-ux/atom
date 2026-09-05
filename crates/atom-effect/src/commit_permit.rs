//! The commit boundary: a short-lived, one-shot [`CommitPermit`] (EFX-004).
//!
//! Authority is checked twice — once when the permit is issued and again when
//! it is consumed — because everything checked at issuance can drift in the
//! window before dispatch: the grant can be revoked, re-issued at a new
//! generation, or the resource can be written by somebody else. A permit that
//! was valid a second ago proves nothing, so consumption re-runs the same
//! checks against the values the permit froze (ATOM-VT-003).
//!
//! Nothing here reads a clock, a random source, or the network: `now`, the
//! permit id and the nonce are supplied by the caller, so an issuance is
//! reproducible from the ledger.

use std::collections::BTreeSet;

use atom_capability::{CapabilityGrant, RevocationState};
use atom_ledger::DurabilityProof;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::CommitPermitted;
use crate::intent::EffectIntent;
use crate::state::EffectState;

/// The longest life a commit permit may be given, in seconds (EFX-004).
///
/// The bound belongs to the crate rather than the caller: "short-lived" is a
/// property of the boundary, not a preference of whoever asks to cross it.
pub const MAX_PERMIT_TTL_SECONDS: u32 = 60;

/// The observed version of the resource an effect is about to write.
///
/// Comparing the witness taken at planning time with the one observed at the
/// commit boundary is what turns a lost update into a refusal.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceWitness {
    /// How the version was observed, e.g. `etag` or `row_version`.
    pub kind: String,
    /// The resource the witness was taken from.
    pub resource_id: String,
    /// The version itself, in the target's own vocabulary.
    pub value: String,
}

impl ResourceWitness {
    /// A `kind` witness reading `value` on `resource_id`.
    #[must_use]
    pub fn new(kind: &str, resource_id: &str, value: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            resource_id: resource_id.to_owned(),
            value: value.to_owned(),
        }
    }
}
// Proof that the intent was written to the ledger before dispatch (EFX-001) is
// no longer a caller-constructible `DurabilityWitness`. It is
// [`atom_ledger::DurabilityProof`], minted only by the ledger's own append path
// and re-exported by this crate. A permit therefore cannot be issued from a
// hand-built claim of durability — the ledger must actually have appended the
// intent (ATOM-INV-004, "no arbitrary caller manufactures a trusted proof").
/// A permit to cross the commit boundary exactly once (EFX-004).
///
/// The permit is bound to everything that could drift: the effect's identity
/// digest, the principal, the grant and its generation, the resource and its
/// observed version — plus, where policy demands it, an approval and the
/// freshness of the evidence the decision rested on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitPermit {
    /// Stable identity of the permit, so its use can be named in the ledger.
    pub permit_id: String,
    /// The identity digest of the effect this permit lets through.
    pub effect_digest: String,
    /// The principal the permit was issued to.
    pub principal_id: String,
    /// The workload identity the permit was issued for. Frozen from the grant's
    /// workload at issuance (ATOM-V4-AUT-001, Constitution IV.1: authority is
    /// subject/workload-bound).
    pub workload_id: String,
    /// The grant the authority was drawn from.
    pub capability_grant_id: String,
    /// The generation of that grant at issuance.
    pub grant_generation: u64,
    /// The audience (sink) the permit was issued for — who may receive the
    /// commit. Frozen from the grant's audience at issuance (ATOM-V4-AUT-001,
    /// Constitution IV.1/V.3: authority must be audience-bound).
    pub audience: String,
    /// The resource about to be written.
    pub resource_id: String,
    /// The resource version observed at issuance.
    pub resource_version_witness: ResourceWitness,
    /// The human approval, when the risk class required one.
    pub approval_id: Option<String>,
    /// How fresh the evidence behind the decision was.
    pub evidence_freshness_digest: Option<String>,
    /// The sink this permit is bound to — wrong sink is refused.
    pub dispatch_sink_id: String,
    /// The connector identity this permit was issued to.
    pub connector_identity: String,
    /// The connector version at issuance time.
    pub connector_version: String,
    /// The connector instance epoch — stale epoch is refused.
    pub connector_instance_epoch: u64,
    /// When the permit was issued.
    pub issued_at: DateTime<Utc>,
    /// When it dies.
    pub expires_at: DateTime<Utc>,
    /// The nonce burned on consumption, which makes the permit one-shot.
    pub one_shot_nonce: String,
}

impl CommitPermit {
    /// How long the permit lives, in seconds.
    #[must_use]
    pub fn ttl_seconds(&self) -> i64 {
        (self.expires_at - self.issued_at).num_seconds()
    }

    /// Whether `instant` falls inside the permit's window, endpoints included.
    #[must_use]
    pub fn is_valid_at(&self, instant: DateTime<Utc>) -> bool {
        instant >= self.issued_at && instant <= self.expires_at
    }

    /// Stable identity of the permit.
    #[must_use]
    pub fn permit_id(&self) -> &str {
        &self.permit_id
    }

    /// The identity digest of the effect this permit lets through.
    #[must_use]
    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    /// The principal the permit was issued to.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// The workload identity the permit was issued for.
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    /// The grant the authority was drawn from.
    #[must_use]
    pub fn capability_grant_id(&self) -> &str {
        &self.capability_grant_id
    }

    /// The generation of that grant at issuance.
    #[must_use]
    pub fn grant_generation(&self) -> u64 {
        self.grant_generation
    }

    /// The audience (sink) the permit was issued for.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The resource about to be written.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// The resource version observed at issuance.
    #[must_use]
    pub fn resource_version_witness(&self) -> &ResourceWitness {
        &self.resource_version_witness
    }

    /// The human approval, when the risk class required one.
    #[must_use]
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }

    /// How fresh the evidence behind the decision was.
    #[must_use]
    pub fn evidence_freshness_digest(&self) -> Option<&str> {
        self.evidence_freshness_digest.as_deref()
    }

    /// When the permit was issued.
    #[must_use]
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// When it dies.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The nonce burned on consumption, which makes the permit one-shot.
    #[must_use]
    pub fn one_shot_nonce(&self) -> &str {
        &self.one_shot_nonce
    }
}
/// Why a permit was refused, at either end of the commit boundary.
///
/// Every variant names the drift it found, because "denied" is not an audit
/// trail: the ledger has to be able to say what moved.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PermitError {
    /// The requested life is not short (EFX-004).
    #[error("a commit permit lives 1..={max} seconds, not {ttl_seconds}")]
    TtlOutOfRange {
        /// The life that was asked for.
        ttl_seconds: u32,
        /// The bound the crate enforces.
        max: u32,
    },
    /// The effect is not standing at the commit boundary.
    #[error("effect is {state}, not COMMIT_REVALIDATING")]
    EffectNotRevalidating {
        /// The state the effect is actually in.
        state: EffectState,
    },
    /// No proof the intent was persisted before dispatch (EFX-001).
    #[error("effect {effect_id} has no durable ledger entry to dispatch from")]
    EffectNotDurable {
        /// The effect whose durability could not be shown.
        effect_id: String,
    },
    /// The durable payload does not match the intent being committed.
    ///
    /// The proof's payload digest must equal the RFC 8785 digest of *this* intent.
    /// A proof on the right stream at the right sequence—but for a different
    /// serialized payload—binds durability to something else, so it is refused
    /// (ATOM-INV-004, "the ledger wrote what the caller means").
    #[error("durable payload for effect {effect_id} does not match the intent digest")]
    EffectPayloadMismatch {
        /// The effect whose durable payload disagreed with the intent.
        effect_id: String,
    },
    /// The intent could not be canonicalized to verify its durable payload.
    #[error("intent for effect {effect_id} could not be canonicalized: {reason}")]
    EffectNotCanonicalizable {
        /// The effect whose intent could not be canonicalized.
        effect_id: String,
        /// Why canonicalization failed.
        reason: String,
    },
    /// The permit was asked for on behalf of somebody the grant does not name.
    #[error("grant belongs to {expected}, not {observed}")]
    PrincipalMismatch {
        /// The grant's subject.
        expected: String,
        /// The principal that asked.
        observed: String,
    },
    /// The grant was revoked or has expired (ATOM-VT-003).
    #[error("grant is {state:?}, not ACTIVE")]
    GrantNotActive {
        /// The revocation state found at the boundary.
        state: RevocationState,
    },
    /// The moment of the crossing lies outside the grant's validity window.
    #[error("{at} is outside the grant window {not_before}..={expires_at}")]
    GrantOutsideValidity {
        /// The instant that was checked.
        at: DateTime<Utc>,
        /// When the grant becomes usable.
        not_before: DateTime<Utc>,
        /// When it stops being usable.
        expires_at: DateTime<Utc>,
    },
    /// The grant was re-issued after planning (ATOM-VT-003).
    #[error("grant generation drifted from {planned} to {observed}")]
    GrantGenerationDrift {
        /// The generation the plan was authorised against.
        planned: u64,
        /// The generation found at the boundary.
        observed: u64,
    },
    /// The grant the permit was issued from does not name the same audience
    /// (sink) for the commit (EFX-004, Constitution V.3 "audience-bound": a
    /// permit minted for one sink cannot be spent draining another).
    #[error("permit was issued for audience {expected}, not {observed}")]
    AudienceMismatch {
        /// The audience the permit froze when it was issued.
        expected: String,
        /// The audience the grant in hand actually names.
        observed: String,
    },
    /// The grant the permit was issued from does not name the same workload
    /// (ATOM-V4-AUT-001, Constitution IV.1 "workload-bound": a permit minted
    /// for one workload cannot be spent as another).
    #[error("permit was issued for workload {expected}, not {observed}")]
    WorkloadMismatch {
        /// The workload the permit froze when it was issued.
        expected: String,
        /// The workload the grant in hand actually names.
        observed: String,
    },
    /// The permit was presented to the wrong dispatch sink.
    #[error("permit was issued for sink {expected}, not {observed}")]
    WrongDispatchSink {
        expected: String,
        observed: String,
    },
    /// The permit was presented by the wrong connector identity.
    #[error("permit was issued to connector {expected}, not {observed}")]
    WrongConnectorIdentity {
        expected: String,
        observed: String,
    },
    /// The permit was presented by the wrong connector version.
    #[error("permit was issued to connector version {expected}, not {observed}")]
    WrongConnectorVersion {
        expected: String,
        observed: String,
    },
    /// The permit was presented by a stale connector instance epoch.
    #[error("permit was issued to instance epoch {expected}, not {observed}")]
    StaleInstanceEpoch {
        expected: u64,
        observed: u64,
    },
    /// The grant does not cover the operation being attempted.
    #[error("grant does not allow {operation}")]
    OperationNotGranted {
        /// The operation that was refused.
        operation: String,
    },
    /// The grant does not cover the resource being written.
    #[error("grant does not cover {resource_type} {resource_id}")]
    ResourceNotGranted {
        /// The type of the resource that was refused.
        resource_type: String,
        /// The resource itself.
        resource_id: String,
    },
    /// Somebody else wrote the resource after planning (ATOM-VT-003).
    #[error("{resource_id} moved from {planned} to {observed} after planning")]
    ResourceWitnessDrift {
        /// The resource whose version moved.
        resource_id: String,
        /// The version the plan was made against.
        planned: String,
        /// The version observed at the boundary.
        observed: String,
    },
    /// The permit does not belong to this effect (EFX-004).
    #[error("permit was issued for {expected}, not {observed}")]
    DigestMismatch {
        /// The digest the permit is bound to.
        expected: String,
        /// The digest of the effect that presented it.
        observed: String,
    },
    /// The permit was already spent (EFX-004).
    #[error("nonce {nonce} was already used; a commit permit is one-shot")]
    NonceAlreadyUsed {
        /// The nonce that had already been burned.
        nonce: String,
    },
    /// The permit is presented before it was issued.
    #[error("permit is not valid until {issued_at}, and it is {at}")]
    PermitNotYetValid {
        /// The instant of the attempted crossing.
        at: DateTime<Utc>,
        /// When the permit was issued.
        issued_at: DateTime<Utc>,
    },
    /// The permit outlived its window (EFX-004).
    #[error("permit expired at {expires_at}, and it is {at}")]
    PermitExpired {
        /// The instant of the attempted crossing.
        at: DateTime<Utc>,
        /// When the permit died.
        expires_at: DateTime<Utc>,
    },
}
/// Everything the commit gate revalidates before it issues a permit (EFX-004).
#[derive(Clone, Debug)]
pub struct PermitRequest<'a> {
    /// The effect standing at the boundary.
    pub intent: &'a EffectIntent,
    /// The grant the authority is drawn from, as it is *now*.
    pub grant: &'a CapabilityGrant,
    /// The principal asking to cross.
    pub principal_id: &'a str,
    /// The operation about to be performed.
    pub operation: &'a str,
    /// The type of the target resource, for the grant's selector.
    pub resource_type: &'a str,
    /// The grant generation the plan was authorised against.
    pub planned_grant_generation: u64,
    /// The resource version observed while planning.
    pub planned_witness: &'a ResourceWitness,
    /// The resource version observed now.
    pub observed_witness: &'a ResourceWitness,
    /// Proof the intent was persisted first (EFX-001). Only the ledger can mint
    /// one, so this cannot be a hand-built claim of durability.
    pub durability: &'a DurabilityProof,
    /// The identity the permit will carry.
    pub permit_id: &'a str,
    /// The nonce that will make it one-shot.
    pub one_shot_nonce: &'a str,
    /// How long the permit may live.
    pub ttl_seconds: u32,
    /// The instant of issuance; supplied, never read from a clock.
    pub now: DateTime<Utc>,
    /// The human approval, when the risk class required one.
    pub approval_id: Option<&'a str>,
    /// How fresh the evidence behind the decision was.
    pub evidence_freshness_digest: Option<&'a str>,
    /// The sink this permit is bound to.
    pub dispatch_sink_id: &'a str,
    /// The connector identity this permit was issued to.
    pub connector_identity: &'a str,
    /// The connector version at issuance time.
    pub connector_version: &'a str,
    /// The connector instance epoch.
    pub connector_instance_epoch: u64,
}

/// Everything the commit gate revalidates before it spends a permit (EFX-004).
#[derive(Clone, Debug)]
pub struct ConsumeRequest<'a> {
    /// The permit being presented.
    pub permit: &'a CommitPermit,
    /// The effect presenting it.
    pub intent: &'a EffectIntent,
    /// The grant as it is *now*.
    pub grant: &'a CapabilityGrant,
    /// The resource version observed now.
    pub observed_witness: &'a ResourceWitness,
    /// The instant of consumption.
    pub now: DateTime<Utc>,
    /// The sink this permit is being presented to.
    pub dispatch_sink_id: &'a str,
    /// The connector identity presenting the permit.
    pub connector_identity: &'a str,
    /// The connector version presenting the permit.
    pub connector_version: &'a str,
    /// The connector instance epoch.
    pub connector_instance_epoch: u64,
}
/// The authority checks, run identically at issuance and at consumption.
///
/// Sharing one function is the point: a TOCTOU defence that checks less on the
/// second pass is not a defence, and two copies of this list would drift.
fn revalidate_authority(
    grant: &CapabilityGrant,
    principal_id: &str,
    expected_generation: u64,
    expected_audience: &str,
    expected_workload: &str,
    now: DateTime<Utc>,
) -> Result<(), PermitError> {
    if grant.subject_id != principal_id {
        return Err(PermitError::PrincipalMismatch {
            expected: grant.subject_id.clone(),
            observed: principal_id.to_owned(),
        });
    }
    if grant.workload_id != expected_workload {
        return Err(PermitError::WorkloadMismatch {
            expected: expected_workload.to_owned(),
            observed: grant.workload_id.clone(),
        });
    }
    if grant.audience != expected_audience {
        return Err(PermitError::AudienceMismatch {
            expected: expected_audience.to_owned(),
            observed: grant.audience.clone(),
        });
    }
    if grant.revocation_state != RevocationState::Active {
        return Err(PermitError::GrantNotActive {
            state: grant.revocation_state,
        });
    }
    if now < grant.not_before || now > grant.expires_at {
        return Err(PermitError::GrantOutsideValidity {
            at: now,
            not_before: grant.not_before,
            expires_at: grant.expires_at,
        });
    }
    if grant.generation != expected_generation {
        return Err(PermitError::GrantGenerationDrift {
            planned: expected_generation,
            observed: grant.generation,
        });
    }
    Ok(())
}

/// Whether the resource still looks the way the plan assumed.
fn revalidate_witness(
    planned: &ResourceWitness,
    observed: &ResourceWitness,
) -> Result<(), PermitError> {
    if planned == observed {
        return Ok(());
    }
    Err(PermitError::ResourceWitnessDrift {
        resource_id: observed.resource_id.clone(),
        planned: planned.value.clone(),
        observed: observed.value.clone(),
    })
}
/// Revalidates the whole plan and issues a permit, or refuses (EFX-001/004).
///
/// # Errors
///
/// Returns the drift that was found: an unbounded TTL, an effect that is not at
/// the boundary or was never made durable, authority that no longer holds, or a
/// resource that somebody else has written since planning.
pub fn issue_commit_permit(request: PermitRequest<'_>) -> Result<CommitPermit, PermitError> {
    let intent = request.intent;
    let grant = request.grant;

    if request.ttl_seconds == 0 || request.ttl_seconds > MAX_PERMIT_TTL_SECONDS {
        return Err(PermitError::TtlOutOfRange {
            ttl_seconds: request.ttl_seconds,
            max: MAX_PERMIT_TTL_SECONDS,
        });
    }
    if intent.state != EffectState::CommitRevalidating {
        return Err(PermitError::EffectNotRevalidating {
            state: intent.state,
        });
    }
    if !request.durability.proves(&intent.effect_id) {
        return Err(PermitError::EffectNotDurable {
            effect_id: intent.effect_id.clone(),
        });
    }
    // Bind the proof to this *exact* intent: the proof must have been minted
    // over a payload whose canonical digest equals this intent's declared
    // payload. The declared payload is what the caller wrote down — identity
    // fields only, stable across lifecycle transitions — so a proof on the right
    // stream at the right sequence but over a different declaration is not
    // durability of *this* intent (ATOM-INV-004).
    let intent_payload_digest = intent.declared_payload_digest().map_err(|error| {
        PermitError::EffectNotCanonicalizable {
            effect_id: intent.effect_id.clone(),
            reason: error.to_string(),
        }
    })?;
    if !request
        .durability
        .proves_intent(&intent.effect_id, &intent_payload_digest)
    {
        return Err(PermitError::EffectPayloadMismatch {
            effect_id: intent.effect_id.clone(),
        });
    }

    revalidate_authority(
        grant,
        request.principal_id,
        request.planned_grant_generation,
        &grant.audience,
        &grant.workload_id,
        request.now,
    )?;

    if !grant.operations.iter().any(|op| op == request.operation) {
        return Err(PermitError::OperationNotGranted {
            operation: request.operation.to_owned(),
        });
    }
    let covered = grant.resources.iter().any(|selector| {
        selector.resource_type == request.resource_type && selector.resource_id == intent.target_id
    });
    if !covered {
        return Err(PermitError::ResourceNotGranted {
            resource_type: request.resource_type.to_owned(),
            resource_id: intent.target_id.clone(),
        });
    }

    revalidate_witness(request.planned_witness, request.observed_witness)?;
    Ok(CommitPermit {
        permit_id: request.permit_id.to_owned(),
        effect_digest: intent.digest(),
        principal_id: request.principal_id.to_owned(),
        workload_id: grant.workload_id.clone(),
        capability_grant_id: grant.grant_id.clone(),
        grant_generation: grant.generation,
        audience: grant.audience.clone(),
        resource_id: intent.target_id.clone(),
        resource_version_witness: request.observed_witness.clone(),
        approval_id: request.approval_id.map(str::to_owned),
        evidence_freshness_digest: request.evidence_freshness_digest.map(str::to_owned),
        dispatch_sink_id: request.dispatch_sink_id.to_owned(),
        connector_identity: request.connector_identity.to_owned(),
        connector_version: request.connector_version.to_owned(),
        connector_instance_epoch: request.connector_instance_epoch,
        issued_at: request.now,
        expires_at: request.now + Duration::seconds(i64::from(request.ttl_seconds)),
        one_shot_nonce: request.one_shot_nonce.to_owned(),
    })
}
/// The burned one-shot nonces (EFX-004).
///
/// A permit is one-shot only because something remembers that it was spent.
/// This is that memory: in-process, ordered, and holding nothing but nonces.
#[derive(Clone, Debug, Default)]
pub struct NonceRegistry {
    used: BTreeSet<String>,
}

impl NonceRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry seeded with nonces already burned on a durable ledger stream.
    ///
    /// A process that restarts rebuilds its one-shot memory from what the ledger
    /// recorded, so a spent permit is refused again instead of being re-served
    /// (ATOM-V4-EFX-004 · durable nonce).
    #[must_use]
    pub fn from_used(used: impl IntoIterator<Item = String>) -> Self {
        Self {
            used: used.into_iter().collect(),
        }
    }

    /// How many permits have been spent.
    #[must_use]
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// Whether nothing has been spent yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }

    /// Whether `nonce` was already burned.
    #[must_use]
    pub fn is_used(&self, nonce: &str) -> bool {
        self.used.contains(nonce)
    }
    /// Spends `request.permit` once, re-running every issuance check first.
    ///
    /// On success the nonce is burned and the [`CommitPermitted`] event the
    /// caller appends to the ledger is returned. A refusal burns nothing: the
    /// permit is still good if the drift that caused it was transient.
    ///
    /// # Errors
    ///
    /// Returns the drift that was found, or [`PermitError::NonceAlreadyUsed`]
    /// if this permit was already spent.
    pub fn consume(&mut self, request: ConsumeRequest<'_>) -> Result<CommitPermitted, PermitError> {
        let ConsumeRequest {
            permit,
            intent,
            grant,
            observed_witness,
            now,
            dispatch_sink_id,
            connector_identity,
            connector_version,
            connector_instance_epoch,
        } = request;

        if self.is_used(&permit.one_shot_nonce) {
            return Err(PermitError::NonceAlreadyUsed {
                nonce: permit.one_shot_nonce.clone(),
            });
        }

        let observed_digest = intent.digest();
        if observed_digest != permit.effect_digest {
            return Err(PermitError::DigestMismatch {
                expected: permit.effect_digest.clone(),
                observed: observed_digest,
            });
        }
        if intent.state != EffectState::CommitRevalidating {
            return Err(PermitError::EffectNotRevalidating {
                state: intent.state,
            });
        }
        if dispatch_sink_id != permit.dispatch_sink_id {
            return Err(PermitError::WrongDispatchSink {
                expected: permit.dispatch_sink_id.clone(),
                observed: dispatch_sink_id.to_owned(),
            });
        }
        if connector_identity != permit.connector_identity {
            return Err(PermitError::WrongConnectorIdentity {
                expected: permit.connector_identity.clone(),
                observed: connector_identity.to_owned(),
            });
        }
        if connector_version != permit.connector_version {
            return Err(PermitError::WrongConnectorVersion {
                expected: permit.connector_version.clone(),
                observed: connector_version.to_owned(),
            });
        }
        if connector_instance_epoch != permit.connector_instance_epoch {
            return Err(PermitError::StaleInstanceEpoch {
                expected: permit.connector_instance_epoch,
                observed: connector_instance_epoch,
            });
        }
        // Against the permit, not against a fresh plan: these are exactly the
        // values that were true when authority was granted, so any difference
        // is drift inside the window (ATOM-VT-003). The operation and resource
        // selectors are not re-checked here because they cannot change without
        // a new grant generation, which is checked. Durability is not re-checked
        // either: it is monotonic — once the ledger has appended the intent it
        // stays appended, so a proof that held at issuance still holds now.
        revalidate_authority(
            grant,
            &permit.principal_id,
            permit.grant_generation,
            &permit.audience,
            &permit.workload_id,
            now,
        )?;
        revalidate_witness(&permit.resource_version_witness, observed_witness)?;

        if now < permit.issued_at {
            return Err(PermitError::PermitNotYetValid {
                at: now,
                issued_at: permit.issued_at,
            });
        }
        if now > permit.expires_at {
            return Err(PermitError::PermitExpired {
                at: now,
                expires_at: permit.expires_at,
            });
        }

        self.used.insert(permit.one_shot_nonce.clone());
        Ok(CommitPermitted {
            permit_id: permit.permit_id.clone(),
            one_shot_nonce: permit.one_shot_nonce.clone(),
            effect_digest: permit.effect_digest.clone(),
        })
    }
}
