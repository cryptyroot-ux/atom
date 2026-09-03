//! Deterministic fixtures for the atom-privd privilege-boundary suite (KRN-002).
//!
//! Every timestamp is a literal and the crate under test reads no clock, so an
//! identical request always yields an identical decision. The executor here is
//! a recording mock: it never touches the real host, and the tests assert it is
//! reached only after a valid [`atom_effect::CommitPermit`] has been consumed.

#![allow(dead_code)]

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_effect::{
    issue_commit_permit, CommitPermit, Compensation, CompensationStrategy, DurabilityProof,
    EffectEvent, EffectIntent, EffectState, Idempotency, PermitRequest, Reconciliation,
    ReconciliationClass, ResourceWitness, RetryClass,
};
use atom_ledger::{HmacSha256Signer, Ledger};
use atom_privd::{AdmissionRequest, ExecError, HostExecutor, HostOp, OpOutcome, PrivilegeBroker};
use chrono::{DateTime, TimeZone, Utc};

pub const PRINCIPAL: &str = "principal/atom-operator";
pub const GRANT_ID: &str = "grant/host-admin";
pub const GRANT_GENERATION: u64 = 7;
pub const MISSION_ID: &str = "mission/01J8Z0MISSIONHOST";
pub const EFFECT_ID: &str = "effect/01J8ZPEFFECTHOST";
pub const FOREIGN_EFFECT_ID: &str = "effect/01J8ZPEFFECTOTHER";
pub const PERMIT_ID: &str = "permit/01J8ZPCOMMITHOST";
pub const NONCE: &str = "nonce/01J8ZPCOMMITHOST";
pub const TTL_SECONDS: u32 = 15;
pub const WITNESS_VALUE: &str = "W/\"17\"";
pub const DRIFTED_WITNESS_VALUE: &str = "W/\"18\"";
pub const LEDGER_HASH: &str = "b9c1f0d7e5a34c2f8de1b6a90c74f3e2118d5c6b7a09e4d3c2b1a0f9e8d7c6b5";
pub const REQUEST_DIGEST: &str =
    "sha256:5f2c9e1d8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d";

/// A fixed instant on 2026-08-30, inside the fixture grant's validity window.
#[must_use]
pub fn at(hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, hour, minute, second)
        .single()
        .expect("fixture timestamp is unambiguous")
}

/// The instant permit issuance and admission are evaluated against.
#[must_use]
pub fn now() -> DateTime<Utc> {
    at(12, 0, 0)
}

/// One valid, schema-clean instance of every closed [`HostOp`] variant.
#[must_use]
pub fn all_ops() -> Vec<HostOp> {
    vec![
        HostOp::WriteFile {
            path: "/etc/atom/app.conf".into(),
            contents: "key = value\n".into(),
        },
        HostOp::RemoveFile {
            path: "/var/lib/atom/stale.lock".into(),
        },
        HostOp::SpawnProcess {
            program: "/usr/bin/systemctl".into(),
            args: vec!["restart".into(), "atomd".into()],
        },
        HostOp::ConfigureNetwork {
            interface: "eth0".into(),
            allow_cidr: "10.0.0.0/24".into(),
        },
    ]
}

/// An active grant that authorises the operation `op` names on its resource.
#[must_use]
pub fn grant_for(op: &HostOp) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: GRANT_ID.into(),
        subject_id: PRINCIPAL.into(),
        workload_id: "workload/atomd".into(),
        operations: vec!["read".into(), op.operation().into()],
        resources: vec![ResourceSelector {
            resource_type: op.resource_type().into(),
            resource_id: op.resource_id(),
        }],
        purpose: "host administration".into(),
        not_before: at(11, 0, 0),
        expires_at: at(13, 0, 0),
        budget: Budget {
            max_cost: 1_000,
            max_seconds: 7_200,
        },
        delegation_depth: 3,
        audience: "atom:host".into(),
        generation: GRANT_GENERATION,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
}

/// A grant that covers `read`/`write` on several files at once.
///
/// Used to show that a permit issued for one file cannot be redirected to
/// another the same grant happens to cover.
#[must_use]
pub fn grant_covering(paths: &[&str]) -> CapabilityGrant {
    CapabilityGrant {
        resources: paths
            .iter()
            .map(|path| ResourceSelector {
                resource_type: "file".into(),
                resource_id: (*path).into(),
            })
            .collect(),
        ..grant_for(&HostOp::WriteFile {
            path: paths[0].into(),
            contents: String::new(),
        })
    }
}

/// The same grant after the owner revoked it (ATOM-VT-003).
#[must_use]
pub fn revoked(grant: &CapabilityGrant) -> CapabilityGrant {
    CapabilityGrant {
        revocation_state: RevocationState::Revoked,
        ..grant.clone()
    }
}

/// The same grant after a re-issue bumped its generation (ATOM-VT-003).
#[must_use]
pub fn regenerated(grant: &CapabilityGrant) -> CapabilityGrant {
    CapabilityGrant {
        generation: GRANT_GENERATION + 1,
        ..grant.clone()
    }
}

/// A witness of `value` on the resource `op` targets.
#[must_use]
pub fn witness_for(op: &HostOp, value: &str) -> ResourceWitness {
    ResourceWitness::new("etag", &op.resource_id(), value)
}

/// The resource version observed at planning time and unchanged since.
#[must_use]
pub fn planned_witness(op: &HostOp) -> ResourceWitness {
    witness_for(op, WITNESS_VALUE)
}

/// The resource version after somebody else wrote to the target.
#[must_use]
pub fn drifted_witness(op: &HostOp) -> ResourceWitness {
    witness_for(op, DRIFTED_WITNESS_VALUE)
}

/// Proof the exact `intent` was persisted before dispatch (EFX-001).
///
/// Minted the only way a real proof can be: by appending the intent's declared
/// payload (the caller's declaration, stable across lifecycle transitions) to a
/// ledger stream named for the effect. There is no `DurabilityProof` constructor
/// a test could call, so a forged proof is inexpressible — passing one effect's
/// proof to another effect's boundary is a mismatch the sealed proof refuses.
#[must_use]
pub fn durability(intent: &EffectIntent) -> DurabilityProof {
    let signer = Box::new(HmacSha256Signer::new(
        "atom-privd-test-seal",
        b"atom-privd-test-key-not-for-production",
    ));
    let mut ledger = Ledger::open_in_memory(signer).expect("in-memory ledger opens");
    let payload = intent
        .declared_payload()
        .expect("fixture intent has a declared payload");
    let (_event, proof) = ledger
        .append_durable(&intent.effect_id, &payload, 1_756_512_000_000)
        .expect("appending the declared intent seals a durability proof");
    proof
}

/// A minimal EFX-002 intent for `op`, driven to `COMMIT_REVALIDATING`.
#[must_use]
pub fn intent_for(op: &HostOp) -> EffectIntent {
    revalidating(EFFECT_ID, op)
}

/// A second intent with a different identity, also at the commit boundary.
///
/// Its digest differs from [`intent_for`], so a permit issued for one effect
/// cannot be consumed by the other.
#[must_use]
pub fn foreign_intent_for(op: &HostOp) -> EffectIntent {
    revalidating(FOREIGN_EFFECT_ID, op)
}

/// Builds `effect_id`'s intent for `op` and advances it to the commit boundary.
fn revalidating(effect_id: &str, op: &HostOp) -> EffectIntent {
    let intent = EffectIntent::builder(effect_id, MISSION_ID, GRANT_ID, &op.resource_id())
        .canonical_request_digest(REQUEST_DIGEST)
        .classes("HOST_ADMINISTRATION", "HIGH")
        .idempotency(Idempotency::natural(&op.resource_id()))
        .reconciliation(Reconciliation::new(
            ReconciliationClass::LedgerReplay,
            RetryClass::Never,
        ))
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .expect("fixture intent satisfies EFX-002");

    let mut current = intent;
    for event in [
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(GRANT_ID, GRANT_GENERATION),
        EffectEvent::CommitRevalidationStarted,
    ] {
        current = current
            .try_advance(&event)
            .expect("INTENT_DURABLE -> COMMIT_REVALIDATING follows effect.yaml");
    }
    assert_eq!(current.state, EffectState::CommitRevalidating);
    current
}

/// Issues the permit a well-behaved commit gate would hand `op`.
#[must_use]
pub fn permit_for(
    op: &HostOp,
    grant: &CapabilityGrant,
    intent: &EffectIntent,
    witness: &ResourceWitness,
) -> CommitPermit {
    issue_commit_permit(PermitRequest {
        intent,
        grant,
        principal_id: PRINCIPAL,
        operation: op.operation(),
        resource_type: op.resource_type(),
        planned_grant_generation: GRANT_GENERATION,
        planned_witness: witness,
        observed_witness: witness,
        durability: &durability(intent),
        permit_id: PERMIT_ID,
        one_shot_nonce: NONCE,
        ttl_seconds: TTL_SECONDS,
        now: now(),
        approval_id: None,
        evidence_freshness_digest: None,
    })
    .expect("fixture permit issues cleanly")
}

/// A complete, admissible privilege crossing for a single [`HostOp`].
pub struct Scenario {
    pub op: HostOp,
    pub grant: CapabilityGrant,
    pub intent: EffectIntent,
    pub witness: ResourceWitness,
    pub permit: CommitPermit,
}

impl Scenario {
    /// The one grant/intent/witness/permit under which `op` is admissible.
    #[must_use]
    pub fn new(op: HostOp) -> Self {
        let grant = grant_for(&op);
        let intent = intent_for(&op);
        let witness = planned_witness(&op);
        let permit = permit_for(&op, &grant, &intent, &witness);
        Self {
            op,
            grant,
            intent,
            witness,
            permit,
        }
    }

    /// The admission request a well-behaved caller submits.
    #[must_use]
    pub fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            op: &self.op,
            permit: &self.permit,
            intent: &self.intent,
            grant: &self.grant,
            observed_witness: &self.witness,
            now: now(),
        }
    }
}

/// A [`HostExecutor`] that touches no host: it records what it was asked to do.
#[derive(Clone, Debug, Default)]
pub struct RecordingExecutor {
    executed: Vec<HostOp>,
    fail: bool,
}

impl RecordingExecutor {
    /// An executor that succeeds and records every op it runs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An executor that refuses every op, modelling a host-side failure.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            executed: Vec::new(),
            fail: true,
        }
    }

    /// The ops that actually reached the host, in execution order.
    #[must_use]
    pub fn executed(&self) -> &[HostOp] {
        &self.executed
    }

    /// How many ops actually reached the host.
    #[must_use]
    pub fn count(&self) -> usize {
        self.executed.len()
    }
}

impl HostExecutor for RecordingExecutor {
    fn execute(&mut self, op: &HostOp) -> Result<OpOutcome, ExecError> {
        if self.fail {
            return Err(ExecError::failed(
                op.kind(),
                "mock executor was told to fail",
            ));
        }
        self.executed.push(op.clone());
        Ok(OpOutcome::new(
            op.kind(),
            format!("recorded {}", op.resource_id()),
        ))
    }
}

/// A fresh broker over a recording executor that touches no host.
#[must_use]
pub fn broker() -> PrivilegeBroker<RecordingExecutor> {
    PrivilegeBroker::new(RecordingExecutor::new())
}
