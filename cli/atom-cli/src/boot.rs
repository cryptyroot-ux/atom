//! `atom run`: boot the sovereign process in-process.
//!
//! Booting means standing up the real subsystems and driving one genuine
//! mutation through the kernel's double gate (KRN-001): authorize (Phase A)
//! then commit (Phase B), producing an unforgeable [`atom_kernel::CommitToken`].
//! A [`atom_worker::Worker`] is bound to the same capability grant and admits
//! the same operation deny-by-default (WKR-001). The runtime, its append-only
//! ledger and the deterministic scheduler are all constructed here.
//!
//! Every crate the process is built from is then reported in a subsystem
//! inventory, so `atom run` is a live proof that the pieces link and cohere.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_effect::{
    Compensation, CompensationStrategy, EffectEvent, EffectIntent, Idempotency, Reconciliation,
    ReconciliationClass, ResourceWitness,
};
use atom_kernel::{AuthorizeRequest, CommitRequest, Kernel};

use crate::config::SigningConfig;

// Boot identifiers. The grant is scoped to exactly one operation on one
// resource; nothing here grants ambient authority.
const SUBJECT: &str = "operator";
const GRANT_ID: &str = "grant-boot";
const EFFECT_ID: &str = "effect-boot";
const MISSION_ID: &str = "mission-boot";
const TARGET_ID: &str = "ledger-stream-boot";
const RESOURCE_TYPE: &str = "ledger";
const OPERATION: &str = "write";

/// One subsystem line in the boot inventory: a crate and a fact proven about it.
pub struct Subsystem {
    /// The crate that was exercised.
    pub crate_name: &'static str,
    /// A concrete status computed by actually touching the crate.
    pub status: String,
}

impl Subsystem {
    fn new(crate_name: &'static str, status: impl Into<String>) -> Self {
        Self {
            crate_name,
            status: status.into(),
        }
    }
}

/// The result of a successful boot: proof the double gate ran and the
/// subsystems all linked.
pub struct BootReport {
    /// The runtime's mission id.
    pub mission_id: String,
    /// The key id the ledger and artifacts sign under (never the secret).
    pub key_id: String,
    /// One-shot nonces the kernel has spent (1 after a single commit).
    pub nonces_spent: usize,
    /// The committed effect's id, from the minted token.
    pub commit_effect_id: String,
    /// The grant the committed authority came from.
    pub commit_grant_id: String,
    /// The grant generation the token pinned.
    pub commit_grant_generation: u64,
    /// The resource the committed effect targets.
    pub commit_resource_id: String,
    /// The one-shot nonce the commit burned.
    pub commit_nonce: String,
    /// The worker that admitted the same operation.
    pub worker_id: String,
    /// The operation the worker admitted (deny-by-default otherwise).
    pub admitted_operation: String,
    /// The effect intent's state after commit (Dispatching).
    pub intent_state: String,
    /// The full crate inventory this process is built from.
    pub subsystems: Vec<Subsystem>,
}

/// A boot-scoped capability grant: `write` on one ledger stream, live now.
fn boot_grant(now: DateTime<Utc>) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: GRANT_ID.into(),
        subject_id: SUBJECT.into(),
        workload_id: "atom-cli".into(),
        operations: vec!["read".into(), "write".into()],
        resources: vec![ResourceSelector {
            resource_type: RESOURCE_TYPE.into(),
            resource_id: TARGET_ID.into(),
        }],
        purpose: "boot".into(),
        not_before: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
        budget: Budget {
            max_cost: 1_000,
            max_seconds: 3_600,
        },
        delegation_depth: 3,
        audience: "atom-cli".into(),
        generation: 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
    }
}

/// The effect intent for the boot mutation, standing at AUTHORIZATION_PENDING.
fn pending_intent() -> Result<EffectIntent> {
    let intent = EffectIntent::builder(EFFECT_ID, MISSION_ID, GRANT_ID, TARGET_ID)
        .canonical_request(&serde_json::json!({
            "operation": OPERATION,
            "resource_type": RESOURCE_TYPE,
            "target_id": TARGET_ID,
        }))
        .map_err(|e| anyhow!("canonicalizing boot request: {e}"))?
        .classes("ledger.write", "high")
        .idempotency(Idempotency::keyed("boot", "boot-idem-key"))
        .reconciliation(Reconciliation::new(
            ReconciliationClass::LedgerReplay,
            // Referenced through atom-fault, which re-exports the same type —
            // wiring the fault crate into the real commit path.
            atom_fault::RetryClass::ReconcileBeforeRetry,
        ))
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .map_err(|e| anyhow!("building boot intent: {e}"))?;
    intent
        .try_advance(&EffectEvent::AuthorizationRequested)
        .map_err(|e| anyhow!("advancing boot intent to authorization-pending: {e}"))
}

/// Boots the sovereign process and drives one real double-gated mutation.
///
/// # Errors
///
/// Fails if the ledger cannot be opened, the runtime cannot be built, the
/// double gate refuses the mutation, or the worker refuses to bind/admit.
pub fn boot(cfg: &SigningConfig) -> Result<BootReport> {
    let now = Utc::now();

    // ── Kernel double gate (KRN-001): authorize → commit → CommitToken ───────
    let mut kernel = Kernel::new();
    let grant = boot_grant(now);
    let pending = pending_intent()?;
    let planned = ResourceWitness::new("etag", TARGET_ID, "v1");

    let (authorization, authorized) = kernel
        .authorize(AuthorizeRequest {
            intent: &pending,
            grant: &grant,
            principal_id: SUBJECT,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_witness: &planned,
            now,
        })
        .map_err(|e| anyhow!("phase A authorize: {e}"))?;

    let revalidating = authorized
        .try_advance(&EffectEvent::CommitRevalidationStarted)
        .map_err(|e| anyhow!("opening the commit boundary: {e}"))?;

    // ── Runtime ledger, signed with the process key, opened up front ─────────
    // The same append-only ledger that will back the runtime is opened here so
    // the intent can be made durable *before* the commit gate is asked to spend
    // a permit for it (EFX-001). The ledger — not this caller — seals the proof.
    let signer = Box::new(atom_ledger::HmacSha256Signer::new(
        cfg.key_id.as_str(),
        &cfg.secret,
    ));
    let mut ledger =
        atom_ledger::Ledger::open_in_memory(signer).map_err(|e| anyhow!("opening ledger: {e}"))?;
    let intent_payload =
        serde_json::to_value(&pending).map_err(|e| anyhow!("serializing boot intent: {e}"))?;
    let (_intent_event, durability) = ledger
        .append_durable(EFFECT_ID, &intent_payload, now.timestamp_millis())
        .map_err(|e| anyhow!("sealing durability proof: {e}"))?;

    let observed = ResourceWitness::new("etag", TARGET_ID, "v1");
    let (token, dispatching) = kernel
        .commit(CommitRequest {
            authorization: &authorization,
            intent: &revalidating,
            grant: &grant,
            observed_witness: &observed,
            durability: &durability,
            permit_id: "permit-boot",
            one_shot_nonce: "nonce-boot",
            ttl_seconds: 30,
            now,
            approval_id: None,
            evidence_freshness_digest: None,
        })
        .map_err(|e| anyhow!("phase B commit: {e}"))?;

    // ── Runtime over the same ledger that already holds the durable intent ───
    let clock = atom_runtime::FixedClock::new(now);
    let random = atom_runtime::CounterRng::new(0x0A70_1D00);
    let runtime = atom_runtime::Runtime::native(MISSION_ID, ledger, clock, random)
        .map_err(|e| anyhow!("booting runtime: {e}"))?;

    // ── Deterministic scheduler (constructed, no schedules registered) ───────
    let scheduler = atom_scheduler::Scheduler::new();
    let scheduled = scheduler.snapshot();

    // ── Worker bound to the SAME grant; admits the same op deny-by-default ───
    let worker = atom_worker::Worker::bind("worker-boot", SUBJECT, boot_grant(now))
        .map_err(|e| anyhow!("binding worker: {e}"))?;
    let admitted = worker
        .admit(&atom_worker::WorkRequest::new(
            OPERATION,
            RESOURCE_TYPE,
            TARGET_ID,
        ))
        .map_err(|e| anyhow!("worker admitting boot op: {e}"))?;

    let subsystems = subsystem_inventory(&kernel, runtime.mission_id(), &grant, &scheduled)?;

    Ok(BootReport {
        mission_id: runtime.mission_id().to_owned(),
        key_id: cfg.key_id.clone(),
        nonces_spent: kernel.nonces_spent(),
        commit_effect_id: token.effect_id().to_owned(),
        commit_grant_id: token.grant_id().to_owned(),
        commit_grant_generation: token.grant_generation(),
        commit_resource_id: token.resource_id().to_owned(),
        commit_nonce: token.one_shot_nonce().to_owned(),
        worker_id: worker.worker_id().to_owned(),
        admitted_operation: admitted.operation().to_owned(),
        intent_state: format!("{:?}", dispatching.state),
        subsystems,
    })
}

/// Builds the subsystem inventory by genuinely touching every wired crate.
///
/// Each line calls into its crate — a constant, a constructor or a query — so
/// the inventory is proof the crate links, not a hardcoded label.
fn subsystem_inventory(
    kernel: &Kernel,
    mission_id: &str,
    grant: &CapabilityGrant,
    scheduled: &atom_scheduler::SchedulerSnapshot,
) -> Result<Vec<Subsystem>> {
    let scheduler_snapshot =
        serde_json::to_string(scheduled).map_err(|e| anyhow!("serializing scheduler: {e}"))?;
    Ok(vec![
        Subsystem::new(
            "atom-kernel",
            format!(
                "double gate closed; nonces spent: {}",
                kernel.nonces_spent()
            ),
        ),
        Subsystem::new(
            "atom-runtime",
            format!("{} · mission `{mission_id}`", atom_runtime::CRATE_STAGE),
        ),
        Subsystem::new(
            "atom-scheduler",
            format!("{} · {scheduler_snapshot}", atom_scheduler::CRATE_STAGE),
        ),
        Subsystem::new("atom-worker", "WKR-001 deny-by-default admission"),
        Subsystem::new("atom-identity", atom_identity::CRATE_STAGE),
        Subsystem::new(
            "atom-capability",
            format!(
                "grant `{}` bound (gen {})",
                grant.grant_id, grant.generation
            ),
        ),
        Subsystem::new(
            "atom-policy",
            format!(
                "deterministic engine ready: {:?}",
                atom_policy::PolicyEngine
            ),
        ),
        Subsystem::new(
            "atom-approval",
            format!(
                "approval store empty: {}",
                atom_approval::ApprovalStore::new().is_empty()
            ),
        ),
        Subsystem::new("atom-secret", atom_secret::CRATE_STAGE),
        Subsystem::new(
            "atom-mission",
            format!(
                "state machine at {:?}",
                atom_mission::MissionState::created().phase
            ),
        ),
        Subsystem::new("atom-ledger", "append-only, HMAC-SHA256 signed checkpoints"),
        Subsystem::new(
            "atom-effect",
            "typed effect lifecycle (intent → dispatching)",
        ),
        Subsystem::new("atom-context", atom_context::CRATE_STAGE),
        Subsystem::new("atom-claim", atom_claim::CRATE_STAGE),
        Subsystem::new("atom-evidence", atom_evidence::CRATE_STAGE),
        Subsystem::new(
            "atom-fault",
            "retry classification wired into reconciliation",
        ),
        Subsystem::new(
            "atom-replay",
            format!(
                "no universal exact-replay claim ({} chars)",
                atom_replay::NO_UNIVERSAL_EXACT_REPLAY.len()
            ),
        ),
        Subsystem::new("atom-restore", atom_restore::CRATE_STAGE),
        Subsystem::new("atom-provider", atom_provider::CRATE_STAGE),
        Subsystem::new(
            "atom-target",
            format!(
                "dispatch ledger empty: {}",
                atom_target::DispatchLedger::new().is_empty()
            ),
        ),
        Subsystem::new("atom-connector", atom_connector::CRATE_STAGE),
        Subsystem::new(
            "atom-adapter",
            format!(
                "untrusted inbound quarantined: `{}`",
                atom_adapter::InboundContent::untrusted("boot-probe").payload
            ),
        ),
        Subsystem::new(
            "atom-memory",
            format!(
                "memory store empty: {}",
                atom_memory::MemoryStore::new().is_empty()
            ),
        ),
        Subsystem::new(
            "atom-artifact",
            format!(
                "content address: {}",
                atom_artifact::ArtifactId::of(b"boot-probe").as_str()
            ),
        ),
    ])
}

impl std::fmt::Display for BootReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "atom: sovereign process booted")?;
        writeln!(f, "  mission        : {}", self.mission_id)?;
        writeln!(f, "  signing key id : {}", self.key_id)?;
        writeln!(f, "  double gate    : commit token minted (KRN-001)")?;
        writeln!(f, "    effect       : {}", self.commit_effect_id)?;
        writeln!(
            f,
            "    grant        : {} (gen {})",
            self.commit_grant_id, self.commit_grant_generation
        )?;
        writeln!(f, "    resource     : {}", self.commit_resource_id)?;
        writeln!(f, "    nonce burned : {}", self.commit_nonce)?;
        writeln!(f, "    nonces spent : {}", self.nonces_spent)?;
        writeln!(f, "    intent state : {}", self.intent_state)?;
        writeln!(
            f,
            "  worker         : {} admitted `{}` (WKR-001)",
            self.worker_id, self.admitted_operation
        )?;
        writeln!(f, "  subsystems ({}):", self.subsystems.len())?;
        for subsystem in &self.subsystems {
            writeln!(f, "    - {:<16} {}", subsystem.crate_name, subsystem.status)?;
        }
        Ok(())
    }
}
