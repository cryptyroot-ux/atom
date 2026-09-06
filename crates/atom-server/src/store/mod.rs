use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use atom_approval::{ApprovalAttestation, ApprovalGrant};
use atom_ledger::{CheckpointSigner, Hash, Ledger};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MISSION_STREAM: &str = "mission";
const EFFECT_STREAM: &str = "effect";
const GRANT_STREAM: &str = "grant";
const EVIDENCE_STREAM: &str = "evidence";
const SECRET_STREAM: &str = "secret";
const APPROVAL_STREAM: &str = "approval";
/// Planned host operations awaiting authorization (never executed by planning).
const HOST_PLAN_STREAM: &str = "host_plan";
/// Burned one-shot permit nonces: the durable half of the one-shot guarantee.
pub const NONCE_BURN_STREAM: &str = "nonce_burn";
/// Domain separation for approval attestations (P0-B): the signed digest binds
/// the approval bytes to attestation specifically, so a signature lifted from
/// any other sealed context (ledger checkpoints, sealed artifacts) can never
/// verify as an approval attestation, even under the same key.
const APPROVAL_ATTESTATION_DOMAIN: &str = "ATOM-APPROVAL-ATTESTATION-v1";

/// Whether a stored approval carries a verifiable daemon attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAttestationState {
    /// Stapled at issue and signature-verified against this daemon's key.
    Attested,
    /// Predates attestation (P0-B): usable until expiry, but never treated
    /// as attested. Accept-but-distinguish, never silently upgrade.
    LegacyUnsigned,
}

/// The daemon-signed digest over an approval's canonical bytes.
///
/// Domain-separated from every other sealed context in the repo, then hashed:
/// verifiers recompute exactly this from the stored record.
fn approval_attestation_digest(grant: &ApprovalGrant) -> anyhow::Result<Hash> {
    let bytes = grant
        .attestation_bytes()
        .context("canonicalising approval for attestation")?;
    let mut prefixed = APPROVAL_ATTESTATION_DOMAIN.as_bytes().to_vec();
    prefixed.extend_from_slice(&bytes);
    let digest = Sha256::digest(&prefixed);
    Hash::from_slice(&digest).context("hashing approval attestation bytes")
}

const SERVER_STREAMS: [&str; 8] = [
    MISSION_STREAM,
    EFFECT_STREAM,
    GRANT_STREAM,
    EVIDENCE_STREAM,
    SECRET_STREAM,
    APPROVAL_STREAM,
    HOST_PLAN_STREAM,
    NONCE_BURN_STREAM,
];

/// Durable application state backed by the authoritative `atom_ledger` SQLite
/// store (ADR-004/006).
///
/// The ledger is authoritative. The vectors below are deliberately disposable
/// projections rebuilt at startup from ledger events; they are never a second
/// persistence layer. A malformed event in one of the server-owned streams is
/// a startup error rather than a silently incomplete projection.
pub struct Store {
    pub ledger: Ledger,
    pub path: Option<PathBuf>,
    missions: Vec<Value>,
    effects: Vec<Value>,
    grants: Vec<Value>,
    observations: Vec<Value>,
    secret_handles: Vec<Value>,
    approvals: Vec<Value>,
    host_plans: Vec<Value>,
    burned_nonces: Vec<String>,
}

impl Store {
    /// Opens a durable SQLite-backed store and rebuilds every HTTP projection
    /// from its append-only ledger before serving a request.
    pub fn open(path: impl AsRef<Path>, signer: Box<dyn CheckpointSigner>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let ledger = Ledger::open(&path, signer)?;
        Self::from_ledger(ledger, Some(path))
    }

    /// Opens an explicitly ephemeral store for tests and local reference use.
    ///
    /// Production daemon startup must use [`Self::open`].
    pub fn open_in_memory(signer: Box<dyn CheckpointSigner>) -> anyhow::Result<Self> {
        let ledger = Ledger::open_in_memory(signer)?;
        Self::from_ledger(ledger, None)
    }

    fn from_ledger(ledger: Ledger, path: Option<PathBuf>) -> anyhow::Result<Self> {
        let mut store = Self {
            ledger,
            path,
            missions: Vec::new(),
            effects: Vec::new(),
            grants: Vec::new(),
            observations: Vec::new(),
            secret_handles: Vec::new(),
            approvals: Vec::new(),
            host_plans: Vec::new(),
            burned_nonces: Vec::new(),
        };
        store.rebuild_projections()?;
        Ok(store)
    }

    /// Rebuilds every live read projection solely from authoritative events.
    fn rebuild_projections(&mut self) -> anyhow::Result<()> {
        self.missions.clear();
        self.effects.clear();
        self.grants.clear();
        self.observations.clear();
        self.secret_handles.clear();
        self.approvals.clear();
        self.host_plans.clear();
        self.burned_nonces.clear();

        for stream_id in SERVER_STREAMS {
            let report = self
                .ledger
                .verify_stream(stream_id)
                .with_context(|| format!("verifying {stream_id} projection stream"))?;
            if !report.is_intact() {
                bail!(
                    "refusing to rebuild `{stream_id}` projection from an invalid ledger stream: {:?}",
                    report.findings
                );
            }
        }

        let mission_records = self
            .ledger
            .scan(MISSION_STREAM, 1)
            .context("scanning mission projection stream")?;
        for record in mission_records {
            self.apply_mission_event(&record.payload)?;
        }

        let effect_records = self
            .ledger
            .scan(EFFECT_STREAM, 1)
            .context("scanning effect projection stream")?;
        for record in effect_records {
            self.apply_effect_event(&record.payload)?;
        }

        let grant_records = self
            .ledger
            .scan(GRANT_STREAM, 1)
            .context("scanning grant projection stream")?;
        for record in grant_records {
            self.apply_grant_event(&record.payload)?;
        }

        let evidence_records = self
            .ledger
            .scan(EVIDENCE_STREAM, 1)
            .context("scanning evidence projection stream")?;
        for record in evidence_records {
            self.apply_observation_event(&record.payload)?;
        }

        let secret_records = self
            .ledger
            .scan(SECRET_STREAM, 1)
            .context("scanning secret-handle projection stream")?;
        for record in secret_records {
            self.apply_secret_handle_event(&record.payload)?;
        }

        for record in self.ledger.scan(APPROVAL_STREAM, 1)? {
            self.apply_approval_event(&record.payload)?;
        }

        for record in self.ledger.scan(HOST_PLAN_STREAM, 1)? {
            self.apply_host_plan_event(&record.payload)?;
        }

        // The one-shot memory: every nonce a prior life burned. A restarted
        // daemon rebuilds this before it will admit any crossing, so a permit
        // spent before the restart stays spent (ATOM-V4-EFX-004).
        for record in self.ledger.scan(NONCE_BURN_STREAM, 1)? {
            let nonce = string_field(&record.payload, "nonce", NONCE_BURN_STREAM)?;
            if !self.burned_nonces.iter().any(|seen| seen == nonce) {
                self.burned_nonces.push(nonce.to_owned());
            }
        }

        Ok(())
    }

    fn apply_mission_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, MISSION_STREAM)? {
            "created" => upsert(
                &mut self.missions,
                "mission_id",
                object_field(payload, "mission", MISSION_STREAM)?,
                "mission",
            ),
            "updated" => {
                let declared_id = string_field(payload, "mission_id", MISSION_STREAM)?;
                let mission = object_field(payload, "mission", MISSION_STREAM)?;
                let actual_id = identifier(mission, "mission_id", "mission")?;
                if declared_id != actual_id {
                    bail!(
                        "mission update in `{MISSION_STREAM}` declares `{declared_id}` but carries `{actual_id}`"
                    );
                }
                upsert(&mut self.missions, "mission_id", mission, "mission")
            }
            other => bail!("unknown `{MISSION_STREAM}` event `{other}`"),
        }
    }

    fn apply_effect_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, EFFECT_STREAM)? {
            "dispatched" => upsert(
                &mut self.effects,
                "effect_id",
                object_field(payload, "effect", EFFECT_STREAM)?,
                "effect",
            ),
            other => bail!("unknown `{EFFECT_STREAM}` event `{other}`"),
        }
    }

    fn apply_grant_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, GRANT_STREAM)? {
            "issued" => upsert(
                &mut self.grants,
                "grant_id",
                object_field(payload, "grant", GRANT_STREAM)?,
                "grant",
            ),
            other => bail!("unknown `{GRANT_STREAM}` event `{other}`"),
        }
    }

    fn apply_observation_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, EVIDENCE_STREAM)? {
            "observed" => upsert(
                &mut self.observations,
                "observation_id",
                object_field(payload, "observation", EVIDENCE_STREAM)?,
                "observation",
            ),
            other => bail!("unknown `{EVIDENCE_STREAM}` event `{other}`"),
        }
    }

    fn apply_secret_handle_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, SECRET_STREAM)? {
            "handle_created" => upsert(
                &mut self.secret_handles,
                "handle_id",
                object_field(payload, "handle", SECRET_STREAM)?,
                "secret handle",
            ),
            other => bail!("unknown `{SECRET_STREAM}` event `{other}`"),
        }
    }

    fn apply_approval_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, APPROVAL_STREAM)? {
            "issued" => {
                let grant = object_field(payload, "grant", APPROVAL_STREAM)?;
                self.check_stored_approval(grant)?;
                upsert(&mut self.approvals, "grant_id", grant, "approval grant")
            }
            "redeemed" => {
                let grant = object_field(payload, "grant", APPROVAL_STREAM)?;
                self.check_stored_approval(grant)?;
                upsert(&mut self.approvals, "grant_id", grant, "approval grant")?;
                Ok(())
            }
            other => bail!("unknown `{APPROVAL_STREAM}` event `{other}`"),
        }
    }

    fn apply_host_plan_event(&mut self, payload: &Value) -> anyhow::Result<()> {
        match event_name(payload, HOST_PLAN_STREAM)? {
            "planned" | "committed" | "refused" => upsert(
                &mut self.host_plans,
                "plan_id",
                object_field(payload, "plan", HOST_PLAN_STREAM)?,
                "host plan",
            ),
            other => bail!("unknown `{HOST_PLAN_STREAM}` event `{other}`"),
        }
    }

    pub fn missions(&self) -> &[Value] {
        &self.missions
    }

    pub fn effects(&self) -> &[Value] {
        &self.effects
    }

    pub fn effect(&self, effect_id: &str) -> Option<Value> {
        self.effects
            .iter()
            .find(|effect| effect["effect_id"] == effect_id)
            .cloned()
    }

    pub fn grants(&self) -> &[Value] {
        &self.grants
    }

    pub fn observations(&self) -> &[Value] {
        &self.observations
    }

    pub fn secret_handles(&self) -> &[Value] {
        &self.secret_handles
    }

    pub fn approvals(&self) -> &[Value] {
        &self.approvals
    }

    /// Planned host operations, oldest first. A plan is a *declaration*, never a
    /// crossing: nothing here has touched the host.
    pub fn host_plans(&self) -> &[Value] {
        &self.host_plans
    }

    /// One host plan by id.
    pub fn host_plan(&self, plan_id: &str) -> Option<Value> {
        self.host_plans
            .iter()
            .find(|plan| plan["plan_id"] == plan_id)
            .cloned()
    }

    /// Every one-shot nonce a prior life burned, rebuilt from the ledger.
    pub fn burned_nonces(&self) -> &[String] {
        &self.burned_nonces
    }

    /// Records a planned host operation (no host contact, no authority).
    pub fn add_host_plan(&mut self, plan: &Value) -> anyhow::Result<()> {
        ensure_identifier(plan, "plan_id", "host plan")?;
        self.ledger.append(
            HOST_PLAN_STREAM,
            &serde_json::json!({ "event": "planned", "plan": plan }),
            now_millis(),
        )?;
        upsert(&mut self.host_plans, "plan_id", plan, "host plan")
    }

    /// Records the terminal fate of a plan: `committed` after the privilege
    /// boundary admitted it, or `refused` with the denial that stopped it.
    pub fn resolve_host_plan(&mut self, plan: &Value, committed: bool) -> anyhow::Result<()> {
        ensure_identifier(plan, "plan_id", "host plan")?;
        let event = if committed { "committed" } else { "refused" };
        self.ledger.append(
            HOST_PLAN_STREAM,
            &serde_json::json!({ "event": event, "plan": plan }),
            now_millis(),
        )?;
        upsert(&mut self.host_plans, "plan_id", plan, "host plan")
    }

    /// Durably burns `nonce`, so the one-shot guarantee survives a restart.
    ///
    /// The append must commit before the caller may treat the permit as spent:
    /// a crash before it returns leaves the nonce unburned, which is the honest
    /// state (the crossing did not happen).
    pub fn burn_nonce(&mut self, nonce: &str) -> anyhow::Result<()> {
        if nonce.trim().is_empty() {
            bail!("refusing to burn an empty nonce");
        }
        if self.burned_nonces.iter().any(|seen| seen == nonce) {
            bail!("nonce `{nonce}` was already burned");
        }
        self.ledger.append(
            NONCE_BURN_STREAM,
            &serde_json::json!({ "nonce": nonce }),
            now_millis(),
        )?;
        self.burned_nonces.push(nonce.to_owned());
        Ok(())
    }

    pub fn add_approval(&mut self, grant: &Value) -> anyhow::Result<()> {
        ensure_identifier(grant, "grant_id", "approval grant")?;
        // Fail closed on malformed approvals: only a valid `ApprovalGrant`
        // shape may enter the ledger — never an arbitrary JSON object that
        // happens to carry a `grant_id`.
        let mut typed: ApprovalGrant = serde_json::from_value(grant.clone())
            .with_context(|| "approval grant is not a valid ApprovalGrant")?;
        // Daemon attestation (P0-B): staple this daemon's seal over the exact
        // bytes recorded, then store exactly what was sealed. Any caller
        // supplied attestation is replaced: this daemon attests what *it*
        // records, nothing else.
        let digest = approval_attestation_digest(&typed)?;
        let key_id = self.ledger.signer().key_id().to_owned();
        let signature = hex::encode(self.ledger.signer().sign(&digest));
        typed.attestation = Some(ApprovalAttestation { key_id, signature });
        let mut stored =
            serde_json::to_value(&typed).context("serializing attested approval grant")?;
        stored["redeemed"] = grant.get("redeemed").cloned().unwrap_or(Value::Bool(false));
        self.ledger.append(
            APPROVAL_STREAM,
            &serde_json::json!({"event":"issued", "grant": stored}),
            now_millis(),
        )?;
        upsert(&mut self.approvals, "grant_id", &stored, "approval grant")
    }

    /// Verifies the attestation on a typed approval.
    ///
    /// Returns [`ApprovalAttestationState::LegacyUnsigned`] for pre-P0-B
    /// records without an attestation, and fails closed on any present-but-bad
    /// attestation (wrong key, corrupt hex, signature mismatch): an
    /// untrustworthy approval must never redeem.
    pub fn check_approval_attestation(
        &self,
        grant: &ApprovalGrant,
    ) -> anyhow::Result<ApprovalAttestationState> {
        let Some(attestation) = grant.attestation.as_ref() else {
            return Ok(ApprovalAttestationState::LegacyUnsigned);
        };
        let digest = approval_attestation_digest(grant)?;
        let signature = hex::decode(attestation.signature.trim()).with_context(|| {
            format!(
                "approval `{}` carries a malformed attestation signature",
                grant.grant_id
            )
        })?;
        if self
            .ledger
            .signer()
            .verify(&attestation.key_id, &digest, &signature)
        {
            Ok(ApprovalAttestationState::Attested)
        } else {
            bail!(
                "approval `{}` failed attestation verification (key_id={})",
                grant.grant_id,
                attestation.key_id
            )
        }
    }

    /// Verifies one raw stored approval record: typed shape plus attestation.
    /// Used by projection rebuild so a tampered record fails the daemon at
    /// startup instead of entering the live projection.
    fn check_stored_approval(&self, grant: &Value) -> anyhow::Result<()> {
        let typed: ApprovalGrant = serde_json::from_value(grant.clone())
            .with_context(|| "stored approval grant is not a valid ApprovalGrant")?;
        self.check_approval_attestation(&typed)?;
        Ok(())
    }

    pub fn redeem_approval(&mut self, grant_id: &str) -> anyhow::Result<Value> {
        let Some(mut grant) = self
            .approvals
            .iter()
            .find(|v| v["grant_id"] == grant_id)
            .cloned()
        else {
            bail!("approval grant `{grant_id}` not found")
        };
        // Integrity before lifecycle: a tampered record is refused even when
        // it would otherwise redeem. Legacy records without an attestation
        // pass this check and keep their existing lifecycle behavior.
        let typed: ApprovalGrant = serde_json::from_value(grant.clone())
            .with_context(|| format!("stored approval grant `{grant_id}` is malformed"))?;
        self.check_approval_attestation(&typed)?;
        if grant["redeemed"].as_bool().unwrap_or(false) {
            bail!("approval grant `{grant_id}` already redeemed")
        }
        grant["redeemed"] = Value::Bool(true);
        self.ledger.append(
            APPROVAL_STREAM,
            &serde_json::json!({"event":"redeemed", "grant_id":grant_id, "grant":grant}),
            now_millis(),
        )?;
        upsert(&mut self.approvals, "grant_id", &grant, "approval grant")?;
        Ok(grant)
    }

    pub fn append_mission_created(&mut self, mission: &Value) -> anyhow::Result<()> {
        ensure_identifier(mission, "mission_id", "mission")?;
        self.ledger.append(
            MISSION_STREAM,
            &serde_json::json!({ "event": "created", "mission": mission }),
            now_millis(),
        )?;
        upsert(&mut self.missions, "mission_id", mission, "mission")
    }

    pub fn update_mission(&mut self, mission_id: &str, mission: &Value) -> anyhow::Result<()> {
        let actual_id = ensure_identifier(mission, "mission_id", "mission")?;
        if mission_id.trim().is_empty() || mission_id != actual_id {
            bail!(
                "mission update id `{mission_id}` does not match payload mission id `{actual_id}`"
            );
        }
        self.ledger.append(
            MISSION_STREAM,
            &serde_json::json!({ "event": "updated", "mission_id": mission_id, "mission": mission }),
            now_millis(),
        )?;
        upsert(&mut self.missions, "mission_id", mission, "mission")
    }

    pub fn append_effect(&mut self, effect: &Value) -> anyhow::Result<()> {
        ensure_identifier(effect, "effect_id", "effect")?;
        self.ledger.append(
            EFFECT_STREAM,
            &serde_json::json!({ "event": "dispatched", "effect": effect }),
            now_millis(),
        )?;
        upsert(&mut self.effects, "effect_id", effect, "effect")
    }

    pub fn add_grant(&mut self, grant: &Value) -> anyhow::Result<()> {
        ensure_identifier(grant, "grant_id", "grant")?;
        self.ledger.append(
            GRANT_STREAM,
            &serde_json::json!({ "event": "issued", "grant": grant }),
            now_millis(),
        )?;
        upsert(&mut self.grants, "grant_id", grant, "grant")
    }

    pub fn add_observation(&mut self, observation: &Value) -> anyhow::Result<()> {
        ensure_identifier(observation, "observation_id", "observation")?;
        self.ledger.append(
            EVIDENCE_STREAM,
            &serde_json::json!({ "event": "observed", "observation": observation }),
            now_millis(),
        )?;
        upsert(
            &mut self.observations,
            "observation_id",
            observation,
            "observation",
        )
    }

    pub fn add_secret_handle(&mut self, handle: &Value) -> anyhow::Result<()> {
        ensure_identifier(handle, "handle_id", "secret handle")?;
        self.ledger.append(
            SECRET_STREAM,
            &serde_json::json!({ "event": "handle_created", "handle": handle }),
            now_millis(),
        )?;
        upsert(
            &mut self.secret_handles,
            "handle_id",
            handle,
            "secret handle",
        )
    }

    /// Every ledger event across the server's streams, oldest first, as the
    /// wire `LedgerEvent` shape (event_id, event_type, payload_hash,
    /// previous_hash, timestamp). Returns `(events, checkpoint)` where
    /// `checkpoint` is the highest event sequence observed (0 when the ledger
    /// is empty). Events strictly after `since_checkpoint` are included.
    pub fn list_ledger_events(
        &self,
        since_checkpoint: Option<u64>,
    ) -> anyhow::Result<(Vec<Value>, u64)> {
        let since = since_checkpoint
            .map(|checkpoint| checkpoint + 1)
            .unwrap_or(1);
        let mut rows = Vec::new();
        let mut checkpoint = 0;
        for stream_id in SERVER_STREAMS {
            for record in self.ledger.scan(stream_id, since)? {
                let event = &record.event;
                let timestamp =
                    chrono::DateTime::from_timestamp_millis(event.ts).map(|time| time.to_rfc3339());
                rows.push(serde_json::json!({
                    "event_id": event.seq,
                    "event_type": event.stream_id,
                    "payload_hash": event.payload_digest.to_hex(),
                    "previous_hash": event.prev_hash.to_hex(),
                    "timestamp": timestamp,
                }));
                checkpoint = checkpoint.max(event.seq);
            }
        }
        rows.sort_by_key(|row| row["event_id"].as_u64().unwrap_or(0));
        Ok((rows, checkpoint))
    }
}

fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn event_name<'a>(payload: &'a Value, stream: &str) -> anyhow::Result<&'a str> {
    string_field(payload, "event", stream)
}

fn object_field<'a>(payload: &'a Value, field: &str, stream: &str) -> anyhow::Result<&'a Value> {
    payload
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| anyhow!("`{stream}` event is missing object field `{field}`"))
}

fn string_field<'a>(payload: &'a Value, field: &str, stream: &str) -> anyhow::Result<&'a str> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("`{stream}` event is missing non-empty string field `{field}`"))
}

fn identifier<'a>(value: &'a Value, field: &str, kind: &str) -> anyhow::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| anyhow!("{kind} is missing non-empty `{field}`"))
}

fn ensure_identifier<'a>(value: &'a Value, field: &str, kind: &str) -> anyhow::Result<&'a str> {
    identifier(value, field, kind)
}

fn upsert(
    projection: &mut Vec<Value>,
    id_field: &str,
    value: &Value,
    kind: &str,
) -> anyhow::Result<()> {
    let id = identifier(value, id_field, kind)?.to_owned();
    if let Some(existing) = projection
        .iter_mut()
        .find(|existing| existing.get(id_field).and_then(Value::as_str) == Some(id.as_str()))
    {
        *existing = value.clone();
    } else {
        projection.push(value.clone());
    }
    Ok(())
}
