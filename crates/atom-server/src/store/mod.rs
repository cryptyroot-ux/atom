use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use atom_ledger::{CheckpointSigner, Ledger};
use serde_json::Value;

const MISSION_STREAM: &str = "mission";
const EFFECT_STREAM: &str = "effect";
const GRANT_STREAM: &str = "grant";
const EVIDENCE_STREAM: &str = "evidence";
const SECRET_STREAM: &str = "secret";
const APPROVAL_STREAM: &str = "approval";
const SERVER_STREAMS: [&str; 6] = [
    MISSION_STREAM,
    EFFECT_STREAM,
    GRANT_STREAM,
    EVIDENCE_STREAM,
    SECRET_STREAM,
    APPROVAL_STREAM,
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
            "issued" => upsert(
                &mut self.approvals,
                "grant_id",
                object_field(payload, "grant", APPROVAL_STREAM)?,
                "approval grant",
            ),
            other => bail!("unknown `{APPROVAL_STREAM}` event `{other}`"),
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

    pub fn add_approval(&mut self, grant: &Value) -> anyhow::Result<()> {
        ensure_identifier(grant, "grant_id", "approval grant")?;
        self.ledger.append(
            APPROVAL_STREAM,
            &serde_json::json!({"event":"issued", "grant": grant}),
            now_millis(),
        )?;
        upsert(&mut self.approvals, "grant_id", grant, "approval grant")
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
