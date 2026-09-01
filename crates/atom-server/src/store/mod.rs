use std::path::Path;

use atom_ledger::{CheckpointSigner, HmacSha256Signer, Ledger};

/// Durable application state backed by the authoritative `atom_ledger` SQLite
/// store (ADR-004/006).
///
/// The ledger is the append-only store; live projections serve the HTTP read
/// path. Missions, effects, evidence and secret handles are projected here
/// from the ledger events that created them.
pub struct Store {
    pub ledger: Ledger,
    pub path: Option<std::path::PathBuf>,
    missions: Vec<serde_json::Value>,
    effects: Vec<serde_json::Value>,
    grants: Vec<serde_json::Value>,
    observations: Vec<serde_json::Value>,
    secret_handles: Vec<serde_json::Value>,
}

fn dev_signer() -> Box<dyn CheckpointSigner> {
    Box::new(HmacSha256Signer::new(
        "atom-server",
        b"00000000000000000000000000000000",
    ))
}

impl Store {
    pub fn open(path: Option<&Path>) -> anyhow::Result<Self> {
        let signer = dev_signer();
        let ledger = match path {
            Some(p) => Ledger::open(p, signer)?,
            None => Ledger::open_in_memory(signer)?,
        };
        let missions_key = std::ffi::OsString::from("none");
        let _ = missions_key;
        Ok(Self {
            ledger,
            path: path.map(|p| p.to_path_buf()),
            missions: Vec::new(),
            effects: Vec::new(),
            grants: Vec::new(),
            observations: Vec::new(),
            secret_handles: Vec::new(),
        })
    }

    pub fn open_in_memory(signer: Box<dyn CheckpointSigner>) -> anyhow::Result<Self> {
        let ledger = Ledger::open_in_memory(signer)?;
        Ok(Self {
            ledger,
            path: None,
            missions: Vec::new(),
            effects: Vec::new(),
            grants: Vec::new(),
            observations: Vec::new(),
            secret_handles: Vec::new(),
        })
    }

    pub fn missions(&self) -> &[serde_json::Value] {
        &self.missions
    }

    pub fn effects(&self) -> &[serde_json::Value] {
        &self.effects
    }

    pub fn grants(&self) -> &[serde_json::Value] {
        &self.grants
    }

    pub fn observations(&self) -> &[serde_json::Value] {
        &self.observations
    }

    pub fn secret_handles(&self) -> &[serde_json::Value] {
        &self.secret_handles
    }

    pub fn append_mission_created(&mut self, mission: &serde_json::Value) -> anyhow::Result<()> {
        let ts = chrono::Utc::now().timestamp();
        self.ledger.append(
            "mission",
            &serde_json::json!({ "event": "created", "mission": mission }),
            ts,
        )?;
        self.missions.push(mission.clone());
        Ok(())
    }

    pub fn update_mission(
        &mut self,
        mission_id: &str,
        mission: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let ts = chrono::Utc::now().timestamp();
        self.ledger.append(
            "mission",
            &serde_json::json!({ "event": "updated", "mission_id": mission_id, "mission": mission }),
            ts,
        )?;
        for m in self.missions.iter_mut() {
            if m["mission_id"] == mission_id {
                *m = mission.clone();
                return Ok(());
            }
        }
        self.missions.push(mission.clone());
        Ok(())
    }

    pub fn append_effect(&mut self, effect: &serde_json::Value) -> anyhow::Result<()> {
        let ts = chrono::Utc::now().timestamp();
        self.ledger.append(
            "effect",
            &serde_json::json!({ "event": "dispatched", "effect": effect }),
            ts,
        )?;
        self.effects.push(effect.clone());
        Ok(())
    }

    pub fn add_grant(&mut self, grant: &serde_json::Value) -> anyhow::Result<()> {
        self.grants.push(grant.clone());
        Ok(())
    }

    pub fn add_observation(&mut self, observation: &serde_json::Value) -> anyhow::Result<()> {
        let ts = chrono::Utc::now().timestamp();
        self.ledger.append(
            "evidence",
            &serde_json::json!({ "event": "observed", "observation": observation }),
            ts,
        )?;
        self.observations.push(observation.clone());
        Ok(())
    }

    pub fn add_secret_handle(&mut self, handle: &serde_json::Value) -> anyhow::Result<()> {
        let ts = chrono::Utc::now().timestamp();
        self.ledger.append(
            "secret",
            &serde_json::json!({ "event": "handle_created", "handle": handle }),
            ts,
        )?;
        self.secret_handles.push(handle.clone());
        Ok(())
    }
}
