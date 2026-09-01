//! Durable mission-queue status machine and idempotent claiming.
//!
//! A mission is stored as a JSON object carrying three canonical lifecycle
//! fields alongside its legacy `state` value:
//!
//! * `phase`     — one of [`MissionPhaseTag`] (CREATED … TERMINAL)
//! * `condition` — one of [`atom_mission::MissionCondition`]'s strings
//! * `outcome`   — a terminal [`atom_mission::MissionOutcome`] or absent/null
//!
//! The invariant mirrors [`atom_mission::MissionState::validate`]: an `outcome`
//! is legal only when `phase == TERMINAL`. Claims are idempotent — an executor
//! may only move a mission `RUNNING` when it observed `READY`, so a crash and
//! restart can never double-execute a mission.

use std::sync::Arc;

use anyhow::anyhow;
use serde_json::Value;
use tokio::sync::Mutex;

use atom_server::store::Store;

/// Canonical mission phases, string-identical to `atom-mission::MissionPhase`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissionPhaseTag {
    Created,
    Compiled,
    Ready,
    Running,
    Verifying,
    Terminal,
}

impl MissionPhaseTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Compiled => "COMPILED",
            Self::Ready => "READY",
            Self::Running => "RUNNING",
            Self::Verifying => "VERIFYING",
            Self::Terminal => "TERMINAL",
        }
    }
}

/// Result of trying to claim a queued mission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The mission was claimed: moved READY → RUNNING.
    Claimed,
    /// The mission was not in READY phase (already running/terminal/failed).
    NotReady,
    /// The mission does not exist in the store.
    Missing,
}

/// A completed run and how the sovereign runtime reached it.
#[derive(Clone, Debug)]
pub struct RunResult {
    pub mission_id: String,
    pub phase: &'static str,
    pub outcome: Option<&'static str>,
    pub steps: usize,
    /// Free-form human-readable reason (condition/hold), if any.
    pub reason: Option<String>,
}

/// Errors raised while transitioning a mission's durable phase.
#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("mission transition failed: {0}")]
    Store(#[from] anyhow::Error),
}

const PHASE: &str = "phase";
const CONDITION: &str = "condition";
const OUTCOME: &str = "outcome";
const MISSION_ID: &str = "mission_id";

/// A durable mission queue over the server store.
///
/// All transitions happen inside a single `Arc<Mutex<Store>>` lock, which is
/// the same lock held by the HTTP write path, so a claim is atomically
/// serialised against creators and cancellers.
pub struct MissionQueue {
    store: Arc<Mutex<Store>>,
}

impl MissionQueue {
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }

    /// Returns every mission currently in `READY` phase.
    pub async fn ready_mission_ids(&self) -> Vec<String> {
        let store = self.store.lock().await;
        store
            .missions()
            .iter()
            .filter(|m| m.get(PHASE).and_then(Value::as_str) == Some("READY"))
            .filter_map(|m| m.get(MISSION_ID).and_then(Value::as_str).map(String::from))
            .collect()
    }

    /// Idempotently claims one mission (`READY → RUNNING`) if it is claimable.
    ///
    /// Pass the `mission_id` observed in `READY`; the claim only succeeds when
    /// the mission is still `READY` at claim time (CAS semantics inside the
    /// single store lock), making double-execution across a restart impossible.
    pub async fn claim(&self, mission_id: &str) -> Result<ClaimOutcome, TransitionError> {
        let mut store = self.store.lock().await;
        let Some(mut mission) = find_mission(&store, mission_id) else {
            return Ok(ClaimOutcome::Missing);
        };

        let phase = mission
            .get(PHASE)
            .and_then(Value::as_str)
            .unwrap_or("CREATED");
        if phase != MissionPhaseTag::Ready.as_str() {
            return Ok(ClaimOutcome::NotReady);
        }

        mission[PHASE] = Value::String(MissionPhaseTag::Running.as_str().to_owned());
        replace_condition(&mut mission, "NORMAL");
        mission[OUTCOME] = Value::Null;
        touch_updated_at(&mut mission);
        store
            .update_mission(mission_id, &mission)
            .map_err(TransitionError::Store)?;

        Ok(ClaimOutcome::Claimed)
    }

    /// Advances a claimed mission to `VERIFYING`.
    pub async fn verifying(
        &self,
        mission_id: &str,
        condition: &str,
    ) -> Result<(), TransitionError> {
        self.transition_phase(mission_id, MissionPhaseTag::Verifying, condition, None)
            .await
            .map(|_| ())
    }

    /// Marks a mission `TERMINAL` with the given outcome.
    pub async fn terminal(
        &self,
        mission_id: &str,
        outcome: &str,
        reason: Option<String>,
    ) -> Result<(), TransitionError> {
        self.transition_phase(
            mission_id,
            MissionPhaseTag::Terminal,
            "NORMAL",
            Some(outcome),
        )
        .await
        .map(|_| ())
        .map_err(|mut e| {
            if let Some(r) = reason {
                e = TransitionError::Store(anyhow!("{r}: {}", store_msg(&e)));
            }
            e
        })
    }

    async fn transition_phase(
        &self,
        mission_id: &str,
        phase: MissionPhaseTag,
        condition: &str,
        outcome: Option<&str>,
    ) -> Result<Option<()>, TransitionError> {
        let mut store = self.store.lock().await;
        let Some(mut mission) = find_mission(&store, mission_id) else {
            return Ok(None);
        };

        if phase == MissionPhaseTag::Terminal {
            mission[OUTCOME] = Value::String(outcome.unwrap_or("FAILED").to_owned());
        }
        mission[PHASE] = Value::String(phase.as_str().to_owned());
        replace_condition(&mut mission, condition);
        touch_updated_at(&mut mission);
        store
            .update_mission(mission_id, &mission)
            .map_err(TransitionError::Store)?;
        Ok(Some(()))
    }
}

fn store_msg(e: &TransitionError) -> String {
    match e {
        TransitionError::Store(inner) => inner.to_string(),
    }
}

fn find_mission(store: &Store, mission_id: &str) -> Option<Value> {
    // `Store` exposes missions() as a slice; clone the matching object so the
    // immutable store borrow ends before any follow-up mutable write.
    store
        .missions()
        .iter()
        .find(|m| m.get(MISSION_ID).and_then(Value::as_str) == Some(mission_id))
        .cloned()
}

fn replace_condition(mission: &mut Value, condition: &str) {
    mission[CONDITION] = Value::String(condition.to_owned());
}

fn touch_updated_at(mission: &mut Value) {
    if let Value::Object(map) = mission {
        map.insert("updated_at".to_owned(), Value::String(iso_now()));
    }
}

fn iso_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_ledger::HmacSha256Signer;
    use atom_server::store::Store;

    fn signer() -> Box<dyn atom_ledger::CheckpointSigner> {
        Box::new(HmacSha256Signer::new(
            "queue-test",
            b"queue-test-signing-key",
        ))
    }

    fn mission(id: &str) -> Value {
        serde_json::json!({
            "mission_id": id,
            "state": "CREATED",
            "phase": "READY",
            "condition": "NORMAL",
            "outcome": null,
            "goal": "drive a mission",
            "updated_at": "now"
        })
    }

    #[tokio::test]
    async fn claim_moves_ready_to_running_once() {
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m1")).unwrap();
        }
        let q = MissionQueue::new(store.clone());

        assert_eq!(q.claim("m1").await.unwrap(), ClaimOutcome::Claimed);
        // Second claim must fail: already RUNNING.
        assert_eq!(q.claim("m1").await.unwrap(), ClaimOutcome::NotReady);

        let s = store.lock().await;
        let m = s
            .missions()
            .iter()
            .find(|m| m["mission_id"] == "m1")
            .unwrap();
        assert_eq!(m["phase"], "RUNNING");
    }

    #[tokio::test]
    async fn claim_is_idempotent_across_restart() {
        // Simulate: executor A claims and dies before finishing. A fresh queue
        // over the same store must NOT be able to claim the mission again.
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-restart")).unwrap();
        }
        let q1 = MissionQueue::new(store.clone());
        assert_eq!(q1.claim("m-restart").await.unwrap(), ClaimOutcome::Claimed);

        // "restart": a new queue over the same persistent store.
        let q2 = MissionQueue::new(store.clone());
        assert_eq!(q2.claim("m-restart").await.unwrap(), ClaimOutcome::NotReady);
    }

    #[tokio::test]
    async fn terminal_requires_outcome_and_reads_back() {
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m2")).unwrap();
        }
        let q = MissionQueue::new(store.clone());
        q.claim("m2").await.unwrap();
        q.terminal("m2", "SUCCEEDED", Some("all activities completed".into()))
            .await
            .unwrap();

        let s = store.lock().await;
        let m = s
            .missions()
            .iter()
            .find(|m| m["mission_id"] == "m2")
            .unwrap();
        assert_eq!(m["phase"], "TERMINAL");
        assert_eq!(m["outcome"], "SUCCEEDED");
    }
}
