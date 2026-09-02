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
//! may only move a mission `RUNNING` when it observed `READY`, so a naive crash
//! and restart can never double-execute a mission.
//!
//! Durable recovery (the executor's recovery store) is the *only* exception:
//! a `RUNNING` mission left behind by a dead daemon can be returned to `READY`
//! ([`Self::reclaim`]) because its next run replays a byte-identical,
//! deterministic snapshot, so re-execution produces the same honest terminal
//! outcome rather than a side effect.

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

    /// Returns every mission that can start a runtime run.
    ///
    /// HTTP-created missions begin at `CREATED`; a previously compiled mission
    /// may already be `READY`. Both are safe to claim because the runtime owns
    /// the authoritative lifecycle transition from its own `CREATED` state.
    pub async fn ready_mission_ids(&self) -> Vec<String> {
        let store = self.store.lock().await;
        store
            .missions()
            .iter()
            .filter(|m| {
                matches!(
                    m.get(PHASE).and_then(Value::as_str),
                    Some("CREATED" | "READY")
                )
            })
            .filter_map(|m| m.get(MISSION_ID).and_then(Value::as_str).map(String::from))
            .collect()
    }

    /// Idempotently claims one mission (`READY → RUNNING`) if it is claimable.
    ///
    /// Pass the `mission_id` observed by [`Self::ready_mission_ids`]; the claim
    /// only succeeds when the mission is still `CREATED` or `READY` at claim
    /// time (CAS semantics inside the single store lock), making
    /// double-execution across a restart impossible.
    pub async fn claim(&self, mission_id: &str) -> Result<ClaimOutcome, TransitionError> {
        let mut store = self.store.lock().await;
        let Some(mut mission) = find_mission(&store, mission_id) else {
            return Ok(ClaimOutcome::Missing);
        };

        let phase = mission
            .get(PHASE)
            .and_then(Value::as_str)
            .unwrap_or("CREATED");
        if !matches!(phase, "CREATED" | "READY") {
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

    /// Returns the durable phase of `mission_id`, or `None` when missing.
    pub async fn phase_of(
        &self,
        mission_id: &str,
    ) -> Result<Option<MissionPhaseTag>, TransitionError> {
        let store = self.store.lock().await;
        let Some(mission) = find_mission(&store, mission_id) else {
            return Ok(None);
        };
        Ok(Some(match match_phase(&mission) {
            Some(p) => p,
            None => return Ok(None),
        }))
    }

    /// Returns every mission that a live executor currently owns.
    ///
    /// A crashed daemon can abandon missions in `RUNNING` or `VERIFYING`; the
    /// recovery scan needs this view to reclaim them (with or without a
    /// snapshot, see [`Self::reclaim`]).
    pub async fn claimed_mission_ids(&self) -> Vec<String> {
        let store = self.store.lock().await;
        store
            .missions()
            .iter()
            .filter(|m| {
                matches!(
                    match_phase(m),
                    Some(MissionPhaseTag::Running | MissionPhaseTag::Verifying)
                )
            })
            .filter_map(|m| m.get(MISSION_ID).and_then(Value::as_str).map(String::from))
            .collect()
    }

    /// Recovers a `RUNNING` (or `VERIFYING`) mission abandoned by a crashed
    /// daemon by returning it to `READY` so the executive pump can re-claim and
    /// replay it.
    ///
    /// This is safe *only* because the executor's recovery store replays the
    /// mission from a deterministic snapshot. Two crash windows are covered:
    ///
    /// * before the snapshot was written (claimed but never executed) — nothing
    ///   deterministic was lost, so a plain reset suffices;
    /// * after the snapshot was written — the replay is byte-identical.
    ///
    /// The caller must have confirmed a snapshot exists before calling this (or
    /// the recovery budget is handled by the executor). The queue records the
    /// transition for auditability.
    pub async fn reclaim(&self, mission_id: &str) -> Result<ClaimOutcome, TransitionError> {
        let mut store = self.store.lock().await;
        let Some(mut mission) = find_mission(&store, mission_id) else {
            return Ok(ClaimOutcome::Missing);
        };
        if !matches!(
            match_phase(&mission),
            Some(MissionPhaseTag::Running | MissionPhaseTag::Verifying)
        ) {
            return Ok(ClaimOutcome::NotReady);
        }
        mission[PHASE] = Value::String(MissionPhaseTag::Ready.as_str().to_owned());
        replace_condition(&mut mission, "NORMAL");
        mission[OUTCOME] = Value::Null;
        touch_updated_at(&mut mission);
        store
            .update_mission(mission_id, &mission)
            .map_err(TransitionError::Store)?;
        Ok(ClaimOutcome::Claimed)
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

/// Maps the stored phase string onto a [`MissionPhaseTag`].
fn match_phase(mission: &Value) -> Option<MissionPhaseTag> {
    match mission.get(PHASE).and_then(Value::as_str) {
        Some("CREATED") => Some(MissionPhaseTag::Created),
        Some("COMPILED") => Some(MissionPhaseTag::Compiled),
        Some("READY") => Some(MissionPhaseTag::Ready),
        Some("RUNNING") => Some(MissionPhaseTag::Running),
        Some("VERIFYING") => Some(MissionPhaseTag::Verifying),
        Some("TERMINAL") => Some(MissionPhaseTag::Terminal),
        _ => None,
    }
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
    async fn claim_moves_http_created_mission_to_running_once() {
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&serde_json::json!({
                "mission_id": "m-created",
                "state": "CREATED",
                "phase": "CREATED",
                "condition": "NORMAL",
                "outcome": null,
                "goal": "drive an HTTP-created mission"
            }))
            .unwrap();
        }
        let q = MissionQueue::new(store.clone());

        assert_eq!(q.claim("m-created").await.unwrap(), ClaimOutcome::Claimed);
        assert_eq!(q.claim("m-created").await.unwrap(), ClaimOutcome::NotReady);
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
    async fn reclaim_returns_running_to_ready_exactly_once() {
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-reclaim")).unwrap();
        }
        let q = MissionQueue::new(store.clone());
        assert_eq!(q.claim("m-reclaim").await.unwrap(), ClaimOutcome::Claimed);

        // A crashed executor's RUNNING mission is reclaimable back to READY...
        assert_eq!(q.reclaim("m-reclaim").await.unwrap(), ClaimOutcome::Claimed);
        // ...exactly once: a second reclaim sees READY, not RUNNING.
        assert_eq!(
            q.reclaim("m-reclaim").await.unwrap(),
            ClaimOutcome::NotReady
        );

        // Reclaiming non-RUNNING missions is rejected.
        assert_eq!(
            q.reclaim("m-reclaim").await.unwrap(),
            ClaimOutcome::NotReady
        );
        assert_eq!(q.reclaim("missing").await.unwrap(), ClaimOutcome::Missing);

        let s = store.lock().await;
        let m = s
            .missions()
            .iter()
            .find(|m| m["mission_id"] == "m-reclaim")
            .unwrap();
        assert_eq!(m["phase"], "READY");
    }

    #[tokio::test]
    async fn phase_of_reflects_lifecycle() {
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-phase")).unwrap();
        }
        let q = MissionQueue::new(store.clone());
        assert_eq!(
            q.phase_of("m-phase").await.unwrap(),
            Some(MissionPhaseTag::Ready)
        );
        q.claim("m-phase").await.unwrap();
        assert_eq!(
            q.phase_of("m-phase").await.unwrap(),
            Some(MissionPhaseTag::Running)
        );
        assert_eq!(q.phase_of("missing").await.unwrap(), None);
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
