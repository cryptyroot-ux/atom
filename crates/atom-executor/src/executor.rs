//! The persistent daemon execution spine.
//!
//! [`AtomExecutor`] owns the mission queue and drives each claimed mission
//! through the sovereign runtime until it reaches a durable, honest terminal
//! state — recording every phase transition on the server ledger.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::sync::{watch, Mutex};

use atom_ledger::{CheckpointSigner, HmacSha256Signer, Ledger};
use atom_provider::ProviderCognition;
use atom_runtime::{Clock, CounterRng, FixedClock, ReferenceActivityPort, RunStatus};
use atom_server::store::Store;

use crate::provider::{CachedProvider, HttpProposalClient, ProviderConfig, ProviderPlan};
use crate::queue::{ClaimOutcome, MissionPhaseTag, MissionQueue, RunResult};
use crate::recovery::{RecoveryStore, MAX_RECOVERY_ATTEMPTS};

/// The deterministic cognition seed used for every fresh run. Persisted in the
/// recovery snapshot so a replay uses the identical sequence.
const COGNITION_SEED: u64 = 0xDAE0_0002;

/// Best-effort host identifier recorded on recovery snapshots for multi-host
/// forensic triage.
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".to_owned())
}

/// Tuning knobs for the execution spine.
#[derive(Clone, Debug)]
pub struct ExecutorConfig {
    /// How long the loop sleeps between queue polls when idle.
    pub poll_interval: Duration,
    /// Hard cap on runtime steps per mission before it is declared non-terminating.
    pub max_steps: usize,
    /// Signing key used for each mission's sovereign runtime ledger.
    pub signing_key: String,
    /// HMAC secret used for each mission's sovereign runtime ledger.
    pub signing_secret: Vec<u8>,
    /// Optional HTTP model-provider cognition backend (disabled by default).
    pub provider: ProviderConfig,
    /// Optional durable-recovery snapshot directory. When set, crashes can be
    /// replayed deterministically instead of leaving `RUNNING` missions stuck.
    pub recovery_dir: Option<PathBuf>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            max_steps: 256,
            signing_key: "atom-executor".to_owned(),
            signing_secret: b"atom-executor-daemon-key".to_vec(),
            provider: ProviderConfig::default(),
            recovery_dir: None,
        }
    }
}

/// A persistent mission-queue driver.
pub struct AtomExecutor {
    queue: MissionQueue,
    config: ExecutorConfig,
    recovery: Option<RecoveryStore>,
    shutdown_tx: watch::Sender<bool>,
}

impl AtomExecutor {
    pub fn new(store: Arc<Mutex<Store>>, config: ExecutorConfig) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let recovery = config
            .recovery_dir
            .as_ref()
            .and_then(|dir| RecoveryStore::new(dir, hostname()).ok());
        Self {
            queue: MissionQueue::new(store),
            config,
            recovery,
            shutdown_tx,
        }
    }

    /// Requests a graceful stop after the current queue pass.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Drives one claimable mission to its honest terminal state.
    ///
    /// Public for deterministic unit testing; the daemon loop calls this for
    /// each `READY` mission it observes.
    pub async fn drive_once(&self, mission_id: &str) -> anyhow::Result<RunResult> {
        match self.queue.claim(mission_id).await? {
            ClaimOutcome::Claimed => {}
            ClaimOutcome::NotReady => {
                return Ok(RunResult {
                    mission_id: mission_id.to_owned(),
                    phase: "READY",
                    outcome: None,
                    steps: 0,
                    reason: None,
                })
            }
            ClaimOutcome::Missing => {
                return Err(anyhow!("mission `{mission_id}` missing from store"));
            }
        }

        let result = self.run_mission(mission_id).await;

        // Always seal a durable terminal status, reflecting the true runtime
        // outcome (never a fabricated success).
        match &result.outcome {
            Some(outcome) => {
                self.queue
                    .terminal(mission_id, outcome, result.reason.clone())
                    .await
                    .with_context(|| format!("sealing terminal outcome for `{mission_id}`"))?;
            }
            None => {
                self.queue
                    .terminal(mission_id, "UNSATISFIABLE", result.reason.clone())
                    .await
                    .with_context(|| format!("sealing unsatisfiable outcome for `{mission_id}`"))?;
            }
        }

        // The mission reached a durable terminal state; the snapshot has done
        // its job and must not be replayed (or crash-loop-reclaimed) again.
        if let Some(recovery) = &self.recovery {
            let _ = recovery.delete(mission_id).await;
        }

        Ok(result)
    }

    /// Runs the mission through the sovereign runtime and reports the outcome.
    async fn run_mission(&self, mission_id: &str) -> RunResult {
        let signer: Box<dyn CheckpointSigner> = Box::new(HmacSha256Signer::new(
            &self.config.signing_key,
            &self.config.signing_secret,
        ));
        let ledger = match Ledger::open_in_memory(signer) {
            Ok(l) => l,
            Err(e) => {
                return RunResult {
                    mission_id: mission_id.to_owned(),
                    phase: "VERIFYING",
                    outcome: None,
                    steps: 0,
                    reason: Some(format!("ledger open failed: {e}")),
                }
            }
        };

        // Recover the deterministic inputs from a crash snapshot when one
        // exists; otherwise start fresh and record them for the next crash.
        let prior = match &self.recovery {
            Some(recovery) => recovery.load(mission_id).await.ok().flatten(),
            None => None,
        };
        let clock = prior
            .as_ref()
            .map(|s| FixedClock::new(s.clock_start()))
            .unwrap_or_else(|| FixedClock::new(chrono::Utc::now()));
        let random = prior
            .as_ref()
            .map(|s| CounterRng::new(s.cognition_seed()))
            .unwrap_or_else(|| CounterRng::new(COGNITION_SEED));

        // Build a mission-specific cognition backend. When a model provider is
        // configured, fetch its plan once (asynchronously, before the runtime
        // loop) and replay it through a deterministic cached provider. The plan
        // is snapshotted for crash recovery; on replay it is rebuilt in-process
        // instead of re-querying the gateway. On any provider failure we refuse
        // to fabricate a run: the mission is sealed honestly as unsatisfiable
        // below.
        if self.config.provider.enabled {
            let plan = match prior {
                Some(snapshot) => Some(ProviderPlan::from_commands(
                    mission_id,
                    snapshot.commands().to_vec(),
                )),
                None => {
                    let client = match HttpProposalClient::new(self.config.provider.clone()) {
                        Ok(client) => client,
                        Err(e) => {
                            return RunResult {
                                mission_id: mission_id.to_owned(),
                                phase: "VERIFYING",
                                outcome: None,
                                steps: 0,
                                reason: Some(format!("provider configuration failed: {e}")),
                            };
                        }
                    };
                    match client.propose(mission_id, "CREATED").await {
                        Ok(plan) => {
                            if let Some(recovery) = &self.recovery {
                                let commands: Vec<_> = plan
                                    .proposals()
                                    .iter()
                                    .filter_map(|p| match p {
                                        atom_provider::ProviderProposal::Activity { command } => {
                                            Some(*command)
                                        }
                                        _ => None,
                                    })
                                    .collect();
                                let _ = recovery
                                    .put(mission_id, commands, clock.now(), COGNITION_SEED)
                                    .await;
                            }
                            Some(plan)
                        }
                        Err(e) => {
                            return RunResult {
                                mission_id: mission_id.to_owned(),
                                phase: "VERIFYING",
                                outcome: None,
                                steps: 0,
                                reason: Some(format!("provider plan failed: {e}")),
                            };
                        }
                    }
                }
            };
            let plan = match plan {
                Some(plan) => plan,
                None => unreachable!("plan is always Some for provider path"),
            };
            let runtime = match atom_runtime::Runtime::new(
                mission_id,
                ledger,
                clock,
                random,
                ProviderCognition::new(CachedProvider::new(plan)),
            ) {
                Ok(r) => r,
                Err(e) => {
                    return RunResult {
                        mission_id: mission_id.to_owned(),
                        phase: "VERIFYING",
                        outcome: None,
                        steps: 0,
                        reason: Some(format!("runtime boot failed: {e}")),
                    };
                }
            };
            return self.drive_runtime(mission_id, runtime);
        }

        let runtime = match atom_runtime::Runtime::native(mission_id, ledger, clock, random) {
            Ok(r) => r,
            Err(e) => {
                return RunResult {
                    mission_id: mission_id.to_owned(),
                    phase: "VERIFYING",
                    outcome: None,
                    steps: 0,
                    reason: Some(format!("runtime boot failed: {e}")),
                };
            }
        };
        if prior.is_none() {
            if let Some(recovery) = &self.recovery {
                // Native runs are deterministic too: snapshot the clock so a
                // crash mid-run replays byte-identically.
                let _ = recovery
                    .put(mission_id, Vec::new(), clock.now(), COGNITION_SEED)
                    .await;
            }
        }
        self.drive_runtime(mission_id, runtime)
    }

    /// Drives one runtime to a terminal status and maps it onto a `RunResult`.
    fn drive_runtime<N>(
        &self,
        mission_id: &str,
        mut runtime: atom_runtime::Runtime<FixedClock, CounterRng, N>,
    ) -> RunResult
    where
        N: atom_runtime::Cognition,
    {
        let mut port = ReferenceActivityPort::default();
        match runtime.run_until_terminal(&mut port, self.config.max_steps) {
            Ok(RunStatus::Terminal { state, steps }) => {
                let outcome = state.outcome.map(|o| o.as_str()).unwrap_or("SUCCEEDED");
                RunResult {
                    mission_id: mission_id.to_owned(),
                    phase: "TERMINAL",
                    outcome: Some(outcome),
                    steps,
                    reason: None,
                }
            }
            Ok(RunStatus::BlockedOnUnknown { effect_id, .. }) => RunResult {
                mission_id: mission_id.to_owned(),
                phase: "VERIFYING",
                outcome: None,
                steps: 0,
                reason: Some(format!("unknown outcome on effect `{effect_id}`")),
            },
            Ok(RunStatus::Blocked { reason, .. }) => RunResult {
                mission_id: mission_id.to_owned(),
                phase: "VERIFYING",
                outcome: None,
                steps: 0,
                reason: Some(format!("blocked: {reason:?}")),
            },
            Ok(RunStatus::Exhausted { steps, .. }) => RunResult {
                mission_id: mission_id.to_owned(),
                phase: "VERIFYING",
                outcome: None,
                steps,
                reason: Some("runtime step budget exhausted".to_owned()),
            },
            Err(e) => RunResult {
                mission_id: mission_id.to_owned(),
                phase: "VERIFYING",
                outcome: None,
                steps: 0,
                reason: Some(format!("runtime error: {e}")),
            },
        }
    }

    /// The daemon loop: recover any crashed runs, then poll the queue and drive
    /// every `READY` mission until a graceful shutdown is requested.
    pub async fn run(self) {
        let _ = self.recover_crashed().await;
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = self.pump() => {}
            }
        }
    }

    /// Scans the recovery directory on startup and resumes any deterministic
    /// run interrupted by a crash (or a hostile `SIGKILL`).
    ///
    /// A mission is *only* re-claimed when its snapshot is available (making the
    /// replay byte-identical) and the recovery budget is not exhausted. Missions
    /// past the budget are sealed terminal with an honest failure instead of
    /// looping forever — the crash-loop breaker.
    async fn recover_crashed(&self) -> anyhow::Result<()> {
        let Some(recovery) = &self.recovery else {
            return Ok(());
        };

        // Every snapshot is a deterministic starting point; reconcile it with
        // the durable queue phase.
        for mission_id in recovery.mission_ids().await? {
            let Some(snapshot) = recovery.load(&mission_id).await? else {
                continue;
            };
            let phase = self.queue.phase_of(&mission_id).await?;
            match phase {
                Some(MissionPhaseTag::Running) => {
                    if snapshot.budget_exhausted() {
                        // Crash-loop breaker: refuse to replay forever. The
                        // outcome is honest: this run never reached terminal.
                        self.queue
                            .terminal(
                                &mission_id,
                                "FAILED",
                                Some(format!(
                                    "recovery budget ({MAX_RECOVERY_ATTEMPTS} attempts) exhausted"
                                )),
                            )
                            .await?;
                        recovery.delete(&mission_id).await?;
                    } else {
                        let bumped = recovery.mark_reclaimed(&snapshot).await?;
                        self.queue.reclaim(&mission_id).await?;
                        eprintln!(
                            "atom: reclaimed crashed mission {mission_id} for deterministic replay (attempt {})",
                            bumped.attempts()
                        );
                    }
                }
                // Already terminal, or abandoned mid-creation: keep the queue
                // authoritative and drop the orphaned pointing snapshot.
                Some(MissionPhaseTag::Verifying) => {
                    self.queue.reclaim(&mission_id).await?;
                }
                _ => {
                    recovery.delete(&mission_id).await?;
                }
            }
        }

        // Snapshots are written *after* a mission is claimed, so a crash in the
        // window between claim and `put` leaves a `RUNNING`/`VERIFYING` mission
        // with no snapshot. Such a run never executed (nothing was snapshotted),
        // so a plain reset is safe and prevents the mission from hanging forever.
        self.recover_snapshotless_claims(recovery).await
    }

    async fn recover_snapshotless_claims(&self, recovery: &RecoveryStore) -> anyhow::Result<()> {
        let snapshotted: std::collections::HashSet<String> =
            recovery.mission_ids().await?.into_iter().collect();
        for mission_id in self.queue.claimed_mission_ids().await {
            if snapshotted.contains(&mission_id) {
                continue;
            }
            if let Err(e) = self.queue.reclaim(&mission_id).await {
                eprintln!("atom: could not reclaim snapshot-less mission {mission_id}: {e}");
            }
        }
        Ok(())
    }

    async fn pump(&self) {
        let ready = self.queue.ready_mission_ids().await;
        for mission_id in ready {
            if self.is_shutting_down() {
                break;
            }
            let _ = self.drive_once(&mission_id).await;
        }
        tokio::time::sleep(self.config.poll_interval).await;
    }

    fn is_shutting_down(&self) -> bool {
        *self.shutdown_tx.subscribe().borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_ledger::HmacSha256Signer;
    use chrono::{TimeZone, Utc};

    fn signer() -> Box<dyn atom_ledger::CheckpointSigner> {
        Box::new(HmacSha256Signer::new(
            "executor-test",
            b"executor-test-signing-key",
        ))
    }

    fn mission(id: &str) -> serde_json::Value {
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

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("atom-executor-test-{}-{name}", std::process::id()))
    }

    fn executor_with(store: Arc<Mutex<Store>>, recovery_dir: Option<PathBuf>) -> AtomExecutor {
        let config = ExecutorConfig {
            recovery_dir,
            ..ExecutorConfig::default()
        };
        AtomExecutor::new(store, config)
    }

    #[tokio::test]
    async fn crashed_running_mission_is_reclaimed_and_deletes_snapshot_on_terminal() {
        let dir = temp_dir("replay");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-recover")).unwrap();
            s.append_mission_created(&mission("m-untouched")).unwrap();
        }
        let ex = executor_with(store.clone(), Some(dir.clone()));

        // Simulate: executor claimed the mission, then was SIGKILLed mid-run.
        let q = MissionQueue::new(store.clone());
        assert_eq!(q.claim("m-recover").await.unwrap(), ClaimOutcome::Claimed);
        assert_eq!(
            q.phase_of("m-recover").await.unwrap(),
            Some(MissionPhaseTag::Running)
        );
        let recovery = RecoveryStore::new(&dir, "test").unwrap();
        let clock = Utc
            .with_ymd_and_hms(2026, 9, 2, 3, 50, 48)
            .single()
            .unwrap();
        recovery
            .put("m-recover", Vec::new(), clock, COGNITION_SEED)
            .await
            .unwrap();

        // Restart: the new executor reclaims the crashed mission for replay.
        ex.recover_crashed().await.unwrap();
        assert_eq!(
            q.phase_of("m-recover").await.unwrap(),
            Some(MissionPhaseTag::Ready)
        );
        let snapshot = recovery.load("m-recover").await.unwrap().unwrap();
        assert_eq!(snapshot.attempts(), 2);

        // The reclaimed mission is replayed (native path with the snapshot's
        // fixed clock) and reaches an honest terminal; the snapshot is gone.
        let result = ex.drive_once("m-recover").await.unwrap();
        assert_eq!(result.phase, "TERMINAL");
        assert_eq!(result.outcome, Some("SUCCEEDED"));
        assert!(recovery.load("m-recover").await.unwrap().is_none());
        assert_eq!(
            q.phase_of("m-recover").await.unwrap(),
            Some(MissionPhaseTag::Terminal)
        );

        // Untouched missions are not disturbed.
        assert_eq!(
            q.phase_of("m-untouched").await.unwrap(),
            Some(MissionPhaseTag::Ready)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exhausted_recovery_budget_seals_failed_terminal() {
        let dir = temp_dir("budget");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-exhausted")).unwrap();
        }
        let ex = executor_with(store.clone(), Some(dir.clone()));
        let q = MissionQueue::new(store.clone());
        assert_eq!(q.claim("m-exhausted").await.unwrap(), ClaimOutcome::Claimed);

        let recovery = RecoveryStore::new(&dir, "test").unwrap();
        let clock = Utc
            .with_ymd_and_hms(2026, 9, 2, 3, 50, 48)
            .single()
            .unwrap();
        let snapshot = recovery
            .put("m-exhausted", Vec::new(), clock, COGNITION_SEED)
            .await
            .unwrap();
        // Push the attempt counter to the budget ceiling.
        let first = recovery.mark_reclaimed(&snapshot).await.unwrap();
        let second = recovery.mark_reclaimed(&first).await.unwrap();
        assert!(second.budget_exhausted());

        // Recovery refuses to keep replaying; the mission is honestly FAILED
        // and the snapshot cleaned up.
        ex.recover_crashed().await.unwrap();
        assert_eq!(
            q.phase_of("m-exhausted").await.unwrap(),
            Some(MissionPhaseTag::Terminal)
        );
        assert!(recovery.load("m-exhausted").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn crashed_before_snapshot_snapshotless_claim_is_reset() {
        // A crash between `claim` (RUNNING) and `recovery.put` must not strand
        // the mission forever: with no snapshot the run never executed, so it is
        // safely reset to READY and driven to a fresh terminal.
        let dir = temp_dir("snapshotless");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-snapshotless"))
                .unwrap();
        }
        let ex = executor_with(store.clone(), Some(dir.clone()));
        let q = MissionQueue::new(store.clone());
        assert_eq!(
            q.claim("m-snapshotless").await.unwrap(),
            ClaimOutcome::Claimed
        );

        ex.recover_crashed().await.unwrap();
        assert_eq!(
            q.phase_of("m-snapshotless").await.unwrap(),
            Some(MissionPhaseTag::Ready)
        );

        let result = ex.drive_once("m-snapshotless").await.unwrap();
        assert_eq!(result.phase, "TERMINAL");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verifying_without_snapshot_is_reset() {
        let dir = temp_dir("verifying-snapshotless");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-verifying")).unwrap();
        }
        let ex = executor_with(store.clone(), Some(dir.clone()));
        let q = MissionQueue::new(store.clone());
        assert_eq!(q.claim("m-verifying").await.unwrap(), ClaimOutcome::Claimed);
        q.verifying("m-verifying", "NORMAL").await.unwrap();

        ex.recover_crashed().await.unwrap();
        assert_eq!(
            q.phase_of("m-verifying").await.unwrap(),
            Some(MissionPhaseTag::Ready)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn healthy_ready_missions_are_untouched_by_recovery_scan() {
        let dir = temp_dir("healthy");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Mutex::new(Store::open_in_memory(signer()).unwrap()));
        {
            let mut s = store.lock().await;
            s.append_mission_created(&mission("m-healthy")).unwrap();
        }
        let ex = executor_with(store.clone(), Some(dir.clone()));
        ex.recover_crashed().await.unwrap();
        let q = MissionQueue::new(store.clone());
        assert_eq!(
            q.phase_of("m-healthy").await.unwrap(),
            Some(MissionPhaseTag::Ready)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
