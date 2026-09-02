//! The persistent daemon execution spine.
//!
//! [`AtomExecutor`] owns the mission queue and drives each claimed mission
//! through the sovereign runtime until it reaches a durable, honest terminal
//! state — recording every phase transition on the server ledger.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::sync::{watch, Mutex};

use atom_ledger::{CheckpointSigner, HmacSha256Signer, Ledger};
use atom_provider::ProviderCognition;
use atom_runtime::{CounterRng, FixedClock, ReferenceActivityPort, RunStatus};
use atom_server::store::Store;

use crate::provider::{CachedProvider, HttpProposalClient, ProviderConfig};
use crate::queue::{ClaimOutcome, MissionQueue, RunResult};

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
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            max_steps: 256,
            signing_key: "atom-executor".to_owned(),
            signing_secret: b"atom-executor-daemon-key".to_vec(),
            provider: ProviderConfig::default(),
        }
    }
}

/// A persistent mission-queue driver.
pub struct AtomExecutor {
    queue: MissionQueue,
    config: ExecutorConfig,
    shutdown_tx: watch::Sender<bool>,
}

impl AtomExecutor {
    pub fn new(store: Arc<Mutex<Store>>, config: ExecutorConfig) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            queue: MissionQueue::new(store),
            config,
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

        let clock = FixedClock::new(chrono::Utc::now());
        let random = CounterRng::new(0xDAE0_0002);

        // Build a mission-specific cognition backend. When a model provider is
        // configured, fetch its plan once (asynchronously, before the runtime
        // loop) and replay it through a deterministic cached provider. On any
        // provider failure we refuse to fabricate a run: the mission is sealed
        // honestly as unsatisfiable below.
        if self.config.provider.enabled {
            let client = HttpProposalClient::new(self.config.provider.clone());
            let plan = match client.propose(mission_id, "CREATED").await {
                Ok(plan) => plan,
                Err(e) => {
                    return RunResult {
                        mission_id: mission_id.to_owned(),
                        phase: "VERIFYING",
                        outcome: None,
                        steps: 0,
                        reason: Some(format!("provider plan failed: {e}")),
                    };
                }
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
        self.drive_runtime(mission_id, runtime)
    }

    /// Drives one runtime to a terminal status and maps it onto a `RunResult`.
    fn drive_runtime<N>(&self, mission_id: &str, mut runtime: atom_runtime::Runtime<FixedClock, CounterRng, N>) -> RunResult
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

    /// The daemon loop: poll the queue and drive every `READY` mission until a
    /// graceful shutdown is requested.
    pub async fn run(self) {
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
