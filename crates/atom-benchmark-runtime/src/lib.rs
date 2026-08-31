//! atom-benchmark-runtime: a REAL [`SystemUnderTest`] backed by the `atom-runtime`
//! G1 mission runtime.
//!
//! `atom-benchmark` is deliberately provider-agnostic: its built-in
//! [`ReferenceSolver`](atom_benchmark::ReferenceSolver) is a labeled placeholder
//! whose per-task success is a deterministic hash roll, not a real system. This
//! crate closes that gap for the **same-model** track: it drives each benchmark
//! task through a genuine [`Runtime`], exercising the real mission reducer, the
//! real append-only ledger, and the real perceive/decide/act/observe loop, then
//! reads the outcome from [`RunStatus`]. The score is therefore a measured
//! mission-orchestration pass-rate of the ATOM runtime itself, not a hash.
//!
//! Honesty boundary: this measures the ATOM runtime's conformance to its own
//! mission state machine. It introduces no competitor and asserts no superiority
//! — the INV-020 claim gate in `atom-benchmark` stays frozen.

#![forbid(unsafe_code)]

use atom_benchmark::{BenchmarkManifest, BenchmarkRun, BenchmarkTask, SystemUnderTest};
use atom_effect::{EffectEvent, EffectIntent};
use atom_ledger::{HmacSha256Signer, Ledger};
use atom_mission::{ActivityKind, ActivityResult};
use atom_runtime::{
    ActionRequest, ActivityError, ActivityObservation, ActivityPort, CounterRng, FixedClock,
    RunStatus, Runtime,
};
use chrono::{DateTime, TimeZone, Utc};

/// A scripted mission scenario: a fixed lifecycle in which one activity may
/// return a non-success result. `expected` is the canonical outcome the real
/// runtime MUST produce for the scenario — the benchmark passes the task iff the
/// runtime's actual classified outcome equals it.
#[derive(Clone, Copy, Debug)]
struct MissionScenario {
    id: &'static str,
    /// Activity at which `injected` is returned; `None` = every activity succeeds.
    fail_at: Option<ActivityKind>,
    injected: ActivityResult,
    expected: &'static str,
}

/// The fixed, content-stable set of mission scenarios exercised by the runtime.
///
/// Each scenario has a known-correct terminal classification, so a correct
/// runtime scores 1.0 and any regression in the state machine lowers the score.
fn scenarios() -> &'static [MissionScenario] {
    &[
        MissionScenario {
            id: "orchestrate-clean",
            fail_at: None,
            injected: ActivityResult::Succeeded,
            expected: "SUCCEEDED",
        },
        MissionScenario {
            id: "fail-on-compile",
            fail_at: Some(ActivityKind::Compile),
            injected: ActivityResult::Failed,
            expected: "FAILED",
        },
        MissionScenario {
            id: "fail-on-execute",
            fail_at: Some(ActivityKind::Execute),
            injected: ActivityResult::Failed,
            expected: "FAILED",
        },
        MissionScenario {
            id: "cancel-on-prepare",
            fail_at: Some(ActivityKind::Prepare),
            injected: ActivityResult::Cancelled,
            expected: "CANCELLED",
        },
        MissionScenario {
            id: "block-on-start",
            fail_at: Some(ActivityKind::Start),
            injected: ActivityResult::Blocked,
            expected: "BLOCKED",
        },
        MissionScenario {
            id: "degrade-on-verify",
            fail_at: Some(ActivityKind::Verify),
            injected: ActivityResult::Degraded,
            expected: "BLOCKED",
        },
    ]
}

/// The benchmark suite exercised by the runtime SUT: one task per scenario,
/// with the canonical expected outcome baked in.
#[must_use]
pub fn runtime_suite() -> Vec<BenchmarkTask> {
    scenarios()
        .iter()
        .enumerate()
        .map(|(i, s)| BenchmarkTask {
            id: s.id.to_owned(),
            prompt: format!(
                "drive an atom-runtime mission to terminal (scenario={})",
                s.id
            ),
            expected: s.expected.to_owned(),
            cost_tokens: 100 + (i as u64) * 10,
        })
        .collect()
}

/// A provider-free port that scripts each lifecycle activity's observed result.
///
/// It has no host side effects; scenarios declare no consequential effects, so
/// `reconcile` is never reached on a valid run.
struct ScriptedPort {
    fail_at: Option<ActivityKind>,
    injected: ActivityResult,
}

impl ActivityPort for ScriptedPort {
    fn act(&mut self, _request: &ActionRequest<'_>) -> Result<(), ActivityError> {
        Ok(())
    }

    fn observe(
        &mut self,
        request: &ActionRequest<'_>,
    ) -> Result<ActivityObservation, ActivityError> {
        let result = if self.fail_at == Some(request.activity.kind) {
            self.injected
        } else {
            ActivityResult::Succeeded
        };
        Ok(ActivityObservation::Mission {
            result,
            reason: None,
        })
    }

    fn reconcile(
        &mut self,
        _effect: &EffectIntent,
        _at: DateTime<Utc>,
    ) -> Result<Vec<EffectEvent>, ActivityError> {
        Err(ActivityError::new(
            "scripted mission scenarios declare no consequential effect to reconcile",
        ))
    }
}

/// A [`SystemUnderTest`] that runs each task through the real `atom-runtime`.
///
/// `attempt` looks the task up by id in [`scenarios`], drives a fresh runtime to
/// a bounded end, and returns the classified [`RunStatus`]. The pass/fail is thus
/// read from the runtime's real terminal state, never derived from the manifest.
pub struct RuntimeSut;

impl RuntimeSut {
    /// Creates the runtime-backed system under test.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RuntimeSut {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemUnderTest for RuntimeSut {
    fn attempt(&self, task: &BenchmarkTask, seed: u64) -> String {
        match scenarios().iter().find(|s| s.id == task.id) {
            Some(scenario) => classify(&run_scenario(scenario, seed)),
            None => format!("UNKNOWN_TASK:{}", task.id),
        }
    }
}

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("fixed benchmark timestamp")
}

fn ledger() -> Ledger {
    Ledger::open_in_memory(Box::new(HmacSha256Signer::new(
        "atom-benchmark-runtime",
        b"atom-benchmark-runtime-secret",
    )))
    .expect("in-memory ledger")
}

/// Builds a fresh real runtime and drives the scripted scenario to a bounded end.
fn run_scenario(scenario: &MissionScenario, seed: u64) -> RunStatus {
    let mut runtime = Runtime::native(
        format!("bench-{}-{seed}", scenario.id),
        ledger(),
        FixedClock::new(fixed_now()),
        CounterRng::new(seed),
    )
    .expect("native runtime");
    let mut port = ScriptedPort {
        fail_at: scenario.fail_at,
        injected: scenario.injected,
    };
    runtime
        .run_until_terminal(&mut port, 16)
        .expect("bounded native run never errors on a scripted scenario")
}

/// Canonical, comparable classification of a bounded run's outcome.
fn classify(status: &RunStatus) -> String {
    match status {
        RunStatus::Terminal { state, .. } => state.outcome.map_or_else(
            || "TERMINAL_NO_OUTCOME".to_owned(),
            |o| o.as_str().to_owned(),
        ),
        RunStatus::Blocked { .. } => "BLOCKED".to_owned(),
        RunStatus::BlockedOnUnknown { .. } => "UNKNOWN".to_owned(),
        RunStatus::Exhausted { .. } => "EXHAUSTED".to_owned(),
    }
}

/// Execute `suite` against `manifest`, running the REAL `atom-runtime` as the
/// system under test on every track. Because the runtime is deterministic and no
/// competitor is introduced, this yields a reproducible conformance pass-rate for
/// the ATOM runtime and emits no superiority claim.
#[must_use]
pub fn execute_runtime(manifest: &BenchmarkManifest, suite: &[BenchmarkTask]) -> BenchmarkRun {
    BenchmarkRun::execute(manifest, suite, |_track| Box::new(RuntimeSut::new()))
}

/// Convenience: benchmark the ATOM runtime with the example manifest and the
/// runtime scenario suite.
#[must_use]
pub fn benchmark_atom_runtime() -> BenchmarkRun {
    execute_runtime(&BenchmarkManifest::example(), &runtime_suite())
}
