//! The three executable conformance checks, each bound to real crate logic.
//!
//! Every check runs the actual production crate — never a stand-in — and reports
//! observed behavior against the acceptance criterion:
//!
//! * **VT-011** drives [`atom_experience_compiler`] over a repeated-task family
//!   and requires an *actionable, non-authoritative* compiled capability whose
//!   holdout cost actually fell while correctness held within threshold.
//! * **VT-012** drives the real [`atom_restore`] router through
//!   promote -> regress -> rollback and compares the transition, field by field,
//!   to the checked-in chaos descriptor's declared expectation.
//! * **VT-015** loads the checked-in benchmark artifact and proves the native
//!   runtime run reproduces bit-for-bit across two executions.
//!
//! None of these open the frozen INV-020 2G-superiority gate; reproducibility is
//! a necessary, not sufficient, condition for any future claim (spec H-14).

use std::path::Path;

use atom_benchmark::disk::load_from_dir;
use atom_benchmark_runtime::execute_runtime;
use atom_experience_compiler::{
    CostSnapshot, ExecutionTrajectory, ExperienceCompiler, TrajectoryStep,
};
use atom_restore::{ArtifactRing, ArtifactRouter, CertifiedRoute};
use serde_json::{json, Value};

use crate::chaos::CanaryRegressionScenario;

/// Catalog id for the repeated-task-learning check.
pub const VT011: &str = "ATOM-VT-011";
/// Catalog id for the evolution-rollback check.
pub const VT012: &str = "ATOM-VT-012";
/// Catalog id for the 2G-benchmark-reproducibility check.
pub const VT015: &str = "ATOM-VT-015";

/// One check's raw verdict before it is paired with its catalog name.
#[derive(Clone, Debug, PartialEq)]
pub struct RawCheck {
    /// Catalog id the check covers.
    pub id: &'static str,
    /// Whether the real crate logic behaved as the acceptance test requires.
    pub passed: bool,
    /// Human-readable evidence: the observed numbers or transitions.
    pub evidence: String,
}

// ----------------------------------------------------------------------------
// VT-011 — Repeated-task learning (atom-experience-compiler).
// ----------------------------------------------------------------------------

/// Measured outcome of running the experience compiler over a task family.
#[derive(Clone, Debug)]
pub struct Vt011Outcome {
    /// Recommendation is actionable (holdout passed and confidence >= 0.8).
    pub actionable: bool,
    /// Ratio of compiled-path cost to baseline cost on the holdout; a value
    /// below 1.0 means cost / model calls actually fell.
    pub cost_improvement_ratio: f64,
    /// Fraction of pattern-bearing holdout cases that stayed correct.
    pub correctness_ratio: f64,
    /// Whether the recommendation tried to expand authority (INV-016 breach).
    pub authority_expanded: bool,
    /// Frequency the mined pattern reached in the training split.
    pub pattern_frequency: usize,
}

fn pattern_steps() -> Vec<TrajectoryStep> {
    vec![
        TrajectoryStep {
            tool_id: "retrieve-context".to_owned(),
            input: json!({ "op": "read" }),
            output: Value::Null,
            is_decision: false,
        },
        TrajectoryStep {
            tool_id: "compile-plan".to_owned(),
            input: json!({ "op": "transform" }),
            output: Value::Null,
            is_decision: true,
        },
    ]
}

fn baseline_steps() -> Vec<TrajectoryStep> {
    vec![TrajectoryStep {
        tool_id: "adhoc-solve".to_owned(),
        input: json!({ "op": "bespoke" }),
        output: Value::Null,
        is_decision: true,
    }]
}

fn trajectory(
    steps: Vec<TrajectoryStep>,
    success: bool,
    cost_cents: u64,
    timestamp: i64,
) -> ExecutionTrajectory {
    ExecutionTrajectory {
        task_family: "conformance-repeated-task".to_owned(),
        steps,
        success,
        cost: CostSnapshot {
            tokens: 100,
            latency_ms: 50,
            cost_cents,
        },
        timestamp,
    }
}

/// Training set: the same two-step pattern solved cheaply and correctly many
/// times, so mining reaches `min_frequency` and yields the compiled capability.
#[must_use]
pub fn vt011_repeated_task_family() -> Vec<ExecutionTrajectory> {
    (0..16)
        .map(|i| trajectory(pattern_steps(), true, 2, i))
        .collect()
}

/// Holdout that can actually demonstrate a cost drop: cheap pattern-bearing
/// successes measure the compiled path, and expensive non-pattern baselines
/// measure the uncompiled path the capability replaces.
#[must_use]
pub fn vt011_mixed_holdout() -> Vec<ExecutionTrajectory> {
    let mut holdout = Vec::new();
    for i in 0..5 {
        holdout.push(trajectory(pattern_steps(), true, 2, 100 + i));
    }
    for i in 0..5 {
        holdout.push(trajectory(baseline_steps(), true, 20, 200 + i));
    }
    holdout
}

/// Control holdout with no baseline trajectories: the compiler cannot measure a
/// cost drop, so `cost_improvement_ratio` stays 1.0 and the check must fail.
/// Used by a test to prove VT-011 is not a rubber stamp.
#[must_use]
pub fn vt011_no_baseline_holdout() -> Vec<ExecutionTrajectory> {
    (0..5)
        .map(|i| trajectory(pattern_steps(), true, 2, 300 + i))
        .collect()
}

/// Runs the real experience compiler: mine the recurring pattern, then evaluate
/// the synthesized recommendation against `holdout`.
///
/// # Errors
/// Returns the compiler's own error text when no pattern is mined or the
/// candidate is rejected (for example correctness below the 0.90 threshold).
pub fn evaluate_repeated_task_learning(
    training: &[ExecutionTrajectory],
    holdout: &[ExecutionTrajectory],
    family: &str,
) -> Result<Vt011Outcome, String> {
    let compiler = ExperienceCompiler::new();
    let subtrajectories = compiler
        .mine_subtrajectories(training)
        .map_err(|err| err.to_string())?;
    let top = subtrajectories
        .first()
        .ok_or_else(|| "no recurring pattern was mined".to_owned())?;
    let recommendation = compiler
        .synthesize_candidate(top, family, holdout)
        .map_err(|err| err.to_string())?;
    Ok(Vt011Outcome {
        actionable: recommendation.is_actionable(),
        cost_improvement_ratio: recommendation.holdout_result.cost_improvement_ratio,
        correctness_ratio: recommendation.holdout_result.correctness_ratio,
        authority_expanded: recommendation.target_capability_id.is_some(),
        pattern_frequency: top.frequency,
    })
}

/// VT-011 passes only when a compiled capability is actionable, cost actually
/// fell, correctness held within threshold, and no authority was expanded.
#[must_use]
pub fn vt011_passes(outcome: &Vt011Outcome) -> bool {
    outcome.actionable
        && !outcome.authority_expanded
        && outcome.cost_improvement_ratio < 1.0
        && outcome.correctness_ratio >= 0.90
}

/// Runs the VT-011 check against the canonical repeated-task fixture.
#[must_use]
pub fn check_vt011() -> RawCheck {
    let training = vt011_repeated_task_family();
    let holdout = vt011_mixed_holdout();
    match evaluate_repeated_task_learning(&training, &holdout, "conformance-repeated-task") {
        Ok(outcome) => RawCheck {
            id: VT011,
            passed: vt011_passes(&outcome),
            evidence: format!(
                "cost_improvement_ratio={:.4} (<1.0 => cost fell), correctness_ratio={:.4} (>=0.90), actionable={}, authority_expanded={}, pattern_frequency={}",
                outcome.cost_improvement_ratio,
                outcome.correctness_ratio,
                outcome.actionable,
                outcome.authority_expanded,
                outcome.pattern_frequency
            ),
        },
        Err(err) => RawCheck {
            id: VT011,
            passed: false,
            evidence: format!("experience compiler rejected the candidate: {err}"),
        },
    }
}

// ----------------------------------------------------------------------------
// VT-012 — Evolution rollback (atom-restore).
// ----------------------------------------------------------------------------

/// What the real router did when the promoted candidate regressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackObservation {
    /// Ring the rollback started from (`Rollback::from`).
    pub observed_ring: String,
    /// Ring the candidate was downgraded to (`Rollback::to`).
    pub downgraded_ring: String,
    /// Artifact of the restored certified route.
    pub restored_artifact_id: String,
    /// Route id of the restored certified route.
    pub restored_route_id: String,
    /// Artifact now serving live traffic.
    pub active_artifact_id: String,
    /// Route id now serving live traffic.
    pub active_route_id: String,
    /// Ring the downgraded candidate artifact now sits in.
    pub candidate_ring: String,
}

/// Drives the real [`ArtifactRouter`] through promote -> regress -> rollback.
///
/// # Errors
/// Returns the router's own error text if any transition is refused.
pub fn drive_canary_regression(
    scenario: &CanaryRegressionScenario,
) -> Result<RollbackObservation, String> {
    let prior = CertifiedRoute::new(
        scenario.prior.artifact_id.clone(),
        scenario.prior.route_id.clone(),
    )
    .map_err(|err| err.to_string())?;
    let candidate = CertifiedRoute::new(
        scenario.candidate.artifact_id.clone(),
        scenario.candidate.route_id.clone(),
    )
    .map_err(|err| err.to_string())?;

    let mut router = ArtifactRouter::new();
    router.register_active(prior).map_err(|err| err.to_string())?;
    router
        .register_canary(candidate)
        .map_err(|err| err.to_string())?;
    router
        .promote_canary(&scenario.candidate.artifact_id)
        .map_err(|err| err.to_string())?;
    let rollback = router
        .rollback_on_regression(&scenario.candidate.artifact_id)
        .map_err(|err| err.to_string())?;

    let active = router
        .active_route()
        .ok_or_else(|| "no active route after rollback".to_owned())?;
    let candidate_ring = router
        .artifact(&scenario.candidate.artifact_id)
        .ok_or_else(|| "candidate artifact missing after rollback".to_owned())?
        .ring();

    Ok(RollbackObservation {
        observed_ring: rollback.from().as_str().to_owned(),
        downgraded_ring: rollback.to().as_str().to_owned(),
        restored_artifact_id: rollback.restored_route().artifact_id().to_owned(),
        restored_route_id: rollback.restored_route().route_id().to_owned(),
        active_artifact_id: active.artifact_id().to_owned(),
        active_route_id: active.route_id().to_owned(),
        candidate_ring: candidate_ring.as_str().to_owned(),
    })
}

/// Runs the VT-012 check: drive a real rollback and compare it, field by field,
/// to the declared expectation in the chaos descriptor. A tampered descriptor
/// (wrong `expected`) makes `matches_declared` false, so the check fails.
#[must_use]
pub fn check_vt012(scenario: &CanaryRegressionScenario) -> RawCheck {
    match drive_canary_regression(scenario) {
        Ok(observed) => {
            let expected = &scenario.expected;
            let downgraded = observed.downgraded_ring == ArtifactRing::Canary.as_str()
                && observed.candidate_ring == ArtifactRing::Canary.as_str();
            let prior_restored = observed.active_route_id == scenario.prior.route_id
                && observed.active_artifact_id == scenario.prior.artifact_id
                && observed.restored_route_id == scenario.prior.route_id
                && observed.restored_artifact_id == scenario.prior.artifact_id;
            let matches_declared = observed.observed_ring == expected.observed_ring
                && observed.downgraded_ring == expected.downgraded_ring
                && observed.restored_route_id == expected.restored_route.route_id
                && observed.restored_artifact_id == expected.restored_route.artifact_id;
            RawCheck {
                id: VT012,
                passed: downgraded && prior_restored && matches_declared,
                evidence: format!(
                    "from={} to={} candidate_ring={} restored={}::{} active={}::{} matches_declared={}",
                    observed.observed_ring,
                    observed.downgraded_ring,
                    observed.candidate_ring,
                    observed.restored_artifact_id,
                    observed.restored_route_id,
                    observed.active_artifact_id,
                    observed.active_route_id,
                    matches_declared
                ),
            }
        }
        Err(err) => RawCheck {
            id: VT012,
            passed: false,
            evidence: format!("router refused the deterministic rollback: {err}"),
        },
    }
}

// ----------------------------------------------------------------------------
// VT-015 — 2G benchmark reproducibility (atom-benchmark + runtime).
// ----------------------------------------------------------------------------

/// Runs the VT-015 check: load the checked-in benchmark artifact and prove the
/// native-runtime run reproduces bit-for-bit across two executions. This does
/// NOT open the frozen INV-020 superiority gate.
#[must_use]
pub fn check_vt015(root: &Path) -> RawCheck {
    let dir = root.join("benchmarks/vt015-native-runtime");
    let loaded = match load_from_dir(&dir) {
        Ok(loaded) => loaded,
        Err(err) => {
            return RawCheck {
                id: VT015,
                passed: false,
                evidence: format!("benchmark artifact did not load: {err}"),
            };
        }
    };

    let first = execute_runtime(&loaded.manifest, &loaded.tasks);
    let second = execute_runtime(&loaded.manifest, &loaded.tasks);

    let reproducible = first.digest() == second.digest() && first.results == second.results;
    let all_scored = !first.results.is_empty() && first.results.iter().all(|r| r.score >= 1.0);
    let result_rows = first.results.len();
    let expected_rows = loaded.manifest.tracks.len() * loaded.manifest.seeds.len();

    RawCheck {
        id: VT015,
        passed: reproducible && all_scored && result_rows == expected_rows,
        evidence: format!(
            "run_digest={} manifest_digest={} result_rows={} expected_rows={} all_score_1.0={} reproducible={}",
            first.digest(),
            first.manifest_digest,
            result_rows,
            expected_rows,
            all_scored,
            reproducible
        ),
    }
}
