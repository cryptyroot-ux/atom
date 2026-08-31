//! Proves the same-model track's numbers come from the REAL atom-runtime state
//! machine, are reproducible, and honestly reflect pass/fail (not a rubber stamp).

use atom_benchmark::{BenchmarkManifest, BenchmarkTask, SystemUnderTest};
use atom_benchmark_runtime::{benchmark_atom_runtime, execute_runtime, runtime_suite, RuntimeSut};

/// The real runtime conforms to its own mission FSM on every scenario, so every
/// (track, seed) result scores exactly 1.0.
#[test]
fn real_runtime_scores_perfect_conformance() {
    let run = benchmark_atom_runtime();
    // example() manifest = 2 tracks * 3 seeds.
    assert_eq!(run.results.len(), 6);
    for r in &run.results {
        assert_eq!(r.score, 1.0, "the real runtime must pass every scenario");
    }
    for agg in &run.aggregates {
        assert_eq!(agg.mean_score, 1.0);
        // All seeds agree (the runtime is deterministic) => zero-width interval.
        assert_eq!(agg.ci95_low, 1.0);
        assert_eq!(agg.ci95_high, 1.0);
    }
}

/// The score is REAL: feed a task whose `expected` contradicts what the runtime
/// actually produces, and it must fail. A hash-stamp could not tell the two apart.
#[test]
fn score_is_real_not_a_rubber_stamp() {
    // id "orchestrate-clean" really terminates SUCCEEDED, but we assert FAILED.
    let wrong = vec![BenchmarkTask {
        id: "orchestrate-clean".to_owned(),
        prompt: "clean mission, but with a deliberately wrong expected".to_owned(),
        expected: "FAILED".to_owned(),
        cost_tokens: 100,
    }];
    let run = execute_runtime(&BenchmarkManifest::example(), &wrong);
    for r in &run.results {
        assert_eq!(r.score, 0.0, "a wrong expected must not pass");
    }
}

/// Same manifest + same suite => identical run digest (VT-015-style reproducibility).
#[test]
fn runtime_run_is_reproducible() {
    assert_eq!(benchmark_atom_runtime().digest(), benchmark_atom_runtime().digest());
}

/// Each canonical outcome (SUCCEEDED / FAILED / CANCELLED / BLOCKED) is produced
/// by driving the real runtime, matching the scenario's baked-in expectation.
#[test]
fn attempt_classifies_each_scenario_from_real_state() {
    let sut = RuntimeSut::new();
    for task in runtime_suite() {
        assert_eq!(
            sut.attempt(&task, 7),
            task.expected,
            "scenario {} must classify from the real runtime outcome",
            task.id
        );
    }
}
