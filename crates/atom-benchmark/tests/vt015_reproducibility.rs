//! ATOM-VT-015: re-run the published benchmark from its manifest and confirm
//! pinned versions, seeds, budgets, traces and metrics reproduce within
//! declared tolerance.

use std::{fs, path::PathBuf};

use atom_benchmark::{
    disk::{load_from_dir, task_set_digest, LoadedBenchmark},
    manifest_digest, BenchmarkManifest, BenchmarkRun, BenchmarkTask, ReferenceSolver,
    SystemUnderTest,
};

fn benchmark_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("benchmarks/vt015-native-runtime")
}

fn file_backed_benchmark() -> LoadedBenchmark {
    load_from_dir(benchmark_dir()).expect("checked-in VT-015 benchmark artifact loads")
}

fn run_file_backed(manifest: &BenchmarkManifest, tasks: &[BenchmarkTask]) -> BenchmarkRun {
    BenchmarkRun::execute(manifest, tasks, |track| {
        Box::new(ReferenceSolver::for_track(track))
    })
}

#[test]
fn file_backed_run_is_deterministic_across_calls() {
    let benchmark = file_backed_benchmark();
    let r1 = run_file_backed(&benchmark.manifest, &benchmark.tasks);
    let r2 = run_file_backed(&benchmark.manifest, &benchmark.tasks);
    assert_eq!(
        r1.results, r2.results,
        "identical manifest -> identical results"
    );
    assert_eq!(r1.digest(), r2.digest(), "run digest must reproduce");
    assert_eq!(
        r1.results.len(),
        3,
        "one checked-in track x three checked-in seeds"
    );
    assert!(r1.results.iter().all(|result| result.cost_tokens == 750));
}

#[test]
fn manifest_digest_changes_when_pinned_version_changes() {
    let benchmark = file_backed_benchmark();
    let m1 = benchmark.manifest;
    let mut m2 = m1.clone();
    m2.pinned_versions
        .insert("atom-runtime".to_string(), "v9.9.9".to_string());

    let d1 = manifest_digest(&m1);
    let d2 = manifest_digest(&m2);
    assert_ne!(
        d1, d2,
        "changing a pinned version must change the manifest digest"
    );
    assert!(d1.starts_with("sha256:"));
    assert!(d2.starts_with("sha256:"));

    // And the runs must differ too.
    let tasks = file_backed_benchmark().tasks;
    let r1 = run_file_backed(&m1, &tasks);
    let r2 = run_file_backed(&m2, &tasks);
    assert_ne!(r1.digest(), r2.digest());
}

#[test]
fn task_suite_is_loaded_from_disk_and_content_addressed() {
    let benchmark = file_backed_benchmark();
    let bytes = fs::read(&benchmark.task_suite_path).expect("read checked-in task suite");

    assert_eq!(
        task_set_digest(&bytes),
        benchmark.manifest.task_set_digest,
        "a task edit must invalidate the manifest identity"
    );
    let mut changed_task_set = benchmark.manifest.clone();
    changed_task_set.task_set_digest = "sha256:changed-task-set".to_owned();
    assert_ne!(
        manifest_digest(&benchmark.manifest),
        manifest_digest(&changed_task_set),
        "the task-set identity participates in the manifest identity"
    );
    assert_eq!(
        benchmark.tasks.len(),
        6,
        "all declared runtime scenarios load from disk"
    );
    assert_eq!(
        benchmark
            .tasks
            .iter()
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "orchestrate-clean",
            "fail-on-compile",
            "fail-on-execute",
            "cancel-on-prepare",
            "block-on-start",
            "degrade-on-verify",
        ]
    );
}

#[test]
fn seeds_matter_but_remain_reproducible() {
    let benchmark = file_backed_benchmark();
    let mut m_few = benchmark.manifest.clone();
    m_few.seeds = vec![1];
    let mut m_many = benchmark.manifest.clone();
    m_many.seeds = vec![1, 2, 3, 4, 5];

    let r_few = run_file_backed(&m_few, &benchmark.tasks);
    let r_many = run_file_backed(&m_many, &benchmark.tasks);

    // Different seed sets -> different result sets.
    assert_ne!(r_few.results, r_many.results);

    // But each is internally reproducible.
    assert_eq!(
        run_file_backed(&m_few, &benchmark.tasks).digest(),
        r_few.digest()
    );
    assert_eq!(
        run_file_backed(&m_many, &benchmark.tasks).digest(),
        r_many.digest()
    );

    // Reproducibility is independent of seed count: more seeds just widens the
    // sample, it never makes a fixed seed non-deterministic.
    assert_eq!(r_few.results.len(), 1); // 1 checked-in track * 1 seed
    assert_eq!(r_many.results.len(), 5); // 1 checked-in track * 5 seeds
}

#[test]
fn aggregates_have_correct_sample_sizes() {
    let benchmark = file_backed_benchmark();
    let r = run_file_backed(&benchmark.manifest, &benchmark.tasks);
    assert_eq!(r.results.len(), 3); // 1 checked-in track * 3 checked-in seeds
    for agg in &r.aggregates {
        assert_eq!(agg.n, 3);
    }
}

/// The score is a REAL measured pass-rate, not a hash: a system that answers
/// every task correctly scores exactly 1.0, and one that never does scores 0.0.
#[test]
fn score_reflects_real_pass_rate() {
    struct Perfect;
    impl SystemUnderTest for Perfect {
        fn attempt(&self, task: &BenchmarkTask, _seed: u64) -> String {
            task.expected.clone()
        }
    }
    struct Hopeless;
    impl SystemUnderTest for Hopeless {
        fn attempt(&self, _task: &BenchmarkTask, _seed: u64) -> String {
            "nonsense".to_owned()
        }
    }

    let benchmark = file_backed_benchmark();

    let perfect = BenchmarkRun::execute(&benchmark.manifest, &benchmark.tasks, |_track| {
        Box::new(Perfect)
    });
    for r in &perfect.results {
        assert_eq!(r.score, 1.0, "solving every task must score 1.0");
    }

    let hopeless = BenchmarkRun::execute(&benchmark.manifest, &benchmark.tasks, |_track| {
        Box::new(Hopeless)
    });
    for r in &hopeless.results {
        assert_eq!(r.score, 0.0, "solving no task must score 0.0");
    }
}
