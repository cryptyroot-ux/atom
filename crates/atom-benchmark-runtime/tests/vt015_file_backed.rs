//! ATOM-VT-015 end-to-end: the checked-in manifest and task suite are loaded
//! from disk, then every task is executed by the real `atom-runtime` SUT.

use std::path::PathBuf;

use atom_benchmark::disk::load_from_dir;
use atom_benchmark_runtime::execute_runtime;

fn benchmark_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("benchmarks/vt015-native-runtime")
}

#[test]
fn vt015_reproduces_the_file_backed_runtime_suite() {
    let benchmark = load_from_dir(benchmark_dir()).expect("checked-in benchmark loads");

    let first = execute_runtime(&benchmark.manifest, &benchmark.tasks);
    let second = execute_runtime(&benchmark.manifest, &benchmark.tasks);

    assert_eq!(
        first.results, second.results,
        "same artifact -> same results"
    );
    assert_eq!(
        first.digest(),
        second.digest(),
        "same artifact -> same run digest"
    );
    assert_eq!(first.results.len(), 3, "one same-model track x three seeds");
    assert!(
        first.results.iter().all(|result| result.score == 1.0),
        "every disk task must be classified by the real runtime's RunStatus"
    );
}
