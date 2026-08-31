//! ATOM-VT-015: re-run the published benchmark from its manifest and confirm
//! pinned versions, seeds, budgets, traces and metrics reproduce within
//! declared tolerance.

use atom_benchmark::{manifest_digest, BenchmarkManifest, BenchmarkRun};

#[test]
fn run_is_deterministic_across_calls() {
    let m = BenchmarkManifest::example();
    let r1 = BenchmarkRun::new(&m);
    let r2 = BenchmarkRun::new(&m);
    assert_eq!(r1.results, r2.results, "identical manifest -> identical results");
    assert_eq!(r1.digest(), r2.digest(), "run digest must reproduce");
}

#[test]
fn manifest_digest_changes_when_pinned_version_changes() {
    let m1 = BenchmarkManifest::example();
    let mut m2 = BenchmarkManifest::example();
    m2.pinned_versions
        .insert("competitor-x".to_string(), "v9.9.9".to_string());

    let d1 = manifest_digest(&m1);
    let d2 = manifest_digest(&m2);
    assert_ne!(d1, d2, "changing a pinned version must change the manifest digest");
    assert!(d1.starts_with("sha256:"));
    assert!(d2.starts_with("sha256:"));

    // And the runs must differ too.
    let r1 = BenchmarkRun::new(&m1);
    let r2 = BenchmarkRun::new(&m2);
    assert_ne!(r1.digest(), r2.digest());
}

#[test]
fn seeds_matter_but_remain_reproducible() {
    let mut m_few = BenchmarkManifest::example();
    m_few.seeds = vec![1];
    let mut m_many = BenchmarkManifest::example();
    m_many.seeds = vec![1, 2, 3, 4, 5];

    let r_few = BenchmarkRun::new(&m_few);
    let r_many = BenchmarkRun::new(&m_many);

    // Different seed sets -> different result sets.
    assert_ne!(r_few.results, r_many.results);

    // But each is internally reproducible.
    assert_eq!(BenchmarkRun::new(&m_few).digest(), r_few.digest());
    assert_eq!(BenchmarkRun::new(&m_many).digest(), r_many.digest());

    // Reproducibility is independent of seed count: more seeds just widens the
    // sample, it never makes a fixed seed non-deterministic.
    assert_eq!(r_few.results.len(), 2); // 2 tracks * 1 seed
    assert_eq!(r_many.results.len(), 10); // 2 tracks * 5 seeds
}

#[test]
fn aggregates_have_correct_sample_sizes() {
    let m = BenchmarkManifest::example(); // 2 tracks * 3 seeds
    let r = BenchmarkRun::new(&m);
    assert_eq!(r.results.len(), 6);
    for agg in &r.aggregates {
        assert_eq!(agg.n, 3);
    }
}
