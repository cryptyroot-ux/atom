//! ATOM-INV-020 + H-14: no superiority claim without pinned versions,
//! comparable budgets, reproducible harness, and published failure traces.
//! The default state is FROZEN — that is the honest contract, and it is tested.

use atom_benchmark::{evaluate_superiority, BenchmarkError, BenchmarkManifest, BenchmarkRun};

#[test]
fn frozen_by_default_no_claim_without_evidence() {
    // The shipped example manifest is frozen (evidence not published).
    let m = BenchmarkManifest::example();
    assert!(!m.evidence_published);
    let run = BenchmarkRun::new(&m);
    let claim = evaluate_superiority(&m, &run);
    assert_eq!(claim, Err(BenchmarkError::ClaimFrozen));
}

#[test]
fn claim_refused_when_failure_traces_missing() {
    // Evidence flag on, but failure traces still not published.
    let m = BenchmarkManifest::example().published();
    let mut m2 = m.clone();
    m2.failure_traces_published = false;
    let run = BenchmarkRun::new(&m2);
    assert_eq!(
        evaluate_superiority(&m2, &run),
        Err(BenchmarkError::Inv020Unmet("failure traces not published"))
    );
}

#[test]
fn claim_refused_with_too_few_seeds() {
    let m = BenchmarkManifest::example().published();
    let mut m2 = m.clone();
    m2.seeds = vec![1, 2]; // < 3
    let run = BenchmarkRun::new(&m2);
    assert_eq!(
        evaluate_superiority(&m2, &run),
        Err(BenchmarkError::Inv020Unmet("fewer than 3 seeds"))
    );
}

#[test]
fn claim_refused_with_noncomparable_budgets() {
    let m = BenchmarkManifest::example().published();
    let mut m2 = m.clone();
    m2.budgets.comparable_across_tracks = false;
    let run = BenchmarkRun::new(&m2);
    assert_eq!(
        evaluate_superiority(&m2, &run),
        Err(BenchmarkError::Inv020Unmet(
            "budgets not comparable across tracks"
        ))
    );
}

#[test]
fn claim_refused_without_fault_scenarios() {
    let m = BenchmarkManifest::example().published();
    let mut m2 = m.clone();
    m2.fault_scenarios.clear();
    let run = BenchmarkRun::new(&m2);
    assert_eq!(
        evaluate_superiority(&m2, &run),
        Err(BenchmarkError::Inv020Unmet("no fault/attack scenarios"))
    );
}

#[test]
fn fully_satisfied_gate_yields_reproducible_claim() {
    // This test proves the GATE WORKS when every INV-020 dimension is met — it
    // does NOT assert ATOM is superior to anything. The winner is whatever the
    // deterministic harness happens to compute; the point is reproducibility.
    let m = BenchmarkManifest::example().published();
    let run1 = BenchmarkRun::new(&m);
    let run2 = BenchmarkRun::new(&m);

    let c1 = evaluate_superiority(&m, &run1).expect("all gates met");
    let c2 = evaluate_superiority(&m, &run2).expect("all gates met");
    assert_eq!(c1, c2, "claim must be reproducible across identical runs");
    assert_eq!(c1.manifest_digest, run1.manifest_digest);
    assert!(c1.confidence == 0.0 || c1.confidence == 0.95);
}
