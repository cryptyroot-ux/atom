//! Integration tests for the acceptance-conformance harness.
//!
//! These pin the catalog to its 15 known entries, run every covered check
//! against real crate logic and require it to pass, prove the report is
//! reproducible via its content-addressed digest, and cross-check the coverage
//! manifest against the harness registry. Two **control** tests make a check
//! genuinely fail on wrong input, so a green suite cannot be a false positive.

use atom_conformance::{
    check_vt012, evaluate_repeated_task_learning, load_canary_regression, load_catalog,
    load_coverage, run_conformance, run_conformance_at, vt011_mixed_holdout,
    vt011_no_baseline_holdout, vt011_passes, vt011_repeated_task_family, workspace_root,
    COVERED_TESTS,
};

/// The catalog's 15 acceptance tests, pinned by id and normative name. A drift
/// in either the catalog or the reader fails loudly here instead of silently
/// under-reporting coverage.
const EXPECTED_CATALOG: [(&str, &str); 15] = [
    ("ATOM-VT-001", "Crash-safe authoritative state"),
    ("ATOM-VT-002", "Unknown external effect"),
    ("ATOM-VT-003", "TOCTOU authority drift"),
    ("ATOM-VT-004", "Secret isolation"),
    ("ATOM-VT-005", "Capability attenuation"),
    ("ATOM-VT-006", "Ledger tamper"),
    ("ATOM-VT-007", "Native independence"),
    ("ATOM-VT-008", "Snapshot split-brain"),
    ("ATOM-VT-009", "Memory poisoning lifecycle"),
    ("ATOM-VT-010", "Foundry holdout"),
    ("ATOM-VT-011", "Repeated-task learning"),
    ("ATOM-VT-012", "Evolution rollback"),
    ("ATOM-VT-013", "MCP/A2A hostile peer"),
    ("ATOM-VT-014", "Scheduler restart/DST"),
    ("ATOM-VT-015", "2G benchmark reproducibility"),
];

#[test]
fn catalog_lists_all_fifteen_acceptance_tests() {
    let catalog = load_catalog(&workspace_root()).expect("catalog loads");
    assert_eq!(catalog.spec_version, "4.0.0");
    assert_eq!(
        catalog.tests.len(),
        EXPECTED_CATALOG.len(),
        "catalog test count drifted"
    );
    for (expected_id, expected_name) in EXPECTED_CATALOG {
        let test = catalog
            .get(expected_id)
            .unwrap_or_else(|| panic!("catalog is missing {expected_id}"));
        assert_eq!(test.name, expected_name, "name drift for {expected_id}");
    }
}

#[test]
fn conformance_suite_passes_against_real_crates() {
    let report = run_conformance().expect("suite runs");
    assert!(report.all_passed(), "a covered check failed: {report:?}");

    let ids: Vec<&str> = report.results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, COVERED_TESTS, "covered ids drifted from the registry");
    assert_eq!(report.catalog_test_count, EXPECTED_CATALOG.len());
    assert_eq!(report.spec_version, "4.0.0");
    for result in &report.results {
        assert!(!result.evidence.is_empty(), "{} has no evidence", result.id);
    }
}

#[test]
fn report_is_reproducible_via_digest() {
    let root = workspace_root();
    let first = run_conformance_at(&root).expect("first run");
    let second = run_conformance_at(&root).expect("second run");
    assert_eq!(first, second, "two runs disagreed");
    assert_eq!(first.digest(), second.digest(), "digest not reproducible");
    assert!(first.digest().starts_with("sha256:"));
}

#[test]
fn covered_checks_match_catalog_names() {
    let root = workspace_root();
    let catalog = load_catalog(&root).expect("catalog loads");
    let report = run_conformance_at(&root).expect("suite runs");
    for result in &report.results {
        let test = catalog
            .get(&result.id)
            .unwrap_or_else(|| panic!("{} not in catalog", result.id));
        assert_eq!(result.name, test.name, "name drift for {}", result.id);
    }
}

#[test]
fn coverage_manifest_matches_harness_registry() {
    let root = workspace_root();
    let coverage = load_coverage(&root).expect("coverage loads");
    let catalog = load_catalog(&root).expect("catalog loads");

    assert_eq!(coverage.spec_version, catalog.spec_version);
    let covered_ids: Vec<&str> = coverage.covered.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        covered_ids, COVERED_TESTS,
        "coverage ids drifted from registry"
    );
    for entry in &coverage.covered {
        let test = catalog
            .get(&entry.id)
            .unwrap_or_else(|| panic!("{} not in catalog", entry.id));
        assert_eq!(
            entry.name, test.name,
            "coverage name drift for {}",
            entry.id
        );
        assert!(!entry.crate_under_test.is_empty());
        assert!(!entry.pass_criterion.is_empty());
    }
}

#[test]
fn vt011_mixed_holdout_passes_but_no_baseline_control_fails() {
    let training = vt011_repeated_task_family();

    let passing = evaluate_repeated_task_learning(
        &training,
        &vt011_mixed_holdout(),
        "conformance-repeated-task",
    )
    .expect("mixed holdout yields an outcome");
    assert!(
        vt011_passes(&passing),
        "canonical holdout must pass: {passing:?}"
    );

    // Control: with no baseline trajectories the compiler cannot measure a cost
    // drop, so the check must not pass — proving VT-011 is not a rubber stamp.
    if let Ok(control) = evaluate_repeated_task_learning(
        &training,
        &vt011_no_baseline_holdout(),
        "conformance-repeated-task",
    ) {
        assert!(
            !vt011_passes(&control),
            "no-baseline control holdout must not pass: {control:?}"
        );
    }
}

#[test]
fn tampered_vt012_expectation_fails_check() {
    let scenario = load_canary_regression(&workspace_root()).expect("scenario loads");
    assert!(
        check_vt012(&scenario).passed,
        "untampered scenario must pass"
    );

    // Control: corrupt the declared restored route; the real router still
    // restores the true prior, so the field-for-field comparison must fail.
    let mut tampered = scenario.clone();
    tampered.expected.restored_route.route_id = "certified-route-wrong-v9".to_owned();
    assert!(
        !check_vt012(&tampered).passed,
        "tampered expectation must fail the check"
    );
}
