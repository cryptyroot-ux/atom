//! atom-conformance: an executable acceptance-conformance harness.
//!
//! This crate binds `spec/acceptance/catalog.yaml` to *real* crate logic for the
//! three acceptance tests that were previously only prose:
//!
//! * **ATOM-VT-011** (Repeated-task learning) via [`atom_experience_compiler`],
//! * **ATOM-VT-012** (Evolution rollback) via [`atom_restore`],
//! * **ATOM-VT-015** (2G benchmark reproducibility) via [`atom_benchmark`] +
//!   [`atom_benchmark_runtime`].
//!
//! Each covered check runs the production crate and is paired with the normative
//! catalog name for its id; a covered id absent from the catalog is a hard error,
//! so coverage cannot silently drift from the spec. The harness deliberately does
//! NOT open the frozen INV-020 2G-superiority gate (spec H-14: "no 2G claim until
//! reproducible") — reproducibility here is necessary, not sufficient, for a claim.

#![forbid(unsafe_code)]

mod catalog;
mod chaos;
mod checks;

use std::{
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use catalog::{
    catalog_path, load_catalog, parse_catalog, AcceptanceCatalog, AcceptanceTest,
    CATALOG_RELATIVE_PATH,
};
pub use chaos::{
    chaos_path, load_canary_regression, CanaryRegressionScenario, ExpectedRollback, RouteRef,
    CHAOS_RELATIVE_PATH, CHAOS_SCHEMA_VERSION,
};
pub use checks::{
    check_vt011, check_vt012, check_vt015, drive_canary_regression,
    evaluate_repeated_task_learning, vt011_mixed_holdout, vt011_no_baseline_holdout, vt011_passes,
    vt011_repeated_task_family, RawCheck, RollbackObservation, Vt011Outcome, VT011, VT012, VT015,
};

/// The acceptance ids this harness executably covers, in report order.
pub const COVERED_TESTS: [&str; 3] = [VT011, VT012, VT015];

/// Location of the checked-in coverage manifest relative to the workspace root.
pub const COVERAGE_RELATIVE_PATH: &str = "conformance/coverage.json";

/// Errors from loading conformance inputs or binding a check to the catalog.
#[derive(Debug, Error)]
pub enum ConformanceError {
    /// An input file could not be read.
    #[error("could not read {path}: {source}")]
    Read {
        /// Path that was read.
        path: PathBuf,
        /// I/O cause.
        #[source]
        source: io::Error,
    },
    /// A JSON input could not be decoded.
    #[error("could not parse {path}: {source}")]
    ParseJson {
        /// Path that was parsed.
        path: PathBuf,
        /// JSON cause.
        #[source]
        source: serde_json::Error,
    },
    /// The acceptance catalog did not match the expected flat shape.
    #[error("acceptance catalog {path} is malformed: {detail}")]
    Catalog {
        /// Catalog path.
        path: PathBuf,
        /// Human-readable reason.
        detail: String,
    },
    /// The VT-012 chaos descriptor was structurally invalid.
    #[error("chaos descriptor {path} is invalid: {detail}")]
    Chaos {
        /// Descriptor path.
        path: PathBuf,
        /// Human-readable reason.
        detail: String,
    },
    /// A covered check has no matching entry in the acceptance catalog.
    #[error("covered check {id} has no entry in the acceptance catalog {path}")]
    UncataloguedCheck {
        /// The covered acceptance id.
        id: String,
        /// Catalog path.
        path: PathBuf,
    },
}

/// One check's verdict, paired with the normative catalog name for its id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    /// Acceptance id (e.g. `ATOM-VT-011`).
    pub id: String,
    /// Normative name copied from the catalog entry.
    pub name: String,
    /// Whether the real crate logic satisfied the acceptance criterion.
    pub passed: bool,
    /// Observed evidence (numbers / transitions) behind the verdict.
    pub evidence: String,
}

/// The full conformance report; reproducible via [`ConformanceReport::digest`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// `spec_version` declared by the acceptance catalog.
    pub spec_version: String,
    /// Total number of tests the catalog declares (coverage denominator).
    pub catalog_test_count: usize,
    /// One entry per covered check, in [`COVERED_TESTS`] order.
    pub results: Vec<CheckResult>,
}

impl ConformanceReport {
    /// True iff every covered check passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|result| result.passed)
    }

    /// Finds a check result by acceptance id.
    #[must_use]
    pub fn result(&self, id: &str) -> Option<&CheckResult> {
        self.results.iter().find(|result| result.id == id)
    }

    /// Content-address of the report: `sha256:<hex>` over its JSON. Two runs
    /// that observed the same behavior produce the same digest.
    #[must_use]
    pub fn digest(&self) -> String {
        let json = serde_json::to_string(self).expect("conformance report serializes");
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// Declared coverage contract checked in at `conformance/coverage.json`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CoverageManifest {
    /// Schema tag for the coverage file.
    pub schema_version: String,
    /// Spec version this coverage claim targets (must match the catalog).
    pub spec_version: String,
    /// One entry per executably covered acceptance test.
    pub covered: Vec<CoverageEntry>,
}

/// One coverage entry: which acceptance test is bound to which crate.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CoverageEntry {
    /// Acceptance id.
    pub id: String,
    /// Normative catalog name.
    pub name: String,
    /// The real crate exercised by the check.
    pub crate_under_test: String,
    /// Plain-language restatement of what the check verifies.
    pub pass_criterion: String,
}

/// Absolute path to the coverage manifest for a given workspace root.
#[must_use]
pub fn coverage_path(root: &Path) -> PathBuf {
    root.join(COVERAGE_RELATIVE_PATH)
}

/// Reads the checked-in coverage manifest under `root`.
///
/// # Errors
/// Returns [`ConformanceError::Read`] / [`ConformanceError::ParseJson`] on I/O
/// or decode failure.
pub fn load_coverage(root: &Path) -> Result<CoverageManifest, ConformanceError> {
    let path = coverage_path(root);
    let bytes = std::fs::read(&path).map_err(|source| ConformanceError::Read {
        path: path.clone(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| ConformanceError::ParseJson { path, source })
}

/// Absolute workspace root inferred from this crate's manifest directory.
#[must_use]
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs the full conformance suite against the real workspace tree.
///
/// # Errors
/// Propagates [`ConformanceError`] from loading the catalog / chaos descriptor,
/// or if a covered check has no matching catalog entry.
pub fn run_conformance() -> Result<ConformanceReport, ConformanceError> {
    run_conformance_at(&workspace_root())
}

/// Runs the full conformance suite against an explicit workspace `root`.
///
/// # Errors
/// See [`run_conformance`].
pub fn run_conformance_at(root: &Path) -> Result<ConformanceReport, ConformanceError> {
    let catalog = load_catalog(root)?;
    let scenario = load_canary_regression(root)?;

    let raw_checks = [check_vt011(), check_vt012(&scenario), check_vt015(root)];
    let mut results = Vec::with_capacity(raw_checks.len());
    for raw in raw_checks {
        let test = catalog
            .get(raw.id)
            .ok_or_else(|| ConformanceError::UncataloguedCheck {
                id: raw.id.to_owned(),
                path: catalog_path(root),
            })?;
        results.push(CheckResult {
            id: raw.id.to_owned(),
            name: test.name.clone(),
            passed: raw.passed,
            evidence: raw.evidence,
        });
    }

    Ok(ConformanceReport {
        spec_version: catalog.spec_version.clone(),
        catalog_test_count: catalog.tests.len(),
        results,
    })
}
