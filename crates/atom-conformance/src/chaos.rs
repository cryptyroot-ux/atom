//! Checked-in fault descriptor for the VT-012 evolution-rollback conformance
//! check.
//!
//! VT-012 ("Evolution rollback") requires that when a canary artifact regresses
//! after promotion, autonomy downgrades and the prior certified route is
//! restored. The scenario is data, not a clock: this descriptor names the prior
//! and candidate routes plus the exact rollback the real [`atom_restore`]
//! router must produce, so the check verifies observed behavior against a
//! declared expectation instead of rubber-stamping it.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::ConformanceError;

/// Schema tag carried by the descriptor file.
pub const CHAOS_SCHEMA_VERSION: &str = "ATOM-CHAOS-VT012-v1";

/// Location of the VT-012 descriptor relative to the workspace root.
pub const CHAOS_RELATIVE_PATH: &str = "chaos/vt012-canary-regression.json";

/// A certified route identity: which artifact it serves and its route id.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RouteRef {
    /// Artifact the route serves.
    pub artifact_id: String,
    /// Certified route identity.
    pub route_id: String,
}

/// The rollback transition the router is expected to perform.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExpectedRollback {
    /// Ring at which the regression is observed (spec spelling, e.g. `ACTIVE`).
    pub observed_ring: String,
    /// Ring the candidate is downgraded to (e.g. `CANARY`).
    pub downgraded_ring: String,
    /// Certified route restored to live traffic.
    pub restored_route: RouteRef,
}

/// A canary-regression scenario: promote a candidate, then regress it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CanaryRegressionScenario {
    /// Schema tag; must equal [`CHAOS_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable scenario identity.
    pub scenario_id: String,
    /// Human-readable description (ignored by the check).
    #[serde(default)]
    pub description: String,
    /// The certified route active before promotion.
    pub prior: RouteRef,
    /// The canary candidate that is promoted and then regresses.
    pub candidate: RouteRef,
    /// The rollback the router must produce.
    pub expected: ExpectedRollback,
}

/// Absolute path to the VT-012 descriptor for a given workspace root.
#[must_use]
pub fn chaos_path(root: &Path) -> PathBuf {
    root.join(CHAOS_RELATIVE_PATH)
}

/// Reads and validates the VT-012 canary-regression descriptor under `root`.
///
/// # Errors
/// Returns [`ConformanceError::Read`] / [`ConformanceError::ParseJson`] on I/O
/// or decode failure, and [`ConformanceError::Chaos`] on a schema mismatch.
pub fn load_canary_regression(root: &Path) -> Result<CanaryRegressionScenario, ConformanceError> {
    let path = chaos_path(root);
    let bytes = fs::read(&path).map_err(|source| ConformanceError::Read {
        path: path.clone(),
        source,
    })?;
    let scenario: CanaryRegressionScenario =
        serde_json::from_slice(&bytes).map_err(|source| ConformanceError::ParseJson {
            path: path.clone(),
            source,
        })?;
    if scenario.schema_version != CHAOS_SCHEMA_VERSION {
        return Err(ConformanceError::Chaos {
            path,
            detail: format!(
                "unsupported schema {:?}; expected {:?}",
                scenario.schema_version, CHAOS_SCHEMA_VERSION
            ),
        });
    }
    Ok(scenario)
}
