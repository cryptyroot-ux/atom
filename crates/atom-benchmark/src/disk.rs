//! Loading and integrity validation for checked-in benchmark artifacts.
//!
//! A VT-015 benchmark is not an in-memory convenience object. Its manifest and
//! task suite are files with independently verifiable identities, so another
//! runner can reproduce the exact input set.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{BenchmarkManifest, BenchmarkTask};

/// Schema carried by the task-suite file itself.
pub const TASK_SUITE_SCHEMA_VERSION: &str = "ATOM-BMK-001-task-suite-v1";

/// A loaded benchmark whose task-suite digest has been verified.
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedBenchmark {
    /// The benchmark definition that participates in a benchmark run digest.
    pub manifest: BenchmarkManifest,
    /// The exact tasks decoded from the content-addressed task-suite file.
    pub tasks: Vec<BenchmarkTask>,
    /// On-disk source of `manifest`.
    pub manifest_path: PathBuf,
    /// On-disk source whose bytes match `manifest.task_set_digest`.
    pub task_suite_path: PathBuf,
}

/// Failure to load or validate a file-backed benchmark artifact.
#[derive(Debug, Error)]
pub enum DiskBenchmarkError {
    /// The benchmark manifest could not be read.
    #[error("could not read benchmark manifest {path}: {source}")]
    ReadManifest {
        /// Path that was read.
        path: PathBuf,
        /// I/O cause.
        #[source]
        source: io::Error,
    },
    /// The benchmark manifest is not valid JSON for the artifact format.
    #[error("could not parse benchmark manifest {path}: {source}")]
    ParseManifest {
        /// Path that was parsed.
        path: PathBuf,
        /// JSON cause.
        #[source]
        source: serde_json::Error,
    },
    /// The manifest tried to escape its benchmark directory.
    #[error("task-suite path must be relative and must not contain `.` or `..`: {path}")]
    UnsafeTaskSuitePath {
        /// Untrusted path value from the manifest.
        path: String,
    },
    /// The referenced task suite could not be read.
    #[error("could not read task suite {path}: {source}")]
    ReadTaskSuite {
        /// Path that was read.
        path: PathBuf,
        /// I/O cause.
        #[source]
        source: io::Error,
    },
    /// The task suite fails the content-address check declared by its manifest.
    #[error("task-suite digest mismatch: manifest declares {declared}, file is {actual}")]
    TaskSetDigestMismatch {
        /// Digest declared by the manifest.
        declared: String,
        /// Digest calculated from the exact raw file bytes.
        actual: String,
    },
    /// The task suite is not valid JSON for the artifact format.
    #[error("could not parse task suite {path}: {source}")]
    ParseTaskSuite {
        /// Path that was parsed.
        path: PathBuf,
        /// JSON cause.
        #[source]
        source: serde_json::Error,
    },
    /// The task suite declared an incompatible schema tag.
    #[error("unsupported task-suite schema {actual:?}; expected {expected:?}")]
    UnsupportedTaskSuiteSchema {
        /// Schema tag found on disk.
        actual: String,
        /// Schema tag accepted by this loader.
        expected: &'static str,
    },
    /// A benchmark must execute at least one real task.
    #[error("task suite must contain at least one task")]
    EmptyTaskSuite,
    /// The suite itself needs a stable, reviewable identity.
    #[error("task suite id must not be blank")]
    BlankSuiteId,
    /// Task identifiers form the stable join between a suite and a SUT.
    #[error("task id must not be blank")]
    BlankTaskId,
    /// A task identifier was declared more than once.
    #[error("task id appears more than once: {id}")]
    DuplicateTaskId {
        /// Duplicate identifier.
        id: String,
    },
    /// The prompt is a required, reviewable benchmark input.
    #[error("task {id} has a blank prompt")]
    BlankTaskPrompt {
        /// Invalid task identifier.
        id: String,
    },
    /// The expected outcome must be explicit; a benchmark cannot infer it.
    #[error("task {id} has a blank expected outcome")]
    BlankTaskExpected {
        /// Invalid task identifier.
        id: String,
    },
    /// Zero-cost tasks cannot participate meaningfully in a declared budget.
    #[error("task {id} must charge at least one token")]
    ZeroTaskCost {
        /// Invalid task identifier.
        id: String,
    },
    /// A task may not silently exceed the manifest's per-task budget.
    #[error("task {id} costs {cost_tokens} tokens, exceeding the declared per-task budget {budget_tokens}")]
    TaskOverBudget {
        /// Invalid task identifier.
        id: String,
        /// Cost declared by the task.
        cost_tokens: u64,
        /// Ceiling declared by the manifest.
        budget_tokens: u64,
    },
}

#[derive(Debug, Deserialize)]
struct DiskManifest {
    #[serde(flatten)]
    manifest: BenchmarkManifest,
    task_suite: TaskSuiteReference,
}

#[derive(Debug, Deserialize)]
struct TaskSuiteReference {
    path: String,
    format: String,
}

#[derive(Debug, Deserialize)]
struct DiskTaskSuite {
    schema_version: String,
    suite_id: String,
    tasks: Vec<BenchmarkTask>,
}

/// Loads `manifest.json` from `benchmark_dir` and verifies its declared task
/// suite before returning any task to the harness.
pub fn load_from_dir(
    benchmark_dir: impl AsRef<Path>,
) -> Result<LoadedBenchmark, DiskBenchmarkError> {
    let benchmark_dir = benchmark_dir.as_ref();
    let manifest_path = benchmark_dir.join("manifest.json");
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|source| DiskBenchmarkError::ReadManifest {
            path: manifest_path.clone(),
            source,
        })?;
    let disk_manifest: DiskManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| {
            DiskBenchmarkError::ParseManifest {
                path: manifest_path.clone(),
                source,
            }
        })?;

    if disk_manifest.task_suite.format != TASK_SUITE_SCHEMA_VERSION {
        return Err(DiskBenchmarkError::UnsupportedTaskSuiteSchema {
            actual: disk_manifest.task_suite.format,
            expected: TASK_SUITE_SCHEMA_VERSION,
        });
    }

    let relative_task_path = Path::new(&disk_manifest.task_suite.path);
    if !is_safe_relative_path(relative_task_path) {
        return Err(DiskBenchmarkError::UnsafeTaskSuitePath {
            path: disk_manifest.task_suite.path,
        });
    }
    let task_suite_path = benchmark_dir.join(relative_task_path);
    let task_suite_bytes =
        fs::read(&task_suite_path).map_err(|source| DiskBenchmarkError::ReadTaskSuite {
            path: task_suite_path.clone(),
            source,
        })?;

    let actual_digest = task_set_digest(&task_suite_bytes);
    if disk_manifest.manifest.task_set_digest != actual_digest {
        return Err(DiskBenchmarkError::TaskSetDigestMismatch {
            declared: disk_manifest.manifest.task_set_digest,
            actual: actual_digest,
        });
    }

    let disk_suite: DiskTaskSuite =
        serde_json::from_slice(&task_suite_bytes).map_err(|source| {
            DiskBenchmarkError::ParseTaskSuite {
                path: task_suite_path.clone(),
                source,
            }
        })?;
    if disk_suite.schema_version != TASK_SUITE_SCHEMA_VERSION {
        return Err(DiskBenchmarkError::UnsupportedTaskSuiteSchema {
            actual: disk_suite.schema_version,
            expected: TASK_SUITE_SCHEMA_VERSION,
        });
    }
    if disk_suite.suite_id.trim().is_empty() {
        return Err(DiskBenchmarkError::BlankSuiteId);
    }
    validate_tasks(&disk_manifest.manifest, &disk_suite.tasks)?;

    Ok(LoadedBenchmark {
        manifest: disk_manifest.manifest,
        tasks: disk_suite.tasks,
        manifest_path,
        task_suite_path,
    })
}

/// SHA-256 identity of the exact raw task-suite bytes, prefixed for clarity.
#[must_use]
pub fn task_set_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn is_safe_relative_path(path: &Path) -> bool {
    path.is_relative()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_tasks(
    manifest: &BenchmarkManifest,
    tasks: &[BenchmarkTask],
) -> Result<(), DiskBenchmarkError> {
    if tasks.is_empty() {
        return Err(DiskBenchmarkError::EmptyTaskSuite);
    }

    let mut ids = BTreeSet::new();
    for task in tasks {
        if task.id.trim().is_empty() {
            return Err(DiskBenchmarkError::BlankTaskId);
        }
        if !ids.insert(task.id.as_str()) {
            return Err(DiskBenchmarkError::DuplicateTaskId {
                id: task.id.clone(),
            });
        }
        if task.prompt.trim().is_empty() {
            return Err(DiskBenchmarkError::BlankTaskPrompt {
                id: task.id.clone(),
            });
        }
        if task.expected.trim().is_empty() {
            return Err(DiskBenchmarkError::BlankTaskExpected {
                id: task.id.clone(),
            });
        }
        if task.cost_tokens == 0 {
            return Err(DiskBenchmarkError::ZeroTaskCost {
                id: task.id.clone(),
            });
        }
        if task.cost_tokens > manifest.budgets.per_task_tokens {
            return Err(DiskBenchmarkError::TaskOverBudget {
                id: task.id.clone(),
                cost_tokens: task.cost_tokens,
                budget_tokens: manifest.budgets.per_task_tokens,
            });
        }
    }
    Ok(())
}
