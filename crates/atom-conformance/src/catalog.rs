//! Dependency-free reader for `spec/acceptance/catalog.yaml`.
//!
//! The workspace deliberately carries no YAML parser (its only data deps are
//! serde_json/sha2/thiserror). Rather than add one, this reads exactly what the
//! conformance binding needs from the known, flat catalog shape: the top-level
//! `spec_version` and, per test entry, its single-line `id` and `name`. The
//! multi-line `scenario`/`pass` bodies are intentionally ignored. A pinned test
//! (`catalog_lists_all_fifteen_acceptance_tests`) guards that this recovers every
//! entry with the correct name, so a format drift fails loudly instead of
//! silently under-reporting coverage.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::ConformanceError;

/// Location of the acceptance catalog relative to the workspace root.
pub const CATALOG_RELATIVE_PATH: &str = "spec/acceptance/catalog.yaml";

/// One acceptance-test entry: the normative `id` and human `name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceTest {
    /// Stable identifier, e.g. `ATOM-VT-011`.
    pub id: String,
    /// Human-readable test name from the catalog.
    pub name: String,
}

/// The parsed acceptance catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceCatalog {
    /// Top-level `spec_version` declared by the catalog.
    pub spec_version: String,
    /// Every test entry, in catalog order.
    pub tests: Vec<AcceptanceTest>,
}

impl AcceptanceCatalog {
    /// Finds a test entry by its identifier.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&AcceptanceTest> {
        self.tests.iter().find(|test| test.id == id)
    }
}

/// Absolute path to the catalog for a given workspace root.
#[must_use]
pub fn catalog_path(root: &Path) -> PathBuf {
    root.join(CATALOG_RELATIVE_PATH)
}

/// Reads and parses the acceptance catalog under `root`.
///
/// # Errors
/// Returns [`ConformanceError::Read`] if the file cannot be read and
/// [`ConformanceError::Catalog`] if it does not match the expected shape.
pub fn load_catalog(root: &Path) -> Result<AcceptanceCatalog, ConformanceError> {
    let path = catalog_path(root);
    let text = fs::read_to_string(&path).map_err(|source| ConformanceError::Read {
        path: path.clone(),
        source,
    })?;
    parse_catalog(&text).map_err(|detail| ConformanceError::Catalog { path, detail })
}

/// Parses the catalog text into an [`AcceptanceCatalog`].
///
/// # Errors
/// Returns a human-readable message when a required field is missing.
pub fn parse_catalog(text: &str) -> Result<AcceptanceCatalog, String> {
    let mut spec_version: Option<String> = None;
    let mut tests: Vec<AcceptanceTest> = Vec::new();
    let mut current_id: Option<String> = None;
    let mut current_name: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let content = line.trim_start();

        if indent == 0 && !content.starts_with('-') {
            // Top-level mapping key (`spec_version:` / `tests:`).
            if let Some((key, value)) = split_key_value(content) {
                if key == "spec_version" {
                    spec_version = Some(value);
                }
            }
            continue;
        }

        if content == "-" || content.starts_with("- ") {
            // A new sequence item begins; finalize the previous entry first.
            finalize(&mut tests, &mut current_id, &mut current_name)?;
            let inline = content[1..].trim_start();
            if let Some((key, value)) = split_key_value(inline) {
                match key.as_str() {
                    "id" => current_id = Some(value),
                    "name" => current_name = Some(value),
                    _ => {}
                }
            }
            continue;
        }

        // A mapping key within the current entry; only id/name are captured, and
        // the first `name` wins so a later continuation line cannot overwrite it.
        if let Some((key, value)) = split_key_value(content) {
            match key.as_str() {
                "id" => current_id = Some(value),
                "name" if current_name.is_none() => current_name = Some(value),
                _ => {}
            }
        }
    }
    finalize(&mut tests, &mut current_id, &mut current_name)?;

    let spec_version = spec_version.ok_or_else(|| "missing top-level spec_version".to_owned())?;
    if tests.is_empty() {
        return Err("no acceptance tests found".to_owned());
    }
    Ok(AcceptanceCatalog {
        spec_version,
        tests,
    })
}

fn finalize(
    tests: &mut Vec<AcceptanceTest>,
    id: &mut Option<String>,
    name: &mut Option<String>,
) -> Result<(), String> {
    match (id.take(), name.take()) {
        (Some(id), Some(name)) => {
            tests.push(AcceptanceTest { id, name });
            Ok(())
        }
        (Some(id), None) => Err(format!("test {id} has no name")),
        (None, Some(name)) => Err(format!("test entry named {name} has no id")),
        (None, None) => Ok(()),
    }
}

fn split_key_value(s: &str) -> Option<(String, String)> {
    let (key, value) = s.split_once(':')?;
    let key = key.trim().to_owned();
    if key.is_empty() {
        return None;
    }
    Some((key, unquote(value.trim())))
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let len = value.len();
    if len >= 2
        && ((bytes[0] == b'"' && bytes[len - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[len - 1] == b'\''))
    {
        value[1..len - 1].to_owned()
    } else {
        value.to_owned()
    }
}
