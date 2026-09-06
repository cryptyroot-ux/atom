//! Deny-by-default, read-only capability dispatcher.
//!
//! This module deliberately exposes no write, process, or network operation.
//! Every request is confined to an operator-supplied root and has a byte/entry
//! budget, making it suitable as the first concrete tool boundary.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileStat {
    pub path: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub len: u64,
    pub readonly: bool,
    pub created: Option<u64>,
    pub modified: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalkEntry {
    pub path: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub len: u64,
    pub depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyTool {
    ListDirectory,
    ReadFile,
    SearchText,
    StatFile,
    WalkDirectory,
}

impl ReadOnlyTool {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListDirectory => "list_directory",
            Self::ReadFile => "read_file",
            Self::SearchText => "search_text",
            Self::StatFile => "stat_file",
            Self::WalkDirectory => "walk_directory",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ToolError {
    #[error("tool `{0}` is not allowed by the read-only dispatcher")]
    NotAllowed(String),
    #[error("path is outside the configured capability root")]
    OutsideRoot,
    #[error("path does not exist: {0}")]
    MissingPath(String),
    #[error("I/O failure: {0}")]
    Io(String),
    #[error("output exceeds the capability budget")]
    BudgetExceeded,
}

#[derive(Clone, Debug)]
pub struct ReadOnlyDispatcher {
    root: PathBuf,
    max_bytes: usize,
    max_entries: usize,
}

impl ReadOnlyDispatcher {
    pub fn new(
        root: impl AsRef<Path>,
        max_bytes: usize,
        max_entries: usize,
    ) -> Result<Self, ToolError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|e| ToolError::Io(e.to_string()))?;
        if !root.is_dir() {
            return Err(ToolError::MissingPath(root.display().to_string()));
        }
        if max_bytes == 0 || max_entries == 0 {
            return Err(ToolError::BudgetExceeded);
        }
        Ok(Self {
            root,
            max_bytes,
            max_entries,
        })
    }

    pub fn list_directory(&self, path: impl AsRef<Path>) -> Result<Vec<String>, ToolError> {
        let path = self.confine(path)?;
        if !path.is_dir() {
            return Err(ToolError::Io("target is not a directory".into()));
        }
        let mut entries = std::fs::read_dir(path)
            .map_err(|e| ToolError::Io(e.to_string()))?
            .map(|entry| {
                entry
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .map_err(|e| ToolError::Io(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        if entries.len() > self.max_entries {
            return Err(ToolError::BudgetExceeded);
        }
        Ok(entries)
    }

    pub fn read_file(&self, path: impl AsRef<Path>) -> Result<String, ToolError> {
        let path = self.confine(path)?;
        let metadata = std::fs::metadata(&path).map_err(|e| ToolError::Io(e.to_string()))?;
        if metadata.len() > self.max_bytes as u64 {
            return Err(ToolError::BudgetExceeded);
        }
        std::fs::read_to_string(path).map_err(|e| ToolError::Io(e.to_string()))
    }

    pub fn search_text(
        &self,
        path: impl AsRef<Path>,
        needle: &str,
    ) -> Result<Vec<String>, ToolError> {
        if needle.is_empty() {
            return Err(ToolError::NotAllowed("empty search pattern".into()));
        }
        let content = self.read_file(path)?;
        let matches = content
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if matches.len() > self.max_entries {
            return Err(ToolError::BudgetExceeded);
        }
        Ok(matches)
    }

    /// Returns file metadata without reading contents (low risk, high utility).
    pub fn stat_file(&self, path: impl AsRef<Path>) -> Result<FileStat, ToolError> {
        let path = self.confine(path)?;
        let meta = std::fs::metadata(&path).map_err(|e| ToolError::Io(e.to_string()))?;
        Ok(FileStat {
            path: path.to_string_lossy().into_owned(),
            is_file: meta.is_file(),
            is_dir: meta.is_dir(),
            len: meta.len(),
            readonly: meta.permissions().readonly(),
            created: meta
                .created()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs()),
            modified: meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs()),
        })
    }

    /// Recursively lists entries under `path` up to `max_depth` levels.
    /// Respects entry budget (counts every entry returned across all levels).
    pub fn walk_directory(
        &self,
        path: impl AsRef<Path>,
        max_depth: usize,
    ) -> Result<Vec<WalkEntry>, ToolError> {
        if max_depth == 0 {
            return Err(ToolError::NotAllowed("max_depth must be >= 1".into()));
        }
        let path = self.confine(path)?;
        if !path.is_dir() {
            return Err(ToolError::Io("target is not a directory".into()));
        }
        let mut entries = Vec::new();
        self.walk_recursive(&path, 1, max_depth, &mut entries)?;
        if entries.len() > self.max_entries {
            return Err(ToolError::BudgetExceeded);
        }
        Ok(entries)
    }

    fn walk_recursive(
        &self,
        dir: &Path,
        depth: usize,
        max_depth: usize,
        out: &mut Vec<WalkEntry>,
    ) -> Result<(), ToolError> {
        if depth > max_depth {
            return Ok(());
        }
        let read_dir = std::fs::read_dir(dir).map_err(|e| ToolError::Io(e.to_string()))?;
        for entry in read_dir {
            if out.len() >= self.max_entries {
                return Err(ToolError::BudgetExceeded);
            }
            let entry = entry.map_err(|e| ToolError::Io(e.to_string()))?;
            let meta = entry.metadata().map_err(|e| ToolError::Io(e.to_string()))?;
            out.push(WalkEntry {
                path: entry.path().to_string_lossy().into_owned(),
                is_file: meta.is_file(),
                is_dir: meta.is_dir(),
                len: meta.len(),
                depth,
            });
            if meta.is_dir() && depth < max_depth {
                self.walk_recursive(&entry.path(), depth + 1, max_depth, out)?;
            }
        }
        Ok(())
    }

    fn confine(&self, path: impl AsRef<Path>) -> Result<PathBuf, ToolError> {
        let candidate = path.as_ref();
        let resolved = candidate
            .canonicalize()
            .map_err(|_| ToolError::MissingPath(candidate.display().to_string()))?;
        if resolved == self.root || resolved.starts_with(&self.root) {
            Ok(resolved)
        } else {
            Err(ToolError::OutsideRoot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn read_and_search_stay_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("note.txt"), "alpha\nbeta alpha\n").unwrap();
        let d = ReadOnlyDispatcher::new(dir.path(), 1024, 8).unwrap();
        assert_eq!(
            d.read_file(dir.path().join("note.txt")).unwrap(),
            "alpha\nbeta alpha\n"
        );
        assert_eq!(
            d.search_text(dir.path().join("note.txt"), "alpha")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn traversal_and_symlink_escape_are_denied() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "no").unwrap();
        symlink(outside.path().join("secret"), dir.path().join("link")).unwrap();
        let d = ReadOnlyDispatcher::new(dir.path(), 1024, 8).unwrap();
        assert_eq!(
            d.read_file(
                dir.path()
                    .join("../")
                    .join(outside.path().file_name().unwrap())
                    .join("secret")
            ),
            Err(ToolError::OutsideRoot)
        );
        assert_eq!(
            d.read_file(dir.path().join("link")),
            Err(ToolError::OutsideRoot)
        );
    }

    #[test]
    fn budgets_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("large"), "123456").unwrap();
        let d = ReadOnlyDispatcher::new(dir.path(), 3, 8).unwrap();
        assert_eq!(
            d.read_file(dir.path().join("large")),
            Err(ToolError::BudgetExceeded)
        );
    }
}
