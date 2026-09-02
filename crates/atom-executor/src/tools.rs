//! Deny-by-default, read-only capability dispatcher.
//!
//! This module deliberately exposes no write, process, or network operation.
//! Every request is confined to an operator-supplied root and has a byte/entry
//! budget, making it suitable as the first concrete tool boundary.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyTool {
    ListDirectory,
    ReadFile,
    SearchText,
}

impl ReadOnlyTool {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListDirectory => "list_directory",
            Self::ReadFile => "read_file",
            Self::SearchText => "search_text",
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
