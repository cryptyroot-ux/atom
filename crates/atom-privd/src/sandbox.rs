//! The production [`HostExecutor`]: a sandbox confined to a root directory.
//!
//! Every file operation resolves inside `root` and is refused when it would
//! escape it — either lexically through `..` or physically through a symlink
//! that reaches outside. A spawned program must be an absolute path *inside*
//! the sandbox, is executed with no shell and a scrubbed environment, and its
//! captured output is bounded before it is written to the audit detail.
//! [`HostOp::ConfigureNetwork`] is refused outright: a filesystem sandbox has
//! no authority over host networking (deny-by-default).

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::executor::{ExecError, HostExecutor, OpOutcome};
use crate::op::HostOp;

/// The largest spawn capture kept in an [`OpOutcome`] detail.
const MAX_CAPTURE_BYTES: usize = 1 << 20;

/// A [`HostExecutor`] whose world is one directory and its descendants.
#[derive(Clone, Debug)]
pub struct SandboxedHostExecutor {
    /// The canonical sandbox root; the root itself is resolved at construction
    /// so a symlinked root cannot redirect a stored configuration later.
    root: PathBuf,
}

impl SandboxedHostExecutor {
    /// Creates an executor confined to `root`.
    ///
    /// # Errors
    ///
    /// [`ExecError`] when `root` cannot be canonicalised or is not a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ExecError> {
        let root = root.as_ref();
        let canonical = fs::canonicalize(root).map_err(|source| {
            ExecError::failed(
                "sandbox_init",
                format!("cannot resolve sandbox root `{}`: {source}", root.display()),
            )
        })?;
        if !canonical.is_dir() {
            return Err(ExecError::failed(
                "sandbox_init",
                format!("sandbox root `{}` is not a directory", canonical.display()),
            ));
        }
        Ok(Self { root: canonical })
    }

    /// The canonical sandbox root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves `requested` to a real path strictly inside the sandbox.
    ///
    /// The caller declares an absolute path; `..` is refused as a lexical
    /// escape, every existing ancestor is canonicalised (so a symlink pointing
    /// outside the root is refused), and missing directories are created along
    /// the way. The final component may not exist yet — its parent has been
    /// verified — which is what a fresh `WriteFile` needs.
    fn resident_path(&self, requested: &str) -> Result<PathBuf, ExecError> {
        let requested = Path::new(requested);
        let mut current = self.root.clone();
        let components: Vec<_> = requested.components().collect();
        for (index, component) in components.iter().enumerate() {
            let is_last = index + 1 == components.len();
            let Component::Normal(name) = component else {
                if matches!(component, Component::ParentDir) {
                    return Err(ExecError::failed(
                        "sandbox",
                        format!(
                            "path `{}` escapes the sandbox through `..`",
                            requested.display()
                        ),
                    ));
                }
                // RootDir, CurDir and prefix call no filesystem activity.
                continue;
            };
            let candidate = current.join(name);
            if is_last {
                // The leaf: resolve it if it exists, so a symlink to the
                // outside is caught, then let the caller create/remove it.
                return self.resolve_leaf(candidate, requested);
            }
            match fs::canonicalize(&candidate) {
                Ok(resolved) => {
                    if !resolved.starts_with(&self.root) {
                        return Err(self.escape(requested, &candidate));
                    }
                    current = resolved;
                }
                Err(_) => {
                    // The directory does not exist yet; create it without
                    // following any symlink with the same name.
                    fs::create_dir(&candidate).map_err(|source| {
                        ExecError::failed(
                            "sandbox",
                            format!(
                                "cannot create sandbox directory `{}`: {source}",
                                candidate.display()
                            ),
                        )
                    })?;
                    current = candidate;
                }
            }
        }
        Err(ExecError::failed(
            "sandbox",
            format!("path `{}` did not name a file", requested.display()),
        ))
    }

    /// Resolves the final component: an existing symlink must still stay inside
    /// the sandbox, a non-existing leaf yields its verified parent path.
    fn resolve_leaf(&self, candidate: PathBuf, requested: &Path) -> Result<PathBuf, ExecError> {
        match fs::canonicalize(&candidate) {
            Ok(resolved) => {
                if !resolved.starts_with(&self.root) {
                    return Err(self.escape(requested, &candidate));
                }
                Ok(resolved)
            }
            Err(_) if !candidate.exists() => Ok(candidate),
            Err(_) => Err(ExecError::failed(
                "sandbox",
                format!(
                    "cannot resolve leaf `{}` for path `{}`",
                    candidate.display(),
                    requested.display()
                ),
            )),
        }
    }

    /// A canonicalised path landed outside the sandbox root.
    fn escape(&self, requested: &Path, resolved: &Path) -> ExecError {
        ExecError::failed(
            "sandbox",
            format!(
                "path `{}` resolves outside the sandbox (`{}`) via `{}`",
                requested.display(),
                self.root.display(),
                resolved.display()
            ),
        )
    }

    fn write(&mut self, path: &str, contents: &str) -> Result<OpOutcome, ExecError> {
        let target = self.resident_path(path)?;
        fs::write(&target, contents).map_err(|source| {
            ExecError::failed(
                "write_file",
                format!("cannot write `{}`: {source}", target.display()),
            )
        })?;
        Ok(OpOutcome::new(
            "write_file",
            format!("wrote {} bytes to {}", contents.len(), target.display()),
        ))
    }

    fn remove(&mut self, path: &str) -> Result<OpOutcome, ExecError> {
        let target = self.resident_path(path)?;
        let metadata = fs::symlink_metadata(&target).map_err(|source| {
            ExecError::failed(
                "remove_file",
                format!("cannot stat `{}`: {source}", target.display()),
            )
        })?;
        if !metadata.is_file() {
            return Err(ExecError::failed(
                "remove_file",
                format!(
                    "refusing to remove non-file `{}` (a sandbox never removes directories)",
                    target.display()
                ),
            ));
        }
        fs::remove_file(&target).map_err(|source| {
            ExecError::failed(
                "remove_file",
                format!("cannot remove `{}`: {source}", target.display()),
            )
        })?;
        Ok(OpOutcome::new(
            "remove_file",
            format!("removed {}", target.display()),
        ))
    }

    fn spawn(&mut self, program: &str, args: &[String]) -> Result<OpOutcome, ExecError> {
        // The program must itself live in the sandbox; there is no PATH lookup.
        let executable = self.resident_path(program)?;
        let metadata = fs::symlink_metadata(&executable).map_err(|source| {
            ExecError::failed(
                "spawn_process",
                format!("cannot stat `{}`: {source}", executable.display()),
            )
        })?;
        if !metadata.is_file() {
            return Err(ExecError::failed(
                "spawn_process",
                format!("refusing to spawn non-file `{}`", executable.display()),
            ));
        }
        let output = std::process::Command::new(&executable)
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", &self.root)
            .output()
            .map_err(|source| {
                ExecError::failed(
                    "spawn_process",
                    format!("cannot spawn `{}`: {source}", executable.display()),
                )
            })?;
        let detail = if output.status.success() {
            format!(
                "spawned `{}` (exit {})",
                executable.display(),
                output.status.code().unwrap_or(-1)
            )
        } else {
            format!(
                "spawned `{}` exited {}: {}",
                executable.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr),
            )
        };
        let stdout = truncate(&output.stdout, MAX_CAPTURE_BYTES);
        let detail = if stdout.is_empty() {
            detail
        } else {
            format!("{detail}\n{stdout}")
        };
        Ok(OpOutcome::new("spawn_process", detail))
    }

    fn configure_network(&self) -> Result<OpOutcome, ExecError> {
        Err(ExecError::failed(
            "configure_network",
            "network configuration is refused by the sandboxed host executor (deny-by-default)",
        ))
    }

    fn create_directory(&mut self, path: &str) -> Result<OpOutcome, ExecError> {
        let target = self.resident_path(path)?;
        fs::create_dir_all(&target).map_err(|source| {
            ExecError::failed(
                "create_directory",
                format!("cannot create directory `{}`: {source}", target.display()),
            )
        })?;
        Ok(OpOutcome::new(
            "create_directory",
            format!("created directory {}", target.display()),
        ))
    }

    fn copy_file(&mut self, source: &str, destination: &str) -> Result<OpOutcome, ExecError> {
        let src = self.resident_path(source)?;
        let dst = self.resident_path(destination)?;

        // Source must exist and be a file
        let src_meta = fs::symlink_metadata(&src).map_err(|source| {
            ExecError::failed(
                "copy_file",
                format!("cannot stat source `{}`: {source}", src.display()),
            )
        })?;
        if !src_meta.is_file() {
            return Err(ExecError::failed(
                "copy_file",
                format!("source `{}` is not a file", src.display()),
            ));
        }

        // Destination parent must exist (resident_path creates parents for destination)
        // Copy atomically: write to temp then rename
        let temp = dst.with_extension("tmp");
        fs::copy(&src, &temp).map_err(|source| {
            ExecError::failed(
                "copy_file",
                format!(
                    "cannot copy `{}` to `{}`: {source}",
                    src.display(),
                    temp.display()
                ),
            )
        })?;
        fs::rename(&temp, &dst).map_err(|source| {
            ExecError::failed(
                "copy_file",
                format!(
                    "cannot finalize copy `{}` -> `{}`: {source}",
                    src.display(),
                    dst.display()
                ),
            )
        })?;

        let src_len = fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
        Ok(OpOutcome::new(
            "copy_file",
            format!(
                "copied {} bytes from {} to {}",
                src_len,
                src.display(),
                dst.display()
            ),
        ))
    }
}

/// Bounds `bytes` and marks any truncation, so a chatty child cannot bloat an
/// audit entry without bound.
fn truncate(bytes: &[u8], limit: usize) -> String {
    if bytes.len() <= limit {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    format!(
        "{}… (truncated {} bytes)",
        String::from_utf8_lossy(&bytes[..limit]),
        bytes.len() - limit
    )
}

impl HostExecutor for SandboxedHostExecutor {
    fn execute(&mut self, op: &HostOp) -> Result<OpOutcome, ExecError> {
        match op {
            HostOp::WriteFile { path, contents } => self.write(path, contents),
            HostOp::RemoveFile { path } => self.remove(path),
            HostOp::SpawnProcess { program, args } => self.spawn(program, args),
            HostOp::ConfigureNetwork { .. } => self.configure_network(),
            HostOp::CreateDirectory { path } => self.create_directory(path),
            HostOp::CopyFile {
                source,
                destination,
            } => self.copy_file(source, destination),
        }
    }
}
