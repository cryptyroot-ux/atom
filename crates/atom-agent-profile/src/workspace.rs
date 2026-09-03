//! Workspace state-directory resolution and file management.

use std::path::PathBuf;

/// Resolve workspace directory for a given agent.
pub fn workspace_dir(agent_id: &str) -> PathBuf {
    PathBuf::from(format!("{}/workspaces/{}", state_dir().display(), agent_id))
}

/// Resolve state directory for ATOM.
pub fn state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ATOM_STATE_DIR") {
        PathBuf::from(dir)
    } else {
        PathBuf::from("/var/lib/atom")
    }
}
