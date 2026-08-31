//! `atom seal` / `atom verify`: content-addressed signed artifacts (SUP-001).
//!
//! These are thin wrappers over [`atom_artifact::Artifact`]: sealing derives the
//! content address and signs the bundle; verifying recomputes both and reports
//! any tamper. The signing secret comes only from [`SigningConfig`] — never a
//! hardcoded key — and is never rendered in output.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use atom_artifact::{Artifact, Provenance, Sbom, SbomComponent};

use crate::config::SigningConfig;

/// The SBOM every atom-cli-sealed artifact carries: this binary's own version.
fn cli_sbom() -> Sbom {
    Sbom::new([SbomComponent::new("atom-cli", env!("CARGO_PKG_VERSION"))])
}

/// Seals `content` into an immutable, signed artifact under the process key.
#[must_use]
pub fn seal_bytes(content: Vec<u8>, provenance: Provenance, cfg: &SigningConfig) -> Artifact {
    Artifact::seal(content, provenance, cli_sbom(), cfg.key_id.as_str(), &cfg.secret)
}

/// Renders an artifact as pretty JSON for on-disk or stdout delivery.
///
/// # Errors
///
/// Fails only if the artifact cannot be serialized, which should not happen for
/// a well-formed [`Artifact`].
pub fn to_json(artifact: &Artifact) -> Result<String> {
    serde_json::to_string_pretty(artifact).map_err(|e| anyhow!("serializing artifact: {e}"))
}

/// Reads and parses an artifact JSON file.
///
/// # Errors
///
/// Fails if the file cannot be read or does not parse as an [`Artifact`].
pub fn read_artifact_file(path: &Path) -> Result<Artifact> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading artifact `{}`", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing artifact `{}`", path.display()))
}

/// Verifies an artifact end to end against the process secret (SUP-001).
///
/// # Errors
///
/// Returns the underlying [`atom_artifact::ArtifactError`] as context if the
/// content address is broken or the signature does not verify — i.e. any tamper
/// or a wrong secret.
pub fn verify_artifact(artifact: &Artifact, cfg: &SigningConfig) -> Result<()> {
    artifact
        .verify(&cfg.secret)
        .map_err(|e| anyhow!("artifact verification failed: {e}"))
}
