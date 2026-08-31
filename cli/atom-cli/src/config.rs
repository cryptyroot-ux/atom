//! Signing configuration for the `atom` process.
//!
//! The signing key id and secret are the process's signing authority: they are
//! used both to seal/verify artifacts (SUP-001) and to sign the runtime's
//! append-only ledger checkpoints. The secret is NEVER hardcoded and NEVER
//! printed — it is read from `--config <file>` or from the environment.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Environment variable holding the signing secret (required when no `--config`).
pub const ENV_SECRET: &str = "ATOM_SIGNING_SECRET";
/// Environment variable holding the signing key id (optional).
pub const ENV_KEY_ID: &str = "ATOM_SIGNING_KEY_ID";
/// Key id used when none is supplied by config or environment.
pub const DEFAULT_KEY_ID: &str = "atom-cli";

/// On-disk config file shape: `{ "key_id": "...", "secret": "..." }`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// Optional key id; defaults to [`DEFAULT_KEY_ID`] when absent.
    key_id: Option<String>,
    /// The signing secret, as UTF-8 text.
    secret: String,
}

/// The resolved signing authority for this process.
///
/// `secret` is kept as bytes and is never rendered in any output.
#[derive(Clone)]
pub struct SigningConfig {
    /// Which key signs, so a verifier knows which secret to use.
    pub key_id: String,
    /// The signing secret bytes.
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for SigningConfig {
    /// Redacts the secret so it can never leak through a debug print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningConfig")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl SigningConfig {
    /// A config from an explicit key id and secret (used directly by tests).
    #[must_use]
    pub fn new(key_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            secret: secret.into(),
        }
    }

    /// Resolves the signing config from `--config <path>` if given, else the
    /// environment.
    ///
    /// # Errors
    ///
    /// Fails if the config file cannot be read or parsed, or if no secret is
    /// available from either source (deny-by-default: there is no built-in key).
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        match config_path {
            Some(path) => Self::from_file(path),
            None => Self::from_env(),
        }
    }

    fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading signing config `{}`", path.display()))?;
        let parsed: ConfigFile = serde_json::from_str(&raw)
            .with_context(|| format!("parsing signing config `{}`", path.display()))?;
        Self::finish(parsed.key_id, parsed.secret)
    }

    fn from_env() -> Result<Self> {
        let secret = std::env::var(ENV_SECRET).map_err(|_| {
            anyhow!(
                "no signing secret: set `{ENV_SECRET}` in the environment or pass `--config <file>`"
            )
        })?;
        let key_id = std::env::var(ENV_KEY_ID).ok();
        Self::finish(key_id, secret)
    }

    fn finish(key_id: Option<String>, secret: String) -> Result<Self> {
        if secret.is_empty() {
            return Err(anyhow!("signing secret must not be empty"));
        }
        Ok(Self {
            key_id: key_id.unwrap_or_else(|| DEFAULT_KEY_ID.to_owned()),
            secret: secret.into_bytes(),
        })
    }
}
