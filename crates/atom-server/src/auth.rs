//! Bearer-token transport authentication (P0-A).
//!
//! The HTTP API had no authentication: anyone who could reach the port could
//! `POST /approvals` with a self-declared `approver_id` and the daemon would
//! record it (verified live 2026-09-05: `HTTP 201` for
//! `approver_id: "anonymous/attacker"`). This module closes that hole.
//!
//! Design notes, read before "simplifying":
//!
//! - **Auth is not authority.** A valid bearer token only proves the caller may
//!   talk to the daemon. Minting capability is still impossible over HTTP
//!   (`atom grant issue` is offline-only) and every `/host/commit` still needs
//!   a one-shot approval for the exact effect digest. The `auth_is_not_authority`
//!   test pins this: valid token + no approval must still refuse.
//! - **`/health` and `/ready` stay public.** Operator diagnostics (`atom status`,
//!   `atom doctor`, load-balancer probes) must work without a secret, and neither
//!   endpoint reads nor writes authority state.
//! - **Deny by default.** `atom serve` refuses to start when no token is
//!   provisioned unless the operator passes the explicit `--no-auth` escape
//!   hatch (loopback development only). There is no silent open mode.
//! - **Tokens are compared by digest.** Both sides are SHA-256 hashed before the
//!   constant-time comparison so a timing probe cannot learn the token length.
//!   `sha2` is already a dependency; no new crate was introduced for this.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request};
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};

use crate::app::AppState;
use crate::error::ApiError;

/// Environment variable holding the API token directly.
pub const ENV_TOKEN: &str = "ATOM_API_TOKEN";
/// Environment variable holding a path to a file containing the API token.
pub const ENV_TOKEN_FILE: &str = "ATOM_API_TOKEN_FILE";
/// Minimum accepted token length in bytes. Shorter values are rejected at load
/// so a `"changeme"`-grade secret can never guard the daemon.
pub const MIN_TOKEN_LEN: usize = 16;

/// Paths that never require authentication. Both are read-only, carry no
/// authority state, and are needed by unauthenticated health probing.
pub const PUBLIC_PATHS: [&str; 2] = ["/health", "/ready"];

/// The daemon's bearer token. The bytes are never logged, never serialized,
/// and never echoed in an error message.
#[derive(Clone)]
pub struct ApiToken {
    token: Vec<u8>,
}

impl std::fmt::Debug for ApiToken {
    /// Redacts the secret so it can never leak through a debug print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiToken")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl ApiToken {
    /// Builds a token from explicit bytes, enforcing the minimum length.
    ///
    /// # Errors
    ///
    /// Fails when `token` is shorter than [`MIN_TOKEN_LEN`] bytes.
    pub fn new(token: impl Into<Vec<u8>>) -> Result<Self> {
        let token = token.into();
        if token.len() < MIN_TOKEN_LEN {
            return Err(anyhow!(
                "API token must be at least {MIN_TOKEN_LEN} bytes, got {}",
                token.len()
            ));
        }
        Ok(Self { token })
    }

    /// Resolves the daemon token: an explicit `--api-token-file` path wins,
    /// then `ATOM_API_TOKEN_FILE`, then `ATOM_API_TOKEN`.
    ///
    /// File contents are trimmed (trailing newline from `echo`/editors must not
    /// become part of the secret) and empty-after-trim values are rejected.
    ///
    /// # Errors
    ///
    /// Fails when no source is configured, a file cannot be read, or the
    /// resolved value is empty or shorter than [`MIN_TOKEN_LEN`].
    pub fn load(api_token_file: Option<&Path>) -> Result<Self> {
        if let Some(path) = api_token_file {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading API token file `{}`", path.display()))?;
            return Self::new(raw.trim().as_bytes().to_vec());
        }
        if let Ok(path) = std::env::var(ENV_TOKEN_FILE) {
            if !path.trim().is_empty() {
                let raw = std::fs::read_to_string(path.trim())
                    .with_context(|| format!("reading API token file `{path}`"))?;
                return Self::new(raw.trim().as_bytes().to_vec());
            }
        }
        let raw = std::env::var(ENV_TOKEN).map_err(|_| {
            anyhow!(
                "no API token: pass `--api-token-file <path>`, set `{ENV_TOKEN_FILE}` or \
                 `{ENV_TOKEN}`, or pass `--no-auth` explicitly for loopback development only"
            )
        })?;
        Self::new(raw.trim().as_bytes().to_vec())
    }

    /// Constant-time verification over SHA-256 digests, so neither value nor
    /// length leaks through timing.
    #[must_use]
    pub fn verify(&self, candidate: &[u8]) -> bool {
        let expected = Sha256::digest(&self.token);
        let got = Sha256::digest(candidate);
        let mut diff = 0u8;
        for (x, y) in expected.iter().zip(got.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// Axum middleware enforcing the bearer token on every non-public route.
///
/// Layer it with `route_layer` on the protected router only; `/health` and
/// `/ready` live on the public router. The in-middleware [`PUBLIC_PATHS`] check
/// is defense in depth so a future route move cannot silently expose a handler.
pub async fn require_bearer(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if PUBLIC_PATHS.contains(&req.uri().path()) {
        return Ok(next.run(req).await);
    }
    let Some(configured) = state.auth.as_ref() else {
        // No token configured (tests and explicit `--no-auth`): the router is
        // intentionally open. Production `atom serve` refuses this state.
        return Ok(next.run(req).await);
    };
    let instance = req.uri().path().to_owned();
    let Some(header) = req.headers().get(header::AUTHORIZATION) else {
        return Err(ApiError::unauthorized(
            instance,
            "missing credentials: this endpoint requires `Authorization: Bearer <token>`",
        ));
    };
    let header = header
        .to_str()
        .map_err(|_| ApiError::unauthorized(instance.clone(), "malformed Authorization header"))?;
    let Some(candidate) = header
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|c| !c.is_empty())
    else {
        return Err(ApiError::unauthorized(
            instance,
            "malformed credentials: expected `Authorization: Bearer <token>`",
        ));
    };
    if !configured.verify(candidate.as_bytes()) {
        return Err(ApiError::unauthorized(instance, "invalid API token"));
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> ApiToken {
        ApiToken::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap()
    }

    #[test]
    fn accepts_exact_token() {
        assert!(token().verify(b"0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn rejects_wrong_token_same_length() {
        assert!(!token().verify(b"0123456789abcdef0123456789abcdeg"));
    }

    #[test]
    fn rejects_short_token() {
        assert!(!token().verify(b"short"));
    }

    #[test]
    fn rejects_empty_candidate() {
        assert!(!token().verify(b""));
    }

    #[test]
    fn constructor_rejects_short_secret() {
        assert!(ApiToken::new(b"too-short".to_vec()).is_err());
        assert!(ApiToken::new(vec![b'x'; MIN_TOKEN_LEN]).is_ok());
    }

    #[test]
    fn public_paths_are_exactly_health_and_ready() {
        assert_eq!(PUBLIC_PATHS, ["/health", "/ready"]);
    }
}
