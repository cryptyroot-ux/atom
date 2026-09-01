//! atom-cli: the sovereign `atom` process (Blueprint §17, G4 Foundry).
//!
//! This library holds the core so it is directly testable; the `atom` binary
//! (`src/main.rs`) is a thin clap wrapper over [`run`]. The CLI surface is:
//!
//! * `atom run`          — boot runtime + scheduler + worker in-process and
//!   drive one real double-gated mutation (KRN-001), reporting a live subsystem
//!   inventory of every wired crate.
//! * `atom seal <bytes>` — produce a content-addressed, signed artifact
//!   (SUP-001) via [`atom_artifact::Artifact`].
//! * `atom verify <file>`— verify a sealed artifact; a tampered bundle or wrong
//!   secret exits non-zero.
//!
//! The signing key id and secret are resolved from `--config <file>` or the
//! environment ([`config`]); no secret is ever hardcoded or printed.

#![forbid(unsafe_code)]

pub mod artifact_ops;
pub mod boot;
pub mod config;

pub use config::SigningConfig;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use atom_artifact::Provenance;

/// The `atom` command line.
#[derive(Debug, Parser)]
#[command(
    name = "atom",
    version,
    about = "ATOM v4 sovereign process: boot the runtime, seal and verify artifacts",
    long_about = None
)]
pub struct Cli {
    /// Path to a JSON signing config: `{ "key_id": "...", "secret": "..." }`.
    ///
    /// When omitted, the key id and secret are read from `ATOM_SIGNING_KEY_ID`
    /// and `ATOM_SIGNING_SECRET` in the environment.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The `atom` subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Boot runtime + scheduler + worker in-process and drive one real mutation.
    Run,

    /// Run the ATOM HTTP API server (spec/openapi.yaml).
    Serve {
        /// Address to bind, e.g. `127.0.0.1:8420`.
        #[arg(
            long,
            value_name = "ADDR",
            default_value = "127.0.0.1:8420",
            env = "ATOM_SERVE_ADDR"
        )]
        addr: String,
    },

    /// Seal bytes into a content-addressed, signed artifact (SUP-001).
    Seal {
        /// Content to seal, given inline. Omit to read from `--input`.
        content: Option<String>,

        /// Read the content from this file instead of the inline argument.
        #[arg(long, value_name = "PATH")]
        input: Option<PathBuf>,

        /// Write the artifact JSON here (default: stdout).
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Provenance: the builder that produced the artifact.
        #[arg(long, default_value = "foundry")]
        builder: String,

        /// Provenance: the source identity the build was driven from.
        #[arg(long, default_value = "atom-cli")]
        source_ref: String,

        /// Provenance: the build recipe identifier.
        #[arg(long, default_value = "atom seal")]
        recipe: String,
    },

    /// Verify a sealed artifact file; exits non-zero on tamper (SUP-001).
    Verify {
        /// Path to the artifact JSON produced by `atom seal`.
        file: PathBuf,
    },
}

/// Runs the parsed CLI to completion.
///
/// # Errors
///
/// Propagates a signing-config failure, an I/O error, a boot refusal, or an
/// artifact verification failure (so a tampered artifact makes `atom verify`
/// exit non-zero).
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { addr } => {
            let version = env!("CARGO_PKG_VERSION");
            let crates_loaded = boot::subsystem_count();
            let store = atom_server::store::Store::open(None)?;
            let addr = addr
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("parsing bind address `{addr}`"))?;
            let future = atom_server::app::serve(version, crates_loaded, addr, store);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building tokio runtime for `atom serve`")?;
            runtime.block_on(future)?;
            Ok(())
        }
        _ => {
            let cfg = SigningConfig::load(cli.config.as_deref())?;
            run_signed(cli, cfg)
        }
    }
}

fn run_signed(cli: Cli, cfg: SigningConfig) -> Result<()> {
    match cli.command {
        Command::Run => {
            let report = boot::boot(&cfg)?;
            print!("{report}");
            Ok(())
        }
        Command::Serve { .. } => Err(anyhow!("`atom serve` does not load a signing config")),
        Command::Seal {
            content,
            input,
            out,
            builder,
            source_ref,
            recipe,
        } => {
            let bytes = resolve_content(content, input.as_deref())?;
            let provenance = Provenance::new(&builder, &source_ref, &recipe);
            let artifact = artifact_ops::seal_bytes(bytes, provenance, &cfg);
            let json = artifact_ops::to_json(&artifact)?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &json)
                        .with_context(|| format!("writing artifact `{}`", path.display()))?;
                    println!("sealed {} -> {}", artifact.id(), path.display());
                }
                None => println!("{json}"),
            }
            Ok(())
        }
        Command::Verify { file } => {
            let artifact = artifact_ops::read_artifact_file(&file)?;
            artifact_ops::verify_artifact(&artifact, &cfg)?;
            println!("OK {}", artifact.id());
            Ok(())
        }
    }
}

/// Resolves the bytes to seal from either an inline argument or `--input`.
fn resolve_content(inline: Option<String>, input: Option<&Path>) -> Result<Vec<u8>> {
    match (inline, input) {
        (Some(_), Some(_)) => Err(anyhow!("provide content inline OR via --input, not both")),
        (Some(text), None) => Ok(text.into_bytes()),
        (None, Some(path)) => {
            std::fs::read(path).with_context(|| format!("reading content `{}`", path.display()))
        }
        (None, None) => Err(anyhow!("no content: pass it inline or via --input <file>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn cfg() -> SigningConfig {
        SigningConfig::new("test-key", b"test-secret".to_vec())
    }

    // ── the clap parser is internally valid ──────────────────────────────────
    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_run_seal_verify() {
        assert!(Cli::try_parse_from(["atom", "run"]).is_ok());
        assert!(Cli::try_parse_from(["atom", "serve"]).is_ok());
        assert!(Cli::try_parse_from(["atom", "serve", "--addr", "0.0.0.0:9000"]).is_ok());
        assert!(Cli::try_parse_from(["atom", "seal", "hello"]).is_ok());
        assert!(Cli::try_parse_from(["atom", "verify", "a.json"]).is_ok());
        assert!(Cli::try_parse_from(["atom", "bogus-subcommand"]).is_err());
    }

    #[test]
    fn config_flag_is_global_and_parses() {
        let cli = Cli::try_parse_from(["atom", "--config", "cfg.json", "run"])
            .expect("global --config before subcommand parses");
        assert_eq!(cli.config.as_deref(), Some(Path::new("cfg.json")));
    }

    // ── seal + verify round-trips ────────────────────────────────────────────
    #[test]
    fn seal_then_verify_round_trips() {
        let cfg = cfg();
        let artifact = artifact_ops::seal_bytes(
            b"echo hello".to_vec(),
            Provenance::new("foundry", "atom-cli", "atom seal"),
            &cfg,
        );
        assert!(artifact_ops::verify_artifact(&artifact, &cfg).is_ok());
        assert!(artifact.id().as_str().starts_with("sha256:"));
    }

    #[test]
    fn round_trips_through_json() {
        let cfg = cfg();
        let artifact = artifact_ops::seal_bytes(
            b"payload".to_vec(),
            Provenance::new("foundry", "atom-cli", "atom seal"),
            &cfg,
        );
        let json = artifact_ops::to_json(&artifact).expect("serializes");
        let restored: atom_artifact::Artifact = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(restored.id(), artifact.id());
        assert!(artifact_ops::verify_artifact(&restored, &cfg).is_ok());
    }

    // ── wrong secret is rejected ─────────────────────────────────────────────
    #[test]
    fn wrong_secret_is_rejected() {
        let artifact = artifact_ops::seal_bytes(
            b"payload".to_vec(),
            Provenance::new("foundry", "atom-cli", "atom seal"),
            &cfg(),
        );
        let attacker = SigningConfig::new("test-key", b"attacker-secret".to_vec());
        assert!(artifact_ops::verify_artifact(&artifact, &attacker).is_err());
    }

    // ── a forged / tampered bundle does not verify ───────────────────────────
    #[test]
    fn forged_bundle_is_rejected() {
        let cfg = cfg();
        let artifact = artifact_ops::seal_bytes(
            b"payload".to_vec(),
            Provenance::new("foundry", "atom-cli", "atom seal"),
            &cfg,
        );
        // Tamper at the wire level: flip the first content byte, keep the id.
        let mut value: serde_json::Value =
            serde_json::from_str(&artifact_ops::to_json(&artifact).unwrap()).unwrap();
        let first = value["content"][0].as_u64().unwrap();
        value["content"][0] = serde_json::json!((first ^ 0xff) & 0xff);
        let forged: atom_artifact::Artifact = serde_json::from_value(value).unwrap();
        assert!(artifact_ops::verify_artifact(&forged, &cfg).is_err());
    }

    // ── the boot path drives the kernel double gate for real ─────────────────
    #[test]
    fn boot_mints_a_commit_token() {
        let report = boot::boot(&cfg()).expect("boot succeeds");
        assert_eq!(report.nonces_spent, 1, "exactly one nonce burned");
        assert_eq!(report.commit_nonce, "nonce-boot");
        assert_eq!(report.admitted_operation, "write");
        assert_eq!(report.subsystems.len(), 24, "all 24 crates inventoried");
        assert_eq!(report.key_id, "test-key");
    }
}
