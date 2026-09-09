//! Certificate operations for the `atom cert` CLI surface (ATOM-V4-CER-001 / CER-001).
//!
//! `atom cert issue`   — seal a binding into a certificate.
//! `atom cert verify`  — verify a certificate against a live evaluation context.
//! `atom cert inspect` — show certificate binding, signature, and validity.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use atom_cert::{
    BehaviorManifestV2, BindingParams, CertVerifier, Certificate, CertificateBinding, Signature,
    EnvironmentScope, EvaluationContext, EvaluationSuite, HmacSha256CertVerifier, VerifierLevel,
};

use crate::{CertAction, SigningConfig};

/// Entry point for `atom cert` subcommands.
pub fn run(action: CertAction, cfg: &SigningConfig) -> Result<()> {
    match action {
        CertAction::Issue {
            certificate_id,
            subject_digest,
            manifest,
            eval_suite,
            env_scope,
            verifier_level,
            verifier_id,
            issued_at,
            valid_until,
            evidence_refs,
            out,
        } => issue(
            cfg,
            &certificate_id,
            &subject_digest,
            &manifest,
            &eval_suite,
            &env_scope,
            &verifier_level,
            &verifier_id,
            &issued_at,
            &valid_until,
            &evidence_refs,
            out.as_deref(),
        ),
        CertAction::Verify {
            certificate,
            manifest,
            eval_suite,
            env_scope,
            required_level,
        } => {
            let level = parse_level(&required_level)?;
            let env_val = read_json_file(&env_scope)?;
            let env_scope_obj = EnvironmentScope::new(env_val)
                .map_err(|e| anyhow::anyhow!("invalid EnvironmentScope: {e}"))?;
            let manifest_val = read_json_file(&manifest)?;
            let manifest_obj = BehaviorManifestV2::new(manifest_val)
                .map_err(|e| anyhow::anyhow!("invalid BehaviorManifestV2: {e}"))?;
            let eval_val = read_json_file(&eval_suite)?;
            let eval_obj = EvaluationSuite::new(eval_val)
                .map_err(|e| anyhow::anyhow!("invalid EvaluationSuite: {e}"))?;

            let context = EvaluationContext::new(
                manifest_obj.digest(),
                eval_obj.digest(),
                &env_scope_obj,
                Utc::now(),
                level,
            );

            verify(
                cfg,
                &certificate,
                &manifest,
                &eval_suite,
                &env_scope,
                &context,
            )
        }
        CertAction::Inspect { certificate } => inspect(&certificate),
    }
}

fn parse_level(s: &str) -> Result<VerifierLevel> {
    match s.to_uppercase().as_str() {
        "V0" => Ok(VerifierLevel::V0),
        "V1" => Ok(VerifierLevel::V1),
        "V2" => Ok(VerifierLevel::V2),
        "V3" => Ok(VerifierLevel::V3),
        "V4" => Ok(VerifierLevel::V4),
        "V5" => Ok(VerifierLevel::V5),
        _ => anyhow::bail!("invalid verifier level `{s}`: expected V0, V1, V2, V3, V4, or V5"),
    }
}

fn parse_hash(hex: &str) -> Result<atom_ledger::Hash> {
    atom_ledger::Hash::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid hex digest `{hex}`: {e}"))
}

fn read_json_file(path: &Path) -> Result<serde_json::Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing `{}` as JSON", path.display()))
}

// ---------------------------------------------------------------------------
// Certificate JSON envelope (round-tripable).
//
// The envelope stores the full binding inputs and the HMAC signature bytes so
// `cert verify` can reconstruct the binding deterministically and check the
// seal without re-issuing.
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct CertEnvelope {
    certificate_id: String,
    subject_digest: String,
    behavior_manifest_digest: String,
    evaluation_suite_digest: String,
    environment_scope_digest: String,
    verifier_level: String,
    verifier_id: String,
    issued_at: String,
    valid_until: String,
    stale_conditions: Vec<String>,
    evidence_refs: Vec<String>,
    signature_key_id: String,
    signature_bytes_hex: String,
}

#[allow(clippy::too_many_arguments)]
fn issue(
    cfg: &SigningConfig,
    certificate_id: &str,
    subject_digest: &str,
    manifest_path: &Path,
    eval_suite_path: &Path,
    env_scope_path: &Path,
    verifier_level: &str,
    verifier_id: &str,
    issued_at: &str,
    valid_until: &str,
    evidence_refs: &[String],
    out: Option<&Path>,
) -> Result<()> {
    let subject = parse_hash(subject_digest)?;
    let level = parse_level(verifier_level)?;
    let issued_at_dt: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(issued_at)
        .with_context(|| format!("parsing issued_at `{issued_at}`"))?
        .with_timezone(&Utc);
    let valid_until_dt: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(valid_until)
        .with_context(|| format!("parsing valid_until `{valid_until}`"))?
        .with_timezone(&Utc);

    let manifest_val = read_json_file(manifest_path)?;
    let eval_val = read_json_file(eval_suite_path)?;
    let env_val = read_json_file(env_scope_path)?;

    let manifest = BehaviorManifestV2::new(manifest_val)
        .map_err(|e| anyhow::anyhow!("invalid BehaviorManifestV2: {e}"))?;
    let eval_suite = EvaluationSuite::new(eval_val)
        .map_err(|e| anyhow::anyhow!("invalid EvaluationSuite: {e}"))?;
    let env_scope = EnvironmentScope::new(env_val)
        .map_err(|e| anyhow::anyhow!("invalid EnvironmentScope: {e}"))?;

    let binding = CertificateBinding::new(BindingParams {
        certificate_id: certificate_id.to_owned(),
        subject_digest: subject,
        behavior_manifest_digest: manifest.digest(),
        evaluation_suite_digest: eval_suite.digest(),
        environment_scope: env_scope.clone(),
        verifier_level: level,
        verifier_id: verifier_id.to_owned(),
        issued_at: issued_at_dt,
        valid_until: valid_until_dt,
        evidence_refs: evidence_refs.to_vec(),
    });

    let signer = HmacSha256CertVerifier::new(&cfg.key_id, &cfg.secret);
    let certificate = Certificate::issue(binding, &signer)
        .map_err(|e| anyhow::anyhow!("certificate issuance failed: {e}"))?;

    let envelope = CertEnvelope {
        certificate_id: certificate_id.to_owned(),
        subject_digest: certificate.binding().subject_digest().to_hex(),
        behavior_manifest_digest: manifest.digest().to_hex(),
        evaluation_suite_digest: eval_suite.digest().to_hex(),
        environment_scope_digest: env_scope.digest().to_hex(),
        verifier_level: level.as_str().to_owned(),
        verifier_id: verifier_id.to_owned(),
        issued_at: issued_at_dt.to_rfc3339(),
        valid_until: valid_until_dt.to_rfc3339(),
        stale_conditions: certificate.binding().stale_conditions().to_vec(),
        evidence_refs: evidence_refs.to_vec(),
        signature_key_id: certificate.signature().key_id().to_owned(),
        signature_bytes_hex: hex::encode(certificate.signature().bytes()),
    };

    let json = serde_json::to_string_pretty(&envelope)?;
    match out {
        Some(path) => {
            std::fs::write(path, &json)
                .with_context(|| format!("writing certificate to `{}`", path.display()))?;
            println!(
                "issued certificate `{certificate_id}` -> {}",
                path.display()
            );
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn verify(
    cfg: &SigningConfig,
    cert_path: &Path,
    manifest_path: &Path,
    eval_suite_path: &Path,
    env_scope_path: &Path,
    _context: &EvaluationContext,
) -> Result<()> {
    let cert_text = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading certificate `{}`", cert_path.display()))?;
    let envelope: CertEnvelope =
        serde_json::from_str(&cert_text).with_context(|| "parsing certificate JSON")?;

    // Reconstruct the binding from stored parameters.
    let subject = parse_hash(&envelope.subject_digest)?;
    let manifest_digest = parse_hash(&envelope.behavior_manifest_digest)?;
    let eval_digest = parse_hash(&envelope.evaluation_suite_digest)?;
    let verifier_level = parse_level(&envelope.verifier_level)?;

    // Parse issued_at and valid_until to DateTime<Utc>.
    let issued_at: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&envelope.issued_at)
        .context("parsing stored issued_at")?
        .with_timezone(&Utc);
    let valid_until: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&envelope.valid_until)
        .context("parsing stored valid_until")?
        .with_timezone(&Utc);

    // Build environment scope.
    let env_val = read_json_file(env_scope_path)?;
    let env_scope = EnvironmentScope::new(env_val)
        .map_err(|e| anyhow::anyhow!("invalid EnvironmentScope: {e}"))?;

    // Build the binding from stored parameters.
    let binding = CertificateBinding::new(BindingParams {
        certificate_id: envelope.certificate_id.clone(),
        subject_digest: subject,
        behavior_manifest_digest: manifest_digest,
        evaluation_suite_digest: eval_digest,
        environment_scope: env_scope.clone(),
        verifier_level,
        verifier_id: envelope.verifier_id.clone(),
        issued_at,
        valid_until,
        evidence_refs: envelope.evidence_refs.clone(),
    });

    // Reconstruct the certificate from the stored binding + signature
    // (no re-issuance needed; signature is validated via constant-time compare).
    let sig_bytes = hex::decode(&envelope.signature_bytes_hex)
        .map_err(|e| anyhow::anyhow!("decoding stored signature hex: {e}"))?;
    let certificate = Certificate::from_parts(binding, Signature {
        key_id: envelope.signature_key_id.clone(),
        bytes: sig_bytes.clone(),
    });

    // Authenticate the seal via constant-time HMAC verification.
    let signer = HmacSha256CertVerifier::new(&cfg.key_id, &cfg.secret);
    if !signer.verify(certificate.binding().verifier_id(), &certificate.binding().digest(), &sig_bytes) {
        anyhow::bail!(
            "signature mismatch: stored seal does not match the signing key `{}`",
            cfg.key_id
        );
    }

    // Validate environment scope digest against stored value.
    if certificate.binding().environment_scope_digest() != parse_hash(&envelope.environment_scope_digest)? {
        anyhow::bail!(
            "environment scope digest mismatch: stored {:?} does not match computed {:?}",
            envelope.environment_scope_digest,
            certificate.binding().environment_scope_digest()
        );
    }

    // Now check against the live evaluation context.
    let manifest_val = read_json_file(manifest_path)?;
    let eval_val = read_json_file(eval_suite_path)?;

    let manifest = BehaviorManifestV2::new(manifest_val)
        .map_err(|e| anyhow::anyhow!("invalid BehaviorManifestV2: {e}"))?;
    let eval_suite = EvaluationSuite::new(eval_val)
        .map_err(|e| anyhow::anyhow!("invalid EvaluationSuite: {e}"))?;

    let context = EvaluationContext::new(
        manifest.digest(),
        eval_suite.digest(),
        &env_scope,
        Utc::now(),
        verifier_level,
    );

    // Check temporal, stale, and level constraints via Certificate::verify().
    certificate.verify(&signer, &context)
        .map_err(|e| anyhow::anyhow!("certificate verification FAILED: {e}"))?;

    println!(
        "VERIFIED: certificate `{}` is valid",
        envelope.certificate_id
    );
    Ok(())
}

fn inspect(cert_path: &Path) -> Result<()> {
    let cert_text = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading certificate `{}`", cert_path.display()))?;
    let envelope: CertEnvelope =
        serde_json::from_str(&cert_text).with_context(|| "parsing certificate JSON")?;

    println!("Certificate: {}", envelope.certificate_id);
    println!("  Subject digest:       {}", envelope.subject_digest);
    println!(
        "  Manifest digest:      {}",
        envelope.behavior_manifest_digest
    );
    println!(
        "  Eval suite digest:    {}",
        envelope.evaluation_suite_digest
    );
    println!(
        "  Env scope digest:     {}",
        envelope.environment_scope_digest
    );
    println!("  Verifier level:       {}", envelope.verifier_level);
    println!("  Verifier id:          {}", envelope.verifier_id);
    println!("  Issued at:            {}", envelope.issued_at);
    println!("  Valid until:          {}", envelope.valid_until);
    println!("  Stale conditions:     {:?}", envelope.stale_conditions);
    println!("  Evidence refs:        {:?}", envelope.evidence_refs);
    println!("  Signature key:        {}", envelope.signature_key_id);
    println!(
        "  Signature ({} bytes)",
        hex::decode(&envelope.signature_bytes_hex)
            .map(|b| b.len())
            .unwrap_or(0)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal hex helpers (no external dep).
// ---------------------------------------------------------------------------
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("odd-length hex string".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex byte at {i}: {e}"))
            })
            .collect()
    }
}
