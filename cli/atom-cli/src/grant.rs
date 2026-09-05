//! Owner-side capability issuance (`atom grant`).
//!
//! Minting root capability is deliberately *not* an HTTP operation. The daemon
//! must never be able to widen its own authority — "capability may grow,
//! authority may not" — so the only way a grant enters the ledger is an owner
//! with filesystem access to the state database and the signing secret.
//!
//! A running daemon rebuilds its projections at startup, so a grant issued while
//! it is live takes effect on its next restart. The command says so rather than
//! implying the grant is immediately usable.

use anyhow::{bail, Context, Result};
use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use chrono::{Duration, Utc};

use crate::SigningConfig;

/// Parses a `type:id` resource selector, e.g. `file:/etc/atom/example.conf`.
///
/// The type is bounded to what [`atom_privd::HostOp`] can actually name, so a
/// grant cannot be issued for a resource class no operation could ever match.
fn parse_resource(spec: &str) -> Result<ResourceSelector> {
    let Some((resource_type, resource_id)) = spec.split_once(':') else {
        bail!("resource `{spec}` must be `type:id`, e.g. `file:/srv/data/report.txt`");
    };
    const KNOWN: [&str; 3] = ["file", "process", "network"];
    if !KNOWN.contains(&resource_type) {
        bail!(
            "resource type `{resource_type}` is not one of {}",
            KNOWN.join(", ")
        );
    }
    if resource_id.trim().is_empty() {
        bail!("resource `{spec}` has an empty id");
    }
    Ok(ResourceSelector {
        resource_type: resource_type.to_owned(),
        resource_id: resource_id.to_owned(),
    })
}

/// Validates an operation against the closed set the broker can admit.
fn check_operation(operation: &str) -> Result<()> {
    const KNOWN: [&str; 4] = ["write", "delete", "spawn", "configure"];
    if !KNOWN.contains(&operation) {
        bail!(
            "operation `{operation}` is not one of {} (no host op requires it)",
            KNOWN.join(", ")
        );
    }
    Ok(())
}

/// Issues a capability grant into the daemon's ledger.
#[allow(clippy::too_many_arguments)]
pub fn run(action: crate::GrantAction, cfg: &SigningConfig) -> Result<()> {
    match action {
        crate::GrantAction::Issue {
            state_db,
            grant_id,
            subject_id,
            workload_id,
            operations,
            resources,
            purpose,
            ttl_seconds,
            max_cost,
            max_seconds,
            audience,
        } => {
            for operation in &operations {
                check_operation(operation)?;
            }
            let resources: Vec<ResourceSelector> = resources
                .iter()
                .map(|spec| parse_resource(spec))
                .collect::<Result<_>>()?;

            let now = Utc::now();
            let grant = CapabilityGrant {
                grant_id: grant_id.clone(),
                subject_id,
                workload_id,
                operations,
                resources,
                purpose,
                not_before: now,
                expires_at: now
                    + Duration::try_seconds(i64::from(ttl_seconds))
                        .context("--ttl-seconds is out of range")?,
                budget: Budget {
                    max_cost,
                    max_seconds,
                },
                delegation_depth: 0,
                audience,
                generation: 1,
                revocation_state: RevocationState::Active,
                parent_grant_id: None,
                parent_authority_digest: None,
                holder_binding: None,
                authority_digest: None,
                nonce: None,
                constraints: None,
            };

            let signer = Box::new(atom_ledger::HmacSha256Signer::new(&cfg.key_id, &cfg.secret));
            let mut store = atom_server::store::Store::open(&state_db, signer)
                .with_context(|| format!("opening state db `{}`", state_db.display()))?;
            store
                .add_grant(&serde_json::to_value(&grant)?)
                .with_context(|| format!("appending grant `{grant_id}` to the ledger"))?;

            println!("issued capability grant `{grant_id}`");
            println!("  operations: {}", grant.operations.join(", "));
            for resource in &grant.resources {
                println!(
                    "  resource:   {}:{}",
                    resource.resource_type, resource.resource_id
                );
            }
            println!("  expires:    {}", grant.expires_at.to_rfc3339());
            println!();
            println!("A running daemon rebuilds its projections at startup:");
            println!("restart it before this grant can authorise anything.");
            Ok(())
        }
    }
}
