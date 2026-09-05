//! Permit finality (ATOM-V4-EFX-004 · AUT-001): a `CommitPermit` is bound to
//! exactly one sink, one connector identity, one connector version, one
//! instance epoch, one effect digest, one grant generation, and one use.
//!
//! Every test here drives the real issuance and consumption path — a permit is
//! obtained from `issue_commit_permit` and presented to `NonceRegistry::consume`
//! — so a refusal is proof of an enforced boundary, not of a literal's contents.

mod support;

use atom_effect::{
    issue_commit_permit, CommitPermit, ConsumeRequest, EffectState, NonceRegistry, PermitError,
    PermitRequest,
};
use support::{
    advanced, durability, grant, intent_in, now, planned_witness, regenerated_grant,
    upstream_intent, GRANT_GENERATION, OPERATION, PRINCIPAL, RESOURCE_TYPE,
};

const PERMIT_ID: &str = "permit/01J8ZPFINALITY";
const NONCE: &str = "nonce/01J8ZPFINALITY";
const TTL_SECONDS: u32 = 15;

const SINK: &str = "sink/atom-privd";
const CONNECTOR: &str = "connector/atom-cli";
const CONNECTOR_VERSION: &str = "1.4.2";
const CONNECTOR_EPOCH: u64 = 3;

/// The commit gate: an effect at the commit boundary plus the authority that
/// was true when the plan was made.
struct Gate {
    effect: atom_effect::EffectIntent,
    grant: atom_capability::CapabilityGrant,
    planned: atom_effect::ResourceWitness,
    durability: atom_effect::DurabilityProof,
}

impl Gate {
    fn new() -> Self {
        Self {
            effect: intent_in(EffectState::CommitRevalidating),
            grant: grant(),
            planned: planned_witness(),
            durability: durability(),
        }
    }

    /// The issuance request, bound to one sink/connector/version/epoch.
    fn request(&self) -> PermitRequest<'_> {
        PermitRequest {
            intent: &self.effect,
            grant: &self.grant,
            principal_id: PRINCIPAL,
            operation: OPERATION,
            resource_type: RESOURCE_TYPE,
            planned_grant_generation: GRANT_GENERATION,
            planned_witness: &self.planned,
            observed_witness: &self.planned,
            durability: &self.durability,
            permit_id: PERMIT_ID,
            one_shot_nonce: NONCE,
            ttl_seconds: TTL_SECONDS,
            now: now(),
            approval_id: None,
            evidence_freshness_digest: None,
            dispatch_sink_id: SINK,
            connector_identity: CONNECTOR,
            connector_version: CONNECTOR_VERSION,
            connector_instance_epoch: CONNECTOR_EPOCH,
        }
    }

    /// The consumption a well-behaved caller submits: every binding matches.
    fn consume<'a>(&'a self, permit: &'a CommitPermit) -> ConsumeRequest<'a> {
        ConsumeRequest {
            permit,
            intent: &self.effect,
            grant: &self.grant,
            observed_witness: &self.planned,
            now: now(),
            dispatch_sink_id: SINK,
            connector_identity: CONNECTOR,
            connector_version: CONNECTOR_VERSION,
            connector_instance_epoch: CONNECTOR_EPOCH,
        }
    }

    fn permit(&self) -> CommitPermit {
        issue_commit_permit(self.request()).expect("nothing has drifted")
    }
}

#[test]
fn a_matching_presentation_consumes_exactly_once() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    let event = registry
        .consume(gate.consume(&permit))
        .expect("every binding matches");

    assert_eq!(event.permit_id, PERMIT_ID);
    assert_eq!(event.one_shot_nonce, NONCE);
    assert_eq!(event.effect_digest, gate.effect.digest());
    assert_eq!(registry.len(), 1);
}

#[test]
fn valid_permit_wrong_connector_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            connector_identity: "connector/impostor",
            ..gate.consume(&permit)
        })
        .expect_err("a permit is bound to the connector it was issued to");

    assert!(
        matches!(error, PermitError::WrongConnectorIdentity { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0, "a refusal must not burn the nonce");
}

#[test]
fn valid_permit_wrong_sink_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            dispatch_sink_id: "sink/somewhere-else",
            ..gate.consume(&permit)
        })
        .expect_err("a permit is bound to one dispatch sink");

    assert!(
        matches!(error, PermitError::WrongDispatchSink { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn valid_permit_wrong_connector_version_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            connector_version: "9.9.9",
            ..gate.consume(&permit)
        })
        .expect_err("a connector that changed version is not the one authorised");

    assert!(
        matches!(error, PermitError::WrongConnectorVersion { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn valid_permit_stale_instance_epoch_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            connector_instance_epoch: CONNECTOR_EPOCH - 1,
            ..gate.consume(&permit)
        })
        .expect_err("a restarted connector instance may not spend an older permit");

    assert!(
        matches!(error, PermitError::StaleInstanceEpoch { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn valid_permit_modified_arguments_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    // Same permit, a different effect declaration: the digest no longer matches
    // what authority was granted over.
    let other = advanced(upstream_intent(), EffectState::CommitRevalidating);
    let error = registry
        .consume(ConsumeRequest {
            intent: &other,
            ..gate.consume(&permit)
        })
        .expect_err("a permit authorises one exact effect declaration");

    assert!(
        matches!(error, PermitError::DigestMismatch { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn permit_after_policy_generation_change_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    let regenerated = regenerated_grant();
    let error = registry
        .consume(ConsumeRequest {
            grant: &regenerated,
            ..gate.consume(&permit)
        })
        .expect_err("a permit dies when the grant generation moves");

    assert!(
        matches!(error, PermitError::GrantGenerationDrift { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn replayed_one_shot_nonce_after_restart_deny() {
    let gate = Gate::new();
    let permit = gate.permit();

    // A process that restarts rebuilds its one-shot memory from the ledger's
    // nonce-burn stream, so a permit spent before the restart stays spent.
    let mut rehydrated = NonceRegistry::from_used([NONCE.to_owned()]);
    assert!(rehydrated.is_used(NONCE));

    let error = rehydrated
        .consume(gate.consume(&permit))
        .expect_err("a nonce burned before the restart must not be re-served");

    assert!(
        matches!(error, PermitError::NonceAlreadyUsed { .. }),
        "{error:?}"
    );
}

#[test]
fn parallel_calls_share_one_permit_deny() {
    let gate = Gate::new();
    let permit = gate.permit();
    let mut registry = NonceRegistry::new();

    // Two callers racing on the same permit: the registry is the serialisation
    // point, so exactly one crossing is authorised.
    registry
        .consume(gate.consume(&permit))
        .expect("the first crossing is authorised");
    let error = registry
        .consume(gate.consume(&permit))
        .expect_err("the second crossing must be refused");

    assert!(
        matches!(error, PermitError::NonceAlreadyUsed { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 1, "one burn, not two");
}

#[test]
fn synthetic_durability_witness_deny() {
    let gate = Gate::new();

    // `DurabilityProof` is only minted by the ledger's append path, so the only
    // forgery available is a real proof belonging to a different effect.
    let borrowed = support::durability_for(&advanced(
        upstream_intent(),
        EffectState::CommitRevalidating,
    ));

    let error = issue_commit_permit(PermitRequest {
        durability: &borrowed,
        ..gate.request()
    })
    .expect_err("durability of another effect does not authorise this one");

    assert!(
        matches!(error, PermitError::EffectNotDurable { .. }),
        "{error:?}"
    );
}
