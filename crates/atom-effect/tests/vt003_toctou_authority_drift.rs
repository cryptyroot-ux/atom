//! ATOM-VT-003 — TOCTOU authority drift (EFX-001, EFX-004).
//!
//! Scenario from `spec/acceptance/catalog.yaml`: the grant is revoked, or the
//! resource witness changes, after the effect was planned. Expected outcome:
//! the CommitPermit can be neither issued nor consumed.

mod support;

use atom_capability::CapabilityGrant;
use atom_effect::{
    issue_commit_permit, CommitPermit, ConsumeRequest, DurabilityProof, EffectEvent, EffectIntent,
    EffectState, NonceRegistry, PermitError, PermitRequest, ResourceWitness,
    MAX_PERMIT_TTL_SECONDS,
};
use support::{
    advanced, at, drifted_witness, durability, durability_for, grant, intent_in, now,
    planned_witness, proof_over, regenerated_grant, revoked_grant, upstream_intent, EFFECT_ID,
    GRANT_GENERATION, GRANT_ID, OPERATION, PRINCIPAL, RESOURCE_TYPE, UPSTREAM_EFFECT_ID,
};

const PERMIT_ID: &str = "permit/01J8ZPCOMMITORDERS";
const NONCE: &str = "nonce/01J8ZPCOMMITORDERS";
const TTL_SECONDS: u32 = 15;
const APPROVAL_ID: &str = "approval/01J8ZPAPPROVEARCHIVE";
const EVIDENCE_DIGEST: &str =
    "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

/// Everything the commit gate holds at the moment of revalidation.
struct Gate {
    effect: EffectIntent,
    grant: CapabilityGrant,
    planned: ResourceWitness,
    durability: DurabilityProof,
}

impl Gate {
    /// An effect in COMMIT_REVALIDATING whose plan is still valid.
    fn new() -> Self {
        Self {
            effect: intent_in(EffectState::CommitRevalidating),
            grant: grant(),
            planned: planned_witness(),
            durability: durability(),
        }
    }

    /// The request a well-behaved commit gate submits.
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
            approval_id: Some(APPROVAL_ID),
            evidence_freshness_digest: Some(EVIDENCE_DIGEST),
        }
    }

    /// The consumption a well-behaved commit gate submits.
    fn consume<'a>(&'a self, permit: &'a CommitPermit) -> ConsumeRequest<'a> {
        ConsumeRequest {
            permit,
            intent: &self.effect,
            grant: &self.grant,
            observed_witness: &self.planned,
            now: now(),
        }
    }
}

#[test]
fn an_undrifted_commit_boundary_issues_and_consumes_exactly_one_permit() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");

    assert_eq!(permit.permit_id(), PERMIT_ID);
    assert_eq!(permit.effect_digest(), gate.effect.digest());
    assert_eq!(permit.principal_id(), PRINCIPAL);
    assert_eq!(permit.capability_grant_id(), GRANT_ID);
    assert_eq!(permit.grant_generation(), GRANT_GENERATION);
    assert_eq!(permit.audience(), "atom:orders");
    assert_eq!(permit.workload_id(), "workload/atomd");
    assert_eq!(permit.resource_id(), gate.effect.target_id);
    assert_eq!(permit.resource_version_witness(), &planned_witness());
    assert_eq!(permit.one_shot_nonce(), NONCE);
    assert_eq!(permit.approval_id(), Some(APPROVAL_ID));
    assert_eq!(permit.evidence_freshness_digest(), Some(EVIDENCE_DIGEST));

    // EFX-004: short-lived.
    assert_eq!(permit.issued_at(), now());
    assert_eq!(permit.expires_at(), at(12, 0, 15));
    assert_eq!(permit.ttl_seconds(), i64::from(TTL_SECONDS));
    assert!(permit.is_valid_at(now()));
    assert!(!permit.is_valid_at(at(12, 0, 16)));

    // EFX-004: one-shot. Consuming it opens the dispatch window exactly once.
    let mut registry = NonceRegistry::new();
    let event = registry
        .consume(gate.consume(&permit))
        .expect("a fresh permit is consumable");
    let dispatching = gate
        .effect
        .try_advance(&EffectEvent::CommitPermitted(event.clone()))
        .expect("COMMIT_REVALIDATING -> DISPATCHING is in spec");

    assert_eq!(event.permit_id, PERMIT_ID);
    assert_eq!(event.one_shot_nonce, NONCE);
    assert_eq!(event.effect_digest, gate.effect.digest());
    assert_eq!(dispatching.state, EffectState::Dispatching);
}

#[test]
fn a_grant_revoked_after_planning_blocks_issuance() {
    let gate = Gate::new();
    let revoked = revoked_grant();
    let error = issue_commit_permit(PermitRequest {
        grant: &revoked,
        ..gate.request()
    })
    .expect_err("VT-003: a revoked grant must not yield a permit");
    assert!(
        matches!(error, PermitError::GrantNotActive { .. }),
        "{error:?}"
    );
}

#[test]
fn a_grant_regenerated_after_planning_blocks_issuance() {
    let gate = Gate::new();
    let regenerated = regenerated_grant();
    let error = issue_commit_permit(PermitRequest {
        grant: &regenerated,
        ..gate.request()
    })
    .expect_err("VT-003: authority drift must not yield a permit");
    assert!(
        matches!(
            error,
            PermitError::GrantGenerationDrift {
                planned: GRANT_GENERATION,
                observed,
            } if observed == GRANT_GENERATION + 1
        ),
        "{error:?}"
    );
}

#[test]
fn a_resource_witness_that_changed_after_planning_blocks_issuance() {
    let gate = Gate::new();
    let drifted = drifted_witness();
    let error = issue_commit_permit(PermitRequest {
        observed_witness: &drifted,
        ..gate.request()
    })
    .expect_err("VT-003: a stale witness must not yield a permit");
    assert!(
        matches!(error, PermitError::ResourceWitnessDrift { .. }),
        "{error:?}"
    );
}

#[test]
fn a_grant_outside_its_validity_window_blocks_issuance() {
    let gate = Gate::new();
    for instant in [at(10, 59, 59), at(13, 0, 1)] {
        let error = issue_commit_permit(PermitRequest {
            now: instant,
            ..gate.request()
        })
        .expect_err("a permit must not outlive its grant window");
        assert!(
            matches!(error, PermitError::GrantOutsideValidity { .. }),
            "at {instant}: {error:?}"
        );
    }
}

#[test]
fn a_grant_that_does_not_cover_the_operation_or_resource_blocks_issuance() {
    let gate = Gate::new();

    let error = issue_commit_permit(PermitRequest {
        operation: "delete",
        ..gate.request()
    })
    .expect_err("the grant only allows read and write");
    assert!(
        matches!(error, PermitError::OperationNotGranted { .. }),
        "{error:?}"
    );

    let error = issue_commit_permit(PermitRequest {
        resource_type: "queue",
        ..gate.request()
    })
    .expect_err("the grant only covers the db resource type");
    assert!(
        matches!(error, PermitError::ResourceNotGranted { .. }),
        "{error:?}"
    );

    let error = issue_commit_permit(PermitRequest {
        principal_id: "principal/someone-else",
        ..gate.request()
    })
    .expect_err("a permit is bound to the grant subject");
    assert!(
        matches!(error, PermitError::PrincipalMismatch { .. }),
        "{error:?}"
    );
}

/// EFX-001: no permit without proof that *this* intent was persisted first.
///
/// A `DurabilityProof` can only be minted by the ledger's own append path, so a
/// caller cannot fabricate one out of chosen fields. The only thing left to try
/// is presenting a *real* proof that belongs to another effect. The commit gate
/// refuses it, because a proof proves durability of the stream it was appended
/// to and no other (ATOM-INV-004).
#[test]
fn an_effect_that_was_never_made_durable_blocks_issuance() {
    let gate = Gate::new();
    let other_effects_proof = durability_for(&advanced(
        upstream_intent(),
        EffectState::CommitRevalidating,
    ));
    assert_ne!(
        UPSTREAM_EFFECT_ID, EFFECT_ID,
        "the borrowed proof must belong to a different effect"
    );

    let error = issue_commit_permit(PermitRequest {
        durability: &other_effects_proof,
        ..gate.request()
    })
    .expect_err("EFX-001: a proof for another effect does not authorise this one");
    assert!(
        matches!(error, PermitError::EffectNotDurable { .. }),
        "{error:?}"
    );
}

/// ATOM-INV-004 payload-swap: a *real* proof on the right stream whose payload
/// is a different JSON object is not durability of the gate's intent, even
/// though every other fact (effect, sequence) lines up. Durability is bound to
/// the exact declaration the ledger persisted.
#[test]
fn a_proof_over_a_different_payload_blocks_issuance() {
    let gate = Gate::new();
    let swapped_payload = serde_json::json!({
        "kind": "EFFECT_INTENT",
        "effect_id": EFFECT_ID,
        "operations": ["write"]
    });
    let swapped_proof = proof_over(EFFECT_ID, &swapped_payload);

    let error = issue_commit_permit(PermitRequest {
        durability: &swapped_proof,
        ..gate.request()
    })
    .expect_err("EFX-001/ATOM-INV-004: a proof over a different payload does not bind");
    assert!(
        matches!(error, PermitError::EffectPayloadMismatch { .. }),
        "{error:?}"
    );
}

/// EFX-004: short-lived. The TTL is bounded by the crate, not by the caller.
#[test]
fn a_permit_must_be_short_lived() {
    let gate = Gate::new();

    for ttl in [0, MAX_PERMIT_TTL_SECONDS + 1, 3_600] {
        let error = issue_commit_permit(PermitRequest {
            ttl_seconds: ttl,
            ..gate.request()
        })
        .expect_err("a commit permit must be short-lived");
        assert!(
            matches!(error, PermitError::TtlOutOfRange { .. }),
            "ttl {ttl}: {error:?}"
        );
    }

    let permit = issue_commit_permit(PermitRequest {
        ttl_seconds: MAX_PERMIT_TTL_SECONDS,
        ..gate.request()
    })
    .expect("the maximum TTL is still allowed");
    assert_eq!(permit.ttl_seconds(), i64::from(MAX_PERMIT_TTL_SECONDS));
}

#[test]
fn a_permit_is_only_issued_while_the_effect_is_revalidating() {
    for state in [
        EffectState::IntentDurable,
        EffectState::AuthorizationPending,
        EffectState::Authorized,
        EffectState::Dispatching,
        EffectState::Dispatched,
        EffectState::UnknownOutcome,
        EffectState::ConfirmedSuccess,
        EffectState::CancelledBeforeEffect,
    ] {
        let gate = Gate {
            effect: intent_in(state),
            ..Gate::new()
        };
        let error = issue_commit_permit(gate.request())
            .expect_err("the commit boundary is COMMIT_REVALIDATING only");
        assert!(
            matches!(error, PermitError::EffectNotRevalidating { .. }),
            "{state}: {error:?}"
        );
    }
}

#[test]
fn a_permit_is_one_shot() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");
    let mut registry = NonceRegistry::new();

    registry
        .consume(gate.consume(&permit))
        .expect("the first consumption succeeds");
    let error = registry
        .consume(gate.consume(&permit))
        .expect_err("EFX-004: a permit is one-shot");

    assert!(
        matches!(error, PermitError::NonceAlreadyUsed { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 1, "one burned nonce, not two");
    assert!(registry.is_used(permit.one_shot_nonce()));
}

/// The TOCTOU window itself: everything was valid at issuance and drifts before
/// the permit is consumed.
#[test]
fn authority_that_drifts_after_issuance_blocks_consumption() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing had drifted yet");
    let mut registry = NonceRegistry::new();

    let revoked = revoked_grant();
    let error = registry
        .consume(ConsumeRequest {
            grant: &revoked,
            ..gate.consume(&permit)
        })
        .expect_err("VT-003: a revoked grant must not be consumable");
    assert!(
        matches!(error, PermitError::GrantNotActive { .. }),
        "{error:?}"
    );

    let regenerated = regenerated_grant();
    let error = registry
        .consume(ConsumeRequest {
            grant: &regenerated,
            ..gate.consume(&permit)
        })
        .expect_err("VT-003: a re-issued grant must not be consumable");
    assert!(
        matches!(error, PermitError::GrantGenerationDrift { .. }),
        "{error:?}"
    );

    let drifted = drifted_witness();
    let error = registry
        .consume(ConsumeRequest {
            observed_witness: &drifted,
            ..gate.consume(&permit)
        })
        .expect_err("VT-003: a changed resource witness must not be consumable");
    assert!(
        matches!(error, PermitError::ResourceWitnessDrift { .. }),
        "{error:?}"
    );

    assert_eq!(
        registry.len(),
        0,
        "a refused attempt must not burn the nonce"
    );
    registry
        .consume(gate.consume(&permit))
        .expect("the undrifted permit is still consumable exactly once");
}

#[test]
fn an_expired_or_premature_permit_cannot_be_consumed() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            now: at(12, 0, 16),
            ..gate.consume(&permit)
        })
        .expect_err("a permit past its TTL is dead");
    assert!(
        matches!(error, PermitError::PermitExpired { .. }),
        "{error:?}"
    );

    let error = registry
        .consume(ConsumeRequest {
            now: at(11, 59, 59),
            ..gate.consume(&permit)
        })
        .expect_err("a permit cannot be consumed before it was issued");
    assert!(
        matches!(error, PermitError::PermitNotYetValid { .. }),
        "{error:?}"
    );

    registry
        .consume(ConsumeRequest {
            now: at(12, 0, 15),
            ..gate.consume(&permit)
        })
        .expect("the last second of the TTL is still valid");
}

#[test]
fn a_permit_bound_to_another_effect_cannot_be_consumed() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");
    let other = advanced(upstream_intent(), EffectState::CommitRevalidating);
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            intent: &other,
            ..gate.consume(&permit)
        })
        .expect_err("EFX-004: a permit is bound to one effect digest");
    assert!(
        matches!(error, PermitError::DigestMismatch { .. }),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn a_permit_cannot_be_consumed_once_the_effect_left_the_commit_boundary() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");
    let moved_on = gate
        .effect
        .try_advance(&EffectEvent::commit_revalidation_failed("grant drifted"))
        .expect("COMMIT_REVALIDATING -> AUTHORIZATION_PENDING is in spec");
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            intent: &moved_on,
            ..gate.consume(&permit)
        })
        .expect_err("only a revalidating effect may consume a permit");
    assert!(
        matches!(error, PermitError::EffectNotRevalidating { .. }),
        "{error:?}"
    );
}

#[test]
fn a_permit_is_consumed_by_a_grant_naming_the_same_audience() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");
    let mut registry = NonceRegistry::new();

    let event = registry
        .consume(gate.consume(&permit))
        .expect("the grant names the same audience the permit froze");
    assert_eq!(event.permit_id, PERMIT_ID);
}

#[test]
fn a_permit_cannot_be_consumed_by_a_grant_naming_a_different_audience() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");

    // The same subject, generation, operations, resources, windows — only the
    // audience (the sink the commit drains into) moved.
    let other_sink = CapabilityGrant {
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
        audience: "atom:hospital-lab".into(),
        ..gate.grant.clone()
    };
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            grant: &other_sink,
            ..gate.consume(&permit)
        })
        .expect_err("EFX-004 / Constitution V.3: a permit is audience-bound");
    assert!(
        matches!(error, PermitError::AudienceMismatch { ref expected, ref observed } if observed == "atom:hospital-lab" && expected == "atom:orders"),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

#[test]
fn a_permit_is_consumed_by_a_grant_naming_the_same_workload() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");
    let mut registry = NonceRegistry::new();

    let event = registry
        .consume(gate.consume(&permit))
        .expect("the grant names the same workload the permit froze");
    assert_eq!(event.permit_id, PERMIT_ID);
}

#[test]
fn a_permit_cannot_be_consumed_by_a_grant_naming_a_different_workload() {
    let gate = Gate::new();
    let permit = issue_commit_permit(gate.request()).expect("nothing drifted");

    // The same subject, generation, operations, resources, windows,
    // audience — only the workload identity the grant binds moved.
    let other_workload = CapabilityGrant {
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
        workload_id: "workload/scanner-2".into(),
        ..gate.grant.clone()
    };
    let mut registry = NonceRegistry::new();

    let error = registry
        .consume(ConsumeRequest {
            grant: &other_workload,
            ..gate.consume(&permit)
        })
        .expect_err("EFX-004 / Constitution IV.1: a permit is workload-bound");
    assert!(
        matches!(error, PermitError::WorkloadMismatch { ref expected, ref observed } if observed == "workload/scanner-2" && expected == "workload/atomd"),
        "{error:?}"
    );
    assert_eq!(registry.len(), 0);
}

/// A drifted commit boundary sends the effect back for re-authorisation instead
/// of dispatching it.
#[test]
fn a_failed_revalidation_returns_the_effect_to_authorization() {
    let effect = intent_in(EffectState::CommitRevalidating)
        .try_advance(&EffectEvent::commit_revalidation_failed(
            "grant generation drifted",
        ))
        .expect("COMMIT_REVALIDATING -> AUTHORIZATION_PENDING is in spec");

    assert_eq!(effect.state, EffectState::AuthorizationPending);
    assert!(!effect.state.is_terminal());

    let gate = Gate {
        effect,
        ..Gate::new()
    };
    assert!(matches!(
        issue_commit_permit(gate.request()),
        Err(PermitError::EffectNotRevalidating { .. })
    ));
}
