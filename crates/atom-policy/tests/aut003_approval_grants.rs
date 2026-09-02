//! AUT-003 / INV-003 / INV-012 acceptance tests for approval-scoped policy.
//!
//! Every timestamp is supplied by the test.  In particular, policy evaluation
//! must not read a clock to decide whether a grant is valid.

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_policy::{
    ApprovalGrant, ApprovalScope, ApprovalStatus, CapabilityScope, EffectIntent, EffectScope,
    PolicyDecision, PolicyEngine,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::json;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("valid fixed timestamp")
}

fn resource(resource_type: &str, resource_id: &str) -> ResourceSelector {
    ResourceSelector {
        resource_type: resource_type.into(),
        resource_id: resource_id.into(),
    }
}

fn capability(
    operations: Vec<&str>,
    resources: Vec<ResourceSelector>,
    budget: Budget,
) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "capability-1".into(),
        subject_id: "worker-1".into(),
        workload_id: "workload-1".into(),
        operations: operations.into_iter().map(str::to_owned).collect(),
        resources,
        purpose: "test-policy".into(),
        not_before: now() - Duration::minutes(1),
        expires_at: now() + Duration::hours(1),
        budget,
        delegation_depth: 1,
        audience: "test".into(),
        generation: 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
        authority_digest: None,
        holder_binding: None,
        parent_authority_digest: None,
    }
}

fn intent(
    effect_digest: &str,
    operation: &str,
    resources: Vec<ResourceSelector>,
    budget: Budget,
) -> EffectIntent {
    EffectIntent {
        effect_intent_digest: effect_digest.into(),
        operation: operation.into(),
        resources,
        resource_witness: json!({"generation": 7, "observed_at": "2026-08-30T11:59:00Z"}),
        budget,
        evidence_freshness_digest: "evidence-fresh-1".into(),
    }
}

fn granted_effect_approval(effect_digest: &str, expires_at: DateTime<Utc>) -> ApprovalGrant {
    ApprovalGrant {
        grant_id: "approval-1".into(),
        approver_id: "operator-1".into(),
        scope: ApprovalScope::Effect(EffectScope {
            effect_intent_digest: effect_digest.into(),
            resource_witness: json!({"generation": 7, "observed_at": "2026-08-30T11:59:00Z"}),
        }),
        expires_at,
        max_uses: 1,
        uses_remaining: 1,
        evidence_freshness_digest: "evidence-fresh-1".into(),
        status: ApprovalStatus::Granted,
    }
}

#[test]
fn aut003_changed_payload_cannot_use_an_effect_scoped_approval() {
    let cap = capability(
        vec!["execute"],
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 100,
            max_seconds: 60,
        },
    );
    let changed_intent = intent(
        "effect-b-digest",
        "execute",
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 10,
            max_seconds: 10,
        },
    );
    let approval = granted_effect_approval("effect-a-digest", now() + Duration::minutes(5));

    let decision = PolicyEngine::evaluate(&changed_intent, &[approval], &cap, now());

    assert!(matches!(
        decision,
        PolicyDecision::RequireApproval(ApprovalScope::Effect(EffectScope {
            effect_intent_digest,
            ..
        })) if effect_intent_digest == "effect-b-digest"
    ));
}

#[test]
fn aut003_expired_approval_is_rejected_using_the_injected_clock() {
    let cap = capability(
        vec!["execute"],
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 100,
            max_seconds: 60,
        },
    );
    let effect = intent(
        "effect-a-digest",
        "execute",
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 10,
            max_seconds: 10,
        },
    );
    let approval = granted_effect_approval("effect-a-digest", now() - Duration::seconds(1));

    let decision = PolicyEngine::evaluate(&effect, &[approval], &cap, now());

    assert!(matches!(decision, PolicyDecision::Deny(reason) if reason.contains("expired")));
}

#[test]
fn aut003_revoked_approval_is_rejected() {
    let cap = capability(
        vec!["execute"],
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 100,
            max_seconds: 60,
        },
    );
    let effect = intent(
        "effect-a-digest",
        "execute",
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 10,
            max_seconds: 10,
        },
    );
    let mut approval = granted_effect_approval("effect-a-digest", now() + Duration::minutes(5));
    approval.status = ApprovalStatus::Revoked;

    let decision = PolicyEngine::evaluate(&effect, &[approval], &cap, now());

    assert!(matches!(decision, PolicyDecision::Deny(reason) if reason.contains("revoked")));
}

#[test]
fn bounded_capability_scope_allows_only_an_authorized_effect() {
    let cap = capability(
        vec!["read", "write"],
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 100,
            max_seconds: 60,
        },
    );
    let effect = intent(
        "effect-write-digest",
        "write",
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 10,
            max_seconds: 10,
        },
    );
    let approval = ApprovalGrant {
        grant_id: "approval-write".into(),
        approver_id: "operator-1".into(),
        scope: ApprovalScope::Capability(CapabilityScope {
            operations: vec!["write".into()],
            resources: vec![resource("server", "srv-1")],
            budget: Budget {
                max_cost: 20,
                max_seconds: 20,
            },
        }),
        expires_at: now() + Duration::minutes(5),
        max_uses: 2,
        uses_remaining: 2,
        evidence_freshness_digest: "evidence-fresh-1".into(),
        status: ApprovalStatus::Granted,
    };

    let decision = PolicyEngine::evaluate(&effect, &[approval], &cap, now());

    assert!(matches!(decision, PolicyDecision::Allow(reason) if reason.contains("approval-write")));
}

#[test]
fn inv003_approval_envelope_cannot_exceed_the_grantees_capability() {
    let cap = capability(
        vec!["read"],
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 100,
            max_seconds: 60,
        },
    );
    let effect = intent(
        "effect-read-digest",
        "read",
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 10,
            max_seconds: 10,
        },
    );
    let approval = ApprovalGrant {
        grant_id: "approval-broad".into(),
        approver_id: "operator-1".into(),
        scope: ApprovalScope::Capability(CapabilityScope {
            operations: vec!["read".into(), "admin".into()],
            resources: vec![resource("server", "srv-1")],
            budget: Budget {
                max_cost: 100,
                max_seconds: 60,
            },
        }),
        expires_at: now() + Duration::minutes(5),
        max_uses: 1,
        uses_remaining: 1,
        evidence_freshness_digest: "evidence-fresh-1".into(),
        status: ApprovalStatus::Granted,
    };

    let decision = PolicyEngine::evaluate(&effect, &[approval], &cap, now());

    assert!(matches!(decision, PolicyDecision::Deny(reason) if reason.contains("capability")));
}

#[test]
fn inv012_pressure_cannot_turn_missing_capability_into_authority() {
    let cap = capability(
        vec!["read"],
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 100,
            max_seconds: 60,
        },
    );
    let effect = intent(
        "effect-execute-digest",
        "execute",
        vec![resource("server", "srv-1")],
        Budget {
            max_cost: 10,
            max_seconds: 10,
        },
    );
    let approval = ApprovalGrant {
        grant_id: "approval-pressure".into(),
        approver_id: "operator-1".into(),
        scope: ApprovalScope::Capability(CapabilityScope {
            operations: vec!["execute".into()],
            resources: vec![resource("server", "srv-1")],
            budget: Budget {
                max_cost: 100,
                max_seconds: 60,
            },
        }),
        expires_at: now() + Duration::minutes(5),
        max_uses: 1,
        uses_remaining: 1,
        evidence_freshness_digest: "evidence-fresh-1".into(),
        status: ApprovalStatus::Granted,
    };

    // The policy API deliberately has no pressure/urgency/recommendation input.
    // Repeated evaluation cannot make an unavailable operation become authorized.
    for _pressure_signal in [
        "resource pressure",
        "urgency",
        "model recommendation",
        "repeated success",
    ] {
        let decision =
            PolicyEngine::evaluate(&effect, std::slice::from_ref(&approval), &cap, now());
        assert!(matches!(decision, PolicyDecision::Deny(reason) if reason.contains("operation")));
    }
}

#[test]
fn approval_lifecycle_is_explicit_and_serializable_for_ledger_persistence() {
    let pending = ApprovalGrant {
        grant_id: "approval-lifecycle".into(),
        approver_id: "operator-1".into(),
        scope: ApprovalScope::Effect(EffectScope {
            effect_intent_digest: "effect-a-digest".into(),
            resource_witness: json!({"generation": 7}),
        }),
        expires_at: now() + Duration::minutes(5),
        max_uses: 2,
        uses_remaining: 2,
        evidence_freshness_digest: "evidence-fresh-1".into(),
        status: ApprovalStatus::Pending,
    };

    let granted = pending.grant().expect("pending approval can be granted");
    let once_used = granted.consume().expect("first use is available");
    let consumed = once_used.consume().expect("second use is available");

    assert_eq!(once_used.status, ApprovalStatus::Granted);
    assert_eq!(once_used.uses_remaining, 1);
    assert_eq!(consumed.status, ApprovalStatus::Consumed);
    assert_eq!(consumed.uses_remaining, 0);
    let durable = serde_json::to_string(&consumed).expect("ledger payload serializes");
    let restored: ApprovalGrant = serde_json::from_str(&durable).expect("ledger payload restores");
    assert_eq!(restored, consumed);
}
