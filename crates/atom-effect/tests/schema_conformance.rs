//! The wire shapes must match the authoritative JSON Schemas in `spec/schemas/`
//! and the state names must match `spec/enums.yaml`.

mod support;

use atom_effect::{
    issue_commit_permit, Compensation, CompensationStrategy, Condition, EffectIntent,
    EffectIntentBuilder, EffectState, Idempotency, IdempotencyMode, IntentError, PermitRequest,
    Reconciliation, ReconciliationClass, RetryClass, COMMIT_PERMIT_SCHEMA, EFFECT_INTENT_SCHEMA,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use support::{
    durability, grant, intent, intent_in, now, planned_witness, EFFECT_ID, EXTERNAL_OPERATION_ID,
    GRANT_GENERATION, OPERATION, PRINCIPAL, RESOURCE_ID, RESOURCE_TYPE, UPSTREAM_EFFECT_ID,
};

const ENUMS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/enums.yaml"
));

fn compiled(schema: &str) -> JSONSchema {
    let value: Value = serde_json::from_str(schema).expect("embedded spec schema is valid JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("embedded spec schema compiles")
}

#[track_caller]
fn assert_valid(schema: &JSONSchema, instance: &Value) {
    if let Err(errors) = schema.validate(instance) {
        let violations: Vec<String> = errors
            .map(|error| format!("{} at {}", error, error.instance_path))
            .collect();
        panic!(
            "{} violates its spec schema: {violations:?}",
            serde_json::to_string_pretty(instance).expect("instance re-serializes")
        );
    }
}

/// The `effect_state:` list from `spec/enums.yaml`.
fn spec_effect_states() -> Vec<String> {
    let mut states = Vec::new();
    let mut inside = false;
    for raw in ENUMS.lines() {
        if raw == "effect_state:" {
            inside = true;
            continue;
        }
        if inside {
            match raw.strip_prefix("- ") {
                Some(name) => states.push(name.to_owned()),
                None => break,
            }
        }
    }
    states
}

#[test]
fn the_state_enum_matches_spec_enums_yaml() {
    let spec = spec_effect_states();
    assert_eq!(spec.len(), 16, "{spec:?}");
    let declared: Vec<&str> = EffectState::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(declared, spec);
}

#[test]
fn every_state_serializes_into_a_schema_valid_effect_intent() {
    let schema = compiled(EFFECT_INTENT_SCHEMA);

    for state in EffectState::ALL {
        let effect = intent_in(state);
        let json = serde_json::to_value(&effect).expect("intent serializes");
        assert_valid(&schema, &json);
        assert_eq!(json["state"], Value::String(state.as_str().to_owned()));
    }
}

#[test]
fn the_intent_round_trips_through_json() {
    let effect = intent_in(EffectState::Dispatched);
    let json = serde_json::to_string(&effect).expect("intent serializes");
    let parsed: EffectIntent = serde_json::from_str(&json).expect("intent deserializes");
    assert_eq!(parsed, effect);
}

#[test]
fn unknown_intent_fields_are_rejected() {
    let mut json = serde_json::to_value(intent()).expect("intent serializes");
    json.as_object_mut()
        .expect("an intent is a JSON object")
        .insert("shadow_field".into(), Value::Bool(true));

    let error = serde_json::from_value::<EffectIntent>(json)
        .expect_err("the schema sets additionalProperties: false");
    assert!(error.to_string().contains("shadow_field"), "{error}");
}

#[test]
fn the_intent_carries_every_efx_002_field() {
    let planned = serde_json::to_value(intent()).expect("intent serializes");
    for field in [
        "effect_id",
        "mission_id",
        "capability_id",
        "target_id",
        "request_digest",
        "effect_class",
        "risk_class",
        "idempotency",
        "preconditions",
        "postconditions",
        "reconciliation",
        "compensation",
        "dependencies",
        "state",
    ] {
        assert!(!planned[field].is_null(), "EFX-002 field {field} is missing");
    }
    assert_eq!(planned["dependencies"], serde_json::json!([UPSTREAM_EFFECT_ID]));
    assert!(planned["external_operation_id"].is_null(), "not dispatched yet");

    let dispatched = serde_json::to_value(intent_in(EffectState::Dispatched))
        .expect("dispatched intent serializes");
    assert_eq!(
        dispatched["external_operation_id"],
        Value::String(EXTERNAL_OPERATION_ID.into()),
        "external operation identity is recorded at dispatch (EFX-002)"
    );
}

#[test]
fn the_commit_permit_matches_its_spec_schema() {
    let schema = compiled(COMMIT_PERMIT_SCHEMA);
    let effect = intent_in(EffectState::CommitRevalidating);
    let authority = grant();
    let witness = planned_witness();
    let proof = durability();

    let request = PermitRequest {
        intent: &effect,
        grant: &authority,
        principal_id: PRINCIPAL,
        operation: OPERATION,
        resource_type: RESOURCE_TYPE,
        planned_grant_generation: GRANT_GENERATION,
        planned_witness: &witness,
        observed_witness: &witness,
        durability: &proof,
        permit_id: "permit/01J8ZPCOMMITORDERS",
        one_shot_nonce: "nonce/01J8ZPCOMMITORDERS",
        ttl_seconds: 10,
        now: now(),
        approval_id: Some("approval/01J8ZPAPPROVEARCHIVE"),
        evidence_freshness_digest: Some("sha256:abc"),
    };

    let with_approval = issue_commit_permit(request.clone()).expect("nothing drifted");
    assert_valid(
        &schema,
        &serde_json::to_value(&with_approval).expect("permit serializes"),
    );

    let bare = issue_commit_permit(PermitRequest {
        approval_id: None,
        evidence_freshness_digest: None,
        ..request
    })
    .expect("approval and evidence freshness are optional");
    let json = serde_json::to_value(&bare).expect("permit serializes");
    assert_valid(&schema, &json);
    assert!(json["approval_id"].is_null());
    assert!(json["evidence_freshness_digest"].is_null());
    assert_eq!(json["grant_generation"], Value::from(GRANT_GENERATION));
    assert_eq!(
        json["issued_at"],
        Value::String("2026-08-30T12:00:00Z".into()),
        "timestamps are RFC 3339 date-times"
    );
}

/// A builder with every mandatory EFX-002 field set except `omit`.
fn builder_without(omit: &str) -> EffectIntentBuilder {
    let mut builder = EffectIntent::builder(
        EFFECT_ID,
        "mission/01J8Z0MISSIONORDERS",
        "grant/orders-writer",
        RESOURCE_ID,
    );
    if omit != "request_digest" {
        builder = builder.request_digest("sha256:deadbeef");
    }
    if omit != "classes" {
        builder = builder.classes("RESOURCE_MUTATION", "LOW");
    }
    if omit != "idempotency" {
        builder = builder.idempotency(Idempotency::natural(RESOURCE_ID));
    }
    if omit != "reconciliation" {
        builder = builder.reconciliation(Reconciliation::new(
            ReconciliationClass::LedgerReplay,
            RetryClass::ReconcileBeforeRetry,
        ));
    }
    if omit != "compensation" {
        builder = builder.compensation(Compensation::new(CompensationStrategy::NotCompensable));
    }
    builder
}

#[test]
fn an_intent_missing_an_efx_002_field_is_rejected() {
    let complete = builder_without("nothing")
        .build()
        .expect("the complete skeleton is valid");
    assert_eq!(complete.state, EffectState::IntentDurable);
    assert!(complete.preconditions.is_empty());

    for field in [
        "request_digest",
        "classes",
        "idempotency",
        "reconciliation",
        "compensation",
    ] {
        let error = builder_without(field)
            .build()
            .expect_err("EFX-002 fields are mandatory");
        assert!(
            matches!(error, IntentError::MissingField { .. }),
            "{field}: {error:?}"
        );
    }
}

#[test]
fn a_blank_identifier_is_rejected() {
    let error = EffectIntent::builder(EFFECT_ID, "  ", "grant/orders-writer", RESOURCE_ID)
        .request_digest("sha256:deadbeef")
        .classes("RESOURCE_MUTATION", "LOW")
        .idempotency(Idempotency::natural(RESOURCE_ID))
        .reconciliation(Reconciliation::new(
            ReconciliationClass::LedgerReplay,
            RetryClass::ReconcileBeforeRetry,
        ))
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .expect_err("a blank mission id is not an identifier");
    assert!(matches!(error, IntentError::EmptyField { .. }), "{error:?}");
}

/// EFX-002 asks for *declared* semantics, so a declaration that contradicts
/// itself is worse than a missing one: it would be replayed as if it were true.
#[test]
fn self_contradicting_semantics_are_rejected() {
    let cases: [(&str, EffectIntentBuilder); 6] = [
        (
            "a keyed scope without a key",
            builder_without("idempotency").idempotency(Idempotency {
                mode: IdempotencyMode::Keyed,
                scope: RESOURCE_ID.into(),
                key: None,
            }),
        ),
        (
            "a naturally idempotent scope carrying a key",
            builder_without("idempotency").idempotency(Idempotency {
                mode: IdempotencyMode::Natural,
                scope: RESOURCE_ID.into(),
                key: Some("idem-8842".into()),
            }),
        ),
        (
            "an external lookup with nothing to look up",
            builder_without("reconciliation").reconciliation(Reconciliation::new(
                ReconciliationClass::ExternalOperationLookup,
                RetryClass::ReconcileBeforeRetry,
            )),
        ),
        (
            "an unreconcilable effect with a probe",
            builder_without("reconciliation").reconciliation(
                Reconciliation::new(ReconciliationClass::NotReconcilable, RetryClass::Never)
                    .with_probe("GET /orders/8842"),
            ),
        ),
        (
            "an inverse operation with no operation",
            builder_without("compensation")
                .compensation(Compensation::new(CompensationStrategy::InverseOperation)),
        ),
        (
            "an uncompensable effect with an undo",
            builder_without("compensation").compensation(
                Compensation::new(CompensationStrategy::NotCompensable)
                    .with_operation("POST /orders/8842/restore"),
            ),
        ),
    ];

    for (label, builder) in cases {
        let error = builder
            .build()
            .expect_err("contradictory semantics must not build");
        assert!(
            matches!(error, IntentError::Inconsistent { .. }),
            "{label}: {error:?}"
        );
    }
}

/// EFX-002 dependency edges feed the EFX-003 blocking check, so the edge set
/// must be a set, and it must be acyclic at least locally.
#[test]
fn a_broken_dependency_edge_is_rejected() {
    let error = builder_without("nothing")
        .dependency(EFFECT_ID)
        .build()
        .expect_err("an effect cannot wait for itself");
    assert!(
        matches!(error, IntentError::SelfDependency { .. }),
        "{error:?}"
    );

    let error = builder_without("nothing")
        .dependency(UPSTREAM_EFFECT_ID)
        .dependency(UPSTREAM_EFFECT_ID)
        .build()
        .expect_err("a dependency edge is declared once");
    assert!(
        matches!(error, IntentError::DuplicateDependency { .. }),
        "{error:?}"
    );

    let error = builder_without("nothing")
        .dependency("   ")
        .build()
        .expect_err("a blank dependency is not an identifier");
    assert!(matches!(error, IntentError::EmptyField { .. }), "{error:?}");

    let ordered = builder_without("nothing")
        .dependency(UPSTREAM_EFFECT_ID)
        .dependency("effect/01J8ZPANOTHERWRITE")
        .build()
        .expect("two distinct upstream edges are fine");
    assert_eq!(
        ordered.dependencies,
        vec![
            UPSTREAM_EFFECT_ID.to_owned(),
            "effect/01J8ZPANOTHERWRITE".to_owned()
        ],
        "declaration order is preserved so the digest is stable"
    );
}

#[test]
fn a_condition_without_an_identity_is_rejected() {
    for (label, builder) in [
        (
            "precondition",
            builder_without("nothing").precondition(Condition::new("", "orders.id == 8842")),
        ),
        (
            "postcondition",
            builder_without("nothing")
                .postcondition(Condition::new("post/row-archived", "   ")),
        ),
    ] {
        let error = builder
            .build()
            .expect_err("a condition needs an id and an expression");
        assert!(
            matches!(error, IntentError::EmptyField { .. }),
            "{label}: {error:?}"
        );
    }

    let effect = builder_without("nothing")
        .precondition(Condition::new("pre/row-exists", "orders.id == 8842"))
        .postcondition(Condition::new("post/row-archived", "orders.state == 'X'"))
        .build()
        .expect("well-formed conditions are kept");
    assert_eq!(effect.preconditions.len(), 1);
    assert_eq!(effect.postconditions.len(), 1);
    assert_eq!(effect.preconditions[0].condition_id, "pre/row-exists");
}
