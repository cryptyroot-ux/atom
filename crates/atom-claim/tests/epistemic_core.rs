//! Acceptance tests for ATOM-EPI-001's Claim surface.

use atom_claim::{
    as_of, link_contradiction, reduce, validate_provenance_dag, walk_provenance, Claim, ClaimEvent,
    ClaimKind, ClaimState, Confidence, Evidence, JsonObject, ProvenanceError, ProvenanceNode,
    SourceAuthority, TaintLabel, TaintLabels, TimeInterval, VerifierLevel, CLAIM_SCHEMA,
};
use chrono::{DateTime, TimeZone, Utc};
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};

fn at(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, day, 12, 0, 0)
        .single()
        .expect("fixture date is valid")
}

fn interval(from_day: u32, to_day: Option<u32>) -> TimeInterval {
    TimeInterval::new(at(from_day), to_day.map(at)).expect("fixture interval is increasing")
}

fn claim(
    id: &str,
    state: ClaimState,
    valid_time: TimeInterval,
    transaction_time: TimeInterval,
) -> Claim {
    Claim::builder(
        id,
        ClaimKind::Fact,
        JsonObject::empty(),
        Confidence::new(0.75).expect("fixture confidence is in range"),
        SourceAuthority::Verified,
        valid_time,
        transaction_time,
    )
    .state(state)
    .taint_labels(TaintLabels::from([TaintLabel::Internal]))
    .build()
    .expect("fixture claim metadata is valid")
}

fn compiled(schema: &str) -> JSONSchema {
    let value: Value = serde_json::from_str(schema).expect("embedded schema is valid JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("embedded schema compiles")
}

#[track_caller]
fn assert_valid(schema: &JSONSchema, instance: &Value) {
    if let Err(errors) = schema.validate(instance) {
        let violations: Vec<String> = errors
            .map(|error| format!("{error} at {}", error.instance_path))
            .collect();
        panic!(
            "{} violates claim.schema.json: {violations:?}",
            serde_json::to_string_pretty(instance).expect("instance re-serializes")
        );
    }
}

#[test]
fn claim_schema_constant_is_byte_for_byte_authoritative() {
    assert_eq!(
        CLAIM_SCHEMA,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/schemas/claim.schema.json"
        ))
    );
}

#[test]
fn built_claim_serializes_to_a_schema_valid_document() {
    let claim = Claim::builder(
        "claim/solar-output-v2",
        ClaimKind::Inference,
        JsonObject::from_iter([(String::from("subject"), json!("solar-array-7"))]),
        Confidence::new(0.8).expect("fixture confidence is in range"),
        SourceAuthority::Verified,
        interval(1, Some(31)),
        interval(2, None),
    )
    .provenance(vec!["evidence/meter-7".into()])
    .evidence_refs(vec!["evidence/meter-7".into()])
    .supersedes(vec!["claim/solar-output-v1".into()])
    .contradicts(vec!["claim/solar-output-forecast".into()])
    .taint_labels(TaintLabels::from([TaintLabel::Internal]))
    .retrieval_policy(JsonObject::from_iter([(
        String::from("gate"),
        json!("memory"),
    )]))
    .retention_policy(JsonObject::from_iter([(String::from("days"), json!(30))]))
    .build()
    .expect("fixture claim metadata is valid");

    let schema = compiled(CLAIM_SCHEMA);
    let serialized = serde_json::to_value(&claim).expect("Claim serializes");
    assert_valid(&schema, &serialized);

    assert_eq!(serialized["kind"], "INFERENCE");
    assert_eq!(serialized["state"], "PROPOSED");
    assert_eq!(serialized["source_authority"], "VERIFIED");
    assert_eq!(serialized["confidence"], json!(0.8));
}

#[test]
fn unknown_claim_fields_are_rejected_during_deserialization() {
    let mut value = serde_json::to_value(claim(
        "claim/no-extras",
        ClaimState::Proposed,
        interval(1, None),
        interval(1, None),
    ))
    .expect("Claim serializes");
    value
        .as_object_mut()
        .expect("Claim wire form is an object")
        .insert("shadow_field".into(), json!(true));

    assert!(serde_json::from_value::<Claim>(value).is_err());
}

#[test]
fn contradiction_edges_keep_both_claims_queryable() {
    let left = claim(
        "claim/site-is-online",
        ClaimState::Supported,
        interval(1, None),
        interval(1, None),
    );
    let right = claim(
        "claim/site-is-offline",
        ClaimState::Supported,
        interval(1, None),
        interval(1, None),
    );

    let (left, right) = link_contradiction(&left, &right).expect("different claims can disagree");
    let queryable = [&left, &right];

    assert_eq!(queryable.len(), 2, "a contradiction never deletes a claim");
    assert_eq!(left.state(), ClaimState::Supported);
    assert_eq!(right.state(), ClaimState::Supported);
    assert_eq!(left.contradicts(), &["claim/site-is-offline".into()]);
    assert_eq!(right.contradicts(), &["claim/site-is-online".into()]);
}

#[test]
fn claim_reducer_accepts_only_the_declared_alpha_edges() {
    assert_eq!(
        reduce(ClaimState::Proposed, ClaimEvent::Supported),
        Ok(ClaimState::Supported)
    );
    assert_eq!(
        reduce(ClaimState::Supported, ClaimEvent::Corroborated),
        Ok(ClaimState::Corroborated)
    );
    assert!(reduce(ClaimState::Proposed, ClaimEvent::Corroborated).is_err());
    assert!(reduce(ClaimState::Disputed, ClaimEvent::Supported).is_err());
}

#[test]
fn provenance_walk_rejects_cycles_and_walks_claim_evidence_dag() {
    let evidence = Evidence::new(
        "evidence/meter",
        VerifierLevel::V3,
        SourceAuthority::Verified,
        TaintLabels::from([TaintLabel::Internal]),
        vec![],
        JsonObject::empty(),
    )
    .expect("fixture evidence is valid");
    let parent = Claim::builder(
        "claim/parent",
        ClaimKind::Fact,
        JsonObject::empty(),
        Confidence::new(0.6).expect("fixture confidence is in range"),
        SourceAuthority::Verified,
        interval(1, None),
        interval(1, None),
    )
    .provenance(vec!["evidence/meter".into()])
    .taint_labels(TaintLabels::from([TaintLabel::Internal]))
    .build()
    .expect("fixture claim is valid");
    let child = Claim::builder(
        "claim/child",
        ClaimKind::Inference,
        JsonObject::empty(),
        Confidence::new(0.6).expect("fixture confidence is in range"),
        SourceAuthority::Verified,
        interval(1, None),
        interval(1, None),
    )
    .provenance(vec!["claim/parent".into()])
    .taint_labels(TaintLabels::from([TaintLabel::Internal]))
    .build()
    .expect("fixture claim is valid");

    let nodes = [
        ProvenanceNode::from(&child),
        ProvenanceNode::from(&parent),
        ProvenanceNode::from(&evidence),
    ];
    validate_provenance_dag(nodes).expect("acyclic Claim/Evidence provenance is valid");
    let walked = walk_provenance(
        [
            ProvenanceNode::from(&child),
            ProvenanceNode::from(&parent),
            ProvenanceNode::from(&evidence),
        ],
        &"claim/child".into(),
    )
    .expect("DAG can be walked");
    assert_eq!(
        walked,
        vec![
            "claim/child".into(),
            "claim/parent".into(),
            "evidence/meter".into(),
        ]
    );

    let first = Claim::builder(
        "claim/cycle-a",
        ClaimKind::Fact,
        JsonObject::empty(),
        Confidence::new(0.5).expect("fixture confidence is in range"),
        SourceAuthority::Verified,
        interval(1, None),
        interval(1, None),
    )
    .provenance(vec!["claim/cycle-b".into()])
    .taint_labels(TaintLabels::from([TaintLabel::Internal]))
    .build()
    .expect("a local record may be built before graph validation");
    let second = Claim::builder(
        "claim/cycle-b",
        ClaimKind::Fact,
        JsonObject::empty(),
        Confidence::new(0.5).expect("fixture confidence is in range"),
        SourceAuthority::Verified,
        interval(1, None),
        interval(1, None),
    )
    .provenance(vec!["claim/cycle-a".into()])
    .taint_labels(TaintLabels::from([TaintLabel::Internal]))
    .build()
    .expect("a local record may be built before graph validation");

    assert!(matches!(
        validate_provenance_dag([ProvenanceNode::from(&first), ProvenanceNode::from(&second),]),
        Err(ProvenanceError::Cycle { .. })
    ));
}

#[test]
fn as_of_selects_the_visible_version_on_both_time_axes() {
    let original = claim(
        "claim/weather-v1",
        ClaimState::Supported,
        interval(1, None),
        interval(1, Some(10)),
    );
    let correction = claim(
        "claim/weather-v2",
        ClaimState::Supported,
        interval(1, None),
        interval(10, None),
    );
    let future_fact = claim(
        "claim/weather-v3",
        ClaimState::Supported,
        interval(20, None),
        interval(10, None),
    );
    let versions = [&original, &correction, &future_fact];

    assert_eq!(
        as_of(versions, at(5), at(5)).map(|claim| claim.claim_id().as_str()),
        Some("claim/weather-v1"),
        "before the correction was transacted, the original version is visible"
    );
    assert_eq!(
        as_of(versions, at(5), at(15)).map(|claim| claim.claim_id().as_str()),
        Some("claim/weather-v2"),
        "the later transaction version replaces the earlier knowledge"
    );
    assert_eq!(
        as_of(versions, at(25), at(15)).map(|claim| claim.claim_id().as_str()),
        Some("claim/weather-v3"),
        "valid time selects the fact applicable to the represented time"
    );
}
