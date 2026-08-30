//! Acceptance tests for INV-009 and INV-015.

use atom_evidence::{
    derive, Evidence, JsonObject, ModelAssertion, ModelAssertionKind, ModelIdentity, Observation,
    ObservationSource, SourceAuthority, StalenessHorizon, TaintCarrier, TaintLabel, TaintLabels,
    VerifierLevel,
};
use chrono::{TimeZone, Utc};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("fixture timestamp is valid")
}

#[test]
fn inv009_untrusted_taint_is_monotonic_and_authority_cannot_rise() {
    let untrusted = Evidence::new(
        "evidence/untrusted-email",
        VerifierLevel::V0,
        SourceAuthority::Untrusted,
        TaintLabels::from([TaintLabel::UntrustedExternal, TaintLabel::INJECTION_RISK]),
        vec![],
        JsonObject::empty(),
    )
    .expect("untrusted evidence has matching authority");
    let authoritative = Evidence::new(
        "evidence/signed-record",
        VerifierLevel::V5,
        SourceAuthority::Authoritative,
        TaintLabels::from([TaintLabel::Internal]),
        vec![],
        JsonObject::empty(),
    )
    .expect("fixture evidence is valid");

    let inputs: [&dyn TaintCarrier; 2] = [&untrusted, &authoritative];
    let metadata = derive(inputs).expect("inputs can be consolidated");

    assert_eq!(metadata.source_authority(), SourceAuthority::Untrusted);
    assert!(metadata
        .taint_labels()
        .contains(&TaintLabel::UntrustedExternal));
    assert!(metadata
        .taint_labels()
        .contains(&TaintLabel::INJECTION_RISK));
    assert!(metadata.taint_labels().contains(&TaintLabel::Internal));
    assert!(metadata.blocks_unauthorized_effect_eligibility());

    let transformed = Evidence::derived(
        "evidence/summary",
        VerifierLevel::V1,
        vec![
            "evidence/untrusted-email".into(),
            "evidence/signed-record".into(),
        ],
        JsonObject::empty(),
        [
            &untrusted as &dyn TaintCarrier,
            &authoritative as &dyn TaintCarrier,
        ],
    )
    .expect("the safe derived metadata can be stored");
    assert_eq!(
        transformed.source_authority(),
        SourceAuthority::Untrusted,
        "a transformation cannot launder an untrusted source into authority"
    );
    assert!(transformed
        .taint_labels()
        .contains(&TaintLabel::UntrustedExternal));
    assert!(transformed.blocks_unauthorized_effect_eligibility());

    assert!(
        Evidence::new(
            "evidence/invalid-laundering",
            VerifierLevel::V1,
            SourceAuthority::Authoritative,
            TaintLabels::from([TaintLabel::UntrustedExternal]),
            vec![],
            JsonObject::empty(),
        )
        .is_err(),
        "direct ingestion cannot label untrusted-external data authoritative"
    );
}

#[test]
fn inv015_model_assertion_cannot_be_stored_as_an_observation() {
    let prediction = ModelAssertion::new(
        "assertion/weather-prediction",
        ModelAssertionKind::Prediction,
        ModelIdentity::new("model/weather-v1").expect("model ID is nonblank"),
        now(),
        JsonObject::empty(),
        vec![],
        SourceAuthority::Unverified,
        TaintLabels::from([TaintLabel::Internal]),
    )
    .expect("model assertions have their own typed record");

    let model_wire = serde_json::to_value(&prediction).expect("assertion serializes");
    assert!(
        serde_json::from_value::<Observation>(model_wire).is_err(),
        "the model assertion wire shape is not an Observation wire shape"
    );

    let observation = Observation::new(
        "observation/weather-station",
        now(),
        ObservationSource::new("weather-station/17").expect("external source ID is nonblank"),
        StalenessHorizon::from_seconds(300).expect("non-negative freshness horizon"),
        vec![],
        SourceAuthority::Verified,
        TaintLabels::from([TaintLabel::Internal]),
        JsonObject::empty(),
    )
    .expect("external reality can be represented as an Observation");
    assert!(observation.is_fresh_at(now()));
    assert!(
        !observation.is_fresh_at(now() + chrono::Duration::seconds(301)),
        "freshness is carried with the observation"
    );
}

#[test]
fn verifier_levels_use_the_v0_to_v5_taxonomy() {
    assert_eq!(VerifierLevel::ALL.len(), 6);
    assert_eq!(VerifierLevel::V0.as_str(), "V0");
    assert_eq!(VerifierLevel::V4.meaning(), "EXTERNAL_REALITY");
    assert_eq!(VerifierLevel::V5.meaning(), "FORMAL_OR_CRYPTOGRAPHIC");
    assert_eq!(
        serde_json::to_value(VerifierLevel::V3).expect("level serializes"),
        serde_json::json!("V3")
    );
}
