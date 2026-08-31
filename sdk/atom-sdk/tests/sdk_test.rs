use atom_sdk::types::{SubmitEffectRequest, SubmitEffectResponse};
use atom_sdk::wire::{
    Compensation, CompensationStrategy, EffectIntent, Idempotency, IdempotencyMode, Reconciliation,
    ReconciliationClass, RetryClass,
};
use atom_sdk::{AtomClient, SdkError};

#[test]
fn test_request_serialization() {
    // Verify we can serialize a structured request properly
    let intent = EffectIntent::builder("eff-123", "msn-456", "cap-789", "tgt-abc")
        .request_digest("sha256:digest")
        .classes("test-mutation", "low")
        .idempotency(Idempotency {
            mode: IdempotencyMode::Natural,
            scope: "test-scope".to_owned(),
            key: None,
        })
        .reconciliation(
            Reconciliation::new(
                ReconciliationClass::ExternalOperationLookup,
                RetryClass::Transient,
            )
            .with_probe("external-op"),
        )
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .unwrap();

    let req = SubmitEffectRequest {
        request_id: "req-111".to_owned(),
        idempotency_key: "idem-222".to_owned(),
        intent,
    };

    let json = serde_json::to_string(&req).expect("must serialize");
    assert!(json.contains("eff-123"));
    assert!(json.contains("req-111"));
    assert!(json.contains("idem-222"));
}

#[test]
fn test_response_deserialization() {
    // Verify we can deserialize a server response envelope
    let raw_resp = r#"{
        "request_id": "req-111",
        "idempotency_key": "idem-222",
        "authorization": {
            "effect_id": "eff-123",
            "effect_digest": "digest",
            "grant_id": "grant-abc",
            "grant_generation": 1,
            "principal_id": "root",
            "operation": "mutate",
            "resource_type": "file",
            "planned_witness": {
                "kind": "etag",
                "resource_id": "tgt-abc",
                "value": "v1"
            }
        },
        "commit_token": {
            "effect_id": "eff-123",
            "grant_id": "grant-abc",
            "grant_generation": 1,
            "resource_id": "tgt-abc",
            "one_shot_nonce": "nonce-999"
        }
    }"#;

    let resp: SubmitEffectResponse = serde_json::from_str(raw_resp).expect("must deserialize");
    assert_eq!(resp.request_id, "req-111");
    assert_eq!(resp.commit_token.one_shot_nonce, "nonce-999");
}

#[tokio::test]
async fn test_invalid_client_config() {
    // Verify builder validation works
    let err = AtomClient::builder().base_url("").build().unwrap_err();
    assert!(matches!(err, SdkError::InvalidConfig(_)));
}
