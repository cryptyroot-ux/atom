use atom_ledger::HmacSha256Signer;
use atom_server::app::build_router;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn test_router() -> axum::Router {
    let signer = Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ));
    let store = Store::open_in_memory(signer).unwrap();
    build_router("0.0.0-alpha", 32, std::time::Instant::now(), store)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn valid_intent_body() -> serde_json::Value {
    serde_json::json!({
        "effect_id": "e-1",
        "mission_id": "m-1",
        "capability_id": "c-1",
        "target_id": "t-1",
        "canonical_request_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "effect_class": "write",
        "risk_class": "low",
        "idempotency": { "mode": "KEYED", "scope": "m-1", "key": "dispatch-1" },
        "preconditions": [],
        "postconditions": [],
        "reconciliation": {
            "class": "LEDGER_REPLAY",
            "retry_class": "RECONCILE_BEFORE_RETRY"
        },
        "compensation": { "strategy": "NOT_COMPENSABLE" },
        "dependencies": []
    })
}

#[tokio::test]
async fn create_and_get_effect_roundtrip() {
    let app = test_router();
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/effects")
                .header("content-type", "application/json")
                .body(Body::from(valid_intent_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);
    let cjson = body_json(created).await;
    assert_eq!(cjson["effect_id"], "e-1");
    assert_eq!(cjson["mission_id"], "m-1");
    assert_eq!(cjson["state"], "AUTHORIZATION_PENDING");

    let fetched = app
        .oneshot(
            Request::builder()
                .uri("/effects/e-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fetched.status(), axum::http::StatusCode::OK);
    let fjson = body_json(fetched).await;
    assert_eq!(fjson["effect_id"], "e-1");
    assert_eq!(fjson["state"], "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn get_missing_effect_is_not_found() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/effects/nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_effect_with_bad_digest_is_bad_request() {
    let app = test_router();
    let mut body = valid_intent_body();
    body["canonical_request_digest"] = serde_json::json!("not-a-digest");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/effects")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
}
