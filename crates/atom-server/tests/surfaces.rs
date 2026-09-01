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

#[tokio::test]
async fn list_capabilities_returns_array() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["grants"].is_array());
}

#[tokio::test]
async fn list_ledger_events_returns_checkpoint() {
    let app = test_router();
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/missions")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "goal": "seed ledger" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ledger/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["events"].is_array());
    assert!(!json["events"].as_array().unwrap().is_empty());
    assert!(json["checkpoint"].is_number());
    assert!(json["checkpoint"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn create_secret_returns_handle_without_value() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/secrets")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "name": "api-key", "scope": "mission", "ttl_seconds": 60 })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
    let json = body_json(resp).await;
    assert!(json["handle_id"].is_string());
    assert!(!json["handle_id"].as_str().unwrap().is_empty());
    assert_eq!(json["name"], "api-key");
    assert_eq!(json["scope"], "mission");
    assert!(json["expires_at"].is_string());
    assert!(
        json.get("value").is_none(),
        "handle must never leak a value"
    );
}
