use std::sync::Arc;

use atom_ledger::HmacSha256Signer;
use atom_server::app::build_router;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn test_store() -> Arc<Mutex<Store>> {
    let signer = Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ));
    Arc::new(Mutex::new(Store::open_in_memory(signer).unwrap()))
}

#[tokio::test]
async fn health_returns_ok_json() {
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), test_store());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "healthy");
    assert_eq!(json["version"], "0.0.0-alpha");
    assert_eq!(json["crates_loaded"], 32);
}

#[tokio::test]
async fn ready_returns_ok() {
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), test_store());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
