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
    Arc::new(Mutex::new(
        Store::open_in_memory(Box::new(HmacSha256Signer::new(
            "chat-test",
            b"chat-test-secret",
        )))
        .unwrap(),
    ))
}

#[tokio::test]
async fn chat_without_provider_explains_how_to_configure_one() {
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), test_store());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/chat")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"messages":[{"role":"user","content":"hi"}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["detail"].as_str().unwrap().contains("atom setup"));
}
