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
async fn create_and_get_mission_roundtrip() {
    let app = test_router();
    let body = serde_json::json!({ "goal": "compare atom vs hermes vs openclaw" });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/missions")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);
    let cjson = body_json(created).await;
    let id = cjson["mission_id"].as_str().unwrap().to_owned();
    assert_eq!(cjson["state"], "CREATED");

    let fetched = app
        .oneshot(
            Request::builder()
                .uri(format!("/missions/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fetched.status(), axum::http::StatusCode::OK);
    let fjson = body_json(fetched).await;
    assert_eq!(fjson["mission_id"], id);
    assert_eq!(fjson["goal"], "compare atom vs hermes vs openclaw");
}

#[tokio::test]
async fn get_missing_mission_is_not_found() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/missions/nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancel_mission_returns_ok() {
    let app = test_router();
    let body = serde_json::json!({ "goal": "cancel me" });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/missions")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let cjson = body_json(created).await;
    let id = cjson["mission_id"].as_str().unwrap().to_owned();

    let cancelled = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/missions/{id}/cancel"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cancelled.status(), axum::http::StatusCode::OK);

    let fetched = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/missions/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let fjson = body_json(fetched).await;
    assert_eq!(fjson["state"], "CANCELLED");
}

#[tokio::test]
async fn create_mission_empty_goal_is_bad_request() {
    let app = test_router();
    let body = serde_json::json!({ "goal": "  " });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/missions")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
}
