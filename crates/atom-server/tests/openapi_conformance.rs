use atom_ledger::HmacSha256Signer;
use atom_server::app::build_router;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::{Method, Request};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Every endpoint in `spec/openapi.yaml` that the v1 server implements, paired
/// with the concrete request path used to probe it.
///
/// Keeping this table in sync with the contract catches dropped routes: if a
/// handler is missing, axum answers with its default plain-text `404 Not
/// Found`, which we detect and fail on.
/// The full set of path templates in `spec/openapi.yaml`.
const SPEC_PATHS: &[&str] = &[
    "/health",
    "/ready",
    "/missions",
    "/missions/{mission_id}",
    "/missions/{mission_id}/cancel",
    "/effects",
    "/effects/{effect_id}",
    "/capabilities",
    "/evidence",
    "/ledger/events",
    "/secrets",
];

const ENDPOINTS: &[(&str, Method, &str)] = &[
    ("/health", Method::GET, "/health"),
    ("/ready", Method::GET, "/ready"),
    ("/missions", Method::GET, "/missions"),
    ("/missions", Method::POST, "/missions"),
    ("/missions/{mission_id}", Method::GET, "/missions/_p_"),
    (
        "/missions/{mission_id}/cancel",
        Method::POST,
        "/missions/_p_/cancel",
    ),
    ("/effects", Method::POST, "/effects"),
    ("/effects/{effect_id}", Method::GET, "/effects/_p_"),
    ("/capabilities", Method::GET, "/capabilities"),
    ("/evidence", Method::GET, "/evidence"),
    ("/ledger/events", Method::GET, "/ledger/events"),
    ("/secrets", Method::POST, "/secrets"),
];

fn test_store() -> Store {
    let signer = Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ));
    Store::open_in_memory(signer).unwrap()
}

/// Axum's default unhandled-route response is a plain-text `404 Not Found`.
/// Handlers return JSON, so any plain-text 404 means the route is not wired.
fn is_unhandled_route(body: &[u8]) -> bool {
    std::str::from_utf8(body)
        .map(|s| s.contains("404 Not Found"))
        .unwrap_or(false)
}

#[tokio::test]
async fn every_spec_endpoint_is_wired() {
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), test_store());
    let mut missing = Vec::new();
    for (template, method, request_path) in ENDPOINTS {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(*request_path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        if is_unhandled_route(&body) {
            missing.push(format!("{method} {template}"));
        }
    }
    assert!(
        missing.is_empty(),
        "endpoints from spec/openapi.yaml are not wired: {missing:?}"
    );
}

#[test]
fn endpoint_templates_match_the_spec_path_set() {
    let templates: Vec<String> = ENDPOINTS
        .iter()
        .map(|(template, _, _)| template.to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let mut expected: Vec<&str> = SPEC_PATHS.to_vec();
    expected.sort_unstable();
    let mut actual = templates;
    actual.sort_unstable();
    assert_eq!(actual, expected, "ENDPOINTS drifted from spec/openapi.yaml");
}
