//! Contract conformance: every operation in `spec/openapi.yaml` must be wired.
//!
//! The path set is read from the spec file itself rather than mirrored in a
//! hand-maintained constant. A mirrored list only proves the two lists agree; it
//! cannot notice a spec operation nobody implemented, which is exactly the drift
//! worth catching.

use std::sync::Arc;

use atom_ledger::HmacSha256Signer;
use atom_server::app::build_router;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::{Method, Request};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

const SPEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/openapi.yaml"
));

/// One operation from the contract: its path template and HTTP method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Operation {
    template: String,
    method: String,
}

impl Operation {
    /// A concrete request path, with every `{param}` filled by a placeholder.
    fn request_path(&self) -> String {
        let mut out = String::new();
        let mut rest = self.template.as_str();
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let Some(close) = rest[open..].find('}') else {
                break;
            };
            out.push_str("_probe_");
            rest = &rest[open + close + 1..];
        }
        out.push_str(rest);
        out
    }

    fn axum_method(&self) -> Method {
        self.method
            .parse()
            .unwrap_or_else(|_| panic!("spec names an unknown HTTP method `{}`", self.method))
    }
}

/// Extracts every operation under the spec's top-level `paths:` mapping.
///
/// The spec is 2-space-indented YAML: path templates sit at indent 2 under
/// `paths:`, and their methods at indent 4. Reading only those two levels keeps
/// this parser small enough to trust without a YAML dependency, and it fails
/// loudly (empty result) rather than silently if the shape ever changes.
fn spec_operations(spec: &str) -> Vec<Operation> {
    const METHODS: [&str; 7] = ["get", "put", "post", "delete", "options", "head", "patch"];
    let mut operations = Vec::new();
    let mut in_paths = false;
    let mut current: Option<String> = None;

    for line in spec.lines() {
        if line.starts_with("paths:") {
            in_paths = true;
            continue;
        }
        if !in_paths {
            continue;
        }
        // A new top-level key ends the paths mapping.
        if !line.starts_with(' ') && !line.trim().is_empty() {
            break;
        }

        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if indent == 2 && trimmed.starts_with('/') {
            current = trimmed.strip_suffix(':').map(str::to_owned);
            continue;
        }
        if indent == 4 {
            if let Some(name) = trimmed.strip_suffix(':') {
                if METHODS.contains(&name) {
                    if let Some(template) = current.clone() {
                        operations.push(Operation {
                            template,
                            method: name.to_uppercase(),
                        });
                    }
                }
            }
        }
    }
    operations
}

fn test_store() -> Arc<Mutex<Store>> {
    let signer = Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ));
    Arc::new(Mutex::new(Store::open_in_memory(signer).unwrap()))
}

/// Axum's default unhandled-route response is a plain-text `404 Not Found`.
/// Handlers return JSON, so any plain-text 404 means the route is not wired.
fn is_unhandled_route(body: &[u8]) -> bool {
    std::str::from_utf8(body)
        .map(|s| s.contains("404 Not Found"))
        .unwrap_or(false)
}

#[test]
fn the_spec_declares_operations_to_check() {
    let operations = spec_operations(SPEC);
    assert!(
        operations.len() >= 12,
        "parsed only {} operations from spec/openapi.yaml — the parser or the \
         spec layout changed, so this suite is no longer checking the contract",
        operations.len()
    );
    assert!(
        operations
            .iter()
            .any(|o| o.template == "/health" && o.method == "GET"),
        "the spec parser did not find GET /health"
    );
}

#[tokio::test]
async fn every_spec_operation_is_wired() {
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), test_store());
    let mut missing = Vec::new();
    for operation in spec_operations(SPEC) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(operation.axum_method())
                    .uri(operation.request_path())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        // A wired route may legitimately answer 400/405/415/503 to an empty
        // probe body; only axum's plain-text 404 means no handler exists.
        if is_unhandled_route(&body) {
            missing.push(format!(
                "{} {} (status {status})",
                operation.method, operation.template
            ));
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "operations declared in spec/openapi.yaml are not wired: {missing:#?}"
    );
}

#[tokio::test]
async fn the_host_mutation_surface_is_in_the_contract() {
    // The governed host path is the most consequential surface in the daemon;
    // it must never be implemented without being declared.
    let operations = spec_operations(SPEC);
    for (template, method) in [
        ("/host/plan", "POST"),
        ("/host/commit", "POST"),
        ("/host/plans", "GET"),
    ] {
        assert!(
            operations
                .iter()
                .any(|o| o.template == template && o.method == method),
            "spec/openapi.yaml does not declare {method} {template}"
        );
    }
}
