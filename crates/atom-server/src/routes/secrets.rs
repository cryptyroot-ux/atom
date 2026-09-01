use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use atom_secret::SecretHandle;

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecretBody {
    pub name: String,
    pub scope: String,
    pub ttl_seconds: Option<i64>,
}

/// Creates a brokered secret handle. A handle is a scoped reference token
/// (INV-006): this slice returns the handle only and never a secret value.
/// Redemption against a real `SecretBroker` store is a later slice; the
/// `handle_id` is the durable handle that dispatch would reference.
pub async fn create_secret_handle(
    State(app_state): State<AppState>,
    Json(body): Json<CreateSecretBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let now = chrono::Utc::now();
    let expires_at = body
        .ttl_seconds
        .map(|ttl| now + chrono::Duration::seconds(ttl));
    let handle = SecretHandle::new(
        "api-gateway",
        "server",
        format!("scope:{}", body.scope),
        "redeem",
        expires_at.unwrap_or(now + chrono::Duration::days(1)),
        1,
        0,
    );
    let record = serde_json::json!({
        "handle_id": handle.secret_id,
        "name": body.name,
        "scope": body.scope,
        "created_at": now.to_rfc3339(),
        "expires_at": expires_at.map(|t| t.to_rfc3339()),
    });
    let mut store = app_state.store.lock().await;
    store
        .add_secret_handle(&record)
        .map_err(|e| ApiError::bad_request("/secrets", format!("persist failed: {e}")))?;
    Ok((StatusCode::CREATED, Json(record)))
}
