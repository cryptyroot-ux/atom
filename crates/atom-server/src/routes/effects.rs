use std::str::FromStr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use atom_effect::event::EffectEvent;
use atom_effect::intent::EffectIntent;
use atom_effect::reducer::try_reduce;
use atom_effect::semantics::{Compensation, Condition, Idempotency, Reconciliation};
use atom_effect::state::EffectState;

use crate::app::AppState;
use crate::error::ApiError;

/// Request body for POST /effects: the declared fields of EFX-002, minus the
/// lifecycle position, which the reducer owns.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntentBody {
    pub effect_id: String,
    pub mission_id: String,
    pub capability_id: String,
    pub target_id: String,
    pub canonical_request_digest: String,
    pub effect_class: String,
    pub risk_class: String,
    pub idempotency: Idempotency,
    pub preconditions: Vec<Condition>,
    pub postconditions: Vec<Condition>,
    pub reconciliation: Reconciliation,
    pub compensation: Compensation,
    pub dependencies: Vec<String>,
}

#[derive(Serialize)]
pub struct EffectResultBody {
    pub effect_id: String,
    pub mission_id: String,
    pub state: &'static str,
    pub external_operation_id: Option<String>,
    pub digest: String,
}

/// Builds the intent through the `atom_effect` builder (EFX-002 validation,
/// including the `sha256:<64 hex>` request-digest rule) and reduces it one
/// durable step into the lifecycle via the spec reducer.
///
/// Honest slice boundary: nothing here authorises or dispatches. The intent
/// rests at `AUTHORIZATION_PENDING` — the reducer's answer to
/// `AuthorizationRequested` — until the kernel two-phase authorize/commit
/// boundary is wired (follow-up slice). No event that would claim the effect
/// was dispatched is fabricated.
fn build_and_advance(body: EffectIntentBody) -> Result<(EffectIntent, EffectState), ApiError> {
    let mut builder = EffectIntent::builder(
        &body.effect_id,
        &body.mission_id,
        &body.capability_id,
        &body.target_id,
    )
    .canonical_request_digest(&body.canonical_request_digest)
    .classes(&body.effect_class, &body.risk_class)
    .idempotency(body.idempotency)
    .reconciliation(body.reconciliation)
    .compensation(body.compensation);
    for condition in body.preconditions {
        builder = builder.precondition(condition);
    }
    for condition in body.postconditions {
        builder = builder.postcondition(condition);
    }
    for dependency in body.dependencies {
        builder = builder.dependency(&dependency);
    }
    let intent = builder.build().map_err(|e| {
        ApiError::bad_request("/effects", format!("intent rejected by EFX-002: {e}"))
    })?;
    let state = try_reduce(intent.state, &EffectEvent::AuthorizationRequested)
        .map_err(|e| ApiError::bad_request("/effects", format!("reducer refused event: {e}")))?;
    Ok((intent, state))
}

fn result_body(intent: &EffectIntent, state: EffectState) -> EffectResultBody {
    EffectResultBody {
        effect_id: intent.effect_id.clone(),
        mission_id: intent.mission_id.clone(),
        state: state.as_str(),
        external_operation_id: intent.external_operation_id.clone(),
        digest: intent.digest(),
    }
}

pub async fn dispatch_effect(
    State(app_state): State<AppState>,
    Json(body): Json<EffectIntentBody>,
) -> Result<(StatusCode, Json<EffectResultBody>), ApiError> {
    let (intent, state) = build_and_advance(body)?;
    let record = serde_json::json!({
        "effect_id": intent.effect_id,
        "mission_id": intent.mission_id,
        "capability_id": intent.capability_id,
        "target_id": intent.target_id,
        "canonical_request_digest": intent.canonical_request_digest,
        "effect_class": intent.effect_class,
        "risk_class": intent.risk_class,
        "state": state.as_str(),
        "digest": intent.digest(),
    });
    let mut store = app_state.store.lock().await;
    store
        .append_effect(&record)
        .map_err(|e| ApiError::bad_request("/effects", format!("append failed: {e}")))?;
    Ok((StatusCode::CREATED, Json(result_body(&intent, state))))
}

pub async fn get_effect(
    State(state): State<AppState>,
    Path(effect_id): Path<String>,
) -> Result<Json<EffectResultBody>, ApiError> {
    let store = state.store.lock().await;
    let effect = store
        .effect(&effect_id)
        .ok_or_else(|| ApiError::not_found(format!("/effects/{effect_id}"), "effect not found"))?;
    let state = match EffectState::from_str(effect["state"].as_str().unwrap_or_default()) {
        Ok(s) => s,
        Err(_) => {
            return Err(ApiError::not_found(
                format!("/effects/{effect_id}"),
                "effect state is not a spec state",
            ))
        }
    };
    Ok(Json(EffectResultBody {
        effect_id: effect["effect_id"].as_str().unwrap_or_default().to_owned(),
        mission_id: effect["mission_id"].as_str().unwrap_or_default().to_owned(),
        state: state.as_str(),
        external_operation_id: None,
        digest: effect["digest"].as_str().unwrap_or_default().to_owned(),
    }))
}
