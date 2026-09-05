//! Governed host-mutation surface: the only HTTP path that can change the host.
//!
//! Two steps, deliberately separate, because a mutation must be *declared* before
//! it can be *authorised* (ATOM-V4-KRN-002, AUT-003, EFX-001/004):
//!
//! 1. `POST /host/plan` — declares a typed [`HostOp`], makes the effect intent
//!    durable, and returns the effect digest an owner must approve. It reaches
//!    no executor and touches nothing on disk.
//! 2. `POST /host/commit` — redeems a durable [`ApprovalGrant`] for that exact
//!    digest, re-validates authority and the resource witness at the boundary,
//!    issues a one-shot [`CommitPermit`], and only then asks the privilege
//!    broker to admit the operation. The broker's sandboxed executor performs
//!    the write; the burned nonce is appended to the ledger before the response
//!    returns, so the one-shot guarantee survives a restart.
//!
//! Deny-by-default at every layer: no host config → refused; no grant → refused;
//! no approval for this digest → refused; witness drift → refused; nonce already
//! burned → refused. Cognition never appears in this file: it can only ask for a
//! plan, and a plan is not authority.

use std::path::{Path, PathBuf};

use atom_approval::{ApprovalGrant, ApprovalStore, RedeemTarget};
use atom_capability::CapabilityGrant;
use atom_effect::{
    issue_commit_permit, Compensation, CompensationStrategy, Condition, EffectEvent, EffectIntent,
    Idempotency, PermitRequest, Reconciliation, ReconciliationClass, ResourceWitness, RetryClass,
};
use atom_privd::{HostOp, PrivilegeBroker, SandboxedHostExecutor};
use atom_runtime::{HostOperationRequest, UnprivilegedHostGateway};
use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{app::AppState, error::ApiError};

/// TTL of an issued commit permit. Short by construction (EFX-004).
const PERMIT_TTL_SECONDS: u32 = 30;

/// The connector identity this daemon presents at the boundary. A permit issued
/// to this identity cannot be spent by any other connector.
const CONNECTOR_IDENTITY: &str = "connector/atom-server";
/// The sink a permit is bound to: the privilege broker in front of the sandbox.
const DISPATCH_SINK: &str = "sink/atom-privd";

/// What the caller declares it wants to happen.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPlanRequest {
    /// The mission this mutation belongs to.
    pub mission_id: String,
    /// The capability grant the authority must come from.
    pub grant_id: String,
    /// The typed host operation, internally tagged on `op`.
    pub op: HostOp,
}

/// The declaration, plus the digest an owner must approve to let it through.
#[derive(Serialize)]
pub struct HostPlanResponse {
    pub plan_id: String,
    pub mission_id: String,
    pub grant_id: String,
    pub operation: String,
    pub resource_type: String,
    pub resource_id: String,
    /// The identity an [`atom_approval::ApprovalScope::Effect`] must name.
    pub effect_digest: String,
    /// The resource version observed while planning; drift refuses the commit.
    pub planned_witness: ResourceWitness,
    /// Always `PLANNED`: nothing has crossed the privilege boundary.
    pub state: &'static str,
}

/// Which plan to commit.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCommitRequest {
    pub plan_id: String,
}

/// What the host actually reported, and the permit that authorised it.
#[derive(Serialize)]
pub struct HostCommitResponse {
    pub plan_id: String,
    pub permit_id: String,
    pub one_shot_nonce: String,
    pub approval_id: String,
    pub effect_digest: String,
    /// The executor's own account of what it did.
    pub outcome: String,
    /// The sealed evidence entry for this crossing.
    pub observation_id: String,
    pub state: &'static str,
}

/// Host-mutation configuration. Absent means the surface is disabled.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// The sandbox root every operation is confined to.
    pub root: PathBuf,
}

/// A deterministic effect id for `op` under `mission_id`.
///
/// Plan and commit must agree on the effect identity without storing it, so the
/// id is derived from the material rather than minted randomly.
fn effect_id_for(mission_id: &str, op: &HostOp) -> Result<String, ApiError> {
    let canonical = serde_json::to_vec(op)
        .map_err(|e| ApiError::bad_request("/host/plan", format!("op is not serializable: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(b"atom.host-plan.effect.v1\0");
    hasher.update(mission_id.as_bytes());
    hasher.update([0x1f]);
    hasher.update(&canonical);
    Ok(format!("effect/{}", hex::encode(hasher.finalize())))
}

/// The resource version as it looks right now.
///
/// A file that does not exist is a witness too (`absent`), so creating a file
/// somebody else created in the meantime is drift, not a silent overwrite.
fn observe_witness(root: &Path, resource_id: &str) -> ResourceWitness {
    let relative = resource_id.trim_start_matches('/');
    let path = root.join(relative);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            ResourceWitness::new("sha256", resource_id, &hex::encode(hasher.finalize()))
        }
        Err(_) => ResourceWitness::new("absent", resource_id, "absent"),
    }
}

/// Builds the effect intent for `op`, declared but not yet authorised.
fn intent_for(mission_id: &str, grant_id: &str, op: &HostOp) -> Result<EffectIntent, ApiError> {
    let effect_id = effect_id_for(mission_id, op)?;
    let resource_id = op.resource_id();
    EffectIntent::builder(&effect_id, mission_id, grant_id, &resource_id)
        .canonical_request(&serde_json::json!({
            "operation": op.operation(),
            "resource_type": op.resource_type(),
            "resource_id": resource_id,
            "kind": op.kind(),
        }))
        .map_err(|e| {
            ApiError::bad_request("/host/plan", format!("canonicalising host request: {e}"))
        })?
        .classes(op.kind(), "HIGH")
        .idempotency(Idempotency::keyed(mission_id, &effect_id))
        .precondition(Condition::new(
            "resource-witness-stable",
            "the resource version matches what planning observed",
        ))
        .postcondition(Condition::new(
            "operation-applied",
            "the host reported the declared operation as applied",
        ))
        .reconciliation(
            Reconciliation::new(
                ReconciliationClass::ResourceStateRead,
                RetryClass::ReconcileBeforeRetry,
            )
            .with_probe("re-read the resource and compare the postcondition"),
        )
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .map_err(|e| ApiError::bad_request("/host/plan", format!("intent rejected: {e}")))
}

/// Reads the capability grant named by `grant_id` out of the durable projection.
fn grant_from_store(
    grants: &[serde_json::Value],
    grant_id: &str,
    instance: &str,
) -> Result<CapabilityGrant, ApiError> {
    let raw = grants
        .iter()
        .find(|g| g["grant_id"] == grant_id)
        .ok_or_else(|| {
            ApiError::bad_request(
                instance,
                format!("no capability grant `{grant_id}` (deny-by-default)"),
            )
        })?;
    serde_json::from_value(raw.clone()).map_err(|e| {
        ApiError::bad_request(
            instance,
            format!("grant `{grant_id}` is not a valid CapabilityGrant: {e}"),
        )
    })
}

/// The host configuration, or a refusal when the surface is disabled.
fn host_config(state: &AppState, instance: &str) -> Result<std::sync::Arc<HostConfig>, ApiError> {
    state.host.clone().ok_or_else(|| {
        ApiError::service_unavailable(
            instance,
            "host mutation surface is disabled (start the daemon with --host-root to enable it)",
        )
    })
}

/// Declares a host mutation and makes its intent durable. Nothing executes.
pub async fn plan(
    State(state): State<AppState>,
    Json(request): Json<HostPlanRequest>,
) -> Result<(StatusCode, Json<HostPlanResponse>), ApiError> {
    let config = host_config(&state, "/host/plan")?;
    request
        .op
        .validate()
        .map_err(|e| ApiError::bad_request("/host/plan", format!("malformed host op: {e}")))?;

    let mut store = state.store.lock().await;
    let grant = grant_from_store(store.grants(), &request.grant_id, "/host/plan")?;

    // The grant must already cover this operation and resource. Refusing here
    // means a plan an owner could never approve is never even recorded.
    let operation = request.op.operation();
    if !grant.operations.iter().any(|op| op == operation) {
        return Err(ApiError::bad_request(
            "/host/plan",
            format!("grant `{}` does not allow `{operation}`", grant.grant_id),
        ));
    }
    let resource_type = request.op.resource_type();
    let resource_id = request.op.resource_id();
    let covered = grant
        .resources
        .iter()
        .any(|s| s.resource_type == resource_type && s.resource_id == resource_id);
    if !covered {
        return Err(ApiError::bad_request(
            "/host/plan",
            format!(
                "grant `{}` does not cover {resource_type} `{resource_id}`",
                grant.grant_id
            ),
        ));
    }

    let intent = intent_for(&request.mission_id, &request.grant_id, &request.op)?;
    let witness = observe_witness(&config.root, &resource_id);

    // EFX-001: the declaration is written down before anything may act on it.
    let payload = intent.declared_payload().map_err(|e| {
        ApiError::bad_request("/host/plan", format!("canonicalising intent: {e}"))
    })?;
    store
        .ledger
        .append(
            &intent.effect_id,
            &payload,
            Utc::now().timestamp_millis(),
        )
        .map_err(|e| {
            ApiError::bad_request("/host/plan", format!("sealing intent durably failed: {e}"))
        })?;

    let plan_id = format!("plan/{}", uuid::Uuid::new_v4());
    let plan = serde_json::json!({
        "plan_id": plan_id,
        "mission_id": request.mission_id,
        "grant_id": request.grant_id,
        "op": request.op,
        "operation": operation,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "effect_id": intent.effect_id,
        "effect_digest": intent.digest(),
        "planned_witness": witness,
        "state": "PLANNED",
    });
    store.add_host_plan(&plan).map_err(|e| {
        ApiError::bad_request("/host/plan", format!("recording plan failed: {e}"))
    })?;

    Ok((
        StatusCode::CREATED,
        Json(HostPlanResponse {
            plan_id,
            mission_id: request.mission_id,
            grant_id: request.grant_id,
            operation: operation.to_owned(),
            resource_type: resource_type.to_owned(),
            resource_id,
            effect_digest: intent.digest(),
            planned_witness: witness,
            state: "PLANNED",
        }),
    ))
}

/// Commits a planned mutation: approval redemption, permit issuance, one
/// brokered crossing, then a durable nonce burn and sealed evidence.
pub async fn commit(
    State(state): State<AppState>,
    Json(request): Json<HostCommitRequest>,
) -> Result<(StatusCode, Json<HostCommitResponse>), ApiError> {
    let instance = "/host/commit";
    let config = host_config(&state, instance)?;
    let mut store = state.store.lock().await;

    let mut plan = store
        .host_plan(&request.plan_id)
        .ok_or_else(|| ApiError::not_found(instance, "host plan not found"))?;
    if plan["state"] != "PLANNED" {
        return Err(ApiError::conflict(
            instance,
            format!(
                "plan `{}` is {}, not PLANNED",
                request.plan_id,
                plan["state"].as_str().unwrap_or("unknown")
            ),
        ));
    }

    let op: HostOp = serde_json::from_value(plan["op"].clone())
        .map_err(|e| ApiError::bad_request(instance, format!("stored op is invalid: {e}")))?;
    let mission_id = plan["mission_id"].as_str().unwrap_or_default().to_owned();
    let grant_id = plan["grant_id"].as_str().unwrap_or_default().to_owned();
    let grant = grant_from_store(store.grants(), &grant_id, instance)?;

    // The intent is rebuilt from the same material, so its digest is the same
    // one the owner approved. A tampered plan yields a different digest and no
    // approval covers it.
    let intent = intent_for(&mission_id, &grant_id, &op)?;
    let effect_digest = intent.digest();
    let planned_witness: ResourceWitness = serde_json::from_value(plan["planned_witness"].clone())
        .map_err(|e| {
        ApiError::bad_request(instance, format!("stored witness is invalid: {e}"))
    })?;

    // AUT-003: a durable approval must cover this exact effect digest, now.
    let now = Utc::now();
    let mut approvals = ApprovalStore::new();
    for raw in store.approvals() {
        if let Ok(grant) = serde_json::from_value::<ApprovalGrant>(raw.clone()) {
            let _ = approvals.record(grant);
        }
    }
    let receipt = approvals
        .redeem(
            &RedeemTarget::Effect {
                effect_digest: effect_digest.clone(),
            },
            now,
        )
        .map_err(|e| {
            ApiError::bad_request(
                instance,
                format!("no usable approval for this effect digest: {e}"),
            )
        })?;

    // The resource must still look the way planning saw it (ATOM-VT-003).
    let observed = observe_witness(&config.root, &op.resource_id());
    if observed != planned_witness {
        plan["state"] = serde_json::Value::String("REFUSED".into());
        plan["refusal"] = serde_json::Value::String(format!(
            "resource witness drifted: planned {}, observed {}",
            planned_witness.value, observed.value
        ));
        let _ = store.resolve_host_plan(&plan, false);
        return Err(ApiError::conflict(
            instance,
            "resource changed since planning; re-plan and re-approve",
        ));
    }

    // EFX-001: mint a real durability proof over this exact declaration. Only
    // the ledger's append path can produce one.
    let payload = intent
        .declared_payload()
        .map_err(|e| ApiError::bad_request(instance, format!("canonicalising intent: {e}")))?;
    let (_event, durability) = store
        .ledger
        .append_durable(&intent.effect_id, &payload, now.timestamp_millis())
        .map_err(|e| {
            ApiError::bad_request(instance, format!("sealing durability proof failed: {e}"))
        })?;

    // Walk the intent to the commit boundary through the reducer, never by hand.
    let mut at_boundary = intent.clone();
    for event in [
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(&grant.grant_id, grant.generation),
        EffectEvent::CommitRevalidationStarted,
    ] {
        at_boundary = at_boundary.try_advance(&event).map_err(|e| {
            ApiError::bad_request(instance, format!("reducer refused a pre-dispatch step: {e}"))
        })?;
    }

    let nonce = format!("nonce/{}", uuid::Uuid::new_v4());
    let permit_id = format!("permit/{}", uuid::Uuid::new_v4());
    let permit = issue_commit_permit(PermitRequest {
        intent: &at_boundary,
        grant: &grant,
        principal_id: &grant.subject_id,
        operation: op.operation(),
        resource_type: op.resource_type(),
        planned_grant_generation: grant.generation,
        planned_witness: &planned_witness,
        observed_witness: &observed,
        durability: &durability,
        permit_id: &permit_id,
        one_shot_nonce: &nonce,
        ttl_seconds: PERMIT_TTL_SECONDS,
        now,
        approval_id: Some(receipt.grant_id.as_str()),
        evidence_freshness_digest: None,
        dispatch_sink_id: DISPATCH_SINK,
        connector_identity: CONNECTOR_IDENTITY,
        connector_version: env!("CARGO_PKG_VERSION"),
        connector_instance_epoch: grant.generation,
    })
    .map_err(|e| {
        ApiError::conflict(instance, format!("commit permit refused: {e}"))
    })?;

    // The broker owns the only executor. Its one-shot memory is rebuilt from the
    // ledger, so a nonce burned in a prior life is still refused.
    let executor = SandboxedHostExecutor::new(&config.root).map_err(|e| {
        ApiError::service_unavailable(instance, format!("sandbox unavailable: {e}"))
    })?;
    let burned: Vec<String> = store.burned_nonces().to_vec();
    let mut gateway =
        UnprivilegedHostGateway::new(PrivilegeBroker::with_burned_nonces(executor, burned));

    let admitted = match gateway.submit(HostOperationRequest {
        op: &op,
        permit: &permit,
        intent: &at_boundary,
        grant: &grant,
        observed_witness: &observed,
        now,
        dispatch_sink_id: DISPATCH_SINK,
        connector_identity: CONNECTOR_IDENTITY,
        connector_version: env!("CARGO_PKG_VERSION"),
        connector_instance_epoch: grant.generation,
    }) {
        Ok(admitted) => admitted,
        Err(denial) => {
            plan["state"] = serde_json::Value::String("REFUSED".into());
            plan["refusal"] = serde_json::Value::String(denial.to_string());
            let _ = store.resolve_host_plan(&plan, false);
            return Err(ApiError::conflict(
                instance,
                format!("privilege boundary refused the crossing: {denial}"),
            ));
        }
    };

    // The crossing happened. Burn the nonce durably *before* answering, so a
    // crash cannot leave a spent permit re-servable.
    store.burn_nonce(&admitted.one_shot_nonce).map_err(|e| {
        ApiError::bad_request(instance, format!("recording the nonce burn failed: {e}"))
    })?;

    let observation_id = uuid::Uuid::new_v4().to_string();
    let observation = serde_json::json!({
        "observation_id": observation_id,
        "tool": admitted.outcome.op_kind,
        "path": op.resource_id(),
        "result": admitted.outcome.detail,
        "permit_id": admitted.permit_id,
        "one_shot_nonce": admitted.one_shot_nonce,
        "approval_id": receipt.grant_id,
        "effect_digest": effect_digest,
        "taint": "HOST_MUTATION_COMMITTED",
    });
    store.add_observation(&observation).map_err(|e| {
        ApiError::bad_request(instance, format!("sealing evidence failed: {e}"))
    })?;

    plan["state"] = serde_json::Value::String("COMMITTED".into());
    plan["permit_id"] = serde_json::Value::String(admitted.permit_id.clone());
    plan["one_shot_nonce"] = serde_json::Value::String(admitted.one_shot_nonce.clone());
    plan["observation_id"] = serde_json::Value::String(observation_id.clone());
    store.resolve_host_plan(&plan, true).map_err(|e| {
        ApiError::bad_request(instance, format!("recording plan outcome failed: {e}"))
    })?;

    Ok((
        StatusCode::OK,
        Json(HostCommitResponse {
            plan_id: request.plan_id,
            permit_id: admitted.permit_id,
            one_shot_nonce: admitted.one_shot_nonce,
            approval_id: receipt.grant_id,
            effect_digest,
            outcome: admitted.outcome.detail,
            observation_id,
            state: "COMMITTED",
        }),
    ))
}

/// Lists every plan and its fate, so an operator can audit what was attempted.
pub async fn list(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    Ok(Json(serde_json::json!({
        "plans": store.host_plans(),
        "burned_nonces": store.burned_nonces().len(),
    })))
}
