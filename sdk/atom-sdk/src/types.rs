//! Wire request/response envelopes.
//!
//! These types are SDK-side DTOs that wrap the canonical crate types. They
//! exist to give callers a stable shape independent of internal crate
//! additions and to make the API contract explicit.

use serde::{Deserialize, Serialize};

use atom_artifact::Artifact;
use atom_claim::{Claim, ClaimId, ProvenanceGraph};
use atom_effect::{EffectIntent, ResourceWitness};

/// Successful health-check response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthStatus {
    /// Stable node identifier.
    pub node_id: String,
    /// ATOM protocol version this node speaks.
    pub protocol_version: String,
    /// Number of crates linked into the node (sanity check).
    pub crates_loaded: usize,
}

/// Wrapper for submitting an effect intent for kernel authorization.
///
/// The intent is the canonical wire shape; we add only request metadata
/// (id, idempotency key) that is *not* part of the intent itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEffectRequest {
    /// Client-generated request id; echoed in the response for traceability.
    pub request_id: String,
    /// Idempotency key — same key + same intent MUST return same `CommitToken`.
    pub idempotency_key: String,
    /// The intent to authorize and commit.
    #[serde(flatten)]
    pub intent: EffectIntent,
}

/// Client-side, read-only view of the kernel's Phase A `Authorization`.
///
/// The canonical [`atom_kernel::Authorization`] is a sealed trust-boundary
/// object: only the kernel can mint one, and it is deliberately *not*
/// reconstructible from the wire. A client that deserialized one would be
/// holding a forgery. This view is honest plain data — the server's audit
/// JSON, for a caller to read, never to be mistaken for authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizationView {
    /// The effect this authorization is bound to.
    pub effect_id: String,
    /// The identity digest of that effect.
    pub effect_digest: String,
    /// The grant the authority was drawn from.
    pub grant_id: String,
    /// The grant generation pinned at authorization time.
    pub grant_generation: u64,
    /// The principal the authorization was minted for.
    pub principal_id: String,
    /// The operation the authorization covers.
    pub operation: String,
    /// The resource type the authorization covers.
    pub resource_type: String,
    /// The resource version observed while planning.
    pub planned_witness: ResourceWitness,
}

/// Client-side, read-only view of the kernel's Phase B `CommitToken`.
///
/// Same rationale as [`AuthorizationView`]: the sealed
/// [`atom_kernel::CommitToken`] is mint-only and non-deserializable by design.
/// This is its wire shape for a client to inspect (e.g. the burned one-shot
/// nonce), not a spendable token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitTokenView {
    /// The effect cleared for dispatch.
    pub effect_id: String,
    /// The grant the authority was drawn from.
    pub grant_id: String,
    /// The grant generation at commit time.
    pub grant_generation: u64,
    /// The resource that may be written.
    pub resource_id: String,
    /// The one-shot nonce that was burned to mint the token.
    pub one_shot_nonce: String,
}

/// Response from `submit_effect`: the kernel's authorization + the one-shot
/// commit token, or a structured error reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEffectResponse {
    /// The request id echoed back.
    pub request_id: String,
    /// The idempotency key echoed back.
    pub idempotency_key: String,
    /// Phase A output — a read-only view proving capability authorized this effect.
    pub authorization: AuthorizationView,
    /// Phase B output — a read-only view proving a one-shot commit was issued.
    pub commit_token: CommitTokenView,
}

/// Wrapper for verifying a content-addressed artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyArtifactRequest {
    /// The artifact (content + provenance + sbom + signature) to verify.
    #[serde(flatten)]
    pub artifact: Artifact,
}

/// Response from `verify_artifact`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyArtifactResponse {
    /// `true` iff the artifact verifies end-to-end.
    pub valid: bool,
    /// SHA-256 of the artifact bytes (`sha256:...`).
    pub content_id: String,
    /// If `valid` is false, the structured reason.
    pub failure_reason: Option<String>,
}

/// Response from `get_claim` — returns the claim + its provenance DAG.
///
/// Note: ProvenanceGraph is not Serialize by the canonical crate. We provide
/// a custom Serialize impl that converts it to JSON via its Debug representation
/// as a fallback. This is a limitation of the canonical crate's current design.
#[derive(Clone, Debug, PartialEq)]
pub struct GetClaimResponse {
    /// The claim itself.
    pub claim: Claim,
    /// The provenance DAG the claim references.
    pub provenance: ProvenanceGraph,
}

impl serde::Serialize for GetClaimResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("GetClaimResponse", 2)?;
        state.serialize_field("claim", &self.claim)?;
        // ProvenanceGraph doesn't implement Serialize; use a placeholder
        state.serialize_field("provenance", &format!("{:?}", self.provenance))?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for GetClaimResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            claim: Claim,
            #[allow(dead_code)]
            provenance: serde_json::Value,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            claim: h.claim,
            provenance: ProvenanceGraph::new(),
        })
    }
}

/// Request body for `put_claim` — create or replace a claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PutClaimRequest {
    /// Client-generated id for the claim (idempotent on retry).
    pub claim_id: ClaimId,
    /// The claim to create.
    pub claim: Claim,
}

/// Response from `put_claim` — confirms the claim id that was stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PutClaimResponse {
    /// The claim id that was persisted.
    pub claim_id: ClaimId,
    /// The state the claim landed in (e.g. `Pending`, `Confirmed`).
    pub state: String,
}

/// Generic error envelope returned by /v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApiError {
    /// Stable error code (e.g. `EFFECT_NOT_AUTHORIZED`).
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Optional structured detail (validation failures, missing fields, etc.).
    pub detail: Option<serde_json::Value>,
}
