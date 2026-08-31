//! atom-kernel — the single unbypassable door for consequential mutation (KRN-001).
//!
//! Every consequential mutation MUST cross two gates, in order:
//!   1. Phase A — capability authorization ([`Kernel::authorize`]): the grant is
//!      revalidated against the effect and an unforgeable [`Authorization`] is minted.
//!   2. Phase B — commit revalidation ([`Kernel::commit`]): the Effect Kernel's
//!      commit boundary re-checks authority + resource witness, issues and spends a
//!      one-shot [`atom_effect::CommitPermit`], and mints an unforgeable [`CommitToken`].
//!
//! [`Authorization`] and [`CommitToken`] have NO public constructor. The only way
//! an external caller can obtain a [`CommitToken`] — the proof a mutation may be
//! dispatched — is to traverse `authorize` then `commit`, in that order. Deny by
//! default: any drift at either gate refuses, and a refusal burns nothing.

#![forbid(unsafe_code)]

use atom_capability::{CapabilityGrant, RevocationState};
use atom_effect::{
    issue_commit_permit, ConsumeRequest, DurabilityProof, EffectEvent, EffectIntent, EffectState,
    NonceRegistry, PermitError, PermitRequest, ResourceWitness,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

/// Why the kernel refused a mutation at either gate.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelError {
    /// The intent was presented to a gate from the wrong lifecycle state.
    #[error("effect is {state}, not the state this gate requires")]
    WrongState {
        /// The state the intent was actually in.
        state: EffectState,
    },
    /// The intent's `capability_id` does not name the grant presented.
    #[error("intent is bound to capability {expected}, not grant {observed}")]
    CapabilityMismatch {
        /// The capability the intent names.
        expected: String,
        /// The grant that was presented.
        observed: String,
    },
    /// The grant belongs to a different principal than the one asking.
    #[error("grant belongs to {expected}, not {observed}")]
    PrincipalMismatch {
        /// The grant's subject.
        expected: String,
        /// The principal that asked.
        observed: String,
    },
    /// The grant is revoked or otherwise not active.
    #[error("grant is {state:?}, not ACTIVE")]
    GrantNotActive {
        /// The revocation state found.
        state: RevocationState,
    },
    /// The moment of the request is outside the grant's validity window.
    #[error("{at} is outside the grant window {not_before}..={expires_at}")]
    GrantOutsideValidity {
        /// The instant checked.
        at: DateTime<Utc>,
        /// When the grant becomes usable.
        not_before: DateTime<Utc>,
        /// When it stops being usable.
        expires_at: DateTime<Utc>,
    },
    /// The grant does not permit the operation being attempted.
    #[error("grant does not allow {operation}")]
    OperationNotGranted {
        /// The operation refused.
        operation: String,
    },
    /// The grant does not cover the resource being written.
    #[error("grant does not cover {resource_type} {resource_id}")]
    ResourceNotGranted {
        /// The resource type refused.
        resource_type: String,
        /// The resource itself.
        resource_id: String,
    },
    /// The authorization presented was minted for a different effect.
    #[error("authorization is for effect digest {expected}, not {observed}")]
    AuthorizationEffectMismatch {
        /// The digest the authorization is bound to.
        expected: String,
        /// The digest of the effect that presented it.
        observed: String,
    },
    /// The commit boundary refused (EFX-001/004, ATOM-VT-003).
    #[error("commit boundary refused: {0}")]
    Permit(#[from] PermitError),
}

/// Phase A output: proof that a specific effect was authorised against a grant.
///
/// Unforgeable: fields are private and the only mint site is [`Kernel::authorize`].
/// It pins the grant generation and the resource witness observed while planning,
/// so Phase B can detect any drift that happened in the window (ATOM-VT-003).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Authorization {
    effect_id: String,
    effect_digest: String,
    grant_id: String,
    grant_generation: u64,
    principal_id: String,
    operation: String,
    resource_type: String,
    planned_witness: ResourceWitness,
}

impl Authorization {
    /// The grant generation pinned at authorization time.
    #[must_use]
    pub fn grant_generation(&self) -> u64 {
        self.grant_generation
    }

    /// The identity digest of the effect this authorization is bound to.
    #[must_use]
    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    /// The effect this authorization is bound to.
    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    /// The grant the authority was drawn from.
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// The principal the authorization was minted for.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// The operation the authorization covers.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// The resource type the authorization covers.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// The resource version observed while planning.
    #[must_use]
    pub fn planned_witness(&self) -> &ResourceWitness {
        &self.planned_witness
    }
}

/// Phase B output: proof that a mutation may now be dispatched, exactly once.
///
/// Unforgeable: fields are private and the only mint site is [`Kernel::commit`],
/// which reaches it only after both gates passed and a one-shot permit was spent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitToken {
    effect_id: String,
    grant_id: String,
    grant_generation: u64,
    resource_id: String,
    one_shot_nonce: String,
}

impl CommitToken {
    /// The effect cleared for dispatch.
    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    /// The grant the authority was drawn from.
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// The grant generation at commit time.
    #[must_use]
    pub fn grant_generation(&self) -> u64 {
        self.grant_generation
    }

    /// The resource that may be written.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// The one-shot nonce that was burned to mint this token.
    #[must_use]
    pub fn one_shot_nonce(&self) -> &str {
        &self.one_shot_nonce
    }
}

/// Everything Phase A revalidates before it mints an [`Authorization`].
#[derive(Clone, Debug)]
pub struct AuthorizeRequest<'a> {
    /// The effect standing for authorization, in AUTHORIZATION_PENDING.
    pub intent: &'a EffectIntent,
    /// The grant the authority is drawn from.
    pub grant: &'a CapabilityGrant,
    /// The principal asking.
    pub principal_id: &'a str,
    /// The operation about to be performed.
    pub operation: &'a str,
    /// The type of the target resource.
    pub resource_type: &'a str,
    /// The resource version observed while planning.
    pub planned_witness: &'a ResourceWitness,
    /// The instant of the request; supplied, never read from a clock.
    pub now: DateTime<Utc>,
}

/// Everything Phase B revalidates before it mints a [`CommitToken`].
#[derive(Clone, Debug)]
pub struct CommitRequest<'a> {
    /// The unforgeable proof Phase A passed for this exact effect.
    pub authorization: &'a Authorization,
    /// The effect standing at the commit boundary, in COMMIT_REVALIDATING.
    pub intent: &'a EffectIntent,
    /// The grant as it is *now* (may have drifted since Phase A).
    pub grant: &'a CapabilityGrant,
    /// The resource version observed *now*.
    pub observed_witness: &'a ResourceWitness,
    /// Proof the intent was persisted first (EFX-001). Only the ledger can mint
    /// one, so it cannot be a hand-built claim of durability.
    pub durability: &'a DurabilityProof,
    /// The identity the permit will carry.
    pub permit_id: &'a str,
    /// The nonce that makes the permit one-shot.
    pub one_shot_nonce: &'a str,
    /// How long the permit may live.
    pub ttl_seconds: u32,
    /// The instant of the request.
    pub now: DateTime<Utc>,
    /// The human approval, when the risk class required one.
    pub approval_id: Option<&'a str>,
    /// How fresh the evidence behind the decision was.
    pub evidence_freshness_digest: Option<&'a str>,
}

/// The sovereign kernel: the single door every consequential mutation crosses.
///
/// It owns the [`NonceRegistry`], so the one-shot guarantee (a permit spent once)
/// is enforced across the whole process, not per call.
#[derive(Debug, Default)]
pub struct Kernel {
    nonces: NonceRegistry,
}

impl Kernel {
    /// A fresh kernel with an empty nonce registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many one-shot permits have been spent (for audit/tests).
    #[must_use]
    pub fn nonces_spent(&self) -> usize {
        self.nonces.len()
    }

    /// Phase A — capability authorization.
    ///
    /// Revalidates the grant against the effect and, on success, advances the
    /// intent AUTHORIZATION_PENDING -> AUTHORIZED and mints an [`Authorization`].
    ///
    /// # Errors
    ///
    /// [`KernelError`] naming the first check that failed: wrong lifecycle state,
    /// a grant that names a different capability/principal, a revoked or expired
    /// grant, or an operation/resource the grant does not cover.
    pub fn authorize(
        &self,
        request: AuthorizeRequest<'_>,
    ) -> Result<(Authorization, EffectIntent), KernelError> {
        let intent = request.intent;
        let grant = request.grant;

        // Gate order: the effect must be standing for authorization first.
        if intent.state != EffectState::AuthorizationPending {
            return Err(KernelError::WrongState {
                state: intent.state,
            });
        }

        // The intent must name this exact grant as its capability.
        if intent.capability_id != grant.grant_id {
            return Err(KernelError::CapabilityMismatch {
                expected: intent.capability_id.clone(),
                observed: grant.grant_id.clone(),
            });
        }

        // Authority: subject, active, window.
        if grant.subject_id != request.principal_id {
            return Err(KernelError::PrincipalMismatch {
                expected: grant.subject_id.clone(),
                observed: request.principal_id.to_owned(),
            });
        }
        if grant.revocation_state != RevocationState::Active {
            return Err(KernelError::GrantNotActive {
                state: grant.revocation_state,
            });
        }
        if request.now < grant.not_before || request.now > grant.expires_at {
            return Err(KernelError::GrantOutsideValidity {
                at: request.now,
                not_before: grant.not_before,
                expires_at: grant.expires_at,
            });
        }

        // Authority: the operation and the resource must be covered.
        if !grant.operations.iter().any(|op| op == request.operation) {
            return Err(KernelError::OperationNotGranted {
                operation: request.operation.to_owned(),
            });
        }
        let covered = grant.resources.iter().any(|selector| {
            selector.resource_type == request.resource_type
                && selector.resource_id == intent.target_id
        });
        if !covered {
            return Err(KernelError::ResourceNotGranted {
                resource_type: request.resource_type.to_owned(),
                resource_id: intent.target_id.clone(),
            });
        }

        // Advance the lifecycle through a durable event; the reducer is the only
        // authority on whether the transition is legal.
        let authorized = intent
            .try_advance(&EffectEvent::authorization_granted(
                &grant.grant_id,
                grant.generation,
            ))
            .map_err(|_| KernelError::WrongState {
                state: intent.state,
            })?;

        let authorization = Authorization {
            effect_id: intent.effect_id.clone(),
            effect_digest: intent.digest(),
            grant_id: grant.grant_id.clone(),
            grant_generation: grant.generation,
            principal_id: request.principal_id.to_owned(),
            operation: request.operation.to_owned(),
            resource_type: request.resource_type.to_owned(),
            planned_witness: request.planned_witness.clone(),
        };
        Ok((authorization, authorized))
    }

    /// Phase B — commit revalidation.
    ///
    /// Requires the unforgeable [`Authorization`] from Phase A, re-checks that it
    /// belongs to this effect, issues and spends a one-shot commit permit through
    /// the Effect Kernel boundary (which re-runs authority + witness checks against
    /// the pinned generation/witness, catching any drift), advances the intent
    /// COMMIT_REVALIDATING -> DISPATCHING, and mints a [`CommitToken`].
    ///
    /// # Errors
    ///
    /// [`KernelError::WrongState`] if the effect is not at the boundary,
    /// [`KernelError::AuthorizationEffectMismatch`] if the authorization is for a
    /// different effect, or [`KernelError::Permit`] wrapping the drift the commit
    /// boundary found. A refusal burns no nonce.
    pub fn commit(
        &mut self,
        request: CommitRequest<'_>,
    ) -> Result<(CommitToken, EffectIntent), KernelError> {
        let intent = request.intent;
        let grant = request.grant;
        let authorization = &request.authorization;

        // Gate order: the effect must be standing at the commit boundary. Checked
        // here (not only inside the permit gate) so the kernel's own state error
        // is distinguishable from a boundary refusal.
        if intent.state != EffectState::CommitRevalidating {
            return Err(KernelError::WrongState {
                state: intent.state,
            });
        }

        // The authorization must belong to THIS effect: an Authorization minted
        // for effect A cannot commit effect B. Digest is identity-stable across
        // lifecycle transitions, so it still matches after AUTHORIZED->REVALIDATING.
        let observed_digest = intent.digest();
        if authorization.effect_digest != observed_digest {
            return Err(KernelError::AuthorizationEffectMismatch {
                expected: authorization.effect_digest.clone(),
                observed: observed_digest,
            });
        }

        // Issue the permit: re-runs authority against the generation pinned in
        // Phase A and the planned witness, so a re-issued/revoked grant or a moved
        // resource is caught here rather than waved through.
        let permit = issue_commit_permit(PermitRequest {
            intent,
            grant,
            principal_id: &authorization.principal_id,
            operation: &authorization.operation,
            resource_type: &authorization.resource_type,
            planned_grant_generation: authorization.grant_generation,
            planned_witness: &authorization.planned_witness,
            observed_witness: request.observed_witness,
            durability: request.durability,
            permit_id: request.permit_id,
            one_shot_nonce: request.one_shot_nonce,
            ttl_seconds: request.ttl_seconds,
            now: request.now,
            approval_id: request.approval_id,
            evidence_freshness_digest: request.evidence_freshness_digest,
        })?;

        // Spend it exactly once. Consumption re-validates everything against the
        // permit and burns the nonce; a replay of a burned nonce is refused here.
        let permitted = self.nonces.consume(ConsumeRequest {
            permit: &permit,
            intent,
            grant,
            observed_witness: request.observed_witness,
            now: request.now,
        })?;

        // Advance the lifecycle through the durable CommitPermitted event.
        let dispatching = intent
            .try_advance(&EffectEvent::CommitPermitted(permitted))
            .map_err(|_| KernelError::WrongState {
                state: intent.state,
            })?;

        let token = CommitToken {
            effect_id: intent.effect_id.clone(),
            grant_id: permit.capability_grant_id().to_owned(),
            grant_generation: permit.grant_generation(),
            resource_id: permit.resource_id().to_owned(),
            one_shot_nonce: permit.one_shot_nonce().to_owned(),
        };
        Ok((token, dispatching))
    }
}
