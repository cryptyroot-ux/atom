//! The one escape from read-only replay: [`LiveForkPolicy`].
//!
//! INV-010 says replay cannot re-emit a consequential external effect *unless
//! an explicit live-fork policy authorizes a NEW effect identity*. This module
//! is that "unless", and it is deliberately the only place in the crate that
//! produces something an effect kernel could act on again.
//!
//! A fork never reuses the original identity. It mints a new `effect_id` from
//! the policy plus the original identity digest, which changes the effect
//! digest, which means the new effect must earn its own authorization and its
//! own commit permit before anything is dispatched (see `atom-effect`). Replay
//! itself still emits nothing; the fork is a *new* effect that happens to
//! branch from a replayed one.

use atom_effect::EffectIntent;
use sha2::{Digest, Sha256};

use crate::digest::{component, finish};
use crate::error::ReplayError;

/// An explicit authorization to branch a replayed effect into a NEW identity.
///
/// The caller has to construct this on purpose — there is no default and no
/// implicit path from [`crate::replay`] to here. Its existence in a call is the
/// "explicit live-fork policy" INV-010 requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveForkPolicy {
    /// Who authorized the fork. Named so the ledger can say who branched.
    pub authorized_by: String,
    /// Why the world may be acted on again. A fork is a decision, not a retry.
    pub reason: String,
    /// A nonce that makes each fork of the same effect a distinct new identity.
    pub fork_nonce: String,
}

impl LiveForkPolicy {
    /// A policy authorizing a fork, distinguished by `fork_nonce`.
    #[must_use]
    pub fn new(authorized_by: &str, reason: &str, fork_nonce: &str) -> Self {
        Self {
            authorized_by: authorized_by.to_owned(),
            reason: reason.to_owned(),
            fork_nonce: fork_nonce.to_owned(),
        }
    }

    fn validate(&self) -> Result<(), ReplayError> {
        for (value, field) in [
            (&self.authorized_by, "authorized_by"),
            (&self.reason, "reason"),
            (&self.fork_nonce, "fork_nonce"),
        ] {
            if value.trim().is_empty() {
                return Err(ReplayError::BlankForkField { field });
            }
        }
        Ok(())
    }
}

/// A brand-new effect, branched from a replayed one under a live-fork policy.
///
/// Its identity differs from the origin's: [`origin_effect_id`] and
/// [`forked_effect_id`] are never equal, and neither are the two digests. The
/// forked intent starts in `INTENT_DURABLE` — it has been authorized by nobody
/// yet — so it must traverse the full effect lifecycle on its own. The fork
/// mints identity; it does not dispatch (INV-010).
///
/// [`origin_effect_id`]: ForkedEffect::origin_effect_id
/// [`forked_effect_id`]: ForkedEffect::forked_effect_id
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkedEffect {
    /// The identity of the effect this one branched from.
    pub origin_effect_id: String,
    /// The identity digest of that origin effect.
    pub origin_digest: String,
    /// The NEW effect's identity.
    pub forked_effect_id: String,
    /// The NEW effect's intent, freshly durable and unauthorized.
    pub forked_intent: EffectIntent,
}

impl ForkedEffect {
    /// The NEW effect's identity digest.
    #[must_use]
    pub fn forked_digest(&self) -> String {
        self.forked_intent.digest()
    }
}

/// Mints a NEW effect identity from `origin` under an explicit `policy`.
///
/// This is the only INV-010 escape. The new `effect_id` is derived from the
/// origin's identity digest and the policy's fields, so a fork is deterministic
/// yet always distinct from the effect it branched from. The result is a fresh
/// `INTENT_DURABLE` intent: nothing is dispatched here.
///
/// # Errors
///
/// * [`ReplayError::BlankForkField`] if any policy field is blank.
/// * [`ReplayError::Reduce`] never — no reduction happens — but the signature
///   keeps the crate's single error type.
pub fn live_fork(
    origin: &EffectIntent,
    policy: &LiveForkPolicy,
) -> Result<ForkedEffect, ReplayError> {
    policy.validate()?;

    let origin_digest = origin.digest();

    // A deterministic, collision-resistant new identity, bound to the origin
    // and the policy so two forks of the same effect differ by their nonce.
    let mut hasher = Sha256::new();
    component(&mut hasher, "live-fork");
    component(&mut hasher, &origin.effect_id);
    component(&mut hasher, &origin_digest);
    component(&mut hasher, &policy.authorized_by);
    component(&mut hasher, &policy.reason);
    component(&mut hasher, &policy.fork_nonce);
    let forked_effect_id = format!("effect/fork-{}", finish(hasher));

    // A fresh intent under the NEW identity. Same declared semantics, new
    // effect_id: the request_digest carries the fork provenance so the forked
    // request is genuinely a new one, and the builder returns it in
    // INTENT_DURABLE — authorized by nobody.
    let forked_intent = EffectIntent::builder(
        &forked_effect_id,
        &origin.mission_id,
        &origin.capability_id,
        &origin.target_id,
    )
    .request_digest(&fork_request_digest(&origin.request_digest, &forked_effect_id))
    .classes(&origin.effect_class, &origin.risk_class)
    .idempotency(origin.idempotency.clone())
    .reconciliation(origin.reconciliation.clone())
    .compensation(
        origin
            .compensation
            .clone()
            .expect("a built EffectIntent always carries a compensation plan"),
    );

    let forked_intent = origin
        .preconditions
        .iter()
        .fold(forked_intent, |builder, condition| {
            builder.precondition(condition.clone())
        });
    let forked_intent = origin
        .postconditions
        .iter()
        .fold(forked_intent, |builder, condition| {
            builder.postcondition(condition.clone())
        });

    let forked_intent = forked_intent
        .build()
        .expect("forked intent inherits the origin's valid EFX-002 semantics");

    Ok(ForkedEffect {
        origin_effect_id: origin.effect_id.clone(),
        origin_digest,
        forked_effect_id,
        forked_intent,
    })
}

/// A new request digest binding the fork's provenance, so the forked request is
/// a distinct one from the origin's.
fn fork_request_digest(origin_request_digest: &str, forked_effect_id: &str) -> String {
    let mut hasher = Sha256::new();
    component(&mut hasher, "fork-request");
    component(&mut hasher, origin_request_digest);
    component(&mut hasher, forked_effect_id);
    finish(hasher)
}
