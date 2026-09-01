//! Unforgeable durability proof: the ledger's own attestation that an intent was
//! persisted before anything downstream may act on it (ATOM-LED-001, EFX-001,
//! ATOM-INV-004).
//!
//! A [`DurabilityProof`] is *evidence*, not data. It is minted in exactly one
//! place — [`DurabilityProof::seal`], `pub(crate)` — from an [`Event`] the store
//! has just appended and committed. There is no public constructor, no
//! `Deserialize`, and no `serde(Deserialize)` derive, so a caller in another
//! crate cannot manufacture one out of hand-picked fields: the only way to hold a
//! proof is to have caused a real append. That is the difference between "the
//! caller says the effect is durable" and "the ledger says so".
//!
//! It carries only what a downstream gate needs to *check* durability — the
//! stream the intent landed on, its sequence, and the appended event's identity —
//! and exposes them read-only. The identity is a genuine [`Hash`], never a
//! free-text string, so "the hash is non-empty" is not something a caller can
//! fake or get wrong.

use crate::event::Event;
use crate::hash::Hash;

/// Proof that an effect intent was durably appended to its own ledger stream.
///
/// Construct only via [`DurabilityProof::seal`], which the ledger calls after a
/// committed append. The fields are private and there is deliberately no
/// `Deserialize`: an authority object that could be deserialized could be forged
/// (INV-004, "no arbitrary caller manufactures a trusted proof").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurabilityProof {
    stream_id: String,
    sequence: u64,
    entry_hash: Hash,
    payload_digest: Hash,
}

impl DurabilityProof {
    /// Seal a proof over an event the store has just appended and committed.
    ///
    /// `pub(crate)` on purpose: only `atom-ledger`'s own append path may mint a
    /// proof, and only from a real [`Event`]. Nothing outside this crate can call
    /// it, so nothing outside this crate can forge a proof.
    #[must_use]
    pub(crate) fn seal(event: &Event) -> Self {
        Self {
            stream_id: event.stream_id.clone(),
            sequence: event.seq,
            entry_hash: event.canonical_hash,
            payload_digest: event.payload_digest,
        }
    }

    /// The stream the intent was appended to (its effect id, by convention).
    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// The 1-based sequence the intent landed at. A genuine append is always `>= 1`.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The appended event's canonical identity (chained hash).
    #[must_use]
    pub fn entry_hash(&self) -> &Hash {
        &self.entry_hash
    }

    /// The appended event's payload digest (hash of canonicalized payload bytes).
    ///
    /// When the payload is a serialized `EffectIntent`, this equals the RFC 8785
    /// digest of that intent, binding the proof to the exact intent structure.
    #[must_use]
    pub fn payload_digest(&self) -> &Hash {
        &self.payload_digest
    }

    /// Whether this proof attests durability of `effect_id`.
    ///
    /// The intent for an effect is appended to a stream named for that effect, so
    /// a proof proves durability of `effect_id` iff it was minted on that stream.
    /// The sequence check is belt-and-braces: `seal` only ever runs on a committed
    /// event, whose sequence is `>= 1` by construction, so a `sequence == 0` proof
    /// cannot exist — but asserting it here keeps the property local and explicit.
    #[must_use]
    pub fn proves(&self, effect_id: &str) -> bool {
        self.stream_id == effect_id && self.sequence >= 1
    }

    /// Whether this proof attests durability of `effect_id` *and* the appended
    /// payload matches the expected canonical payload digest.
    ///
    /// This binds the proof to the exact `EffectIntent` that was appended,
    /// preventing an arbitrary payload from being swapped in after the fact.
    #[must_use]
    pub fn proves_intent(&self, effect_id: &str, expected_payload_digest: &Hash) -> bool {
        self.proves(effect_id) && self.payload_digest == *expected_payload_digest
    }
}
