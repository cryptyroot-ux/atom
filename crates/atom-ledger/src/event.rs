//! Events: the only authoritative record in ATOM (ATOM-LED-001, ADR-021).
//!
//! An event's identity binds its position (`seq`), its stream, its predecessor
//! (`prev_hash`), its content (`payload_digest`) and its timestamp. Change any of those and
//! `canonical_hash` changes, which is what makes delete, reorder, edit and truncation
//! detectable.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash::{domain_digest, Hash, EVENT_DOMAIN};
use crate::jcs::{identity_document, Field};

/// The hashed identity of one appended event. The payload itself is stored beside it (see
/// [`EventRecord`]) and is bound into the identity through `payload_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Position in the stream: 1-based and strictly monotonic, no gaps.
    pub seq: u64,
    /// Stream this event belongs to, e.g. `mission/<ULID>`.
    pub stream_id: String,
    /// `canonical_hash` of event `seq - 1`, or [`Hash::GENESIS`] for the first event.
    pub prev_hash: Hash,
    /// Digest of the canonical payload bytes.
    pub payload_digest: Hash,
    /// This event's identity: `SHA-256(ATOM-EVENT-v1: || JCS(identity))`.
    pub canonical_hash: Hash,
    /// Caller-supplied event time, in milliseconds since the Unix epoch. It is *data*: the
    /// ledger never reads a clock, so identities stay reproducible.
    pub ts: i64,
}

impl Event {
    /// Derive the canonical hash of an event from the five fields that identify it.
    ///
    /// Public because tamper detection is only meaningful if anyone — a replica, an
    /// auditor, a test — can recompute an identity independently.
    #[must_use]
    pub fn compute_canonical_hash(
        seq: u64,
        stream_id: &str,
        prev_hash: &Hash,
        payload_digest: &Hash,
        ts: i64,
    ) -> Hash {
        let payload_hex = payload_digest.to_hex();
        let prev_hex = prev_hash.to_hex();
        let document = identity_document(&[
            ("payload_digest", Field::Str(&payload_hex)),
            ("prev_hash", Field::Str(&prev_hex)),
            ("seq", Field::Uint(seq)),
            ("stream_id", Field::Str(stream_id)),
            ("ts", Field::Int(ts)),
        ]);
        domain_digest(EVENT_DOMAIN, &document)
    }

    /// Recompute this event's identity from its own fields.
    #[must_use]
    pub fn recompute_canonical_hash(&self) -> Hash {
        Self::compute_canonical_hash(
            self.seq,
            &self.stream_id,
            &self.prev_hash,
            &self.payload_digest,
            self.ts,
        )
    }
}

/// An event together with its decoded payload, as returned by reads.
///
/// Projections are rebuilt from these and never stored (ATOM-INV-007).
#[derive(Debug, Clone, PartialEq)]
pub struct EventRecord {
    /// The hashed identity.
    pub event: Event,
    /// The payload, decoded from the canonical bytes the store holds.
    pub payload: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::payload_digest;
    use serde_json::json;

    fn digest() -> Hash {
        payload_digest(&json!({"kind": "MISSION_PHASE_CHANGED"})).unwrap()
    }

    #[test]
    fn every_identity_field_changes_the_hash() {
        let base = Event::compute_canonical_hash(2, "mission/a", &Hash::GENESIS, &digest(), 10);
        let other_digest = payload_digest(&json!({"kind": "OTHER"})).unwrap();
        for variant in [
            Event::compute_canonical_hash(3, "mission/a", &Hash::GENESIS, &digest(), 10),
            Event::compute_canonical_hash(2, "mission/b", &Hash::GENESIS, &digest(), 10),
            Event::compute_canonical_hash(2, "mission/a", &digest(), &digest(), 10),
            Event::compute_canonical_hash(2, "mission/a", &Hash::GENESIS, &other_digest, 10),
            Event::compute_canonical_hash(2, "mission/a", &Hash::GENESIS, &digest(), 11),
        ] {
            assert_ne!(base, variant);
        }
        assert_eq!(
            base,
            Event::compute_canonical_hash(2, "mission/a", &Hash::GENESIS, &digest(), 10),
            "identity must be a pure function of its fields"
        );
    }

    #[test]
    fn negative_timestamps_are_hashable() {
        let before_epoch =
            Event::compute_canonical_hash(1, "mission/a", &Hash::GENESIS, &digest(), -1);
        let after_epoch =
            Event::compute_canonical_hash(1, "mission/a", &Hash::GENESIS, &digest(), 1);
        assert_ne!(before_epoch, after_epoch);
    }
}
