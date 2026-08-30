//! Checkpoints: signed seals over a stream head (ATOM-V4-LED-001, ADR-021).
//!
//! A hash chain proves that nobody edited history *in place*. It cannot, on its own, prove
//! that nobody rewrote the whole chain — a rewritten chain is internally consistent. A
//! checkpoint closes that hole: it pins `(stream, seq, head_hash, event_count, ts)` under a
//! signature, so an attacker without the seal key cannot make a rewrite look sealed.

use serde::{Deserialize, Serialize};

use crate::hash::{domain_digest, Hash, CHECKPOINT_DOMAIN, CHECKPOINT_SEAL_DOMAIN};
use crate::jcs::{identity_document, Field};

/// A sealed stream head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Stream this checkpoint seals.
    pub stream_id: String,
    /// Sequence of the sealed head event.
    pub seq: u64,
    /// `canonical_hash` of the sealed head event.
    pub head_hash: Hash,
    /// How many events the stream held when it was sealed. Bound into the digest, so a
    /// stream rebuilt with a different number of events cannot claim this seal.
    pub event_count: u64,
    /// Caller-supplied seal time, in milliseconds since the Unix epoch (data, not a clock
    /// read).
    pub ts: i64,
    /// `SHA-256(ATOM-CHECKPOINT-v1: || JCS(identity))` over the five fields above.
    pub digest: Hash,
    /// Which key signed [`Checkpoint::digest`].
    pub key_id: String,
    /// Signature over the digest, produced by a [`CheckpointSigner`].
    pub signature: Vec<u8>,
}

impl Checkpoint {
    /// Derive the digest a checkpoint must carry for the head it claims to seal.
    #[must_use]
    pub fn compute_digest(
        stream_id: &str,
        seq: u64,
        head_hash: &Hash,
        event_count: u64,
        ts: i64,
    ) -> Hash {
        let head_hex = head_hash.to_hex();
        let document = identity_document(&[
            ("event_count", Field::Uint(event_count)),
            ("head_hash", Field::Str(&head_hex)),
            ("seq", Field::Uint(seq)),
            ("stream_id", Field::Str(stream_id)),
            ("ts", Field::Int(ts)),
        ]);
        domain_digest(CHECKPOINT_DOMAIN, &document)
    }

    /// Recompute this checkpoint's digest from its own fields.
    #[must_use]
    pub fn recompute_digest(&self) -> Hash {
        Self::compute_digest(
            &self.stream_id,
            self.seq,
            &self.head_hash,
            self.event_count,
            self.ts,
        )
    }
}

/// Seals checkpoints, and verifies seals it did not create.
///
/// The default implementation is [`HmacSha256Signer`], a symmetric seal: anyone who can
/// verify can also sign, which is the right trade for a single-node store where the same
/// process owns both sides. Swapping in an asymmetric signer (so an auditor can verify
/// without being able to seal) is a matter of another implementation of this trait — the
/// ledger never assumes symmetry.
pub trait CheckpointSigner: Send + Sync {
    /// Identifier recorded on every checkpoint this signer seals.
    fn key_id(&self) -> &str;

    /// Sign a checkpoint digest.
    fn sign(&self, digest: &Hash) -> Vec<u8>;

    /// Verify a signature that claims to come from `key_id`. Must be constant-time in the
    /// signature comparison and must reject an unknown `key_id`.
    fn verify(&self, key_id: &str, digest: &Hash, signature: &[u8]) -> bool;
}

/// HMAC-SHA256 seal over `ATOM-CHECKPOINT-SEAL-v1: || digest`.
pub struct HmacSha256Signer {
    key_id: String,
    key: Vec<u8>,
}

impl HmacSha256Signer {
    /// Build a signer from a key identifier and key material.
    pub fn new(key_id: impl Into<String>, key: impl AsRef<[u8]>) -> Self {
        Self {
            key_id: key_id.into(),
            key: key.as_ref().to_vec(),
        }
    }

    fn mac(&self, digest: &Hash) -> hmac::Hmac<sha2::Sha256> {
        use hmac::Mac as _;
        let mut mac = <hmac::Hmac<sha2::Sha256>>::new_from_slice(&self.key)
            .expect("HMAC accepts a key of any length");
        mac.update(CHECKPOINT_SEAL_DOMAIN.as_bytes());
        mac.update(digest.as_bytes());
        mac
    }
}

/// Never render the key material.
impl std::fmt::Debug for HmacSha256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha256Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl CheckpointSigner for HmacSha256Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, digest: &Hash) -> Vec<u8> {
        use hmac::Mac as _;
        self.mac(digest).finalize().into_bytes().to_vec()
    }

    fn verify(&self, key_id: &str, digest: &Hash, signature: &[u8]) -> bool {
        use hmac::Mac as _;
        key_id == self.key_id && self.mac(digest).verify_slice(signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> HmacSha256Signer {
        HmacSha256Signer::new("k1", b"unit-test-key")
    }

    fn digest() -> Hash {
        Checkpoint::compute_digest("mission/a", 3, &Hash::GENESIS, 3, 42)
    }

    #[test]
    fn digest_binds_every_sealed_field() {
        let base = digest();
        let head = Hash::from_slice(&[7u8; 32]).unwrap();
        for variant in [
            Checkpoint::compute_digest("mission/b", 3, &Hash::GENESIS, 3, 42),
            Checkpoint::compute_digest("mission/a", 4, &Hash::GENESIS, 3, 42),
            Checkpoint::compute_digest("mission/a", 3, &head, 3, 42),
            Checkpoint::compute_digest("mission/a", 3, &Hash::GENESIS, 2, 42),
            Checkpoint::compute_digest("mission/a", 3, &Hash::GENESIS, 3, 43),
        ] {
            assert_ne!(base, variant);
        }
    }

    #[test]
    fn signature_round_trips_and_rejects_tampering() {
        let signer = signer();
        let signature = signer.sign(&digest());
        assert!(signer.verify("k1", &digest(), &signature));
        assert!(!signer.verify("other-key", &digest(), &signature));
        assert!(!signer.verify(
            "k1",
            &Checkpoint::compute_digest("mission/a", 4, &Hash::GENESIS, 3, 42),
            &signature
        ));

        let mut flipped = signature.clone();
        flipped[0] ^= 0x01;
        assert!(!signer.verify("k1", &digest(), &flipped));
        assert!(!signer.verify("k1", &digest(), &[]));

        let other = HmacSha256Signer::new("k1", b"a-different-key");
        assert!(!other.verify("k1", &digest(), &signature));
    }

    #[test]
    fn debug_never_prints_key_material() {
        let rendered = format!("{:?}", signer());
        assert!(rendered.contains("k1"));
        assert!(!rendered.contains("unit-test-key"));
    }
}
