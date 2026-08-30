//! Content identity: domain-separated SHA-256 over RFC 8785 bytes (ADR-020).
//!
//! Domain separation is mandatory, not decorative. Every normative identity is
//! `SHA-256(domain_tag || canonical_bytes)`, so an event identity can never collide with a
//! payload digest or a checkpoint digest even if their canonical bytes were identical.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::jcs::canonicalize;

/// Identity of an event: seq, stream, previous hash, payload digest and timestamp.
pub const EVENT_DOMAIN: &str = "ATOM-EVENT-v1:";
/// Identity of an event payload: the canonical payload bytes.
pub const PAYLOAD_DOMAIN: &str = "ATOM-PAYLOAD-v1:";
/// Identity of a checkpoint: the sealed head of a stream.
pub const CHECKPOINT_DOMAIN: &str = "ATOM-CHECKPOINT-v1:";
/// Input to a checkpoint signature, kept distinct from the digest itself so a seal key can
/// never be coaxed into signing some other ATOM identity.
pub const CHECKPOINT_SEAL_DOMAIN: &str = "ATOM-CHECKPOINT-SEAL-v1:";
/// Rolling digest of a whole stream: the "state digest" of ATOM-VT-001.
pub const STREAM_DIGEST_DOMAIN: &str = "ATOM-STREAM-DIGEST-v1:";

/// Length of every hash in this crate, in bytes.
pub const HASH_LEN: usize = 32;

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// The zero hash, used as the `prev_hash` of the first event in a stream and as the
    /// head of an empty stream. It is not a valid SHA-256 output of any known input.
    pub const GENESIS: Self = Self([0u8; HASH_LEN]);

    /// Borrow the raw digest bytes, e.g. to bind them as a SQLite `BLOB`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Lowercase hex, the only textual form of a hash in ATOM.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// True for [`Hash::GENESIS`].
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        *self == Self::GENESIS
    }

    /// Parse lowercase or uppercase hex of exactly 32 bytes.
    pub fn from_hex(text: &str) -> Result<Self> {
        let bytes = hex::decode(text).map_err(|error| Error::InvalidHash {
            detail: format!("`{text}` is not hex: {error}"),
        })?;
        Self::from_slice(&bytes)
    }

    /// Adopt exactly 32 bytes as a hash.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; HASH_LEN] = bytes.try_into().map_err(|_| Error::InvalidHash {
            detail: format!("expected {HASH_LEN} bytes, got {}", bytes.len()),
        })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// `SHA-256(domain || bytes)` — the one place a hash is ever produced.
#[must_use]
pub fn domain_digest(domain: &str, bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    Hash(hasher.finalize().into())
}

/// Digest of a payload value: canonicalize (RFC 8785), then hash under
/// [`PAYLOAD_DOMAIN`].
pub fn payload_digest(payload: &Value) -> Result<Hash> {
    Ok(payload_digest_bytes(&canonicalize(payload)?))
}

/// Digest of already-canonical payload bytes.
///
/// Verification uses this rather than [`payload_digest`]: it must hash exactly the bytes
/// the store holds, including bytes that no longer parse as JSON.
#[must_use]
pub fn payload_digest_bytes(canonical: &[u8]) -> Hash {
    domain_digest(PAYLOAD_DOMAIN, canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn domains_separate_identical_bytes() {
        let bytes = b"same bytes";
        assert_ne!(
            domain_digest(EVENT_DOMAIN, bytes),
            domain_digest(PAYLOAD_DOMAIN, bytes)
        );
        assert_ne!(
            domain_digest(CHECKPOINT_DOMAIN, bytes),
            domain_digest(CHECKPOINT_SEAL_DOMAIN, bytes)
        );
        assert_ne!(
            domain_digest(STREAM_DIGEST_DOMAIN, bytes),
            domain_digest(PAYLOAD_DOMAIN, bytes)
        );
    }

    #[test]
    fn payload_digest_is_key_order_independent() {
        let left = json!({"a": 1, "b": [1, 2]});
        let right = json!({"b": [1, 2], "a": 1});
        assert_eq!(
            payload_digest(&left).unwrap(),
            payload_digest(&right).unwrap()
        );
        assert_ne!(
            payload_digest(&json!({"a": 1})).unwrap(),
            payload_digest(&json!({"a": 2})).unwrap()
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let hash = payload_digest(&json!({"k": "v"})).unwrap();
        assert_eq!(Hash::from_hex(&hash.to_hex()).unwrap(), hash);
        assert_eq!(hash.to_hex().len(), HASH_LEN * 2);
        assert!(Hash::from_hex("zz").is_err());
        assert!(Hash::from_slice(&[0u8; 31]).is_err());
        assert!(Hash::GENESIS.is_genesis());
        assert!(!hash.is_genesis());
    }

    #[test]
    fn hash_serializes_as_hex() {
        let hash = payload_digest(&json!(1)).unwrap();
        let text = serde_json::to_string(&hash).unwrap();
        assert_eq!(text, format!("\"{}\"", hash.to_hex()));
        assert_eq!(serde_json::from_str::<Hash>(&text).unwrap(), hash);
    }
}
