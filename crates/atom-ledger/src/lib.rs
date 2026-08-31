//! ATOM authoritative event ledger: append-only, hash-chained, checkpoint-sealed.
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-LED-001** — an authoritative event stream carries a monotonic sequence, the
//!   previous event's hash and a canonical event hash; checkpoints seal stream heads.
//! * **ATOM-INV-007** — projections are rebuilt from the ledger and never override it.
//! * **ADR-020** — canonical encoding is RFC 8785 JCS over UTF-8, hashed with SHA-256 under
//!   a mandatory domain tag.
//! * **ADR-021** — hash-chain every stream, seal heads with periodic checkpoints.
//! * **ADR-004 / ADR-006** — a single SQLite file is the authoritative single-node store;
//!   materialized views are rebuildable, never authoritative.
//!
//! ```
//! use atom_ledger::{HmacSha256Signer, Ledger};
//! use serde_json::json;
//!
//! # fn main() -> atom_ledger::Result<()> {
//! let signer = Box::new(HmacSha256Signer::new("seal-key-1", b"not-a-production-key"));
//! let mut ledger = Ledger::open_in_memory(signer)?;
//!
//! ledger.append("mission/demo", &json!({"kind": "MISSION_CREATED"}), 1_756_512_000_000)?;
//! ledger.append("mission/demo", &json!({"kind": "MISSION_STARTED"}), 1_756_512_001_000)?;
//! let sealed = ledger.checkpoint("mission/demo", 1_756_512_002_000)?;
//!
//! assert_eq!(sealed.seq, 2);
//! assert!(ledger.verify_stream("mission/demo")?.is_intact());
//! # Ok(())
//! # }
//! ```
//!
//! Two properties hold throughout. Timestamps are always caller-supplied data — the ledger
//! never reads a clock, so two machines fed the same events derive the same identities. And
//! an integrity problem is never an [`Error`]: errors are questions the store could not
//! answer, while a [`Finding`] is an answer that is provably wrong.

#![forbid(unsafe_code)]

mod checkpoint;
mod error;
mod event;
mod hash;
mod jcs;
mod store;
mod verify;

pub use crate::checkpoint::{Checkpoint, CheckpointSigner, HmacSha256Signer};
pub use crate::error::{Error, Result};
pub use crate::event::{Event, EventRecord};
pub use crate::hash::{
    domain_digest, payload_digest, payload_digest_bytes, Hash, CHECKPOINT_DOMAIN,
    CHECKPOINT_SEAL_DOMAIN, EVENT_DOMAIN, HASH_LEN, PAYLOAD_DOMAIN, STREAM_DIGEST_DOMAIN,
};
pub use crate::jcs::canonicalize;
pub use crate::store::{Ledger, LedgerTx};
pub use crate::verify::{Finding, VerifyReport};
