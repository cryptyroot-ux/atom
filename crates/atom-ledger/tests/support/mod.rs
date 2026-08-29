//! Shared deterministic fixtures for the ledger verification tests
//! (ATOM-VT-001 crash safety, ATOM-VT-006 ledger tamper).
//!
//! Everything here is deterministic: payloads and timestamps are pure functions of
//! an index, so two independent ledgers fed the same indices MUST produce identical
//! canonical hashes and stream digests. No wall clock is read anywhere.

#![allow(dead_code)]

use std::collections::BTreeMap;

use atom_ledger::{payload_digest, CheckpointSigner, EventRecord, Hash, HmacSha256Signer, Ledger};
use serde_json::{json, Value};

/// Stream under test. Mission streams are the primary authoritative stream class.
pub const STREAM: &str = "mission/01JVT0ATOMV4MISSION";

/// Checkpoint seal key id / key. Test-only value; never a production key.
pub const KEY_ID: &str = "vt-checkpoint-key-1";
pub const KEY: &[u8] = b"atom-vt-hmac-seal-key/not-a-production-key";

/// Canonical mission phases (spec/enums.yaml `mission.phase`).
pub const PHASES: [&str; 6] = [
    "CREATED",
    "COMPILED",
    "READY",
    "RUNNING",
    "VERIFYING",
    "TERMINAL",
];

pub fn signer() -> Box<dyn CheckpointSigner> {
    Box::new(HmacSha256Signer::new(KEY_ID, KEY))
}

/// Deterministic mission event payload for 1-based index `i`.
pub fn payload(i: u64) -> Value {
    json!({
        "kind": "MISSION_PHASE_CHANGED",
        "index": i,
        "phase": PHASES[((i - 1) as usize) % PHASES.len()],
        "condition": "NORMAL",
    })
}

/// Deterministic event timestamp (ms since Unix epoch) for 1-based index `i`.
pub fn ts(i: u64) -> i64 {
    1_756_512_000_000 + (i as i64) * 1_000
}

/// Append events `1..=n` to `stream`.
pub fn seed(ledger: &mut Ledger, n: u64) {
    for i in 1..=n {
        ledger
            .append(STREAM, &payload(i), ts(i))
            .expect("append must succeed");
    }
}

/// A projection rebuilt purely from ledger events (INV-007: projections are
/// rebuildable from the ledger and never authoritative).
pub fn project(records: &[EventRecord]) -> Value {
    let mut phase_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut last_phase = Value::Null;
    for record in records {
        if let Some(phase) = record.payload.get("phase").and_then(Value::as_str) {
            *phase_counts.entry(phase.to_owned()).or_insert(0) += 1;
            last_phase = Value::String(phase.to_owned());
        }
    }
    json!({
        "event_count": records.len(),
        "head_seq": records.last().map(|r| r.event.seq).unwrap_or(0),
        "last_phase": last_phase,
        "phase_counts": phase_counts,
    })
}

/// Digest of the rebuilt projection: the "recovered state digest" of ATOM-VT-001.
pub fn projection_digest(records: &[EventRecord]) -> Hash {
    payload_digest(&project(records)).expect("projection is canonicalizable")
}

/// Reference `(stream_digest, projection_digest)` for a clean ledger holding
/// exactly events `1..=n`, built in memory.
pub fn reference_digests(n: u64) -> (Hash, Hash) {
    let mut ledger = Ledger::open_in_memory(signer()).expect("in-memory ledger");
    seed(&mut ledger, n);
    let stream_digest = ledger.stream_digest(STREAM).expect("stream digest");
    let records = ledger.scan(STREAM, 1).expect("scan");
    (stream_digest, projection_digest(&records))
}
