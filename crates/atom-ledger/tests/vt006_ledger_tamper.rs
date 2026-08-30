//! ATOM-VT-006 — Ledger tamper (`spec/acceptance/catalog.yaml`).
//!
//! Scenario: delete / reorder / edit an event before checkpoint verify.
//! Pass: verification detects corruption, truncation and fork.
//!
//! Tampering is done with raw SQL against the SQLite file, i.e. an attacker who already
//! has write access to the authoritative store. The append-only triggers are dropped
//! first, exactly as such an attacker would: they are a speed bump, the hash chain plus
//! sealed checkpoints (LED-001) are the actual integrity mechanism.

mod support;

use std::path::Path;

use atom_ledger::{payload_digest, Checkpoint, Event, Finding, Hash, Ledger, VerifyReport};
use rusqlite::Connection;
use serde_json::{json, Value};
use support::{payload, seed, signer, ts, STREAM};

/// Seed a fresh on-disk ledger with events `1..=n`, optionally sealing the head, and
/// close it before the attacker touches the file.
fn seeded(db: &Path, n: u64, checkpoint: bool) -> (Vec<Event>, Option<Checkpoint>) {
    let mut ledger = Ledger::open(db, signer()).expect("open ledger");
    seed(&mut ledger, n);
    let sealed = if checkpoint {
        Some(
            ledger
                .checkpoint(STREAM, ts(n) + 500)
                .expect("checkpoint head"),
        )
    } else {
        None
    };
    let events = ledger
        .scan(STREAM, 1)
        .expect("scan")
        .into_iter()
        .map(|record| record.event)
        .collect();
    (events, sealed)
}

/// Give the attacker raw SQL access, append-only triggers removed.
fn tamper(db: &Path, mutate: impl FnOnce(&Connection)) {
    let conn = Connection::open(db).expect("open raw sqlite");
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS ledger_event_no_update;
         DROP TRIGGER IF EXISTS ledger_event_no_delete;
         DROP TRIGGER IF EXISTS ledger_checkpoint_no_update;
         DROP TRIGGER IF EXISTS ledger_checkpoint_no_delete;",
    )
    .expect("drop append-only triggers");
    mutate(&conn);
}

fn verify(db: &Path) -> VerifyReport {
    Ledger::open(db, signer())
        .expect("reopen tampered ledger")
        .verify_stream(STREAM)
        .expect("verify stream")
}

#[track_caller]
fn assert_detects(report: &VerifyReport, what: &str, pred: impl Fn(&Finding) -> bool) {
    assert!(
        !report.is_intact(),
        "tamper undetected ({what}): {report:#?}"
    );
    assert!(
        report.findings.iter().any(pred),
        "missing {what} finding: {report:#?}"
    );
}

/// Control: an untouched stream verifies clean, including its checkpoint.
#[test]
fn vt006_untampered_stream_verifies_intact() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let (events, sealed) = seeded(&db, 5, true);
    assert_eq!(events.len(), 5);
    let sealed = sealed.expect("checkpoint");
    assert_eq!(sealed.seq, 5);
    assert_eq!(sealed.head_hash, events[4].canonical_hash);

    let report = verify(&db);
    assert!(report.is_intact(), "{report:#?}");
    assert_eq!(report.events_verified, 5);
    assert_eq!(report.checkpoints_verified, 1);
    assert_eq!(report.head_seq, 5);
}

/// The store itself refuses in-place edits and deletes while its triggers stand.
#[test]
fn vt006_append_only_triggers_reject_update_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 3, true);

    let conn = Connection::open(&db).unwrap();
    let update = conn.execute("UPDATE ledger_event SET ts = ts + 1 WHERE seq = 2", []);
    assert!(update.is_err(), "UPDATE must be rejected: {update:?}");
    let delete = conn.execute("DELETE FROM ledger_event WHERE seq = 2", []);
    assert!(delete.is_err(), "DELETE must be rejected: {delete:?}");
    let cp_update = conn.execute("UPDATE ledger_checkpoint SET seq = 99", []);
    assert!(cp_update.is_err(), "checkpoint UPDATE must be rejected");
    drop(conn);

    assert!(verify(&db).is_intact());
}

/// Delete: a hole in the sequence is detected.
#[test]
fn vt006_deleted_event_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, true);
    tamper(&db, |conn| {
        conn.execute("DELETE FROM ledger_event WHERE seq = 3", [])
            .expect("delete event 3");
    });

    let report = verify(&db);
    assert_detects(&report, "delete", |f| {
        matches!(
            f,
            Finding::MissingEvent {
                expected_seq: 3,
                found_seq: 4,
                ..
            }
        )
    });
}

/// Reorder: swapping two sequence numbers breaks the canonical hash, which binds `seq`.
#[test]
fn vt006_reordered_events_are_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, true);
    tamper(&db, |conn| {
        conn.execute_batch(
            "UPDATE ledger_event SET seq = 99 WHERE seq = 2;
             UPDATE ledger_event SET seq = 2  WHERE seq = 3;
             UPDATE ledger_event SET seq = 3  WHERE seq = 99;",
        )
        .expect("swap seq 2 and 3");
    });

    let report = verify(&db);
    assert_detects(&report, "reorder", |f| {
        matches!(f, Finding::CanonicalHashMismatch { seq: 2, .. })
    });
}

/// Bit-flip inside a stored payload: caught by the payload digest.
#[test]
fn vt006_payload_bitflip_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, true);
    tamper(&db, |conn| {
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM ledger_event WHERE seq = 4",
                [],
                |row| row.get(0),
            )
            .expect("read payload");
        blob[10] ^= 0x01;
        conn.execute(
            "UPDATE ledger_event SET payload = ?1 WHERE seq = 4",
            rusqlite::params![blob],
        )
        .expect("flip payload bit");
    });

    let report = verify(&db);
    assert_detects(&report, "payload bit-flip", |f| {
        matches!(f, Finding::PayloadDigestMismatch { seq: 4, .. })
    });
}

/// Edit: a semantically meaningful rewrite of a payload, left canonical, is caught.
#[test]
fn vt006_edited_event_payload_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, true);
    tamper(&db, |conn| {
        let forged: Value = json!({
            "kind": "MISSION_PHASE_CHANGED",
            "index": 2,
            "phase": "TERMINAL",
            "condition": "NORMAL",
        });
        let bytes = atom_ledger::canonicalize(&forged).expect("canonicalize");
        conn.execute(
            "UPDATE ledger_event SET payload = ?1 WHERE seq = 2",
            rusqlite::params![bytes],
        )
        .expect("rewrite payload");
    });

    let report = verify(&db);
    assert_detects(&report, "payload edit", |f| {
        matches!(f, Finding::PayloadDigestMismatch { seq: 2, .. })
    });
}

/// Bit-flip in a chain link: the previous-event hash is inside the hashed identity.
#[test]
fn vt006_prev_hash_bitflip_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, false);
    tamper(&db, |conn| {
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT prev_hash FROM ledger_event WHERE seq = 3",
                [],
                |row| row.get(0),
            )
            .expect("read prev_hash");
        blob[0] ^= 0x80;
        conn.execute(
            "UPDATE ledger_event SET prev_hash = ?1 WHERE seq = 3",
            rusqlite::params![blob],
        )
        .expect("flip prev_hash bit");
    });

    let report = verify(&db);
    assert_detects(&report, "prev_hash bit-flip", |f| {
        matches!(f, Finding::ChainBreak { seq: 3, .. })
    });
    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f, Finding::CanonicalHashMismatch { seq: 3, .. })));
}

/// Timestamps are hashed content: editing one invalidates the canonical hash.
#[test]
fn vt006_timestamp_edit_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 4, false);
    tamper(&db, |conn| {
        conn.execute("UPDATE ledger_event SET ts = ts - 60000 WHERE seq = 2", [])
            .expect("rewrite ts");
    });

    let report = verify(&db);
    assert_detects(&report, "timestamp edit", |f| {
        matches!(f, Finding::CanonicalHashMismatch { seq: 2, .. })
    });
}

/// A forged event that is internally well-formed but does not chain to the head.
#[test]
fn vt006_forged_event_with_wrong_prev_hash_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let (events, _) = seeded(&db, 3, false);
    let forged_payload = json!({"kind": "FORGED", "index": 4});
    let digest = payload_digest(&forged_payload).unwrap();
    let forged_ts = ts(4);
    // Chains to genesis instead of event 3, but its own canonical hash is correct.
    let canonical = Event::compute_canonical_hash(4, STREAM, &Hash::GENESIS, &digest, forged_ts);
    assert_ne!(events[2].canonical_hash, Hash::GENESIS);
    tamper(&db, |conn| {
        conn.execute(
            "INSERT INTO ledger_event
               (stream_id, seq, prev_hash, payload_digest, canonical_hash, ts, payload)
             VALUES (?1, 4, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                STREAM,
                Hash::GENESIS.as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
                canonical.as_bytes().to_vec(),
                forged_ts,
                atom_ledger::canonicalize(&forged_payload).unwrap(),
            ],
        )
        .expect("insert forged event");
    });

    let report = verify(&db);
    assert_detects(&report, "forged event", |f| {
        matches!(f, Finding::ChainBreak { seq: 4, .. })
    });
}

/// Truncation: the sealed head is gone.
#[test]
fn vt006_truncation_after_checkpoint_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, true);
    tamper(&db, |conn| {
        conn.execute("DELETE FROM ledger_event WHERE seq = 5", [])
            .expect("truncate head");
    });

    let report = verify(&db);
    assert_detects(&report, "truncation", |f| {
        matches!(
            f,
            Finding::Truncated {
                checkpoint_seq: 5,
                head_seq: 4,
                ..
            }
        )
    });
}

/// Truncation to nothing is still detected, because the checkpoint remembers the head.
#[test]
fn vt006_full_truncation_after_checkpoint_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 5, true);
    tamper(&db, |conn| {
        conn.execute("DELETE FROM ledger_event", [])
            .expect("delete all events");
    });

    let report = verify(&db);
    assert_eq!(report.head_seq, 0);
    assert_detects(&report, "full truncation", |f| {
        matches!(
            f,
            Finding::Truncated {
                checkpoint_seq: 5,
                head_seq: 0,
                ..
            }
        )
    });
}

/// A gap left at the tail (events silently dropped mid-stream) is detected.
#[test]
fn vt006_sequence_gap_at_tail_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let (events, _) = seeded(&db, 3, false);
    let head = events[2].canonical_hash;
    let forged_payload = json!({"kind": "GAP", "index": 6});
    let digest = payload_digest(&forged_payload).unwrap();
    let forged_ts = ts(6);
    let canonical = Event::compute_canonical_hash(6, STREAM, &head, &digest, forged_ts);
    tamper(&db, |conn| {
        conn.execute(
            "INSERT INTO ledger_event
               (stream_id, seq, prev_hash, payload_digest, canonical_hash, ts, payload)
             VALUES (?1, 6, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                STREAM,
                head.as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
                canonical.as_bytes().to_vec(),
                forged_ts,
                atom_ledger::canonicalize(&forged_payload).unwrap(),
            ],
        )
        .expect("insert event past the gap");
    });

    let report = verify(&db);
    assert_detects(&report, "sequence gap", |f| {
        matches!(
            f,
            Finding::MissingEvent {
                expected_seq: 4,
                found_seq: 6,
                ..
            }
        )
    });
}

/// Rewrite events `from..=head` so the chain is internally consistent again — the
/// strongest tamper an attacker with SQL access can mount without the seal key.
fn rewrite_chain_from(conn: &Connection, events: &[Event], from: u64) {
    assert!(from >= 2, "need a preceding event to chain from");
    let mut prev = events[(from - 2) as usize].canonical_hash;
    for event in events.iter().filter(|event| event.seq >= from) {
        let forged = if event.seq == from {
            json!({
                "kind": "MISSION_PHASE_CHANGED",
                "index": event.seq,
                "phase": "TERMINAL",
                "condition": "NORMAL",
            })
        } else {
            payload(event.seq)
        };
        let bytes = atom_ledger::canonicalize(&forged).unwrap();
        let digest = payload_digest(&forged).unwrap();
        let canonical = Event::compute_canonical_hash(event.seq, STREAM, &prev, &digest, event.ts);
        conn.execute(
            "UPDATE ledger_event
                SET prev_hash = ?1, payload_digest = ?2, canonical_hash = ?3, payload = ?4
              WHERE stream_id = ?5 AND seq = ?6",
            rusqlite::params![
                prev.as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
                canonical.as_bytes().to_vec(),
                bytes,
                STREAM,
                event.seq,
            ],
        )
        .expect("rewrite event");
        prev = canonical;
    }
}

/// Fork: a fully recomputed chain diverges from the sealed head.
#[test]
fn vt006_rewritten_chain_is_detected_by_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let (events, sealed) = seeded(&db, 5, true);
    let sealed = sealed.expect("checkpoint");
    tamper(&db, |conn| rewrite_chain_from(conn, &events, 3));

    let report = verify(&db);
    // The rewritten chain is self-consistent: no per-event finding fires.
    assert!(
        !report.findings.iter().any(|f| matches!(
            f,
            Finding::ChainBreak { .. }
                | Finding::CanonicalHashMismatch { .. }
                | Finding::PayloadDigestMismatch { .. }
                | Finding::MissingEvent { .. }
        )),
        "rewrite should be internally consistent: {report:#?}"
    );
    // The seal is what catches it.
    assert_detects(&report, "fork", |f| {
        matches!(f, Finding::Fork { seq: 5, .. })
    });
    assert_ne!(report.head_hash, sealed.head_hash);
}

/// Why LED-001 mandates checkpoints: without a sealed head, a full rewrite is
/// internally consistent and only an externally held digest can expose it.
#[test]
fn vt006_rewritten_chain_without_a_seal_needs_an_external_digest() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let (events, _) = seeded(&db, 5, false);
    let before = Ledger::open(&db, signer())
        .unwrap()
        .stream_digest(STREAM)
        .unwrap();

    tamper(&db, |conn| rewrite_chain_from(conn, &events, 3));

    let ledger = Ledger::open(&db, signer()).unwrap();
    let report = ledger.verify_stream(STREAM).unwrap();
    assert!(
        report.is_intact(),
        "an unsealed chain rewrite is internally consistent by construction: {report:#?}"
    );
    assert_ne!(
        ledger.stream_digest(STREAM).unwrap(),
        before,
        "the stream digest must still diverge — that digest is what a checkpoint seals"
    );
}

/// Editing what a checkpoint sealed invalidates the checkpoint digest.
#[test]
fn vt006_checkpoint_head_hash_tamper_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 4, true);
    tamper(&db, |conn| {
        conn.execute(
            "UPDATE ledger_checkpoint SET head_hash = ?1",
            rusqlite::params![Hash::GENESIS.as_bytes().to_vec()],
        )
        .expect("rewrite sealed head");
    });

    let report = verify(&db);
    assert_detects(&report, "checkpoint head tamper", |f| {
        matches!(f, Finding::CheckpointDigestMismatch { seq: 4, .. })
    });
}

/// A tampered seal fails signature verification.
#[test]
fn vt006_checkpoint_signature_tamper_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    seeded(&db, 4, true);
    tamper(&db, |conn| {
        let mut signature: Vec<u8> = conn
            .query_row("SELECT signature FROM ledger_checkpoint", [], |row| {
                row.get(0)
            })
            .expect("read signature");
        signature[3] ^= 0x40;
        conn.execute(
            "UPDATE ledger_checkpoint SET signature = ?1",
            rusqlite::params![signature],
        )
        .expect("flip signature bit");
    });

    let report = verify(&db);
    assert_detects(&report, "checkpoint signature tamper", |f| {
        matches!(f, Finding::CheckpointSignatureInvalid { seq: 4, .. })
    });
}

/// The seal key is the boundary: an attacker can rewrite the chain and re-derive a
/// consistent checkpoint digest, but cannot produce a valid signature over it.
#[test]
fn vt006_reseal_without_the_key_fails_signature_verification() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let (events, sealed) = seeded(&db, 5, true);
    let sealed = sealed.expect("checkpoint");
    tamper(&db, |conn| {
        rewrite_chain_from(conn, &events, 3);
        let head: Vec<u8> = conn
            .query_row(
                "SELECT canonical_hash FROM ledger_event WHERE seq = 5",
                [],
                |row| row.get(0),
            )
            .expect("read rewritten head");
        let head = Hash::from_slice(&head).expect("32-byte hash");
        let digest =
            Checkpoint::compute_digest(STREAM, sealed.seq, &head, sealed.event_count, sealed.ts);
        conn.execute(
            "UPDATE ledger_checkpoint SET head_hash = ?1, digest = ?2 WHERE seq = ?3",
            rusqlite::params![
                head.as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
                sealed.seq
            ],
        )
        .expect("reseal without the key");
    });

    let report = verify(&db);
    assert_detects(&report, "unsigned reseal", |f| {
        matches!(f, Finding::CheckpointSignatureInvalid { seq: 5, .. })
    });
}

/// Two stores share a prefix and then diverge at seq 4.
fn branched(db: &Path, branch: &str) -> Checkpoint {
    let mut ledger = Ledger::open(db, signer()).expect("open ledger");
    seed(&mut ledger, 3);
    ledger
        .append(
            STREAM,
            &json!({"kind": "REPLICA_DIVERGENCE", "branch": branch}),
            ts(4),
        )
        .expect("append divergent event");
    ledger.checkpoint(STREAM, ts(4) + 500).expect("checkpoint")
}

/// Fork across instances: verifying against a checkpoint held elsewhere (replica,
/// witness, offline seal) exposes the divergence.
#[test]
fn vt006_replica_fork_is_detected_against_an_external_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let db_a = dir.path().join("a.db");
    let db_b = dir.path().join("b.db");
    let checkpoint_a = branched(&db_a, "a");
    let checkpoint_b = branched(&db_b, "b");
    assert_eq!(checkpoint_a.seq, checkpoint_b.seq);
    assert_ne!(checkpoint_a.head_hash, checkpoint_b.head_hash);

    let ledger_b = Ledger::open(&db_b, signer()).unwrap();
    let report = ledger_b
        .verify_stream_with(STREAM, std::slice::from_ref(&checkpoint_a))
        .unwrap();
    assert_detects(&report, "replica fork", |f| {
        matches!(f, Finding::Fork { seq: 4, .. })
    });
    assert!(
        ledger_b.verify_stream(STREAM).unwrap().is_intact(),
        "each branch is internally consistent on its own"
    );
}

/// A witness that sealed more events than the local store holds proves truncation.
#[test]
fn vt006_external_checkpoint_beyond_local_head_is_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let witness_db = dir.path().join("witness.db");
    let local_db = dir.path().join("local.db");

    let witness_checkpoint = {
        let mut witness = Ledger::open(&witness_db, signer()).unwrap();
        seed(&mut witness, 6);
        witness.checkpoint(STREAM, ts(6) + 500).unwrap()
    };
    let mut local = Ledger::open(&local_db, signer()).unwrap();
    seed(&mut local, 3);

    let report = local
        .verify_stream_with(STREAM, std::slice::from_ref(&witness_checkpoint))
        .unwrap();
    assert_detects(&report, "external truncation", |f| {
        matches!(
            f,
            Finding::Truncated {
                checkpoint_seq: 6,
                head_seq: 3,
                ..
            }
        )
    });
}
