//! The SQLite store: one file, append-only, WAL (ADR-004, ADR-006, ATOM-LED-001).
//!
//! `synchronous=FULL` means a commit is not reported until SQLite has fsynced it — which is
//! exactly what ATOM-VT-001 measures when it kills the process mid-flight. No external
//! database, cache or broker takes part in authoritative state (ADR-004): everything below
//! is one file plus its WAL.
//!
//! Append-only is enforced twice:
//!
//! * this API never issues an `UPDATE` or `DELETE` against either table;
//! * `BEFORE UPDATE` / `BEFORE DELETE` triggers `RAISE(ABORT, …)` when something else does.
//!
//! The triggers stop accidents and casual SQL, not an adversary — anyone with the file can
//! drop them, and ATOM-VT-006 does exactly that before every tamper. They are not the
//! integrity mechanism. The hash chain and the sealed checkpoints are: they make the damage
//! *detectable afterwards*, which is the property LED-001 actually asks for.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde_json::Value;

use crate::checkpoint::{Checkpoint, CheckpointSigner};
use crate::error::{Error, Result};
use crate::event::{Event, EventRecord};
use crate::hash::{domain_digest, payload_digest_bytes, Hash, HASH_LEN, STREAM_DIGEST_DOMAIN};
use crate::jcs::canonicalize;
use crate::verify::{StreamWalk, VerifyReport};

/// Columns of one stored event, in the order [`RawEvent::read`] expects them.
const EVENT_COLUMNS: &str = "seq, prev_hash, payload_digest, canonical_hash, ts, payload";

/// Columns of one stored checkpoint, in the order [`RawCheckpoint::read`] expects them.
const CHECKPOINT_COLUMNS: &str = "seq, head_hash, event_count, ts, digest, key_id, signature";

/// Tables, index and append-only triggers.
///
/// Applied on every open, and `IF NOT EXISTS` throughout: reopening an existing ledger — or
/// one whose triggers someone dropped — restores the guard rails without touching a row.
/// `STRICT` keeps SQLite's type affinity out of the way, so a hash column cannot quietly
/// start holding text.
const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS ledger_event (
    stream_id      TEXT    NOT NULL,
    seq            INTEGER NOT NULL,
    prev_hash      BLOB    NOT NULL,
    payload_digest BLOB    NOT NULL,
    canonical_hash BLOB    NOT NULL,
    ts             INTEGER NOT NULL,
    payload        BLOB    NOT NULL,
    PRIMARY KEY (stream_id, seq)
) STRICT;

CREATE INDEX IF NOT EXISTS ledger_event_canonical_hash
    ON ledger_event (canonical_hash);

CREATE TABLE IF NOT EXISTS ledger_checkpoint (
    stream_id   TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    head_hash   BLOB    NOT NULL,
    event_count INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    digest      BLOB    NOT NULL,
    key_id      TEXT    NOT NULL,
    signature   BLOB    NOT NULL,
    PRIMARY KEY (stream_id, seq)
) STRICT;

CREATE TRIGGER IF NOT EXISTS ledger_event_no_update
BEFORE UPDATE ON ledger_event BEGIN
    SELECT RAISE(ABORT, 'atom-ledger: ledger_event is append-only (ATOM-LED-001)');
END;

CREATE TRIGGER IF NOT EXISTS ledger_event_no_delete
BEFORE DELETE ON ledger_event BEGIN
    SELECT RAISE(ABORT, 'atom-ledger: ledger_event is append-only (ATOM-LED-001)');
END;

CREATE TRIGGER IF NOT EXISTS ledger_checkpoint_no_update
BEFORE UPDATE ON ledger_checkpoint BEGIN
    SELECT RAISE(ABORT, 'atom-ledger: ledger_checkpoint is append-only (ADR-021)');
END;

CREATE TRIGGER IF NOT EXISTS ledger_checkpoint_no_delete
BEFORE DELETE ON ledger_checkpoint BEGIN
    SELECT RAISE(ABORT, 'atom-ledger: ledger_checkpoint is append-only (ADR-021)');
END;
";

/// An authoritative event ledger: one SQLite database plus the key that seals its heads.
pub struct Ledger {
    conn: Connection,
    signer: Box<dyn CheckpointSigner>,
}

impl Ledger {
    /// Open, or create, the ledger at `path`.
    pub fn open(path: impl AsRef<Path>, signer: Box<dyn CheckpointSigner>) -> Result<Self> {
        let conn = Connection::open(path)?;
        // WAL so a reader never blocks the writer; FULL so a returned commit is on disk.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        Self::with_connection(conn, signer)
    }

    /// Open an ephemeral ledger. Handy for reference rebuilds — journalling does not apply
    /// to an in-memory database, so this makes no durability promise.
    pub fn open_in_memory(signer: Box<dyn CheckpointSigner>) -> Result<Self> {
        Self::with_connection(Connection::open_in_memory()?, signer)
    }

    fn with_connection(conn: Connection, signer: Box<dyn CheckpointSigner>) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn, signer })
    }

    /// Append one event and commit it before returning (ATOM-LED-001).
    ///
    /// `ts` is data, never a clock read: identities have to be reproducible.
    ///
    /// The sequence is assigned inside an `IMMEDIATE` transaction, so the head read and the
    /// insert cannot interleave with another writer. Two concurrent appends therefore cannot
    /// mint the same `seq` — one of them waits, then chains onto the other's event.
    pub fn append(&mut self, stream_id: &str, payload: &Value, ts: i64) -> Result<Event> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = append_in(&tx, stream_id, payload, ts)?;
        tx.commit()?;
        Ok(event)
    }

    /// Seal the current head of `stream_id` (ADR-021).
    ///
    /// Fails with [`Error::EmptyStream`] if there is nothing to seal, and with
    /// [`Error::AlreadySealed`] if the head already carries a seal: a second signature over
    /// the same head would add no evidence, and two seals disagreeing at one sequence is
    /// precisely the shape of [`Finding::Fork`](crate::Finding::Fork).
    pub fn checkpoint(&mut self, stream_id: &str, ts: i64) -> Result<Checkpoint> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let checkpoint = checkpoint_in(&tx, self.signer.as_ref(), stream_id, ts)?;
        tx.commit()?;
        Ok(checkpoint)
    }

    /// Run `work` as a single transaction: every event it appends commits together, or none
    /// of them does.
    ///
    /// This is the boundary ATOM-VT-001 kills the process inside. An `Err` — or a panic —
    /// rolls the whole thing back, so a reducer can never leave half a decision in the
    /// ledger.
    pub fn transaction<T>(
        &mut self,
        work: impl FnOnce(&mut LedgerTx<'_>) -> Result<T>,
    ) -> Result<T> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut scope = LedgerTx {
            tx,
            signer: self.signer.as_ref(),
        };
        let value = work(&mut scope)?;
        scope.tx.commit()?;
        Ok(value)
    }

    /// Read one event with its payload decoded, or `None` if the stream has no such
    /// sequence.
    pub fn read(&self, stream_id: &str, seq: u64) -> Result<Option<EventRecord>> {
        let sql =
            format!("SELECT {EVENT_COLUMNS} FROM ledger_event WHERE stream_id = ?1 AND seq = ?2");
        let raw = self
            .conn
            .query_row(
                &sql,
                params![stream_id, to_sql_int(seq, "sequence")?],
                RawEvent::read,
            )
            .optional()?;
        match raw {
            Some(raw) => Ok(Some(raw.decode(stream_id)?.into_record()?)),
            None => Ok(None),
        }
    }

    /// Read every event from `from_seq` (inclusive) to the head, in sequence order.
    ///
    /// This is the only input a projection is allowed to have (ATOM-INV-007): views are
    /// rebuilt from the ledger and never write back to it.
    pub fn scan(&self, stream_id: &str, from_seq: u64) -> Result<Vec<EventRecord>> {
        let sql = format!(
            "SELECT {EVENT_COLUMNS} FROM ledger_event
             WHERE stream_id = ?1 AND seq >= ?2 ORDER BY seq ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![stream_id, to_sql_int(from_seq, "sequence")?],
            RawEvent::read,
        )?;
        let mut records = Vec::new();
        for raw in rows {
            records.push(raw?.decode(stream_id)?.into_record()?);
        }
        Ok(records)
    }

    /// Every checkpoint held for `stream_id`, oldest first.
    pub fn checkpoints(&self, stream_id: &str) -> Result<Vec<Checkpoint>> {
        let sql = format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM ledger_checkpoint
             WHERE stream_id = ?1 ORDER BY seq ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![stream_id], RawCheckpoint::read)?;
        let mut checkpoints = Vec::new();
        for raw in rows {
            checkpoints.push(raw?.decode(stream_id)?);
        }
        Ok(checkpoints)
    }

    /// The rolling digest of a whole stream — the state digest of ATOM-VT-001.
    ///
    /// `H(stream_id)` folded over every stored identity in sequence order. It is a pure
    /// function of the chain, so two ledgers fed the same events agree on it, a crash that
    /// loses uncommitted events leaves it equal to the reference for what survived, and a
    /// rewritten chain diverges from it even though the rewrite is internally consistent.
    pub fn stream_digest(&self, stream_id: &str) -> Result<Hash> {
        let mut digest = domain_digest(STREAM_DIGEST_DOMAIN, stream_id.as_bytes());
        let mut stmt = self.conn.prepare(
            "SELECT canonical_hash FROM ledger_event WHERE stream_id = ?1 ORDER BY seq ASC",
        )?;
        let mut rows = stmt.query(params![stream_id])?;
        let mut folded = [0u8; HASH_LEN * 2];
        while let Some(row) = rows.next()? {
            let identity: Vec<u8> = row.get(0)?;
            folded[..HASH_LEN].copy_from_slice(digest.as_bytes());
            folded[HASH_LEN..].copy_from_slice(Hash::from_slice(&identity)?.as_bytes());
            digest = domain_digest(STREAM_DIGEST_DOMAIN, &folded);
        }
        Ok(digest)
    }

    /// Verify a stream against its own chain and the checkpoints this store holds
    /// (ATOM-VT-006).
    pub fn verify_stream(&self, stream_id: &str) -> Result<VerifyReport> {
        self.verify_stream_with(stream_id, &[])
    }

    /// Verify a stream, also weighing checkpoints held elsewhere: a replica, a witness, an
    /// offline seal.
    ///
    /// A store cannot expose its own wholesale rewrite — the rewrite reseals itself and
    /// every local check passes. Only a seal from outside can, which is why this entry point
    /// exists next to [`Self::verify_stream`].
    pub fn verify_stream_with(
        &self,
        stream_id: &str,
        external: &[Checkpoint],
    ) -> Result<VerifyReport> {
        let mut walk = StreamWalk::start();
        {
            let sql = format!(
                "SELECT {EVENT_COLUMNS} FROM ledger_event WHERE stream_id = ?1 ORDER BY seq ASC"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query(params![stream_id])?;
            while let Some(row) = rows.next()? {
                let stored = RawEvent::read(row)?.decode(stream_id)?;
                walk.visit(&stored.event, &stored.payload);
            }
        }

        // Seals are judged after the walk: a checkpoint speaks about the whole stream.
        let local = self.checkpoints(stream_id)?;
        for checkpoint in local.iter().chain(external) {
            if checkpoint.stream_id != stream_id {
                continue;
            }
            let at_seq = canonical_hash_at(&self.conn, stream_id, checkpoint.seq)?;
            walk.seal(checkpoint, self.signer.as_ref(), at_seq);
        }
        Ok(walk.finish(stream_id))
    }
}

/// A batch of appends that commit together.
///
/// Dropping this without committing rolls the batch back, which is what makes an `Err` or a
/// panic inside [`Ledger::transaction`] leave the ledger untouched.
pub struct LedgerTx<'a> {
    tx: Transaction<'a>,
    signer: &'a dyn CheckpointSigner,
}

impl LedgerTx<'_> {
    /// Append one event inside the transaction. It chains onto whatever this transaction has
    /// already appended.
    pub fn append(&mut self, stream_id: &str, payload: &Value, ts: i64) -> Result<Event> {
        append_in(&self.tx, stream_id, payload, ts)
    }

    /// Seal the head the transaction has reached, committing seal and events together.
    pub fn checkpoint(&mut self, stream_id: &str, ts: i64) -> Result<Checkpoint> {
        checkpoint_in(&self.tx, self.signer, stream_id, ts)
    }
}

/// Insert one event, chained onto the current head of its stream.
fn append_in(conn: &Connection, stream_id: &str, payload: &Value, ts: i64) -> Result<Event> {
    let canonical_payload = canonicalize(payload)?;
    let payload_digest = payload_digest_bytes(&canonical_payload);
    let (head_seq, prev_hash) = head_of(conn, stream_id)?;
    let seq = head_seq + 1;
    let canonical_hash =
        Event::compute_canonical_hash(seq, stream_id, &prev_hash, &payload_digest, ts);
    conn.execute(
        "INSERT INTO ledger_event
             (stream_id, seq, prev_hash, payload_digest, canonical_hash, ts, payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            stream_id,
            to_sql_int(seq, "sequence")?,
            prev_hash.as_bytes(),
            payload_digest.as_bytes(),
            canonical_hash.as_bytes(),
            ts,
            canonical_payload,
        ],
    )?;
    Ok(Event {
        seq,
        stream_id: stream_id.to_owned(),
        prev_hash,
        payload_digest,
        canonical_hash,
        ts,
    })
}

/// Seal the current head of a stream.
fn checkpoint_in(
    conn: &Connection,
    signer: &dyn CheckpointSigner,
    stream_id: &str,
    ts: i64,
) -> Result<Checkpoint> {
    let (head_seq, head_hash) = head_of(conn, stream_id)?;
    if head_seq == 0 {
        return Err(Error::EmptyStream {
            stream_id: stream_id.to_owned(),
        });
    }
    if let Some(sealed_seq) = latest_seal(conn, stream_id)? {
        if sealed_seq >= head_seq {
            return Err(Error::AlreadySealed {
                stream_id: stream_id.to_owned(),
                seq: sealed_seq,
            });
        }
    }
    let event_count = count_events(conn, stream_id)?;
    let digest = Checkpoint::compute_digest(stream_id, head_seq, &head_hash, event_count, ts);
    let signature = signer.sign(&digest);
    conn.execute(
        "INSERT INTO ledger_checkpoint
             (stream_id, seq, head_hash, event_count, ts, digest, key_id, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            stream_id,
            to_sql_int(head_seq, "sequence")?,
            head_hash.as_bytes(),
            to_sql_int(event_count, "event count")?,
            ts,
            digest.as_bytes(),
            signer.key_id(),
            signature,
        ],
    )?;
    Ok(Checkpoint {
        stream_id: stream_id.to_owned(),
        seq: head_seq,
        head_hash,
        event_count,
        ts,
        digest,
        key_id: signer.key_id().to_owned(),
        signature,
    })
}

/// `(seq, canonical_hash)` of the stream head, or `(0, GENESIS)` when the stream is empty.
fn head_of(conn: &Connection, stream_id: &str) -> Result<(u64, Hash)> {
    let head: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT seq, canonical_hash FROM ledger_event
             WHERE stream_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![stream_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match head {
        Some((seq, identity)) => Ok((from_sql_int(seq, "sequence")?, Hash::from_slice(&identity)?)),
        None => Ok((0, Hash::GENESIS)),
    }
}

/// How many events the stream holds. Sealed into every checkpoint.
fn count_events(conn: &Connection, stream_id: &str) -> Result<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM ledger_event WHERE stream_id = ?1",
        params![stream_id],
        |row| row.get(0),
    )?;
    from_sql_int(count, "event count")
}

/// Sequence of the newest seal on the stream, if it has one.
fn latest_seal(conn: &Connection, stream_id: &str) -> Result<Option<u64>> {
    let sealed: Option<i64> = conn.query_row(
        "SELECT MAX(seq) FROM ledger_checkpoint WHERE stream_id = ?1",
        params![stream_id],
        |row| row.get(0),
    )?;
    sealed
        .map(|seq| from_sql_int(seq, "checkpoint sequence"))
        .transpose()
}

/// The identity the stream stores at `seq`, if it holds that event at all.
fn canonical_hash_at(conn: &Connection, stream_id: &str, seq: u64) -> Result<Option<Hash>> {
    let identity: Option<Vec<u8>> = conn
        .query_row(
            "SELECT canonical_hash FROM ledger_event WHERE stream_id = ?1 AND seq = ?2",
            params![stream_id, to_sql_int(seq, "sequence")?],
            |row| row.get(0),
        )
        .optional()?;
    identity
        .map(|identity| Hash::from_slice(&identity))
        .transpose()
}

/// SQLite integers are signed, ATOM sequences and counts are not. Both directions are
/// explicit so an out-of-range value becomes an error instead of a silent wrap.
fn to_sql_int(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::MalformedRow {
        detail: format!("{what} {value} exceeds the range SQLite can store"),
    })
}

fn from_sql_int(value: i64, what: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::MalformedRow {
        detail: format!("{what} is negative: {value}"),
    })
}

/// One `ledger_event` row exactly as SQLite handed it over: nothing decoded, nothing
/// recomputed. Verification depends on that — a repaired read cannot detect tampering.
struct RawEvent {
    seq: i64,
    prev_hash: Vec<u8>,
    payload_digest: Vec<u8>,
    canonical_hash: Vec<u8>,
    ts: i64,
    payload: Vec<u8>,
}

impl RawEvent {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            seq: row.get(0)?,
            prev_hash: row.get(1)?,
            payload_digest: row.get(2)?,
            canonical_hash: row.get(3)?,
            ts: row.get(4)?,
            payload: row.get(5)?,
        })
    }

    /// `stream_id` comes from the query rather than the row: every read is scoped to one
    /// stream, and the column would just be that same value repeated.
    fn decode(self, stream_id: &str) -> Result<StoredEvent> {
        Ok(StoredEvent {
            event: Event {
                seq: from_sql_int(self.seq, "sequence")?,
                stream_id: stream_id.to_owned(),
                prev_hash: Hash::from_slice(&self.prev_hash)?,
                payload_digest: Hash::from_slice(&self.payload_digest)?,
                canonical_hash: Hash::from_slice(&self.canonical_hash)?,
                ts: self.ts,
            },
            payload: self.payload,
        })
    }
}

/// A stored event with its canonical payload bytes still in byte form.
struct StoredEvent {
    event: Event,
    payload: Vec<u8>,
}

impl StoredEvent {
    /// Decode the payload for a caller. Verification never takes this path: it hashes the
    /// bytes, which must work even for bytes that no longer parse as JSON.
    fn into_record(self) -> Result<EventRecord> {
        Ok(EventRecord {
            event: self.event,
            payload: serde_json::from_slice(&self.payload)?,
        })
    }
}

/// One `ledger_checkpoint` row, undecoded.
struct RawCheckpoint {
    seq: i64,
    head_hash: Vec<u8>,
    event_count: i64,
    ts: i64,
    digest: Vec<u8>,
    key_id: String,
    signature: Vec<u8>,
}

impl RawCheckpoint {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            seq: row.get(0)?,
            head_hash: row.get(1)?,
            event_count: row.get(2)?,
            ts: row.get(3)?,
            digest: row.get(4)?,
            key_id: row.get(5)?,
            signature: row.get(6)?,
        })
    }

    fn decode(self, stream_id: &str) -> Result<Checkpoint> {
        Ok(Checkpoint {
            stream_id: stream_id.to_owned(),
            seq: from_sql_int(self.seq, "checkpoint sequence")?,
            head_hash: Hash::from_slice(&self.head_hash)?,
            event_count: from_sql_int(self.event_count, "event count")?,
            ts: self.ts,
            digest: Hash::from_slice(&self.digest)?,
            key_id: self.key_id,
            signature: self.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::HmacSha256Signer;
    use serde_json::json;

    fn ledger() -> Ledger {
        Ledger::open_in_memory(Box::new(HmacSha256Signer::new("k1", b"unit-test-key")))
            .expect("open in-memory ledger")
    }

    #[test]
    fn appends_are_numbered_from_one_and_chained() {
        let mut ledger = ledger();
        let first = ledger.append("s", &json!({"n": 1}), 10).unwrap();
        let second = ledger.append("s", &json!({"n": 2}), 20).unwrap();

        assert_eq!((first.seq, second.seq), (1, 2));
        assert!(first.prev_hash.is_genesis());
        assert_eq!(second.prev_hash, first.canonical_hash);
        assert_eq!(second.canonical_hash, second.recompute_canonical_hash());
        assert!(ledger.verify_stream("s").unwrap().is_intact());
    }

    #[test]
    fn each_stream_has_its_own_chain() {
        let mut ledger = ledger();
        ledger.append("a", &json!(1), 1).unwrap();
        let other = ledger.append("b", &json!(1), 1).unwrap();

        assert_eq!(other.seq, 1);
        assert!(other.prev_hash.is_genesis());
        assert_ne!(
            ledger.stream_digest("a").unwrap(),
            ledger.stream_digest("b").unwrap(),
            "the digest binds the stream it belongs to"
        );
    }

    #[test]
    fn a_failed_transaction_appends_nothing() {
        let mut ledger = ledger();
        ledger.append("s", &json!(1), 1).unwrap();

        let outcome: Result<()> = ledger.transaction(|tx| {
            tx.append("s", &json!(2), 2)?;
            tx.append("s", &json!(3), 3)?;
            Err(Error::MalformedRow {
                detail: "forced rollback".to_owned(),
            })
        });

        assert!(outcome.is_err());
        assert_eq!(ledger.scan("s", 1).unwrap().len(), 1, "all or nothing");
        assert_eq!(ledger.verify_stream("s").unwrap().head_seq, 1);
    }

    #[test]
    fn a_committed_transaction_appends_everything_and_can_seal() {
        let mut ledger = ledger();
        let sealed = ledger
            .transaction(|tx| {
                for i in 1..=3i64 {
                    tx.append("s", &json!({"n": i}), i)?;
                }
                tx.checkpoint("s", 99)
            })
            .unwrap();

        let report = ledger.verify_stream("s").unwrap();
        assert!(report.is_intact(), "{report:#?}");
        assert_eq!(report.head_seq, 3);
        assert_eq!(report.events_verified, 3);
        assert_eq!(report.checkpoints_verified, 1);
        assert_eq!((sealed.seq, sealed.event_count), (3, 3));
        assert_eq!(sealed.head_hash, report.head_hash);
    }

    #[test]
    fn sealing_needs_events_and_refuses_to_reseal_one_head() {
        let mut ledger = ledger();
        assert!(matches!(
            ledger.checkpoint("s", 1),
            Err(Error::EmptyStream { .. })
        ));

        ledger.append("s", &json!(1), 1).unwrap();
        ledger.checkpoint("s", 2).unwrap();
        assert!(matches!(
            ledger.checkpoint("s", 3),
            Err(Error::AlreadySealed { seq: 1, .. })
        ));

        ledger.append("s", &json!(2), 3).unwrap();
        assert_eq!(ledger.checkpoint("s", 4).unwrap().seq, 2);
        assert_eq!(ledger.checkpoints("s").unwrap().len(), 2);
    }

    #[test]
    fn reads_return_the_stored_payload() {
        let mut ledger = ledger();
        let payload = json!({"b": [1, 2], "a": "x"});
        let appended = ledger.append("s", &payload, 7).unwrap();

        let record = ledger.read("s", 1).unwrap().expect("event 1");
        assert_eq!(record.event, appended);
        assert_eq!(record.payload, payload);
        assert!(ledger.read("s", 2).unwrap().is_none());
        assert!(ledger.read("other", 1).unwrap().is_none());

        ledger.append("s", &json!(2), 8).unwrap();
        let tail = ledger.scan("s", 2).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event.seq, 2);
    }
    #[test]
    fn the_stream_digest_is_a_pure_function_of_the_chain() {
        let payloads = [json!({"n": 1}), json!({"n": 2})];
        let digest_of = |count: usize| {
            let mut ledger = ledger();
            for (index, payload) in payloads.iter().take(count).enumerate() {
                ledger
                    .append("s", payload, 100 + i64::try_from(index).unwrap())
                    .expect("append");
            }
            ledger.stream_digest("s").expect("digest")
        };

        assert_eq!(digest_of(2), digest_of(2), "same events, same digest");
        assert_ne!(digest_of(1), digest_of(2), "every event moves it");
        assert_ne!(
            digest_of(0),
            Hash::GENESIS,
            "an empty stream still has an identity"
        );
    }

    #[test]
    fn the_triggers_refuse_updates_and_deletes() {
        let mut ledger = ledger();
        ledger.append("s", &json!(1), 1).unwrap();
        ledger.checkpoint("s", 2).unwrap();

        for statement in [
            "UPDATE ledger_event SET ts = 0",
            "DELETE FROM ledger_event",
            "UPDATE ledger_checkpoint SET seq = 99",
            "DELETE FROM ledger_checkpoint",
        ] {
            assert!(
                ledger.conn.execute(statement, []).is_err(),
                "append-only violated by: {statement}"
            );
        }
        assert!(ledger.verify_stream("s").unwrap().is_intact());
    }
}
