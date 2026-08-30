//! ATOM-VT-001 — Crash-safe authoritative state (`spec/acceptance/catalog.yaml`).
//!
//! Scenario: kill the process at every reducer/append boundary.
//! Pass: the recovered state digest is identical and no committed event is lost.
//!
//! The kill is a real `SIGABRT` of a real child process (`std::process::abort`), which
//! runs no destructors and flushes nothing, so only data SQLite already committed and
//! fsynced can survive. Boundaries covered:
//!   * after each committed append (`k = 0..=5`),
//!   * inside a multi-event reducer transaction, before commit,
//!   * after a checkpoint seals the stream head.

mod support;

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use atom_ledger::{Hash, Ledger};
use support::{payload, projection_digest, reference_digests, seed, signer, ts, STREAM};

/// Env var carrying the crash spec to the child process.
const CHILD_ENV: &str = "ATOM_LEDGER_VT001_CHILD";
/// Name of the test function the child process re-executes.
const CHILD_TEST: &str = "vt001_crash_child_worker";

#[derive(Debug, Clone)]
struct CrashSpec {
    db: PathBuf,
    log: PathBuf,
    mode: String,
    /// Number of events committed one-per-transaction before the crash.
    k: u64,
    /// Number of events written inside an uncommitted transaction.
    m: u64,
}

impl CrashSpec {
    fn encode(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.db.display(),
            self.log.display(),
            self.mode,
            self.k,
            self.m
        )
    }

    fn decode(raw: &str) -> Self {
        let parts: Vec<&str> = raw.split('|').collect();
        assert_eq!(parts.len(), 5, "malformed crash spec: {raw}");
        Self {
            db: PathBuf::from(parts[0]),
            log: PathBuf::from(parts[1]),
            mode: parts[2].to_owned(),
            k: parts[3].parse().expect("k"),
            m: parts[4].parse().expect("m"),
        }
    }
}

/// Child side of the crash matrix. A no-op unless `CHILD_ENV` is set, so it stays
/// harmless when the suite runs normally.
#[test]
fn vt001_crash_child_worker() {
    let Ok(raw) = std::env::var(CHILD_ENV) else {
        return;
    };
    let spec = CrashSpec::decode(&raw);
    let mut ledger = Ledger::open(&spec.db, signer()).expect("open ledger");

    // Each append is its own committed transaction; only fsynced commits are logged.
    for i in 1..=spec.k {
        let event = ledger.append(STREAM, &payload(i), ts(i)).expect("append");
        record_commit(&spec.log, event.seq, &event.canonical_hash);
    }

    match spec.mode.as_str() {
        "after_appends" => {}
        "after_checkpoint" => {
            ledger
                .checkpoint(STREAM, ts(spec.k) + 1)
                .expect("checkpoint");
        }
        "mid_tx" => {
            // Crash *inside* a reducer boundary: m events written, transaction never
            // committed. Nothing from this transaction may survive recovery.
            let outcome: atom_ledger::Result<()> = ledger.transaction(|tx| {
                for i in spec.k + 1..=spec.k + spec.m {
                    tx.append(STREAM, &payload(i), ts(i))?;
                }
                std::process::abort();
            });
            let _ = outcome;
        }
        other => panic!("unknown crash mode: {other}"),
    }
    std::process::abort();
}

fn spawn_crash(spec: &CrashSpec) -> ExitStatus {
    let exe = std::env::current_exe().expect("test binary path");
    Command::new(exe)
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--test-threads=1")
        .arg("--quiet")
        .env(CHILD_ENV, spec.encode())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn crash child")
}

/// Durable record of what the child considered committed, fsynced line by line so the
/// abort cannot leave it buffered.
fn record_commit(log: &Path, seq: u64, hash: &Hash) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .expect("open commit log");
    writeln!(file, "{seq} {hash}").expect("write commit log");
    file.flush().expect("flush commit log");
    file.sync_all().expect("fsync commit log");
}

fn committed(log: &Path) -> Vec<(u64, Hash)> {
    if !log.exists() {
        return Vec::new();
    }
    let file = std::fs::File::open(log).expect("open commit log");
    BufReader::new(file)
        .lines()
        .map(|line| line.expect("read commit log line"))
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (seq, hash) = line.split_once(' ').expect("`<seq> <hash>` line");
            (
                seq.parse().expect("seq"),
                Hash::from_hex(hash).expect("hash"),
            )
        })
        .collect()
}

/// Kill at one boundary, then assert the ATOM-VT-001 pass criteria on the recovered
/// ledger: chain intact, exact committed prefix, no committed event lost, and a state
/// digest identical to a clean rebuild of the same prefix.
fn run_boundary(mode: &str, k: u64, m: u64) {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = CrashSpec {
        db: dir.path().join("ledger.db"),
        log: dir.path().join("committed.log"),
        mode: mode.to_owned(),
        k,
        m,
    };

    let status = spawn_crash(&spec);
    assert!(
        !status.success(),
        "child must die abnormally (mode={mode} k={k} m={m})"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(6),
            "child must die by SIGABRT (mode={mode} k={k} m={m})"
        );
    }

    let ledger = Ledger::open(&spec.db, signer()).expect("reopen after crash");

    let report = ledger.verify_stream(STREAM).expect("verify stream");
    assert!(
        report.is_intact(),
        "recovered ledger must verify (mode={mode} k={k} m={m}): {report:#?}"
    );
    assert_eq!(
        report.head_seq, k,
        "committed prefix must be exactly {k} (mode={mode} m={m})"
    );

    let committed = committed(&spec.log);
    assert_eq!(committed.len() as u64, k, "child logged {k} commits");
    for (seq, hash) in &committed {
        let record = ledger
            .read(STREAM, *seq)
            .expect("read")
            .unwrap_or_else(|| panic!("committed event {seq} lost after crash"));
        assert_eq!(
            &record.event.canonical_hash, hash,
            "committed event {seq} changed after crash"
        );
    }

    let (want_stream_digest, want_projection_digest) = reference_digests(k);
    assert_eq!(
        ledger.stream_digest(STREAM).expect("stream digest"),
        want_stream_digest,
        "recovered state digest must match a clean rebuild (mode={mode} k={k} m={m})"
    );
    let records = ledger.scan(STREAM, 1).expect("scan");
    assert_eq!(
        projection_digest(&records),
        want_projection_digest,
        "INV-007: projection must be rebuildable from the ledger"
    );

    if mode == "after_checkpoint" {
        let checkpoints = ledger.checkpoints(STREAM).expect("checkpoints");
        assert_eq!(checkpoints.len(), 1, "checkpoint must survive the crash");
        assert_eq!(checkpoints[0].seq, k);
        assert_eq!(checkpoints[0].event_count, k);
    }
}

#[test]
fn vt001_kill_after_every_committed_append() {
    for k in 0..=5 {
        run_boundary("after_appends", k, 0);
    }
}

#[test]
fn vt001_kill_inside_reducer_transaction_before_commit() {
    for k in 0..=3 {
        for m in 1..=2 {
            run_boundary("mid_tx", k, m);
        }
    }
}

#[test]
fn vt001_kill_after_checkpoint_seals_head() {
    for k in 1..=3 {
        run_boundary("after_checkpoint", k, 0);
    }
}

/// Identity is deterministic: same inputs, same digests, on two independent ledgers.
/// No wall clock participates in the hashed identity.
#[test]
fn vt001_state_digest_is_deterministic_across_instances() {
    let (stream_a, projection_a) = reference_digests(4);
    let (stream_b, projection_b) = reference_digests(4);
    assert_eq!(stream_a, stream_b);
    assert_eq!(projection_a, projection_b);
}

/// Baseline: a clean close/reopen must preserve the same digests as the crash paths.
#[test]
fn vt001_clean_reopen_preserves_state_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("ledger.db");
    {
        let mut ledger = Ledger::open(&db, signer()).expect("open");
        seed(&mut ledger, 4);
    }
    let ledger = Ledger::open(&db, signer()).expect("reopen");
    let (want_stream_digest, want_projection_digest) = reference_digests(4);
    assert_eq!(
        ledger.stream_digest(STREAM).expect("stream digest"),
        want_stream_digest
    );
    assert_eq!(
        projection_digest(&ledger.scan(STREAM, 1).expect("scan")),
        want_projection_digest
    );
    assert!(ledger.verify_stream(STREAM).expect("verify").is_intact());
}
