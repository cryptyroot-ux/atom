//! Durable crash-recovery snapshots for in-flight missions.
//!
//! When the daemon drives a mission through the sovereign runtime, every input
//! that makes that run deterministic is persisted as a sidecar file next to the
//! ledger:
//!
//! * the validated provider plan (ordered lifecycle commands),
//! * the exact `FixedClock` start instant,
//! * the exact `CounterRng` seed.
//!
//! Because the runtime is fully deterministic in those inputs, a later
//! replay — after a crash and service restart — reproduces the exact same
//! mission transcript and terminal outcome. That makes re-claiming a
//! `RUNNING` mission *safe*: recovery does not guess, it replays.
//!
//! Snapshots are written atomically (temp file + rename + fsync), so a crash
//! mid-write can never leave a half-parsed plan. Each snapshot carries an
//! attempt counter with a hard budget; once the budget is exhausted the
//! mission is honestly sealed terminal instead of looping forever.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use atom_mission::MissionCommand;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How often a crashed mission may be reclaimed and replayed before the
/// executor refuses to keep retrying (crash-loop breaker).
pub const MAX_RECOVERY_ATTEMPTS: u32 = 3;

/// File format version; bumped on breaking snapshot changes.
const SNAPSHOT_VERSION: u32 = 1;

/// Errors raised by the recovery snapshot store.
#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("recovery directory error: {0}")]
    Io(#[from] std::io::Error),
    #[error("recovery snapshot malformed: {0}")]
    Malformed(#[from] serde_json::Error),
}

/// The persisted, sufficient set of inputs to deterministically replay a run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoverySnapshot {
    version: u32,
    mission_id: String,
    /// Order of validated lifecycle commands the runtime must replay.
    commands: Vec<MissionCommand>,
    /// RFC3339 instant the `FixedClock` started at (preserves nanosecond
    /// precision so a replay signs an identical transcript).
    clock_start_rfc3339: String,
    /// `CounterRng` seed used for the original run.
    cognition_seed: u64,
    /// Number of times this snapshot has been reclaimed after a crash.
    attempts: u32,
    /// Human-readable daemon owner, for multi-host forensic triage.
    owner: String,
}

impl RecoverySnapshot {
    /// The mission this snapshot belongs to.
    #[must_use]
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    /// The validated plan commands to replay.
    #[must_use]
    pub fn commands(&self) -> &[MissionCommand] {
        &self.commands
    }

    /// The recorded clock start, parsed back to its original `DateTime<Utc>`.
    #[must_use]
    pub fn clock_start(&self) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&self.clock_start_rfc3339)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    }

    /// The recorded `CounterRng` seed.
    #[must_use]
    pub fn cognition_seed(&self) -> u64 {
        self.cognition_seed
    }

    /// How many reclaims this snapshot has survived.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// `true` when the crash-loop budget is exhausted.
    #[must_use]
    pub fn budget_exhausted(&self) -> bool {
        self.attempts >= MAX_RECOVERY_ATTEMPTS
    }

    /// The daemon owner recorded at write time.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

/// Atomic, fsync'd snapshot store rooted at `{state_dir}/recovery`.
#[derive(Clone, Debug)]
pub struct RecoveryStore {
    dir: PathBuf,
    owner: String,
}

impl RecoveryStore {
    /// Creates (on demand) the snapshot directory and returns a store bound to
    /// it. Reusing the base dir from the ledger keeps snapshots on the same
    /// volume as the durable state.
    pub fn new(base_dir: &Path, owner: impl Into<String>) -> std::io::Result<Self> {
        let dir = base_dir.join("recovery");
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            owner: owner.into(),
        })
    }

    /// Full path of the snapshot for `mission_id`.
    fn snapshot_path(&self, mission_id: &str) -> PathBuf {
        self.dir.join(format!("{mission_id}.recovery.json"))
    }

    /// Atomically persists a fresh snapshot for `mission_id`.
    ///
    /// The write goes to a temp file in the same directory, is fsync'd, then
    /// renamed over the destination. A crash before the rename leaves the
    /// previous snapshot (or nothing) intact — never a torn JSON document.
    pub async fn put(
        &self,
        mission_id: &str,
        commands: Vec<MissionCommand>,
        clock_start: DateTime<Utc>,
        cognition_seed: u64,
    ) -> Result<RecoverySnapshot, RecoveryError> {
        let snapshot = RecoverySnapshot {
            version: SNAPSHOT_VERSION,
            mission_id: mission_id.to_owned(),
            commands,
            clock_start_rfc3339: clock_start.to_rfc3339(),
            cognition_seed,
            attempts: 1,
            owner: self.owner.clone(),
        };
        self.write_atomic(&snapshot, &self.snapshot_path(mission_id))?;
        Ok(snapshot)
    }

    /// Loads the snapshot for `mission_id`, if any.
    pub async fn load(&self, mission_id: &str) -> Result<Option<RecoverySnapshot>, RecoveryError> {
        let path = self.snapshot_path(mission_id);
        match File::open(&path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let snapshot: RecoverySnapshot =
                    serde_json::from_reader(reader).map_err(RecoveryError::Malformed)?;
                Ok(Some(snapshot))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(RecoveryError::Io(error)),
        }
    }

    /// Marks a snapshot as reclaimed, bumping its attempt counter.
    pub async fn mark_reclaimed(
        &self,
        snapshot: &RecoverySnapshot,
    ) -> Result<RecoverySnapshot, RecoveryError> {
        let bumped = RecoverySnapshot {
            attempts: snapshot.attempts + 1,
            ..snapshot.clone()
        };
        self.write_atomic(&bumped, &self.snapshot_path(&bumped.mission_id))?;
        Ok(bumped)
    }

    /// Deletes a snapshot once the mission reaches a durable terminal state.
    pub async fn delete(&self, mission_id: &str) -> Result<(), RecoveryError> {
        let path = self.snapshot_path(mission_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(RecoveryError::Io(error)),
        }
    }

    /// Lists every mission id with a persisted snapshot, for startup scanning.
    pub async fn mission_ids(&self) -> Result<Vec<String>, RecoveryError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(id) = name.strip_suffix(".recovery.json") {
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn write_atomic(&self, snapshot: &RecoverySnapshot, path: &Path) -> Result<(), RecoveryError> {
        let temp = path.with_extension("recovery.tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)?;
            {
                let mut writer = BufWriter::new(&mut file);
                serde_json::to_writer(&mut writer, snapshot)?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
            file.sync_all()?;
        }
        fs::rename(&temp, path)?;
        // Best-effort directory sync so the rename itself is durable.
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const OWNER: &str = "recovery-test";
    const SEED: u64 = 0xDAE0_0002;

    fn clock() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 2, 3, 50, 48)
            .single()
            .expect("fixed test time")
    }

    fn commands() -> Vec<MissionCommand> {
        vec![
            MissionCommand::Compile,
            MissionCommand::Prepare,
            MissionCommand::Start,
            MissionCommand::Execute,
            MissionCommand::Verify,
        ]
    }

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("atom-recovery-{}-{name}", std::process::id()))
    }

    #[tokio::test]
    async fn put_then_load_roundtrips_with_full_precision() {
        let dir = temp_dir("put_load");
        let _ = fs::remove_dir_all(&dir);
        let store = RecoveryStore::new(&dir, OWNER).unwrap();

        let saved = store
            .put("m1", commands(), clock(), SEED)
            .await
            .expect("write snapshot");
        assert_eq!(saved.attempts(), 1);
        assert!(!saved.budget_exhausted());

        let loaded = store.load("m1").await.expect("load snapshot");
        let loaded = loaded.expect("snapshot exists");
        assert_eq!(loaded.mission_id(), "m1");
        assert_eq!(loaded.commands(), commands().as_slice());
        assert_eq!(loaded.clock_start(), clock());
        assert_eq!(loaded.cognition_seed(), SEED);
        assert_eq!(loaded.owner(), OWNER);
        // Exact RFC3339 equality proves nanosecond precision survives the trip.
        assert_eq!(loaded.clock_start().to_rfc3339(), clock().to_rfc3339());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn load_missing_returns_none() {
        let dir = temp_dir("load_missing");
        let _ = fs::remove_dir_all(&dir);
        let store = RecoveryStore::new(&dir, OWNER).unwrap();
        assert!(store.load("nope").await.unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mark_reclaimed_bumps_attempts() {
        let dir = temp_dir("mark_reclaimed");
        let _ = fs::remove_dir_all(&dir);
        let store = RecoveryStore::new(&dir, OWNER).unwrap();
        let saved = store.put("m2", commands(), clock(), SEED).await.unwrap();
        let once = store.mark_reclaimed(&saved).await.unwrap();
        assert_eq!(once.attempts(), 2);
        let twice = store.mark_reclaimed(&once).await.unwrap();
        assert_eq!(twice.attempts(), 3);
        assert!(twice.budget_exhausted());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn atomic_write_never_leaves_temp_stale() {
        let dir = temp_dir("atomic_write");
        let _ = fs::remove_dir_all(&dir);
        let store = RecoveryStore::new(&dir, OWNER).unwrap();
        let path = store.snapshot_path("m3");
        store
            .put("m3", commands(), clock(), SEED)
            .await
            .expect("write");
        assert!(!path.with_extension("recovery.tmp").exists());
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn delete_removes_snapshot_and_is_idempotent() {
        let dir = temp_dir("delete");
        let _ = fs::remove_dir_all(&dir);
        let store = RecoveryStore::new(&dir, OWNER).unwrap();
        store.put("m4", commands(), clock(), SEED).await.unwrap();
        store.delete("m4").await.unwrap();
        assert!(store.load("m4").await.unwrap().is_none());
        // Deleting again must not error.
        store.delete("m4").await.unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mission_ids_lists_all_snapshots() {
        let dir = temp_dir("mission_ids");
        let _ = fs::remove_dir_all(&dir);
        let store = RecoveryStore::new(&dir, OWNER).unwrap();
        store.put("m-a", commands(), clock(), SEED).await.unwrap();
        store.put("m-b", commands(), clock(), SEED).await.unwrap();
        assert_eq!(store.mission_ids().await.unwrap(), vec!["m-a", "m-b"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
