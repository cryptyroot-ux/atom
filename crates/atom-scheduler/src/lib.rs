//! Deterministic, durable admission for local-time schedules.
//!
//! A [`Scheduler`] never reads a wall clock.  Its callers pass a [`Clock`] to
//! registration, polling, and completion, which makes the state machine
//! reproducible in production and in tests.  A caller that dispatches an
//! [`AdmittedRun`] must durably persist [`Scheduler::snapshot`] after `poll`
//! or a queue-promoting `complete` (and before dispatch). Restoring that
//! snapshot records the trigger-window dedupe key, so a restart cannot admit
//! the same consequential run twice.
//!
//! ## Normative policy semantics (SCH-001)
//!
//! * A schedule is a daily local-time trigger in an explicit IANA timezone.
//! * [`DstPolicy::SkipNonexistentRunOnceAmbiguous`] skips a spring-forward
//!   local time that does not exist.  For a fall-back ambiguity it chooses the
//!   earliest UTC instant and emits one local trigger window, never two.
//! * A window older than [`LatenessPolicy::max_lateness`] is a misfire.
//!   [`MisfirePolicy::FireImmediately`] admits it now, [`MisfirePolicy::Skip`]
//!   records a durable skip, and [`MisfirePolicy::Coalesce`] keeps only the
//!   newest stale window in a poll.
//! * [`CatchUpPolicy`] controls the normal backlog discovered in one poll:
//!   `All` evaluates every window, `Latest` keeps only the newest, and `None`
//!   only considers the present local date.  Suppressed windows are recorded
//!   and therefore cannot reappear after a restart.
//! * [`OverlapPolicy::Skip`] (the recommended default) records a durable skip
//!   when a prior run is active.  [`OverlapPolicy::Queue`] persists the window
//!   FIFO and admits it once the active run is completed.
//! * [`DedupePolicy::PerTriggerWindow`] retains every observed trigger window
//!   in the durable snapshot.  It is intentionally never garbage-collected by
//!   this crate: trimming it would weaken the at-most-once guarantee.
//! * [`CancellationPolicy::StopAndDropQueued`] stops new admissions and drops
//!   queued work, but does not attempt to revoke an already-admitted run.
//! * Each [`AdmittedRun`] carries an [`AuthorityProfileRef`] containing the
//!   capability grant id and generation.  It never obtains ambient authority.
//!
//! The crate deliberately implements the schedule calculation natively; it
//! has no cron daemon, Redis, or other external scheduler dependency.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use atom_capability::CapabilityGrant;
use chrono::{DateTime, Duration, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// The implementation maturity marker for this crate.
pub const CRATE_STAGE: &str = "G2-deterministic-scheduler";

/// A source of scheduler time.
///
/// Implementations are intentionally supplied by the embedding application.
/// `atom-scheduler` does not provide a system-clock implementation, preventing
/// accidental wall-clock reads in deterministic execution paths.
pub trait Clock {
    /// Returns the current UTC timestamp observed by the scheduler.
    fn now(&self) -> DateTime<Utc>;
}

impl Clock for DateTime<Utc> {
    fn now(&self) -> DateTime<Utc> {
        *self
    }
}

/// A stable identity for one schedule.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ScheduleId(String);

impl ScheduleId {
    /// Creates a non-empty schedule id.
    pub fn new(value: impl Into<String>) -> Result<Self, SchedulerError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SchedulerError::EmptyScheduleId);
        }
        Ok(Self(value))
    }

    /// Returns the textual id used in a durable dedupe key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScheduleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A reference to the capability grant under which a scheduled run was
/// planned.  The scheduler carries a reference, not a grant with ambient
/// powers; the dispatch boundary must revalidate the referenced grant.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AuthorityProfileRef {
    /// The stable id of the capability grant.
    pub capability_grant_id: String,
    /// The grant generation observed while scheduling this work.
    pub grant_generation: u64,
}

impl AuthorityProfileRef {
    /// Creates a capability-grant reference with an explicit generation.
    pub fn new(
        capability_grant_id: impl Into<String>,
        grant_generation: u64,
    ) -> Result<Self, SchedulerError> {
        let capability_grant_id = capability_grant_id.into();
        if capability_grant_id.trim().is_empty() {
            return Err(SchedulerError::EmptyCapabilityGrantId);
        }
        Ok(Self {
            capability_grant_id,
            grant_generation,
        })
    }

    /// Builds a reference from an `atom-capability` grant without copying its
    /// authority into the schedule.
    pub fn from_grant(grant: &CapabilityGrant) -> Result<Self, SchedulerError> {
        Self::new(&grant.grant_id, grant.generation)
    }

    fn validate(&self) -> Result<(), SchedulerError> {
        if self.capability_grant_id.trim().is_empty() {
            return Err(SchedulerError::EmptyCapabilityGrantId);
        }
        Ok(())
    }
}

/// The local-time trigger currently supported by the native scheduler.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// Trigger once per local calendar date at this wall-clock time.
    DailyAt {
        /// Local hour in `0..=23`.
        hour: u8,
        /// Local minute in `0..=59`.
        minute: u8,
        /// Local second in `0..=59`.
        second: u8,
    },
}

impl Trigger {
    /// Constructs a validated daily local-time trigger.
    pub fn daily_at(hour: u8, minute: u8, second: u8) -> Result<Self, SchedulerError> {
        let trigger = Self::DailyAt {
            hour,
            minute,
            second,
        };
        trigger.local_time()?;
        Ok(trigger)
    }

    fn local_time(&self) -> Result<(u8, u8, u8), SchedulerError> {
        match self {
            Self::DailyAt {
                hour,
                minute,
                second,
            } if *hour < 24 && *minute < 60 && *second < 60 => Ok((*hour, *minute, *second)),
            Self::DailyAt {
                hour,
                minute,
                second,
            } => Err(SchedulerError::InvalidTriggerTime {
                hour: *hour,
                minute: *minute,
                second: *second,
            }),
        }
    }
}

/// DST behavior for a local-time trigger.
///
/// This single policy is deliberately restrictive: it prevents the accidental
/// double-fire most dangerous for consequential work.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DstPolicy {
    /// Skip a nonexistent local time and choose the earliest instant of an
    /// ambiguous local time, yielding exactly one trigger window.
    #[default]
    SkipNonexistentRunOnceAmbiguous,
}

/// Action for a trigger that exceeds its configured lateness allowance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MisfirePolicy {
    /// Admit each stale candidate immediately, subject to overlap policy.
    FireImmediately,
    /// Record every stale candidate as skipped.
    Skip,
    /// Record all but the newest stale candidate as coalesced, then admit the
    /// newest one subject to overlap policy.
    Coalesce,
}

/// How normal backlog discovered in a single poll is handled.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatchUpPolicy {
    /// Consider only candidates on the current local calendar date.
    None,
    /// Keep only the newest candidate in the polling interval.
    Latest,
    /// Evaluate every candidate in the polling interval.
    All,
}

/// What happens if a schedule has a currently running consequential run.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    /// Skip and durably remember the later trigger window.
    #[default]
    Skip,
    /// Persist the later trigger window in FIFO order until the active run is
    /// completed.
    Queue,
}

/// Durability scope for dedupe keys.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupePolicy {
    /// Retain an observed key forever for this immutable schedule id and local
    /// trigger window.  This is the policy that enforces VT-014.
    PerTriggerWindow,
}

/// Cancellation behavior for an active schedule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationPolicy {
    /// Do not admit future work; remove queued work; leave an already-admitted
    /// run to its dispatch/reconciliation boundary.
    StopAndDropQueued,
}

/// The maximum delay that is still considered on-time for a schedule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LatenessPolicy {
    /// Windows older than this duration are handled by [`MisfirePolicy`].
    pub max_lateness: Duration,
}

impl LatenessPolicy {
    /// Creates a lateness policy.  Negative durations are invalid because they
    /// make the classification of an exactly-on-time trigger ambiguous.
    pub fn new(max_lateness: Duration) -> Result<Self, SchedulerError> {
        let policy = Self { max_lateness };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), SchedulerError> {
        if self.max_lateness < Duration::zero() {
            return Err(SchedulerError::NegativeLateness);
        }
        Ok(())
    }
}

/// All required semantics for a native daily local-time schedule.
///
/// The fields are intentionally non-optional: a caller must make every
/// SCH-001 policy decision before [`Scheduler::register`] accepts the spec.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleSpec {
    /// Immutable schedule identity.  Re-registering an id is rejected.
    pub id: ScheduleId,
    /// Local-time cadence.
    pub trigger: Trigger,
    /// IANA timezone used to resolve the local trigger.
    pub timezone: Tz,
    /// Spring-forward and fall-back resolution policy.
    pub dst_policy: DstPolicy,
    /// Policy for windows beyond the lateness allowance.
    pub misfire_policy: MisfirePolicy,
    /// Policy when a prior run has not completed.
    pub overlap_policy: OverlapPolicy,
    /// Policy for a normal backlog found in one poll.
    pub catch_up_policy: CatchUpPolicy,
    /// Durability scope for trigger-window dedupe.
    pub dedupe_policy: DedupePolicy,
    /// Explicit bound that separates ordinary delay from a misfire.
    pub lateness: LatenessPolicy,
    /// Capability grant reference carried into every run.
    pub authority_profile: AuthorityProfileRef,
    /// Explicit behavior when the schedule is cancelled.
    pub cancellation_policy: CancellationPolicy,
}

impl ScheduleSpec {
    /// Validates values that can be bypassed by deserializing or constructing a
    /// public enum directly.
    pub fn validate(&self) -> Result<(), SchedulerError> {
        if self.id.as_str().trim().is_empty() {
            return Err(SchedulerError::EmptyScheduleId);
        }
        self.trigger.local_time()?;
        self.lateness.validate()?;
        self.authority_profile.validate()?;
        Ok(())
    }
}

/// Stable identity for one trigger window.  The local wall-clock timestamp is
/// used rather than an offset timestamp so both fall-back folds map to exactly
/// the same key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DedupeKey {
    /// Schedule owning this window.
    pub schedule_id: ScheduleId,
    /// Intended local wall-clock trigger time.
    pub trigger_window: NaiveDateTime,
}

impl fmt::Display for DedupeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.schedule_id, self.trigger_window)
    }
}

impl Serialize for DedupeKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.wire_value())
    }
}

impl<'de> Deserialize<'de> for DedupeKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_wire_value(&value).map_err(D::Error::custom)
    }
}

impl DedupeKey {
    /// Encodes a key without an ambiguous delimiter in the schedule id.  This
    /// is deliberately a string because JSON object keys must be strings; it
    /// also makes `BTreeMap<DedupeKey, _>` snapshots portable to JSON stores.
    fn wire_value(&self) -> String {
        let schedule_id = self.schedule_id.as_str();
        format!(
            "{}:{}{}",
            schedule_id.len(),
            schedule_id,
            self.trigger_window.format("%Y-%m-%dT%H:%M:%S%.f")
        )
    }

    fn from_wire_value(value: &str) -> Result<Self, String> {
        let (length, remainder) = value
            .split_once(':')
            .ok_or_else(|| "dedupe key is missing its schedule-id length".to_owned())?;
        let schedule_id_length = length
            .parse::<usize>()
            .map_err(|_| "dedupe key has an invalid schedule-id length".to_owned())?;
        let schedule_id = remainder
            .get(..schedule_id_length)
            .ok_or_else(|| "dedupe key schedule-id length exceeds input".to_owned())?;
        let trigger_window = remainder
            .get(schedule_id_length..)
            .ok_or_else(|| "dedupe key is missing its trigger window".to_owned())?;
        let schedule_id = ScheduleId::new(schedule_id)
            .map_err(|error| format!("invalid dedupe key schedule id: {error}"))?;
        let trigger_window = NaiveDateTime::parse_from_str(trigger_window, "%Y-%m-%dT%H:%M:%S%.f")
            .map_err(|_| "dedupe key has an invalid trigger window".to_owned())?;

        Ok(Self {
            schedule_id,
            trigger_window,
        })
    }
}

/// A consequential run admitted by the scheduler.
///
/// The presence of this value means its dedupe key is already present in the
/// scheduler state.  Persist the state before dispatching the run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmittedRun {
    /// Idempotency identity for this local trigger window.
    pub dedupe_key: DedupeKey,
    /// UTC instant selected from the local trigger and DST policy.
    pub scheduled_for: DateTime<Utc>,
    /// Clock timestamp when the scheduler admitted this run.
    pub admitted_at: DateTime<Utc>,
    /// Capability grant reference that must be revalidated at dispatch.
    pub authority_profile: AuthorityProfileRef,
}

/// Serializable state that must be retained across process restart.
///
/// Its fields are private so callers restore it only through
/// [`Scheduler::from_snapshot`], which revalidates runtime invariants.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchedulerSnapshot {
    version: u8,
    schedules: BTreeMap<ScheduleId, PersistedSchedule>,
}

/// An in-memory deterministic scheduler.  It contains no task executor and
/// never performs a consequential action itself.
#[derive(Clone, Debug)]
pub struct Scheduler {
    snapshot: SchedulerSnapshot,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    /// Creates a scheduler with no schedules or observed trigger windows.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: SchedulerSnapshot {
                version: SNAPSHOT_VERSION,
                schedules: BTreeMap::new(),
            },
        }
    }

    /// Restores a persisted scheduler snapshot after validating its invariants.
    pub fn from_snapshot(snapshot: SchedulerSnapshot) -> Result<Self, SchedulerError> {
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot })
    }

    /// Returns a clone suitable for durable storage before external dispatch.
    #[must_use]
    pub fn snapshot(&self) -> SchedulerSnapshot {
        self.snapshot.clone()
    }

    /// Registers an immutable schedule at the timestamp supplied by `clock`.
    /// Windows before registration are deliberately outside this scheduler's
    /// authority and are never synthesized on first poll.
    pub fn register<C: Clock>(
        &mut self,
        spec: ScheduleSpec,
        clock: &C,
    ) -> Result<(), SchedulerError> {
        spec.validate()?;
        if self.snapshot.schedules.contains_key(&spec.id) {
            return Err(SchedulerError::DuplicateSchedule {
                schedule_id: spec.id.clone(),
            });
        }

        self.snapshot.schedules.insert(
            spec.id.clone(),
            PersistedSchedule {
                spec,
                registered_at: clock.now(),
                last_observed_at: None,
                cancelled: false,
                active_window: None,
                queued_windows: VecDeque::new(),
                windows: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Resolves all windows due at the supplied clock value and returns newly
    /// admitted work.  The durable dedupe record is created before each item is
    /// added to the returned vector.
    pub fn poll<C: Clock>(&mut self, clock: &C) -> Result<Vec<AdmittedRun>, SchedulerError> {
        let now = clock.now();
        let ids: Vec<ScheduleId> = self.snapshot.schedules.keys().cloned().collect();
        // Derive every candidate before mutating the durable state. A rejected
        // clock or impossible date range therefore cannot partially advance a
        // subset of schedules.
        let pending: Result<Vec<(ScheduleId, Vec<Candidate>)>, SchedulerError> = ids
            .iter()
            .map(|id| {
                let schedule = self
                    .snapshot
                    .schedules
                    .get(id)
                    .expect("ids are cloned from the schedule map");
                let lower_bound = schedule.last_observed_at.unwrap_or(schedule.registered_at);
                if now < lower_bound {
                    return Err(SchedulerError::ClockMovedBackwards {
                        schedule_id: id.clone(),
                        previous: lower_bound,
                        observed: now,
                    });
                }
                let candidates = due_candidates(
                    &schedule.spec,
                    lower_bound,
                    now,
                    schedule.last_observed_at.is_none(),
                )?;
                Ok((id.clone(), candidates))
            })
            .collect();

        let pending = pending?;
        let mut admitted = Vec::new();

        for (id, candidates) in pending {
            let schedule = self
                .snapshot
                .schedules
                .get_mut(&id)
                .expect("ids are cloned from the schedule map");
            // Persist the polling cursor before handling policies.  Every
            // candidate is then recorded as admitted or suppressed, so replay
            // of a snapshot cannot rediscover consequential work.
            schedule.last_observed_at = Some(now);

            if schedule.cancelled {
                for candidate in candidates {
                    record_if_new(schedule, candidate, WindowState::Cancelled);
                }
                continue;
            }

            let selected = apply_catch_up(schedule, candidates, now);
            let ready = apply_misfire_policy(schedule, selected, now);
            for candidate in ready {
                if let Some(run) = admit_or_suppress_overlap(schedule, candidate, now) {
                    admitted.push(run);
                }
            }
        }

        Ok(admitted)
    }

    /// Marks an active run complete at the supplied clock value.  Under the
    /// queue overlap policy, returns the next already-deduped queued run. Save
    /// a snapshot before dispatching the returned run.
    pub fn complete<C: Clock>(
        &mut self,
        dedupe_key: &DedupeKey,
        clock: &C,
    ) -> Result<Option<AdmittedRun>, SchedulerError> {
        let now = clock.now();
        let schedule = self
            .snapshot
            .schedules
            .get_mut(&dedupe_key.schedule_id)
            .ok_or_else(|| SchedulerError::UnknownSchedule {
                schedule_id: dedupe_key.schedule_id.clone(),
            })?;

        if schedule.active_window.as_ref() != Some(dedupe_key) {
            return Err(SchedulerError::RunNotActive {
                dedupe_key: dedupe_key.clone(),
            });
        }

        let admitted_at = match schedule.windows.get(dedupe_key) {
            Some(WindowRecord {
                state: WindowState::Running { admitted_at },
                ..
            }) => *admitted_at,
            _ => {
                return Err(SchedulerError::RunNotActive {
                    dedupe_key: dedupe_key.clone(),
                });
            }
        };
        if now < admitted_at {
            return Err(SchedulerError::CompletionBeforeAdmission {
                dedupe_key: dedupe_key.clone(),
                admitted_at,
                completed_at: now,
            });
        }

        let record = schedule
            .windows
            .get_mut(dedupe_key)
            .expect("active window must have a record");
        record.state = WindowState::Completed {
            admitted_at,
            completed_at: now,
        };
        schedule.active_window = None;

        if schedule.cancelled {
            return Ok(None);
        }

        let Some(next_key) = schedule.queued_windows.pop_front() else {
            return Ok(None);
        };
        let next_record = schedule
            .windows
            .get_mut(&next_key)
            .expect("queued window must have a record");
        if !matches!(next_record.state, WindowState::Queued) {
            return Err(SchedulerError::InvalidSnapshot {
                reason: "queued window is not in QUEUED state".to_owned(),
            });
        }
        next_record.state = WindowState::Running { admitted_at: now };
        schedule.active_window = Some(next_key.clone());

        Ok(Some(AdmittedRun {
            dedupe_key: next_key,
            scheduled_for: next_record.scheduled_for,
            admitted_at: now,
            authority_profile: schedule.spec.authority_profile.clone(),
        }))
    }

    /// Cancels a schedule according to its explicit cancellation policy.
    /// Existing running work remains tracked so it can be completed, while all
    /// queued windows are durably marked cancelled.
    pub fn cancel(&mut self, schedule_id: &ScheduleId) -> Result<(), SchedulerError> {
        let schedule = self
            .snapshot
            .schedules
            .get_mut(schedule_id)
            .ok_or_else(|| SchedulerError::UnknownSchedule {
                schedule_id: schedule_id.clone(),
            })?;
        if schedule.cancelled {
            return Ok(());
        }

        schedule.cancelled = true;
        match schedule.spec.cancellation_policy {
            CancellationPolicy::StopAndDropQueued => {
                while let Some(key) = schedule.queued_windows.pop_front() {
                    if let Some(record) = schedule.windows.get_mut(&key) {
                        record.state = WindowState::Cancelled;
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns whether a trigger window has a durable outcome of any kind.
    /// This includes running, completed, queued, and policy-suppressed windows.
    #[must_use]
    pub fn has_seen(&self, dedupe_key: &DedupeKey) -> bool {
        self.snapshot
            .schedules
            .get(&dedupe_key.schedule_id)
            .is_some_and(|schedule| schedule.windows.contains_key(dedupe_key))
    }
}

const SNAPSHOT_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedSchedule {
    spec: ScheduleSpec,
    registered_at: DateTime<Utc>,
    last_observed_at: Option<DateTime<Utc>>,
    cancelled: bool,
    active_window: Option<DedupeKey>,
    queued_windows: VecDeque<DedupeKey>,
    windows: BTreeMap<DedupeKey, WindowRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WindowRecord {
    scheduled_for: DateTime<Utc>,
    state: WindowState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WindowState {
    Running {
        admitted_at: DateTime<Utc>,
    },
    Queued,
    Completed {
        admitted_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    },
    SkippedMisfire,
    CoalescedMisfire,
    SkippedCatchUp,
    CoalescedCatchUp,
    SkippedOverlap,
    Cancelled,
}

#[derive(Clone, Debug)]
struct Candidate {
    dedupe_key: DedupeKey,
    scheduled_for: DateTime<Utc>,
}

fn due_candidates(
    spec: &ScheduleSpec,
    lower_bound: DateTime<Utc>,
    upper_bound: DateTime<Utc>,
    include_lower_bound: bool,
) -> Result<Vec<Candidate>, SchedulerError> {
    let start_date = lower_bound.with_timezone(&spec.timezone).date_naive();
    let end_date = upper_bound.with_timezone(&spec.timezone).date_naive();
    let mut date = start_date;
    let mut candidates = Vec::new();

    loop {
        if let Some(candidate) = candidate_for_date(spec, date)? {
            let at_or_after_lower = if include_lower_bound {
                candidate.scheduled_for >= lower_bound
            } else {
                candidate.scheduled_for > lower_bound
            };
            if at_or_after_lower && candidate.scheduled_for <= upper_bound {
                candidates.push(candidate);
            }
        }

        if date == end_date {
            break;
        }
        date = date.succ_opt().ok_or(SchedulerError::DateRangeOverflow)?;
    }

    candidates.sort_by(|left, right| {
        left.scheduled_for
            .cmp(&right.scheduled_for)
            .then_with(|| left.dedupe_key.cmp(&right.dedupe_key))
    });
    Ok(candidates)
}

fn candidate_for_date(
    spec: &ScheduleSpec,
    date: NaiveDate,
) -> Result<Option<Candidate>, SchedulerError> {
    let (hour, minute, second) = spec.trigger.local_time()?;
    let local_window = date
        .and_hms_opt(u32::from(hour), u32::from(minute), u32::from(second))
        .ok_or(SchedulerError::InvalidTriggerTime {
            hour,
            minute,
            second,
        })?;

    let scheduled_for = match spec.timezone.from_local_datetime(&local_window) {
        LocalResult::Single(instant) => instant.with_timezone(&Utc),
        LocalResult::Ambiguous(first, second) => match spec.dst_policy {
            DstPolicy::SkipNonexistentRunOnceAmbiguous => {
                let first = first.with_timezone(&Utc);
                let second = second.with_timezone(&Utc);
                first.min(second)
            }
        },
        LocalResult::None => match spec.dst_policy {
            DstPolicy::SkipNonexistentRunOnceAmbiguous => return Ok(None),
        },
    };

    Ok(Some(Candidate {
        dedupe_key: DedupeKey {
            schedule_id: spec.id.clone(),
            trigger_window: local_window,
        },
        scheduled_for,
    }))
}

fn apply_catch_up(
    schedule: &mut PersistedSchedule,
    candidates: Vec<Candidate>,
    now: DateTime<Utc>,
) -> Vec<Candidate> {
    match schedule.spec.catch_up_policy {
        CatchUpPolicy::All => candidates,
        CatchUpPolicy::Latest => {
            let Some((latest_index, _)) = candidates
                .iter()
                .enumerate()
                .max_by(|(_, left), (_, right)| left.scheduled_for.cmp(&right.scheduled_for))
            else {
                return Vec::new();
            };

            candidates
                .into_iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    if index == latest_index {
                        Some(candidate)
                    } else {
                        record_if_new(schedule, candidate, WindowState::CoalescedCatchUp);
                        None
                    }
                })
                .collect()
        }
        CatchUpPolicy::None => {
            let current_local_date = now.with_timezone(&schedule.spec.timezone).date_naive();
            candidates
                .into_iter()
                .filter_map(|candidate| {
                    if candidate.dedupe_key.trigger_window.date() == current_local_date {
                        Some(candidate)
                    } else {
                        record_if_new(schedule, candidate, WindowState::SkippedCatchUp);
                        None
                    }
                })
                .collect()
        }
    }
}

fn apply_misfire_policy(
    schedule: &mut PersistedSchedule,
    candidates: Vec<Candidate>,
    now: DateTime<Utc>,
) -> Vec<Candidate> {
    let mut ready = Vec::new();
    let mut stale = Vec::new();

    for candidate in candidates {
        if is_misfire(&schedule.spec.lateness, candidate.scheduled_for, now) {
            stale.push(candidate);
        } else {
            ready.push(candidate);
        }
    }

    match schedule.spec.misfire_policy {
        MisfirePolicy::FireImmediately => ready.extend(stale),
        MisfirePolicy::Skip => {
            for candidate in stale {
                record_if_new(schedule, candidate, WindowState::SkippedMisfire);
            }
        }
        MisfirePolicy::Coalesce => {
            let latest = stale
                .iter()
                .enumerate()
                .max_by(|(_, left), (_, right)| left.scheduled_for.cmp(&right.scheduled_for))
                .map(|(index, _)| index);
            for (index, candidate) in stale.into_iter().enumerate() {
                if Some(index) == latest {
                    ready.push(candidate);
                } else {
                    record_if_new(schedule, candidate, WindowState::CoalescedMisfire);
                }
            }
        }
    }

    ready.sort_by(|left, right| {
        left.scheduled_for
            .cmp(&right.scheduled_for)
            .then_with(|| left.dedupe_key.cmp(&right.dedupe_key))
    });
    ready
}

fn is_misfire(lateness: &LatenessPolicy, scheduled_for: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(scheduled_for) > lateness.max_lateness
}

fn admit_or_suppress_overlap(
    schedule: &mut PersistedSchedule,
    candidate: Candidate,
    now: DateTime<Utc>,
) -> Option<AdmittedRun> {
    if schedule.windows.contains_key(&candidate.dedupe_key) {
        return None;
    }

    if schedule.active_window.is_some() {
        match schedule.spec.overlap_policy {
            OverlapPolicy::Skip => {
                record_if_new(schedule, candidate, WindowState::SkippedOverlap);
            }
            OverlapPolicy::Queue => {
                let key = candidate.dedupe_key.clone();
                record_if_new(schedule, candidate, WindowState::Queued);
                schedule.queued_windows.push_back(key);
            }
        }
        return None;
    }

    // The window record is inserted before constructing the externally visible
    // admission receipt.  Persisting a subsequent snapshot before dispatch
    // makes this transition idempotent across restart.
    let dedupe_key = candidate.dedupe_key;
    let scheduled_for = candidate.scheduled_for;
    schedule.windows.insert(
        dedupe_key.clone(),
        WindowRecord {
            scheduled_for,
            state: WindowState::Running { admitted_at: now },
        },
    );
    schedule.active_window = Some(dedupe_key.clone());

    Some(AdmittedRun {
        dedupe_key,
        scheduled_for,
        admitted_at: now,
        authority_profile: schedule.spec.authority_profile.clone(),
    })
}

fn record_if_new(schedule: &mut PersistedSchedule, candidate: Candidate, state: WindowState) {
    schedule
        .windows
        .entry(candidate.dedupe_key)
        .or_insert(WindowRecord {
            scheduled_for: candidate.scheduled_for,
            state,
        });
}

fn validate_snapshot(snapshot: &SchedulerSnapshot) -> Result<(), SchedulerError> {
    if snapshot.version != SNAPSHOT_VERSION {
        return Err(SchedulerError::UnsupportedSnapshotVersion {
            version: snapshot.version,
        });
    }

    for (id, schedule) in &snapshot.schedules {
        schedule.spec.validate()?;
        if &schedule.spec.id != id {
            return Err(SchedulerError::InvalidSnapshot {
                reason: "schedule map key differs from schedule spec id".to_owned(),
            });
        }
        if let Some(last_observed_at) = schedule.last_observed_at {
            if last_observed_at < schedule.registered_at {
                return Err(SchedulerError::InvalidSnapshot {
                    reason: "last_observed_at precedes registered_at".to_owned(),
                });
            }
        }
        if schedule.cancelled && !schedule.queued_windows.is_empty() {
            return Err(SchedulerError::InvalidSnapshot {
                reason: "cancelled schedule contains queued work".to_owned(),
            });
        }

        let mut queued = BTreeSet::new();
        for key in &schedule.queued_windows {
            if !queued.insert(key) {
                return Err(SchedulerError::InvalidSnapshot {
                    reason: "queued trigger window appears more than once".to_owned(),
                });
            }
            if key.schedule_id != *id {
                return Err(SchedulerError::InvalidSnapshot {
                    reason: "queued trigger window belongs to another schedule".to_owned(),
                });
            }
            if !matches!(
                schedule.windows.get(key),
                Some(WindowRecord {
                    state: WindowState::Queued,
                    ..
                })
            ) {
                return Err(SchedulerError::InvalidSnapshot {
                    reason: "queued trigger window lacks a QUEUED record".to_owned(),
                });
            }
        }

        let running_count = schedule
            .windows
            .values()
            .filter(|record| matches!(&record.state, WindowState::Running { .. }))
            .count();
        for (key, record) in &schedule.windows {
            if key.schedule_id != *id {
                return Err(SchedulerError::InvalidSnapshot {
                    reason: "window record belongs to another schedule".to_owned(),
                });
            }
            if matches!(&record.state, WindowState::Queued) && !queued.contains(key) {
                return Err(SchedulerError::InvalidSnapshot {
                    reason: "QUEUED record is absent from the queue".to_owned(),
                });
            }
        }

        match &schedule.active_window {
            Some(key) => {
                if key.schedule_id != *id
                    || running_count != 1
                    || !matches!(
                        schedule.windows.get(key),
                        Some(WindowRecord {
                            state: WindowState::Running { .. },
                            ..
                        })
                    )
                {
                    return Err(SchedulerError::InvalidSnapshot {
                        reason: "active trigger window lacks a RUNNING record".to_owned(),
                    });
                }
            }
            None => {
                if running_count != 0 {
                    return Err(SchedulerError::InvalidSnapshot {
                        reason: "RUNNING record exists without an active trigger window".to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Errors returned while defining, restoring, or advancing the scheduler.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SchedulerError {
    /// Schedule IDs are durable namespace keys and cannot be blank.
    #[error("schedule id must not be empty")]
    EmptyScheduleId,
    /// A scheduled run cannot carry an empty authority reference.
    #[error("capability grant id must not be empty")]
    EmptyCapabilityGrantId,
    /// A daily local clock time was not valid.
    #[error("invalid daily trigger time {hour:02}:{minute:02}:{second:02}")]
    InvalidTriggerTime {
        /// Requested hour.
        hour: u8,
        /// Requested minute.
        minute: u8,
        /// Requested second.
        second: u8,
    },
    /// Lateness must be a non-negative duration.
    #[error("max lateness must not be negative")]
    NegativeLateness,
    /// A schedule id has already been registered in this durable state.
    #[error("schedule already registered: {schedule_id}")]
    DuplicateSchedule {
        /// Duplicated id.
        schedule_id: ScheduleId,
    },
    /// No schedule is registered under the requested id.
    #[error("unknown schedule: {schedule_id}")]
    UnknownSchedule {
        /// Requested id.
        schedule_id: ScheduleId,
    },
    /// A poll used an earlier timestamp than the persistent cursor.
    #[error("clock moved backwards for {schedule_id}: observed={observed}, previous={previous}")]
    ClockMovedBackwards {
        /// Schedule whose cursor would regress.
        schedule_id: ScheduleId,
        /// Persisted cursor.
        previous: DateTime<Utc>,
        /// Newly injected clock value.
        observed: DateTime<Utc>,
    },
    /// The run is not the active run for its schedule.
    #[error("run is not active: {dedupe_key}")]
    RunNotActive {
        /// Idempotency key presented to completion.
        dedupe_key: DedupeKey,
    },
    /// Completion cannot predate admission according to the supplied clock.
    #[error(
        "completion before admission for {dedupe_key}: completed={completed_at}, admitted={admitted_at}"
    )]
    CompletionBeforeAdmission {
        /// Idempotency key presented to completion.
        dedupe_key: DedupeKey,
        /// Recorded admission time.
        admitted_at: DateTime<Utc>,
        /// Supplied completion time.
        completed_at: DateTime<Utc>,
    },
    /// Snapshot schema version does not match this implementation.
    #[error("unsupported scheduler snapshot version: {version}")]
    UnsupportedSnapshotVersion {
        /// Version found in the persisted snapshot.
        version: u8,
    },
    /// A persisted snapshot violates scheduler state invariants.
    #[error("invalid scheduler snapshot: {reason}")]
    InvalidSnapshot {
        /// Invariant that failed.
        reason: String,
    },
    /// A local-date range could not be advanced safely.
    #[error("scheduler local-date range overflow")]
    DateRangeOverflow,
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use chrono_tz::{America::New_York, UTC};

    use super::{
        AuthorityProfileRef, CancellationPolicy, CatchUpPolicy, Clock, DedupePolicy, DstPolicy,
        LatenessPolicy, MisfirePolicy, OverlapPolicy, ScheduleId, ScheduleSpec, Scheduler,
        SchedulerSnapshot, Trigger,
    };

    /// The scheduler only observes this injected clock in tests.  In particular,
    /// tests never use a process wall clock.
    #[derive(Clone, Copy)]
    struct TestClock {
        now: DateTime<Utc>,
    }

    impl TestClock {
        fn at(now: DateTime<Utc>) -> Self {
            Self { now }
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            self.now
        }
    }

    fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .expect("valid test timestamp")
    }

    fn daily_spec(
        id: &str,
        timezone: chrono_tz::Tz,
        local_time: (u8, u8),
        policies: (MisfirePolicy, OverlapPolicy, CatchUpPolicy, Duration),
    ) -> ScheduleSpec {
        let (misfire_policy, overlap_policy, catch_up_policy, max_lateness) = policies;
        ScheduleSpec {
            id: ScheduleId::new(id).expect("non-empty id"),
            trigger: Trigger::daily_at(local_time.0, local_time.1, 0).expect("valid local time"),
            timezone,
            dst_policy: DstPolicy::SkipNonexistentRunOnceAmbiguous,
            misfire_policy,
            overlap_policy,
            catch_up_policy,
            dedupe_policy: DedupePolicy::PerTriggerWindow,
            lateness: LatenessPolicy::new(max_lateness).expect("non-negative lateness"),
            authority_profile: AuthorityProfileRef::new("grant-rotation", 7)
                .expect("non-empty grant reference"),
            cancellation_policy: CancellationPolicy::StopAndDropQueued,
        }
    }

    #[test]
    fn vt014_restart_in_a_trigger_window_admits_exactly_once() {
        let registered = TestClock::at(utc(2025, 1, 15, 14, 59, 50));
        let trigger_window = TestClock::at(utc(2025, 1, 15, 15, 0, 10));
        let spec = daily_spec(
            "rotation",
            New_York,
            (10, 0),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::All,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        let first = scheduler.poll(&trigger_window).expect("first poll");
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].authority_profile.capability_grant_id,
            "grant-rotation"
        );

        // A durable snapshot is taken after admission and before any
        // consequential dispatch.  A restarted process sees the same window,
        // but the persisted dedupe key prevents a second admission.
        let persisted = serde_json::to_string(&scheduler.snapshot()).expect("serialize snapshot");
        let snapshot: SchedulerSnapshot =
            serde_json::from_str(&persisted).expect("deserialize snapshot");
        let mut restarted = Scheduler::from_snapshot(snapshot).expect("restore scheduler");
        let duplicate = restarted.poll(&trigger_window).expect("restart poll");

        assert!(duplicate.is_empty());
        assert!(restarted.has_seen(&first[0].dedupe_key));
    }

    #[test]
    fn dst_spring_forward_skips_nonexistent_local_time() {
        let registered = TestClock::at(utc(2024, 3, 10, 6, 0, 0)); // 01:00 EST
        let after_gap = TestClock::at(utc(2024, 3, 10, 8, 0, 0)); // 04:00 EDT
        let next_day = TestClock::at(utc(2024, 3, 11, 6, 31, 0)); // 02:31 EDT
        let spec = daily_spec(
            "spring-forward",
            New_York,
            (2, 30),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::All,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        assert!(scheduler
            .poll(&after_gap)
            .expect("poll through gap")
            .is_empty());

        let next = scheduler.poll(&next_day).expect("poll next valid day");
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].scheduled_for, utc(2024, 3, 11, 6, 30, 0));
    }

    #[test]
    fn dst_fall_back_chooses_earliest_fold_and_runs_once() {
        let registered = TestClock::at(utc(2024, 11, 3, 4, 0, 0)); // 00:00 EDT
        let after_both_folds = TestClock::at(utc(2024, 11, 3, 7, 0, 0)); // 02:00 EST
        let spec = daily_spec(
            "fall-back",
            New_York,
            (1, 30),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::All,
                Duration::hours(2),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        let admitted = scheduler.poll(&after_both_folds).expect("poll fall-back");

        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].scheduled_for, utc(2024, 11, 3, 5, 30, 0));
        assert!(scheduler
            .poll(&after_both_folds)
            .expect("repeat poll")
            .is_empty());
    }

    #[test]
    fn vt014_restart_during_fall_back_window_never_double_fires() {
        let registered = TestClock::at(utc(2024, 11, 3, 4, 0, 0)); // 00:00 EDT
        let first_fold = TestClock::at(utc(2024, 11, 3, 5, 35, 0)); // 01:35 EDT
        let second_fold = TestClock::at(utc(2024, 11, 3, 6, 35, 0)); // 01:35 EST
        let spec = daily_spec(
            "restart-fall-back",
            New_York,
            (1, 30),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::All,
                Duration::hours(2),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        assert_eq!(scheduler.poll(&first_fold).expect("first fold").len(), 1);

        let persisted = serde_json::to_string(&scheduler.snapshot()).expect("serialize snapshot");
        let snapshot: SchedulerSnapshot =
            serde_json::from_str(&persisted).expect("deserialize snapshot");
        let mut restarted = Scheduler::from_snapshot(snapshot).expect("restore scheduler");

        assert!(restarted
            .poll(&second_fold)
            .expect("second fold after restart")
            .is_empty());
    }

    #[test]
    fn overlap_skip_drops_a_second_window_while_the_first_is_running() {
        let registered = TestClock::at(utc(2025, 1, 1, 8, 59, 0));
        let first_tick = TestClock::at(utc(2025, 1, 1, 9, 0, 0));
        let second_tick = TestClock::at(utc(2025, 1, 2, 9, 0, 0));
        let spec = daily_spec(
            "skip-overlap",
            UTC,
            (9, 0),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::All,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        assert_eq!(scheduler.poll(&first_tick).expect("first run").len(), 1);
        assert!(scheduler
            .poll(&second_tick)
            .expect("overlapping run")
            .is_empty());
    }

    #[test]
    fn overlap_queue_admits_one_queued_window_after_completion() {
        let registered = TestClock::at(utc(2025, 1, 1, 8, 59, 0));
        let first_tick = TestClock::at(utc(2025, 1, 1, 9, 0, 0));
        let second_tick = TestClock::at(utc(2025, 1, 2, 9, 0, 0));
        let completed = TestClock::at(utc(2025, 1, 2, 9, 1, 0));
        let spec = daily_spec(
            "queue-overlap",
            UTC,
            (9, 0),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Queue,
                CatchUpPolicy::All,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        let first = scheduler.poll(&first_tick).expect("first run");
        assert_eq!(first.len(), 1);
        assert!(scheduler
            .poll(&second_tick)
            .expect("queue window")
            .is_empty());

        let queued = scheduler
            .complete(&first[0].dedupe_key, &completed)
            .expect("complete first run")
            .expect("admit queued window");
        assert_eq!(queued.scheduled_for, utc(2025, 1, 2, 9, 0, 0));
    }

    #[test]
    fn duplicate_poll_for_one_window_has_one_execution() {
        let registered = TestClock::at(utc(2025, 2, 1, 8, 59, 0));
        let window = TestClock::at(utc(2025, 2, 1, 9, 0, 0));
        let spec = daily_spec(
            "dedupe",
            UTC,
            (9, 0),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::All,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        assert_eq!(scheduler.poll(&window).expect("first poll").len(), 1);
        assert!(scheduler.poll(&window).expect("duplicate poll").is_empty());
    }

    #[test]
    fn misfire_policy_is_explicit_and_coalesce_uses_the_latest_window() {
        let registered = TestClock::at(utc(2025, 2, 1, 8, 0, 0));
        let late = TestClock::at(utc(2025, 2, 3, 10, 0, 0));
        let base = |id, policy| {
            daily_spec(
                id,
                UTC,
                (9, 0),
                (
                    policy,
                    OverlapPolicy::Skip,
                    CatchUpPolicy::All,
                    Duration::minutes(5),
                ),
            )
        };

        let mut skip = Scheduler::new();
        skip.register(base("skip-misfire", MisfirePolicy::Skip), &registered)
            .expect("register skip");
        assert!(skip.poll(&late).expect("poll skip").is_empty());

        let mut fire = Scheduler::new();
        fire.register(
            base("fire-misfire", MisfirePolicy::FireImmediately),
            &registered,
        )
        .expect("register fire");
        let admitted = fire.poll(&late).expect("poll fire");
        // FireImmediately tries every stale window. The explicit Skip overlap
        // policy allows the first one and durably suppresses the other two.
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].scheduled_for, utc(2025, 2, 1, 9, 0, 0));

        let mut coalesce = Scheduler::new();
        coalesce
            .register(
                base("coalesce-misfire", MisfirePolicy::Coalesce),
                &registered,
            )
            .expect("register coalesce");
        let admitted = coalesce.poll(&late).expect("poll coalesce");
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].scheduled_for, utc(2025, 2, 3, 9, 0, 0));
    }

    #[test]
    fn catch_up_latest_keeps_only_the_newest_due_window() {
        let registered = TestClock::at(utc(2025, 2, 1, 8, 0, 0));
        let resumed = TestClock::at(utc(2025, 2, 3, 9, 0, 0));
        let spec = daily_spec(
            "latest-catch-up",
            UTC,
            (9, 0),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Skip,
                CatchUpPolicy::Latest,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        let admitted = scheduler.poll(&resumed).expect("resume schedule");

        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].scheduled_for, utc(2025, 2, 3, 9, 0, 0));
    }

    #[test]
    fn cancellation_drops_queued_work_and_blocks_future_admissions() {
        let registered = TestClock::at(utc(2025, 1, 1, 8, 59, 0));
        let first_tick = TestClock::at(utc(2025, 1, 1, 9, 0, 0));
        let second_tick = TestClock::at(utc(2025, 1, 2, 9, 0, 0));
        let completed = TestClock::at(utc(2025, 1, 2, 9, 1, 0));
        let spec = daily_spec(
            "cancelled",
            UTC,
            (9, 0),
            (
                MisfirePolicy::FireImmediately,
                OverlapPolicy::Queue,
                CatchUpPolicy::All,
                Duration::minutes(5),
            ),
        );

        let mut scheduler = Scheduler::new();
        scheduler
            .register(spec, &registered)
            .expect("register schedule");
        let first = scheduler.poll(&first_tick).expect("first run");
        assert!(scheduler
            .poll(&second_tick)
            .expect("queue second run")
            .is_empty());
        scheduler
            .cancel(&ScheduleId::new("cancelled").expect("valid id"))
            .expect("cancel schedule");

        assert!(scheduler
            .complete(&first[0].dedupe_key, &completed)
            .expect("complete running work")
            .is_none());
    }
}
