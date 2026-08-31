//! atom-benchmark: the reproducible 2G benchmark harness for ATOM.
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-BMK-001** (P0) — Any 2G superiority claim MUST use pinned
//!   competitor/runtime versions, same-model and best-native tracks, comparable
//!   budgets, multiple seeds, confidence intervals, fault/attack scenarios and
//!   public failure traces.
//! * **ATOM-VT-015** (acceptance) — Re-run the published benchmark from its
//!   manifest; pinned versions, seeds, budgets, traces and metrics MUST
//!   reproduce within declared tolerance.
//! * **ATOM-INV-020** (invariant) — No superiority claim is valid without
//!   pinned versions, comparable budgets, reproducible harnesses, and published
//!   failure traces.
//!
//! Status in the repo: the benchmark was `NOT-BUILT` and frozen (spec
//! `g0-release-checklist.yaml` H-14: "no 2G claim until reproducible"). This
//! crate closes H-14 by providing (a) a canonical, content-addressed benchmark
//! manifest, (b) a deterministic, reproducible run, and (c) an INV-020 claim
//! gate that REFUSES to emit a superiority claim unless every dimension is met
//! AND evidence has been published. The default state stays frozen — that is a
//! deliberate, tested property, not a missing feature.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod disk;

/// Error type for benchmark construction, execution and claim evaluation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BenchmarkError {
    /// The claim is frozen until evidence is published (H-14 / BMK-001 stance).
    #[error("claim frozen until evidence is published (H-14 / BMK-001)")]
    ClaimFrozen,
    /// An INV-020 dimension is unmet; the message names the missing dimension.
    #[error("INV-020 unmet: {0}")]
    Inv020Unmet(&'static str),
    /// Fewer than two tracks were present, so no comparison is possible.
    #[error("cannot compare fewer than two tracks")]
    CannotCompare,
}

/// Which kind of track a benchmark evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackType {
    /// Same model family, ATOM-native path.
    SameModel,
    /// Best native competitor implementation.
    BestNative,
}

/// A single evaluated track (same-model or best-native).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Track {
    pub name: String,
    pub track_type: TrackType,
    pub model: String,
}

/// Comparable budget spec across tracks (INV-020: comparable budgets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSpec {
    pub per_task_tokens: u64,
    /// True iff the budget is held constant across all tracks.
    pub comparable_across_tracks: bool,
}

/// Declared reproduction tolerance for a metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tolerance {
    pub metric: String,
    pub abs: f64,
}

/// The authoritative, content-addressed benchmark definition (BMK-001).
///
/// Every field participates in the canonical digest, so any change to a pinned
/// version, seed, budget or fault scenario produces a different manifest digest
/// (VT-015 sensitivity).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkManifest {
    pub name: String,
    /// Schema tag, e.g. "ATOM-BMK-001-v1".
    pub schema_version: String,
    /// Pinned competitor/runtime versions (INV-020: pinned versions).
    pub pinned_versions: BTreeMap<String, String>,
    pub tracks: Vec<Track>,
    pub budgets: BudgetSpec,
    /// Multiple seeds for reproducible variance (INV-020: multiple seeds).
    pub seeds: Vec<u64>,
    /// Fault/attack scenarios exercised (INV-020).
    pub fault_scenarios: Vec<String>,
    pub metrics: Vec<String>,
    pub tolerance: Tolerance,
    /// Freeze gate (H-14 / BMK-001): no claim until evidence published.
    pub evidence_published: bool,
    /// INV-020: public failure traces must be published.
    pub failure_traces_published: bool,
    /// SHA-256 digest of the exact task-suite bytes referenced by a published
    /// disk manifest. This makes task edits part of benchmark identity.
    pub task_set_digest: String,
}

impl BenchmarkManifest {
    /// A minimal, *frozen* in-memory fixture (evidence not published).
    ///
    /// This exists solely for isolated claim-gate tests. VT-015 must load the
    /// checked-in benchmark artifact under `benchmarks/`, never this fixture.
    #[must_use]
    pub fn example() -> Self {
        let mut pinned = BTreeMap::new();
        pinned.insert("atom-runtime".to_string(), "0.0.0-alpha.0".to_string());
        pinned.insert("competitor-x".to_string(), "v2.3.1".to_string());
        Self {
            name: "2g-repro-example".to_string(),
            schema_version: "ATOM-BMK-001-v1".to_string(),
            pinned_versions: pinned,
            tracks: vec![
                Track {
                    name: "same-model".to_string(),
                    track_type: TrackType::SameModel,
                    model: "atom-runtime".to_string(),
                },
                Track {
                    name: "best-native".to_string(),
                    track_type: TrackType::BestNative,
                    model: "competitor-x".to_string(),
                },
            ],
            budgets: BudgetSpec {
                per_task_tokens: 4_000,
                comparable_across_tracks: true,
            },
            seeds: vec![1, 2, 3],
            fault_scenarios: vec!["prompt-injection".to_string()],
            metrics: vec!["score".to_string()],
            tolerance: Tolerance {
                metric: "score".to_string(),
                abs: 0.01,
            },
            // Frozen by default — no 2G claim until evidence is published.
            evidence_published: false,
            failure_traces_published: false,
            task_set_digest: "sha256:example-not-file-backed".to_string(),
        }
    }

    /// Returns a copy with both evidence gates opened (used only in tests that
    /// exercise the *capability* of the claim gate, never to assert a win).
    #[must_use]
    pub fn published(mut self) -> Self {
        self.evidence_published = true;
        self.failure_traces_published = true;
        self
    }
}

/// Canonicalize a `serde_json::Value`: recursively sort object keys (RFC 8785
/// spirit) while preserving array order. Two manifests that differ only in key
/// ordering serialize identically.
fn canonicalize(value: &serde_json::Value) -> String {
    fn sort(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                let mut rebuilt = serde_json::Map::new();
                for k in keys {
                    let mut child = map.get(&k).cloned().unwrap();
                    sort(&mut child);
                    rebuilt.insert(k, child);
                }
                *v = serde_json::Value::Object(rebuilt);
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    sort(item);
                }
            }
            _ => {}
        }
    }
    let mut v = value.clone();
    sort(&mut v);
    serde_json::to_string(&v).expect("canonical json serializes")
}

/// Content-address of a manifest: `sha256:<hex>` over its canonical form.
#[must_use]
pub fn manifest_digest(manifest: &BenchmarkManifest) -> String {
    let value = serde_json::to_value(manifest).expect("manifest serializes");
    let canon = canonicalize(&value);
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Deterministic 64-bit derivation from a manifest digest + salt. No entropy
/// from time, RNG or system state — this is what makes a run reproducible.
fn derive_u64(digest: &str, salt: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(digest.as_bytes());
    hasher.update(salt);
    let out = hasher.finalize();
    u64::from_le_bytes(out[0..8].try_into().unwrap())
}

/// A single benchmark task with a known-correct answer.
///
/// The suite is fixed and content-addressed, so the same tasks run on every
/// invocation (VT-015 reproducibility). A task is "passed" only when the system
/// under test returns exactly `expected`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkTask {
    pub id: String,
    pub prompt: String,
    pub expected: String,
    /// Tokens charged when this task is attempted (counts toward the budget).
    pub cost_tokens: u64,
}

/// The system being measured. A real ATOM runtime — or a competitor — implements
/// this trait; the harness stays provider-agnostic and only observes pass/fail.
///
/// This is the seam that replaces the old manifest-digest hash: scores now come
/// from actually attempting tasks through a swappable implementation, not from
/// hashing the manifest.
pub trait SystemUnderTest {
    /// Attempt one task under a given seed and return the produced answer.
    fn attempt(&self, task: &BenchmarkTask, seed: u64) -> String;
}

/// The default, fixed task suite: `sum(0..=i)` with a known integer answer.
#[must_use]
pub fn default_suite() -> Vec<BenchmarkTask> {
    (0..10u64)
        .map(|i| BenchmarkTask {
            id: format!("sum-{i:02}"),
            prompt: format!("compute the sum of 0..={i}"),
            expected: (0..=i).sum::<u64>().to_string(),
            cost_tokens: 100 + i * 10,
        })
        .collect()
}

/// A deterministic reference solver used as the default system under test.
///
/// It is a stand-in agent, NOT a real ATOM runtime: its per-task success is a
/// deterministic function of the track and seed (never of unrelated manifest
/// fields), so runs reproduce exactly. Swap in a real [`SystemUnderTest`] to
/// measure a real system.
pub struct ReferenceSolver {
    track_salt: String,
    competence: u64,
}

impl ReferenceSolver {
    /// Builds a reference solver whose competence depends on the track type.
    #[must_use]
    pub fn for_track(track: &Track) -> Self {
        let competence = match track.track_type {
            TrackType::SameModel => 70,
            TrackType::BestNative => 60,
        };
        Self {
            track_salt: format!("{}::{}", track.name, track.model),
            competence,
        }
    }
}

impl SystemUnderTest for ReferenceSolver {
    fn attempt(&self, task: &BenchmarkTask, seed: u64) -> String {
        let salt = format!("{};seed={seed};task={}", self.track_salt, task.id);
        // Deterministic "roll" in 0..100; the task is solved iff it falls below
        // the competence bar. No time/RNG entropy => reproducible.
        let roll = derive_u64(&salt, b"attempt") % 100;
        if roll < self.competence {
            task.expected.clone()
        } else {
            format!("WRONG:{}", task.id)
        }
    }
}

/// One (track, seed) evaluation result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackResult {
    pub track: String,
    pub seed: u64,
    pub score: f64,
    pub cost_tokens: u64,
    pub latency_ms: f64,
}

/// Per-track aggregate over all seeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackAggregate {
    pub track: String,
    pub mean_score: f64,
    pub ci95_low: f64,
    pub ci95_high: f64,
    pub n: usize,
}

/// A full, deterministic benchmark run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRun {
    pub manifest_digest: String,
    pub results: Vec<TrackResult>,
    pub aggregates: Vec<TrackAggregate>,
}

/// 95% Wald confidence interval from a sample.
fn ci95(samples: &[f64]) -> (f64, f64) {
    let n = samples.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    let mean = samples.iter().sum::<f64>() / n as f64;
    if n == 1 {
        return (mean, mean);
    }
    let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
    let se = (var / n as f64).sqrt();
    let z = 1.96;
    (mean - z * se, mean + z * se)
}

impl BenchmarkRun {
    /// Execute the manifest against the default task suite with the built-in
    /// reference solver per track. Identical manifest + identical environment =>
    /// identical results (VT-015).
    #[must_use]
    pub fn new(manifest: &BenchmarkManifest) -> Self {
        Self::execute(manifest, &default_suite(), |track| {
            Box::new(ReferenceSolver::for_track(track))
        })
    }

    /// Execute the manifest against an explicit task suite, building one system
    /// under test per track via `sut_for`. This is the real (if reference-backed)
    /// evaluation loop: every task is attempted and checked against its expected
    /// answer; the score is the measured pass-rate, not a hash of the manifest.
    #[must_use]
    pub fn execute<F>(manifest: &BenchmarkManifest, suite: &[BenchmarkTask], mut sut_for: F) -> Self
    where
        F: FnMut(&Track) -> Box<dyn SystemUnderTest>,
    {
        let md = manifest_digest(manifest);
        let mut results = Vec::new();
        for track in &manifest.tracks {
            let sut = sut_for(track);
            for &seed in &manifest.seeds {
                let mut passed = 0usize;
                let mut cost_tokens = 0u64;
                for task in suite {
                    cost_tokens = cost_tokens.saturating_add(task.cost_tokens);
                    if sut.attempt(task, seed) == task.expected {
                        passed += 1;
                    }
                }
                let score = if suite.is_empty() {
                    0.0
                } else {
                    passed as f64 / suite.len() as f64
                };
                let latency = 50.0 + (cost_tokens as f64) * 0.01;
                results.push(TrackResult {
                    track: track.name.clone(),
                    seed,
                    score,
                    cost_tokens,
                    latency_ms: latency,
                });
            }
        }
        let mut aggregates = Vec::new();
        for track in &manifest.tracks {
            let samples: Vec<f64> = results
                .iter()
                .filter(|r| r.track == track.name)
                .map(|r| r.score)
                .collect();
            let n = samples.len();
            let mean = if n > 0 {
                samples.iter().sum::<f64>() / n as f64
            } else {
                0.0
            };
            let (lo, hi) = ci95(&samples);
            aggregates.push(TrackAggregate {
                track: track.name.clone(),
                mean_score: mean,
                ci95_low: lo,
                ci95_high: hi,
                n,
            });
        }
        Self {
            manifest_digest: md,
            results,
            aggregates,
        }
    }

    /// Content-address of the run's results — used to prove reproducibility
    /// (VT-015): two runs of the same manifest must yield the same digest.
    #[must_use]
    pub fn digest(&self) -> String {
        let value = serde_json::to_value(self).expect("run serializes");
        let canon = canonicalize(&value);
        let mut hasher = Sha256::new();
        hasher.update(canon.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// A superiority claim produced only when INV-020 is fully satisfied.
#[derive(Clone, Debug, PartialEq)]
pub struct SuperiorityClaim {
    pub manifest_digest: String,
    pub winner_track: String,
    pub loser_track: String,
    pub metric: String,
    pub delta: f64,
    pub ci95_low: f64,
    pub ci95_high: f64,
    /// 0.95 if the winner's CI excludes zero, else 0.0.
    pub confidence: f64,
}

/// Evaluate a 2G superiority claim against the manifest and its run.
///
/// Refuses (returns `Err`) unless:
/// 1. evidence is published (H-14 / BMK-001 freeze),
/// 2. failure traces are published (INV-020),
/// 3. at least two pinned versions, at least three seeds, comparable budgets,
///    one or more fault scenarios (INV-020), and at least two tracks compared.
///
/// This is the honest "no superiority claim without reproducible evidence" gate.
pub fn evaluate_superiority(
    manifest: &BenchmarkManifest,
    run: &BenchmarkRun,
) -> Result<SuperiorityClaim, BenchmarkError> {
    if !manifest.evidence_published {
        return Err(BenchmarkError::ClaimFrozen);
    }
    if !manifest.failure_traces_published {
        return Err(BenchmarkError::Inv020Unmet("failure traces not published"));
    }
    if manifest.pinned_versions.len() < 2 {
        return Err(BenchmarkError::Inv020Unmet("fewer than 2 pinned versions"));
    }
    if manifest.seeds.len() < 3 {
        return Err(BenchmarkError::Inv020Unmet("fewer than 3 seeds"));
    }
    if !manifest.budgets.comparable_across_tracks {
        return Err(BenchmarkError::Inv020Unmet(
            "budgets not comparable across tracks",
        ));
    }
    if manifest.fault_scenarios.is_empty() {
        return Err(BenchmarkError::Inv020Unmet("no fault/attack scenarios"));
    }
    if run.aggregates.len() < 2 {
        return Err(BenchmarkError::CannotCompare);
    }

    // Pick winner = highest mean score, loser = lowest.
    let mut best = &run.aggregates[0];
    let mut worst = &run.aggregates[0];
    for a in &run.aggregates {
        if a.mean_score > best.mean_score {
            best = a;
        }
        if a.mean_score < worst.mean_score {
            worst = a;
        }
    }
    let delta = best.mean_score - worst.mean_score;
    let confidence = if best.ci95_low > 0.0 { 0.95 } else { 0.0 };

    Ok(SuperiorityClaim {
        manifest_digest: run.manifest_digest.clone(),
        winner_track: best.track.clone(),
        loser_track: worst.track.clone(),
        metric: manifest
            .metrics
            .first()
            .cloned()
            .unwrap_or_else(|| "score".to_string()),
        delta,
        ci95_low: best.ci95_low,
        ci95_high: best.ci95_high,
        confidence,
    })
}
