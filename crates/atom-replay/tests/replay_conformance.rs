//! Conformance for atom-replay against ATOM-RPL-001 and ATOM-INV-010.
//!
//! Every acceptance bullet in TASK.md has a test here:
//!
//! * R0/R1 identical-state-digest — replaying the same committed log twice
//!   yields the same state and trajectory digest (RPL-001 verification).
//! * R2 cassette — replay resolves only from the cassette; a missing entry is a
//!   typed `CassetteMiss`; no live-call path exists.
//! * INV-010 — a log with consequential effects, when replayed, re-dispatches
//!   nothing; a `LiveForkPolicy` mints a NEW effect identity that differs from
//!   the original.
//! * R3/R4 — calling replay at R3/R4 returns the typed labeled `Unsupported`
//!   result, not a fabricated success and not a panic.
//! * No universal exact-replay — the explicit non-claim is exposed and worded.
//!
//! Fixtures are literal and clock-free, mirroring the atom-effect suite: the
//! crate under test never reads a clock, so identical inputs must produce
//! identical digests.

use atom_effect::{
    Compensation, CompensationStrategy, Condition, EffectEvent, EffectIntent, EffectState,
    Idempotency, ObservedOutcome, Reconciliation, ReconciliationClass, RetryClass,
};
use atom_replay::{
    live_fork, replay, Cassette, LiveForkPolicy, RecordedResponse, ReplayClass, ReplayError,
    ReplayInput, NO_UNIVERSAL_EXACT_REPLAY,
};

const GRANT_ID: &str = "grant/orders-writer";
const GRANT_GENERATION: u64 = 7;
const EXTERNAL_OPERATION_ID: &str = "ext-op-8842";

/// The CommitPermitted event a real commit gate emits (identity, not action).
fn sample_commit_permitted(effect: &EffectIntent) -> EffectEvent {
    use atom_effect::CommitPermitted;
    EffectEvent::CommitPermitted(CommitPermitted {
        permit_id: "permit/01J8ZPCOMMITORDERS".into(),
        one_shot_nonce: "nonce/01J8ZPCOMMITORDERS".into(),
        effect_digest: effect.digest(),
    })
}

/// A complete EffectIntent carrying every EFX-002 field, in INTENT_DURABLE.
fn intent() -> EffectIntent {
    EffectIntent::builder(
        "effect/01J8ZPEFFECTORDERS",
        "mission/01J8Z0MISSIONORDERS",
        GRANT_ID,
        "db/orders",
    )
    .canonical_request_digest(
        "sha256:5f2c9e1d8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
    )
    .classes("RESOURCE_MUTATION", "HIGH")
    .idempotency(Idempotency::keyed("db/orders", "idem-8842"))
    .reconciliation(
        Reconciliation::new(
            ReconciliationClass::ExternalOperationLookup,
            RetryClass::ReconcileBeforeRetry,
        )
        .with_probe("GET /orders/8842"),
    )
    .precondition(Condition::new("pre/row-exists", "orders.id == 8842"))
    .postcondition(Condition::new(
        "post/row-archived",
        "orders.state == 'ARCHIVED'",
    ))
    .compensation(
        Compensation::new(CompensationStrategy::InverseOperation)
            .with_operation("POST /orders/8842/restore"),
    )
    .build()
    .expect("fixture intent satisfies EFX-002")
}

/// A committed log that dispatched a consequential effect and confirmed success.
///
/// This is the log INV-010 protects: it contains a real DISPATCHED transition.
fn consequential_log(effect: &EffectIntent) -> Vec<EffectEvent> {
    vec![
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(GRANT_ID, GRANT_GENERATION),
        EffectEvent::CommitRevalidationStarted,
        sample_commit_permitted(effect),
        EffectEvent::dispatched(Some(EXTERNAL_OPERATION_ID)),
        EffectEvent::ObservationStarted,
        EffectEvent::observed(ObservedOutcome::Success),
    ]
}

// --- R0 / R1: identical-state-digest (RPL-001 verification) ----------------

#[test]
fn r0_state_replay_is_deterministic_across_reruns() {
    let effect = intent();
    let input = ReplayInput::new(EffectState::IntentDurable, consequential_log(&effect));

    let first = replay(ReplayClass::StateReplay, &input).expect("R0 supported");
    let second = replay(ReplayClass::StateReplay, &input).expect("R0 supported");

    assert_eq!(first.derived_state, EffectState::ConfirmedSuccess);
    assert_eq!(
        first.digest, second.digest,
        "R0: the same committed log must project to the same state digest"
    );
    assert!(first.digest.starts_with("sha256:"));
    assert_eq!(first.digest.len(), "sha256:".len() + 64);
}

#[test]
fn r1_reducer_replay_yields_byte_identical_trajectory_digest() {
    let effect = intent();
    let log = consequential_log(&effect);
    let input = ReplayInput::new(EffectState::IntentDurable, log.clone());

    let first = replay(ReplayClass::ReducerReplay, &input).expect("R1 supported");
    let second = replay(ReplayClass::ReducerReplay, &input).expect("R1 supported");

    assert_eq!(
        first.digest, second.digest,
        "R1: identical log yields byte-identical trajectory digest (RPL-001)"
    );
    // R1 reuses atom-effect's trajectory digest exactly.
    assert_eq!(
        first.digest,
        atom_effect::trajectory_digest(EffectState::IntentDurable, &log)
    );
    assert_eq!(first.derived_state, EffectState::ConfirmedSuccess);
}

#[test]
fn r0_and_r1_digests_are_distinct_domains() {
    let effect = intent();
    let input = ReplayInput::new(EffectState::IntentDurable, consequential_log(&effect));

    let r0 = replay(ReplayClass::StateReplay, &input).unwrap();
    let r1 = replay(ReplayClass::ReducerReplay, &input).unwrap();
    assert_ne!(
        r0.digest, r1.digest,
        "a destination digest and a trajectory digest must not collide"
    );
}

#[test]
fn a_different_route_to_the_same_state_replays_to_a_different_r1_digest() {
    // Two logs both ending in UNKNOWN_OUTCOME by different routes.
    let effect = intent();
    let mut via_dispatch = vec![
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(GRANT_ID, GRANT_GENERATION),
        EffectEvent::CommitRevalidationStarted,
        sample_commit_permitted(&effect),
    ];
    via_dispatch.push(EffectEvent::dispatch_ambiguous("connection reset"));

    let via_observation = vec![
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(GRANT_ID, GRANT_GENERATION),
        EffectEvent::CommitRevalidationStarted,
        sample_commit_permitted(&effect),
        EffectEvent::dispatched(Some(EXTERNAL_OPERATION_ID)),
        EffectEvent::observation_lost("remote dropped the response"),
    ];

    let a = replay(
        ReplayClass::ReducerReplay,
        &ReplayInput::new(EffectState::IntentDurable, via_dispatch),
    )
    .unwrap();
    let b = replay(
        ReplayClass::ReducerReplay,
        &ReplayInput::new(EffectState::IntentDurable, via_observation),
    )
    .unwrap();

    assert_eq!(a.derived_state, EffectState::UnknownOutcome);
    assert_eq!(b.derived_state, EffectState::UnknownOutcome);
    assert_ne!(
        a.digest, b.digest,
        "different routes must be distinguishable"
    );
}

#[test]
fn an_off_spec_committed_log_is_a_typed_reduce_error_not_a_panic() {
    // Re-requesting authorization after dispatch has no spec edge.
    let effect = intent();
    let mut log = consequential_log(&effect);
    log.push(EffectEvent::AuthorizationRequested);

    let error = replay(
        ReplayClass::ReducerReplay,
        &ReplayInput::new(EffectState::IntentDurable, log),
    )
    .expect_err("an off-spec event in a committed log is a divergence");
    assert!(matches!(error, ReplayError::Reduce(_)), "{error:?}");
}

// --- R2: cassette-only, typed miss, no live path ---------------------------

#[test]
fn r2_resolves_only_from_the_cassette() {
    let req = "sha256:req-archive-8842";
    let mut cassette = Cassette::new();
    cassette.record(req, RecordedResponse::recorded("SUCCESS", b"{\"ok\":true}"));

    let effect = intent();
    let input = ReplayInput::new(EffectState::IntentDurable, consequential_log(&effect))
        .with_cassette(cassette, vec![req.to_owned()]);

    let report = replay(ReplayClass::ActivityCassetteReplay, &input).expect("R2 supported");
    assert_eq!(report.cassette_resolutions.len(), 1);
    assert_eq!(report.cassette_resolutions[0].request_digest, req);
    assert_eq!(report.cassette_resolutions[0].outcome, "SUCCESS");
    assert!(
        !report.re_emitted(),
        "R2 resolves recordings, it does not act"
    );
}

#[test]
fn r2_cassette_miss_is_a_typed_error_never_a_live_call() {
    let recorded = "sha256:req-archive-8842";
    let missing = "sha256:req-archive-9999";
    let mut cassette = Cassette::new();
    cassette.record(recorded, RecordedResponse::recorded("SUCCESS", b"{}"));

    let effect = intent();
    let input = ReplayInput::new(EffectState::IntentDurable, consequential_log(&effect))
        .with_cassette(cassette, vec![missing.to_owned()]);

    let error =
        replay(ReplayClass::ActivityCassetteReplay, &input).expect_err("a miss must stop replay");
    match error {
        ReplayError::CassetteMiss { request_digest } => assert_eq!(request_digest, missing),
        other => panic!("expected CassetteMiss, got {other:?}"),
    }
}

#[test]
fn r2_replay_is_deterministic_across_reruns() {
    let req = "sha256:req-archive-8842";
    let mut cassette = Cassette::new();
    cassette.record(req, RecordedResponse::recorded("SUCCESS", b"body"));

    let effect = intent();
    let input = ReplayInput::new(EffectState::IntentDurable, consequential_log(&effect))
        .with_cassette(cassette, vec![req.to_owned()]);

    let a = replay(ReplayClass::ActivityCassetteReplay, &input).unwrap();
    let b = replay(ReplayClass::ActivityCassetteReplay, &input).unwrap();
    assert_eq!(a.digest, b.digest, "R2 digest must be reproducible");
}

#[test]
fn a_cassette_reserializes_identically() {
    // A cassette is itself replay-stable data (ordered map).
    let mut cassette = Cassette::new();
    cassette.record("b", RecordedResponse::recorded("OK", b"1"));
    cassette.record("a", RecordedResponse::recorded("OK", b"2"));

    let json = serde_json::to_string(&cassette).unwrap();
    let back: Cassette = serde_json::from_str(&json).unwrap();
    assert_eq!(cassette, back);
    assert_eq!(cassette.len(), 2);
    assert!(cassette.contains("a") && cassette.contains("b"));
}

// --- INV-010: no re-emit unless explicit live-fork -------------------------

#[test]
fn replay_never_re_emits_consequential_effects() {
    let effect = intent();
    let log = consequential_log(&effect);

    // The log DID dispatch a consequential effect.
    let input = ReplayInput::new(EffectState::IntentDurable, log);
    for class in [
        ReplayClass::StateReplay,
        ReplayClass::ReducerReplay,
        ReplayClass::ActivityCassetteReplay,
    ] {
        let report = replay(class, &input).expect("supported class");
        assert_eq!(
            report.consequential_in_log,
            1,
            "{}: the log's dispatch must be re-derived and counted",
            class.code()
        );
        assert!(
            report.re_dispatched.is_empty(),
            "{}: replay must re-dispatch nothing (INV-010)",
            class.code()
        );
        assert!(
            !report.re_emitted(),
            "{}: replay must not re-emit (INV-010)",
            class.code()
        );
    }
}

#[test]
fn live_fork_mints_a_new_effect_identity_that_differs_from_the_original() {
    let origin = intent();
    let policy = LiveForkPolicy::new(
        "principal/operator",
        "authorized re-run after incident review",
        "fork-nonce-001",
    );

    let forked = live_fork(&origin, &policy).expect("explicit policy authorizes a fork");

    // The whole point of INV-010's escape: identity CHANGES.
    assert_ne!(
        forked.forked_effect_id, forked.origin_effect_id,
        "a live fork must mint a NEW effect_id"
    );
    assert_eq!(forked.origin_effect_id, origin.effect_id);
    assert_eq!(forked.origin_digest, origin.digest());
    assert_ne!(
        forked.forked_digest(),
        origin.digest(),
        "the forked effect digest must differ from the original identity"
    );
    // The fork mints identity only: the new intent is durable-but-unauthorized.
    assert_eq!(forked.forked_intent.state, EffectState::IntentDurable);
    assert_eq!(forked.forked_intent.effect_id, forked.forked_effect_id);
}

#[test]
fn two_forks_of_the_same_effect_have_distinct_identities() {
    let origin = intent();
    let a = live_fork(&origin, &LiveForkPolicy::new("p", "reason", "fork-nonce-A")).unwrap();
    let b = live_fork(&origin, &LiveForkPolicy::new("p", "reason", "fork-nonce-B")).unwrap();
    assert_ne!(a.forked_effect_id, b.forked_effect_id);
    assert_ne!(a.forked_digest(), b.forked_digest());
}

#[test]
fn live_fork_is_deterministic_for_the_same_policy() {
    let origin = intent();
    let policy = LiveForkPolicy::new("p", "reason", "fork-nonce-X");
    let a = live_fork(&origin, &policy).unwrap();
    let b = live_fork(&origin, &policy).unwrap();
    assert_eq!(a.forked_effect_id, b.forked_effect_id);
    assert_eq!(a.forked_digest(), b.forked_digest());
}

#[test]
fn a_blank_live_fork_policy_field_is_refused() {
    let origin = intent();
    let error = live_fork(&origin, &LiveForkPolicy::new("", "reason", "nonce"))
        .expect_err("a blank authorizer cannot mint identity");
    assert!(matches!(
        error,
        ReplayError::BlankForkField {
            field: "authorized_by"
        }
    ));
}

// --- R3 / R4: typed labeled Unsupported, never fabricated, never panic -----

#[test]
fn r3_and_r4_return_the_typed_labeled_unsupported_result() {
    let input = ReplayInput::new(EffectState::IntentDurable, Vec::new());

    for class in [
        ReplayClass::LiveForkModelReexecution,
        ReplayClass::StatisticalReproduction,
    ] {
        assert!(
            !class.is_supported(),
            "{} is out of scope for alpha",
            class.code()
        );
        let error = replay(class, &input).expect_err("R3/R4 must refuse, not fabricate a success");
        match error {
            ReplayError::Unsupported {
                class: refused,
                code,
                label,
                guarantee,
            } => {
                assert_eq!(refused, class);
                assert_eq!(code, class.code());
                assert_eq!(label, class.label());
                assert_eq!(guarantee, class.guarantee());
            }
            other => panic!("expected Unsupported for {}, got {other:?}", class.code()),
        }
    }
}

#[test]
fn the_class_table_matches_spec_enums() {
    assert_eq!(ReplayClass::ALL.len(), 5);
    let table = [
        (ReplayClass::StateReplay, "R0", "STATE_REPLAY", true),
        (ReplayClass::ReducerReplay, "R1", "REDUCER_REPLAY", true),
        (
            ReplayClass::ActivityCassetteReplay,
            "R2",
            "ACTIVITY_CASSETTE_REPLAY",
            true,
        ),
        (
            ReplayClass::LiveForkModelReexecution,
            "R3",
            "LIVE_FORK_MODEL_REEXECUTION",
            false,
        ),
        (
            ReplayClass::StatisticalReproduction,
            "R4",
            "STATISTICAL_REPRODUCTION",
            false,
        ),
    ];
    for (class, code, label, supported) in table {
        assert_eq!(class.code(), code);
        assert_eq!(class.label(), label);
        assert_eq!(class.is_supported(), supported);
        assert!(!class.guarantee().is_empty());
    }
}

// --- The explicit non-claim (ATOM-RPL-001) ------------------------------

#[test]
fn there_is_no_universal_exact_replay_claim() {
    assert!(NO_UNIVERSAL_EXACT_REPLAY.contains("no universal exact-replay"));
    // Each class states its own bounded guarantee rather than a universal one.
    assert!(ReplayClass::ActivityCassetteReplay
        .guarantee()
        .contains("bounded to the recorded cassette"));
    assert!(ReplayClass::StatisticalReproduction
        .guarantee()
        .contains("never an exact-replay claim"));
}
