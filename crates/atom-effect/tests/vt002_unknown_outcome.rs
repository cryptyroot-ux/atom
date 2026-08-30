//! ATOM-VT-002 — unknown external effect (EFX-003, INV-002).
//!
//! Scenario from `spec/acceptance/catalog.yaml`: the remote target commits the
//! write and then drops the response. Expected outcome: the effect sits in
//! UNKNOWN_OUTCOME and no blind duplicate is emitted.

mod support;

use atom_effect::{
    admit_dispatch, try_reduce, AdmissionError, EffectEvent, EffectIntent, EffectState,
    ObservedOutcome, ReconciledOutcome,
};
use support::{advanced, intent_in, sample_events, upstream_intent};

/// A target that really applies the write, then loses the response.
#[derive(Default)]
struct FlakyRemote {
    dispatched_keys: Vec<String>,
    probes: usize,
    committed: bool,
}

impl FlakyRemote {
    /// Applies the write, then drops the response — the classic ambiguity.
    fn dispatch(&mut self, idempotency_key: &str) -> Result<String, String> {
        self.dispatched_keys.push(idempotency_key.to_owned());
        self.committed = true;
        Err("connection reset before the response arrived".to_owned())
    }

    /// The reconciliation probe: a read, never a second write.
    fn probe(&mut self) -> ReconciledOutcome {
        self.probes += 1;
        if self.committed {
            ReconciledOutcome::Success
        } else {
            ReconciledOutcome::Failure
        }
    }
}

/// One admission-checked dispatch, with a lost response mapped to the
/// `DispatchAmbiguous` event a real dispatcher would append to the ledger.
fn dispatch_once(remote: &mut FlakyRemote, effect: &EffectIntent) -> EffectIntent {
    admit_dispatch(effect, &[]).expect("a DISPATCHING effect with no blockers is admissible");
    let key = effect
        .idempotency
        .key
        .as_deref()
        .expect("fixture effect carries a keyed idempotency scope (EFX-002)");
    match remote.dispatch(key) {
        Ok(external_id) => effect.try_advance(&EffectEvent::dispatched(Some(&external_id))),
        Err(reason) => effect.try_advance(&EffectEvent::dispatch_ambiguous(&reason)),
    }
    .expect("dispatch outcome events are legal in DISPATCHING")
}

#[test]
fn remote_that_commits_then_drops_the_response_lands_in_unknown_outcome() {
    let mut remote = FlakyRemote::default();
    let effect = dispatch_once(&mut remote, &intent_in(EffectState::Dispatching));

    assert_eq!(effect.state, EffectState::UnknownOutcome);
    assert!(remote.committed, "the fake remote really applied the write");
    assert_eq!(remote.dispatched_keys.len(), 1, "exactly one dispatch");
    assert!(effect.state.is_ambiguous());
    assert!(
        !effect.state.is_retryable_failure(),
        "INV-002: UNKNOWN_OUTCOME is not a retryable failure"
    );
    assert!(!effect.state.is_terminal(), "UNKNOWN_OUTCOME must be resolvable");
}

#[test]
fn no_blind_duplicate_is_emitted_while_the_outcome_is_unknown() {
    let mut remote = FlakyRemote::default();
    let effect = dispatch_once(&mut remote, &intent_in(EffectState::Dispatching));

    let denied = admit_dispatch(&effect, &[]).expect_err("an ambiguous effect must not re-dispatch");
    assert!(
        matches!(denied, AdmissionError::AmbiguousOutcome { .. }),
        "{denied:?}"
    );
    assert_eq!(
        remote.dispatched_keys.len(),
        1,
        "the remote was never called a second time"
    );

    // The reducer refuses the same thing structurally: no event walks
    // UNKNOWN_OUTCOME back into the dispatch or observation path.
    for event in [
        EffectEvent::dispatched(Some("ext-op-retry")),
        EffectEvent::ObservationStarted,
        EffectEvent::observed(ObservedOutcome::Success),
        EffectEvent::observed(ObservedOutcome::Failure),
    ] {
        assert!(
            try_reduce(EffectState::UnknownOutcome, &event).is_err(),
            "{event:?} must not be accepted in UNKNOWN_OUTCOME"
        );
    }
}

#[test]
fn unknown_outcome_is_never_coerced_to_success_or_failure() {
    for event in sample_events() {
        if let Ok(next) = try_reduce(EffectState::UnknownOutcome, &event) {
            assert_eq!(
                next,
                EffectState::Reconciling,
                "INV-002: UNKNOWN_OUTCOME may only advance to RECONCILING, got {next} via {event:?}"
            );
        }
    }
}

#[test]
fn dependent_mutation_is_blocked_until_the_unknown_effect_is_reconciled() {
    let mut remote = FlakyRemote::default();
    let upstream = dispatch_once(
        &mut remote,
        &advanced(upstream_intent(), EffectState::Dispatching),
    );
    assert_eq!(upstream.state, EffectState::UnknownOutcome);

    let dependent = intent_in(EffectState::Dispatching);
    assert_eq!(
        dependent.dependencies,
        vec![upstream.effect_id.clone()],
        "the fixture dependent declares the upstream edge (EFX-002)"
    );

    let blocked = admit_dispatch(&dependent, &[&upstream])
        .expect_err("EFX-003: dependents block until the ambiguity is resolved");
    assert!(
        matches!(blocked, AdmissionError::DependencyAmbiguous { .. }),
        "{blocked:?}"
    );

    let resolved = upstream
        .try_advance(&EffectEvent::ReconciliationStarted)
        .and_then(|effect| effect.try_advance(&EffectEvent::reconciled(ReconciledOutcome::Success)))
        .expect("UNKNOWN_OUTCOME -> RECONCILING -> CONFIRMED_SUCCESS is in spec");
    assert_eq!(resolved.state, EffectState::ConfirmedSuccess);
    admit_dispatch(&dependent, &[&resolved])
        .expect("a reconciled dependency unblocks the dependent mutation");
}

#[test]
fn reconciliation_resolves_the_unknown_without_a_second_write() {
    let mut remote = FlakyRemote::default();
    let effect = dispatch_once(&mut remote, &intent_in(EffectState::Dispatching));
    let effect = effect
        .try_advance(&EffectEvent::ReconciliationStarted)
        .expect("UNKNOWN_OUTCOME -> RECONCILING is the only exit");
    assert_eq!(effect.state, EffectState::Reconciling);

    let outcome = remote.probe();
    assert_eq!(
        outcome,
        ReconciledOutcome::Success,
        "the probe sees the write that really landed"
    );
    let effect = effect
        .try_advance(&EffectEvent::reconciled(outcome))
        .expect("RECONCILING -> CONFIRMED_SUCCESS is in spec");

    assert_eq!(effect.state, EffectState::ConfirmedSuccess);
    assert_eq!(
        remote.dispatched_keys.len(),
        1,
        "reconciliation reads the target, it never re-writes it"
    );
    assert_eq!(remote.probes, 1);
}

#[test]
fn inconclusive_reconciliation_returns_to_unknown_outcome() {
    let effect = intent_in(EffectState::Reconciling)
        .try_advance(&EffectEvent::reconciled(ReconciledOutcome::Inconclusive))
        .expect("RECONCILING -> UNKNOWN_OUTCOME is in spec");

    assert_eq!(effect.state, EffectState::UnknownOutcome);
    assert!(!effect.state.is_retryable_failure());
    assert!(matches!(
        admit_dispatch(&effect, &[]),
        Err(AdmissionError::AmbiguousOutcome { .. })
    ));
}

#[test]
fn every_ambiguity_source_lands_in_unknown_outcome() {
    let cases = [
        (
            EffectState::Dispatching,
            EffectEvent::dispatch_ambiguous("connection reset while sending"),
        ),
        (
            EffectState::Dispatched,
            EffectEvent::observation_lost("remote dropped the response"),
        ),
        (
            EffectState::Observing,
            EffectEvent::observed(ObservedOutcome::Ambiguous),
        ),
        (
            EffectState::Reconciling,
            EffectEvent::reconciled(ReconciledOutcome::Inconclusive),
        ),
        (
            EffectState::Compensating,
            EffectEvent::compensation_ambiguous("undo response was lost"),
        ),
    ];

    for (state, event) in cases {
        let next = try_reduce(state, &event)
            .unwrap_or_else(|error| panic!("{state} + {event:?} must be legal: {error}"));
        assert_eq!(next, EffectState::UnknownOutcome, "{state} + {event:?}");
    }
}

#[test]
fn a_definite_rejection_is_a_retryable_failure_unlike_an_unknown() {
    let effect = intent_in(EffectState::Dispatching)
        .try_advance(&EffectEvent::dispatch_rejected("target rejected the request"))
        .expect("DISPATCHING -> CONFIRMED_FAILURE is in spec");

    assert_eq!(effect.state, EffectState::ConfirmedFailure);
    assert!(
        effect.state.is_retryable_failure(),
        "a definite rejection is the only retryable failure"
    );
    assert!(!effect.state.is_ambiguous());
    admit_dispatch(&effect, &[]).expect_err("a settled effect is not dispatchable again");
}
