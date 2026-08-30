//! Conformance of the reducer against `spec/state-machines/effect.yaml`.
//!
//! The spec file is the authority: it is parsed here and every claim in this
//! suite is checked against it, so a code/spec disagreement fails the build
//! rather than drifting silently.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use atom_effect::{
    project, reduce, trajectory_digest, try_project, try_reduce, EffectEvent, EffectState,
    ReduceError,
};
use support::{intent, intent_in, path_to, sample_events};

const SPEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/state-machines/effect.yaml"
));

/// The two facts this suite needs from the spec: the state list and the
/// adjacency map. `effect.yaml` is regular enough that a short reader is safer
/// than a YAML dependency — and the counts asserted below make a misparse loud.
fn spec_machine() -> (Vec<String>, BTreeMap<String, Vec<String>>) {
    let mut states = Vec::new();
    let mut transitions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut section = String::new();
    let mut source = String::new();

    for raw in SPEC.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(item) = line.strip_prefix("- ") {
            match section.as_str() {
                "states" => states.push(item.to_owned()),
                "transitions" => transitions
                    .get_mut(&source)
                    .expect("a target list follows its source key")
                    .push(item.to_owned()),
                other => panic!("unexpected list under `{other}`: {line}"),
            }
            continue;
        }
        let Some(name) = line.strip_suffix(':') else {
            continue; // `version:` and `invariant:` scalars
        };
        if raw.len() == line.len() {
            section = name.to_owned();
            source.clear();
        } else if section == "transitions" {
            source = name.to_owned();
            transitions.entry(source.clone()).or_default();
        }
    }

    (states, transitions)
}

fn state(name: &str) -> EffectState {
    EffectState::from_str(name).unwrap_or_else(|error| panic!("spec state {name}: {error}"))
}

#[test]
fn the_spec_file_parses_into_the_shape_this_suite_assumes() {
    let (states, transitions) = spec_machine();

    assert_eq!(states.len(), 16, "spec/state-machines/effect.yaml: {states:?}");
    assert_eq!(transitions.len(), 11, "source states: {transitions:?}");
    assert_eq!(
        transitions.values().map(Vec::len).sum::<usize>(),
        28,
        "edges: {transitions:?}"
    );
}

#[test]
fn the_state_enum_is_exactly_the_spec_state_list() {
    let (states, _) = spec_machine();

    let declared: Vec<&str> = EffectState::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(declared, states, "16 states, in spec order, no redefinition");

    let unique: BTreeSet<&str> = declared.iter().copied().collect();
    assert_eq!(unique.len(), EffectState::ALL.len());

    for name in &states {
        let parsed = state(name);
        assert_eq!(parsed.as_str(), name);
        assert_eq!(parsed.to_string(), *name);
    }
    assert!(EffectState::from_str("NOT_A_STATE").is_err());
}

#[test]
fn the_adjacency_map_matches_the_spec_edge_for_edge() {
    let (_, transitions) = spec_machine();

    let mut expected: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (source, targets) in &transitions {
        for target in targets {
            expected.insert((source.as_str(), target.as_str()));
            assert!(
                state(source).can_transition_to(state(target)),
                "spec edge {source} -> {target} is missing from the code"
            );
        }
    }

    for from in EffectState::ALL {
        for to in EffectState::ALL {
            let in_spec = expected.contains(&(from.as_str(), to.as_str()));
            assert_eq!(
                from.can_transition_to(to),
                in_spec,
                "{from} -> {to}: code says {}, spec says {in_spec}",
                from.can_transition_to(to)
            );
        }
    }
}

#[test]
fn every_spec_edge_is_reachable_through_at_least_one_event() {
    let (_, transitions) = spec_machine();
    let events = sample_events();

    for (source, targets) in &transitions {
        let from = state(source);
        for target in targets {
            let to = state(target);
            let reached = events
                .iter()
                .any(|event| try_reduce(from, event) == Ok(to));
            assert!(reached, "no event drives {source} -> {target}");
        }
    }
}

#[test]
fn no_event_produces_a_transition_the_spec_does_not_list() {
    for from in EffectState::ALL {
        for event in sample_events() {
            match try_reduce(from, &event) {
                Ok(to) => assert!(
                    from.can_transition_to(to),
                    "{from} + {event:?} produced the off-spec edge {from} -> {to}"
                ),
                Err(_) => {
                    assert_eq!(
                        reduce(from, &event),
                        from,
                        "the total reducer must leave a refused event as a no-op"
                    );
                }
            }
        }
    }
}

#[test]
fn terminal_states_accept_no_further_events() {
    let terminal = [
        EffectState::ConfirmedSuccess,
        EffectState::ConfirmedFailure,
        EffectState::CancelledBeforeEffect,
        EffectState::Compensated,
        EffectState::CompensationFailed,
    ];

    for from in EffectState::ALL {
        assert_eq!(
            from.is_terminal(),
            terminal.contains(&from),
            "{from}: terminality must match the spec's empty transition list"
        );
        if from.is_terminal() {
            assert!(from.allowed_transitions().is_empty(), "{from}");
            for event in sample_events() {
                assert!(
                    try_reduce(from, &event).is_err(),
                    "{from} is terminal but accepted {event:?}"
                );
            }
        }
    }
}

/// INV-002 at the level of the transition table.
#[test]
fn unknown_outcome_leaves_only_through_reconciliation() {
    let (_, transitions) = spec_machine();
    assert_eq!(transitions["UNKNOWN_OUTCOME"], vec!["RECONCILING".to_owned()]);
    assert_eq!(
        EffectState::UnknownOutcome.allowed_transitions(),
        &[EffectState::Reconciling]
    );

    for from in EffectState::ALL {
        assert_eq!(
            from.is_ambiguous(),
            from == EffectState::UnknownOutcome,
            "{from}"
        );
        assert_eq!(
            from.is_retryable_failure(),
            from == EffectState::ConfirmedFailure,
            "{from}: UNKNOWN_OUTCOME is not a retryable failure"
        );
        assert_eq!(
            from.blocks_dependents(),
            matches!(from, EffectState::UnknownOutcome | EffectState::Reconciling),
            "{from}: EFX-003 blocks dependents until reconciled"
        );
    }
}

#[test]
fn projection_replays_every_fixture_log_deterministically() {
    for target in EffectState::ALL {
        let log = path_to(target);
        assert_eq!(try_project(EffectState::IntentDurable, &log), Ok(target));
        assert_eq!(project(EffectState::IntentDurable, &log), target);

        let digest = trajectory_digest(EffectState::IntentDurable, &log);
        assert_eq!(
            digest,
            trajectory_digest(EffectState::IntentDurable, &path_to(target)),
            "{target}: the same event log must digest identically"
        );
        assert!(digest.starts_with("sha256:"), "{digest}");
        assert_eq!(digest.len(), "sha256:".len() + 64, "{digest}");

        let effect = intent_in(target);
        assert_eq!(effect.state, target);
        assert_eq!(effect.state_digest(), intent_in(target).state_digest());
        assert_eq!(
            effect.digest(),
            intent().digest(),
            "{target}: the identity digest must not move with the state"
        );
    }

    let state_digests: BTreeSet<String> = EffectState::ALL
        .iter()
        .map(|target| intent_in(*target).state_digest())
        .collect();
    assert_eq!(state_digests.len(), 16, "each state digests differently");
}

#[test]
fn the_trajectory_digest_covers_the_route_and_not_just_the_destination() {
    let mut via_dispatch = path_to(EffectState::Dispatching);
    via_dispatch.push(EffectEvent::dispatch_ambiguous(
        "connection reset while sending",
    ));
    let via_observation = path_to(EffectState::UnknownOutcome);

    assert_eq!(
        project(EffectState::IntentDurable, &via_dispatch),
        project(EffectState::IntentDurable, &via_observation),
        "both routes end in UNKNOWN_OUTCOME"
    );
    assert_ne!(
        trajectory_digest(EffectState::IntentDurable, &via_dispatch),
        trajectory_digest(EffectState::IntentDurable, &via_observation),
        "different routes must be distinguishable"
    );
}

#[test]
fn try_project_stops_at_the_first_off_spec_event() {
    let mut log = path_to(EffectState::Dispatched);
    log.push(EffectEvent::AuthorizationRequested);

    let error = try_project(EffectState::IntentDurable, &log)
        .expect_err("re-requesting authorization after dispatch is not in spec");
    assert!(
        matches!(
            error,
            ReduceError::EventNotAccepted {
                state: EffectState::Dispatched,
                ..
            }
        ),
        "{error:?}"
    );

    // The total reducer keeps replaying instead of failing: the refused event is
    // a no-op, so the projection still ends where the legal prefix left it.
    assert_eq!(
        project(EffectState::IntentDurable, &log),
        EffectState::Dispatched
    );
}
