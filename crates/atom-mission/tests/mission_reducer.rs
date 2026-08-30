use std::collections::BTreeMap;

use atom_mission::{
    reduce, state_digest, ActivityKind, ActivityResult, ActivityResultEvent, MissionCommand,
    MissionCondition, MissionEvent, MissionOutcome, MissionPhase, MissionSpec, MissionState,
};

fn valid_spec() -> MissionSpec {
    MissionSpec {
        goal: "Produce a verified release candidate".into(),
        success_criteria: vec!["All acceptance checks pass".into()],
        constraints: vec!["Do not modify production".into()],
        budgets: BTreeMap::from([("max_steps".into(), 12)]),
        authority_profile_ref: "authority/operate".into(),
        evidence_requirements: vec!["Attach test report".into()],
        stopping_rules: vec!["Stop after a policy denial".into()],
    }
}

fn successful_replay_log() -> Vec<MissionEvent> {
    vec![
        MissionEvent::ActivityResult(ActivityResultEvent::succeeded(ActivityKind::Compile)),
        MissionEvent::ActivityResult(ActivityResultEvent::succeeded(ActivityKind::Prepare)),
        MissionEvent::ActivityResult(ActivityResultEvent::succeeded(ActivityKind::Start)),
        MissionEvent::ActivityResult(ActivityResultEvent::succeeded(ActivityKind::Execute)),
        MissionEvent::ActivityResult(ActivityResultEvent::succeeded(ActivityKind::Verify)),
    ]
}

fn replay(log: &[MissionEvent]) -> MissionState {
    log.iter().fold(MissionState::created(), |state, event| {
        reduce(&state, event)
    })
}

#[test]
fn mission_spec_rejects_malformed_objectives() {
    let mut missing_goal = valid_spec();
    missing_goal.goal.clear();
    assert!(missing_goal.validate().is_err());

    let mut missing_success_criteria = valid_spec();
    missing_success_criteria.success_criteria.clear();
    assert!(missing_success_criteria.validate().is_err());

    let mut missing_budget = valid_spec();
    missing_budget.budgets.clear();
    assert!(missing_budget.validate().is_err());

    assert!(MissionSpec::from_json(r#"{"goal":"incomplete"}"#).is_err());
}

#[test]
fn reducer_replays_an_identical_state_digest_for_the_same_durable_log() {
    let log = successful_replay_log();

    let first = replay(&log);
    let second = replay(&log);

    assert_eq!(first, second);
    assert_eq!(state_digest(&first), state_digest(&second));
    assert_eq!(first.phase, MissionPhase::Terminal);
    assert_eq!(first.outcome, Some(MissionOutcome::Succeeded));
}

#[test]
fn state_rejects_noncanonical_enum_values_from_json() {
    let invalid_phase = r#"{"phase":"MODEL_DECIDED","condition":"NORMAL"}"#;
    let invalid_condition = r#"{"phase":"RUNNING","condition":"MAYBE"}"#;
    let invalid_outcome = r#"{"phase":"TERMINAL","condition":"NORMAL","outcome":"UNKNOWN"}"#;

    assert!(MissionState::from_json(invalid_phase).is_err());
    assert!(MissionState::from_json(invalid_condition).is_err());
    assert!(MissionState::from_json(invalid_outcome).is_err());
}

#[test]
fn terminal_and_outcome_are_biconditional_and_running_can_require_approval() {
    assert!(
        MissionState::new(MissionPhase::Terminal, MissionCondition::Normal, None, None).is_err()
    );
    assert!(MissionState::new(
        MissionPhase::Running,
        MissionCondition::Normal,
        Some(MissionOutcome::Failed),
        None,
    )
    .is_err());

    let approval_while_running = MissionState::new(
        MissionPhase::Running,
        MissionCondition::ApprovalRequired,
        None,
        Some("awaiting reviewer".into()),
    )
    .expect("APPROVAL_REQUIRED may coexist with RUNNING");

    assert_eq!(approval_while_running.phase, MissionPhase::Running);
    assert_eq!(
        approval_while_running.condition,
        MissionCondition::ApprovalRequired
    );
}

#[test]
fn blocked_is_a_nonterminal_condition_not_a_failed_outcome() {
    let running = MissionState::new(MissionPhase::Running, MissionCondition::Normal, None, None)
        .expect("running is valid");

    let blocked = reduce(
        &running,
        &MissionEvent::ActivityResult(ActivityResultEvent::new(
            ActivityKind::Execute,
            ActivityResult::Blocked,
            Some("waiting for a dependency".into()),
        )),
    );

    assert_eq!(blocked.phase, MissionPhase::Running);
    assert_eq!(blocked.condition, MissionCondition::Blocked);
    assert_eq!(blocked.outcome, None);
}

#[test]
fn commands_are_validated_before_their_activity_result_is_reduced() {
    let initial = MissionState::created();
    let activity = MissionCommand::Compile
        .validate(&initial)
        .expect("compile is valid for a created mission");

    assert_eq!(activity.kind, ActivityKind::Compile);

    let next = reduce(
        &initial,
        &MissionEvent::ActivityResult(ActivityResultEvent::succeeded(activity.kind)),
    );

    assert_eq!(next.phase, MissionPhase::Compiled);
}
