//! Acceptance coverage for the native, unprivileged cognition loop.
//!
//! These tests intentionally use only ATOM crates and fixed inputs.  In
//! particular, no test reads a process clock or starts Hermes/OpenClaw.

use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_effect::{
    issue_commit_permit, CommitPermitted, Compensation, CompensationStrategy, Condition,
    DurabilityProof, EffectEvent, EffectIntent, Idempotency, PermitRequest, ReconciledOutcome,
    Reconciliation, ReconciliationClass, ResourceWitness, RetryClass,
};
use atom_ledger::{HmacSha256Signer, Ledger};
use atom_mission::{ActivityKind, MissionOutcome, MissionPhase};
use atom_privd::{HostExecutor, HostOp, OpOutcome, PrivilegeBroker};
use atom_runtime::{
    ActionRequest, ActivityObservation, ActivityPort, CounterRng, FixedClock, HostOperationRequest,
    LoopPhase, LoopStep, NativeCognition, ReferenceActivityPort, RunStatus, Runtime,
    UnprivilegedHostGateway,
};
use chrono::{DateTime, Duration, TimeZone, Utc};

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("fixed test timestamp")
}

fn ledger() -> Ledger {
    Ledger::open_in_memory(Box::new(HmacSha256Signer::new(
        "runtime-test-key",
        b"runtime-test-secret",
    )))
    .expect("in-memory ledger")
}

/// Mints a real, ledger-sealed durability proof on `intent`'s own stream.
///
/// There is no `DurabilityProof` constructor a test could call, so this is the
/// only way to obtain one: append the declared intent (the identity payload,
/// stable across lifecycle transitions) to a ledger stream named for the effect
/// and take the proof the ledger seals over it.
fn durable_proof(intent: &EffectIntent) -> DurabilityProof {
    let payload = intent
        .declared_payload()
        .expect("fixture intent has a declared payload");
    let (_event, proof) = ledger()
        .append_durable(&intent.effect_id, &payload, 1_756_512_000_000)
        .expect("appending the declared intent seals a durability proof");
    proof
}

fn reference_effect(effect_id: &str, mission_id: &str, target_id: &str) -> EffectIntent {
    EffectIntent::builder(effect_id, mission_id, "capability-write", target_id)
        .canonical_request_digest(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .classes("WRITE_FILE", "LOW")
        .idempotency(Idempotency::keyed(
            "reference-mission",
            "reference-effect-key",
        ))
        .precondition(Condition::new("target-present", "target exists"))
        .postcondition(Condition::new(
            "contents-applied",
            "contents equal desired value",
        ))
        .reconciliation(
            Reconciliation::new(
                ReconciliationClass::ResourceStateRead,
                RetryClass::ReconcileBeforeRetry,
            )
            .with_probe("read target and compare postcondition"),
        )
        .compensation(Compensation::new(CompensationStrategy::NotCompensable))
        .build()
        .expect("complete effect intent")
}

#[test]
fn vt007_native_reference_mission_reaches_terminal_without_external_runtime() {
    let mut runtime = Runtime::native(
        "reference-mission",
        ledger(),
        FixedClock::new(fixed_now()),
        CounterRng::new(41),
    )
    .expect("native runtime");
    let mut activity_port = ReferenceActivityPort::default();

    let outcome = runtime
        .run_until_terminal(&mut activity_port, 8)
        .expect("reference mission completes natively");

    match outcome {
        RunStatus::Terminal { state, steps } => {
            assert_eq!(steps, 5, "one native cycle per canonical activity");
            assert_eq!(state.phase, MissionPhase::Terminal);
            assert_eq!(state.outcome, Some(MissionOutcome::Succeeded));
        }
        other => panic!("reference mission must terminate, got {other:?}"),
    }
    assert_eq!(
        activity_port.activities(),
        &[
            ActivityKind::Compile,
            ActivityKind::Prepare,
            ActivityKind::Start,
            ActivityKind::Execute,
            ActivityKind::Verify,
        ],
    );
    assert_eq!(runtime.trace().len(), 20, "five complete cognition cycles");
    for cycle in runtime.trace().as_chunks::<4>().0 {
        assert_eq!(
            cycle.iter().map(|entry| entry.phase).collect::<Vec<_>>(),
            vec![
                LoopPhase::Perceive,
                LoopPhase::Decide,
                LoopPhase::Act,
                LoopPhase::Observe,
            ],
        );
    }

    // Same injected clock/RNG and native port produce the same durable stream.
    let first_digest = runtime
        .ledger()
        .stream_digest("reference-mission")
        .expect("stream digest");
    let mut replay = Runtime::native(
        "reference-mission",
        ledger(),
        FixedClock::new(fixed_now()),
        CounterRng::new(41),
    )
    .expect("second native runtime");
    let mut replay_port = ReferenceActivityPort::default();
    let replay_outcome = replay
        .run_until_terminal(&mut replay_port, 8)
        .expect("second reference mission completes");
    assert!(matches!(replay_outcome, RunStatus::Terminal { .. }));
    assert_eq!(
        first_digest,
        replay
            .ledger()
            .stream_digest("reference-mission")
            .expect("replayed stream digest"),
        "the loop must be reproducible from injected inputs",
    );
}

#[derive(Default)]
struct AmbiguousEffectPort {
    act_calls: usize,
    reconcile_calls: usize,
}

impl ActivityPort for AmbiguousEffectPort {
    fn act(&mut self, request: &ActionRequest<'_>) -> Result<(), atom_runtime::ActivityError> {
        assert_eq!(request.activity.kind, ActivityKind::Compile);
        assert!(
            request.effect.is_some(),
            "the effect is durable before action"
        );
        self.act_calls += 1;
        Ok(())
    }

    fn observe(
        &mut self,
        request: &ActionRequest<'_>,
    ) -> Result<ActivityObservation, atom_runtime::ActivityError> {
        let effect = request.effect.expect("effect proposal");
        Ok(ActivityObservation::Effect {
            events: vec![
                EffectEvent::AuthorizationRequested,
                EffectEvent::authorization_granted("grant-1", 1),
                EffectEvent::CommitRevalidationStarted,
                EffectEvent::CommitPermitted(CommitPermitted {
                    permit_id: "permit-1".to_owned(),
                    one_shot_nonce: "nonce-1".to_owned(),
                    effect_digest: effect.digest(),
                }),
                EffectEvent::dispatch_ambiguous("target committed but response was lost"),
            ],
        })
    }

    fn reconcile(
        &mut self,
        _effect: &EffectIntent,
        _at: DateTime<Utc>,
    ) -> Result<Vec<EffectEvent>, atom_runtime::ActivityError> {
        self.reconcile_calls += 1;
        Ok(vec![
            EffectEvent::ReconciliationStarted,
            EffectEvent::reconciled(ReconciledOutcome::Inconclusive),
        ])
    }
}

#[test]
fn unknown_effect_outcome_stays_unknown_and_never_blindly_retries() {
    let mission_id = "unknown-outcome-mission";
    let effect_id = "unknown-outcome-effect";
    let cognition = NativeCognition::new().with_effect(
        ActivityKind::Compile,
        reference_effect(effect_id, mission_id, "/var/lib/atom/reference"),
    );
    let mut runtime = Runtime::new(
        mission_id,
        ledger(),
        FixedClock::new(fixed_now()),
        CounterRng::new(7),
        cognition,
    )
    .expect("runtime");
    let mut activity_port = AmbiguousEffectPort::default();

    let first = runtime
        .tick(&mut activity_port)
        .expect("ambiguous observation");
    assert!(matches!(
        first,
        LoopStep::UnknownOutcome { effect_id: ref actual } if actual == effect_id
    ));
    assert_eq!(runtime.state().phase, MissionPhase::Created);
    assert_eq!(
        runtime
            .effect(effect_id)
            .expect("tracked effect")
            .intent
            .state
            .as_str(),
        "UNKNOWN_OUTCOME",
    );
    assert_eq!(
        runtime
            .effect(effect_id)
            .expect("tracked effect")
            .durability
            .stream_id(),
        effect_id,
        "the effect intent was durable before action",
    );

    // The next cycle reconciles the existing effect.  It never sends a second
    // Compile action, and an inconclusive read remains UNKNOWN_OUTCOME.
    let second = runtime
        .tick(&mut activity_port)
        .expect("reconcile ambiguity");
    assert!(matches!(
        second,
        LoopStep::UnknownOutcome { effect_id: ref actual } if actual == effect_id
    ));
    assert_eq!(activity_port.act_calls, 1, "no blind duplicate dispatch");
    assert_eq!(activity_port.reconcile_calls, 1);
    assert_eq!(runtime.state().phase, MissionPhase::Created);
    assert_eq!(
        runtime
            .effect(effect_id)
            .expect("tracked effect")
            .intent
            .state
            .as_str(),
        "UNKNOWN_OUTCOME",
        "ambiguity is never coerced into mission success or failure",
    );
}

#[derive(Default, Debug)]
struct RecordingExecutor {
    operations: Vec<HostOp>,
}

impl HostExecutor for RecordingExecutor {
    fn execute(&mut self, op: &HostOp) -> Result<OpOutcome, atom_privd::ExecError> {
        self.operations.push(op.clone());
        Ok(OpOutcome::new(op.kind(), "recorded by test executor"))
    }
}

fn host_grant(now: DateTime<Utc>, target_id: &str) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "host-grant".to_owned(),
        subject_id: "runtime-workload".to_owned(),
        workload_id: "runtime".to_owned(),
        operations: vec!["write".to_owned()],
        resources: vec![ResourceSelector {
            resource_type: "file".to_owned(),
            resource_id: target_id.to_owned(),
        }],
        purpose: "reference test".to_owned(),
        not_before: now - Duration::seconds(1),
        expires_at: now + Duration::seconds(30),
        budget: Budget {
            max_cost: 1,
            max_seconds: 30,
        },
        delegation_depth: 0,
        audience: "runtime".to_owned(),
        generation: 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        nonce: None,
        constraints: None,
    }
}

#[test]
fn host_operation_crosses_only_the_atom_privd_permit_gate() {
    let now = fixed_now();
    let target_id = "/var/lib/atom/runtime-proof";
    let grant = host_grant(now, target_id);
    let witness = ResourceWitness::new("etag", target_id, "v1");
    let mut intent = reference_effect("host-effect", "host-mission", target_id);
    for event in [
        EffectEvent::AuthorizationRequested,
        EffectEvent::authorization_granted(&grant.grant_id, grant.generation),
        EffectEvent::CommitRevalidationStarted,
    ] {
        intent = intent
            .try_advance(&event)
            .expect("valid pre-dispatch transition");
    }
    let permit = issue_commit_permit(PermitRequest {
        intent: &intent,
        grant: &grant,
        principal_id: "runtime-workload",
        operation: "write",
        resource_type: "file",
        planned_grant_generation: grant.generation,
        planned_witness: &witness,
        observed_witness: &witness,
        durability: &durable_proof(&intent),
        permit_id: "host-permit",
        one_shot_nonce: "host-nonce",
        ttl_seconds: 10,
        now,
        approval_id: None,
        evidence_freshness_digest: None,
    })
    .expect("valid permit");
    let op = HostOp::WriteFile {
        path: target_id.to_owned(),
        contents: "proof".to_owned(),
    };
    let mut gateway =
        UnprivilegedHostGateway::new(PrivilegeBroker::new(RecordingExecutor::default()));

    gateway
        .submit(HostOperationRequest {
            op: &op,
            permit: &permit,
            intent: &intent,
            grant: &grant,
            observed_witness: &witness,
            now,
        })
        .expect("only atom-privd may admit a host operation");

    assert_eq!(gateway.client().spent(), 1);
    assert_eq!(gateway.client().executor().operations, vec![op]);
}
