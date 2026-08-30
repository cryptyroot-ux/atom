//! Provider conformance: interchangeable injected backends never receive state
//! mutation authority.

use atom_ledger::{HmacSha256Signer, Ledger};
use atom_mission::{MissionCommand, MissionPhase, MissionState};
use atom_provider::{Provider, ProviderCognition, ProviderProposal, ProviderRequest};
use atom_runtime::{
    Cognition, CounterRng, FixedClock, Perception, ReferenceActivityPort, RunStatus, Runtime,
};
use chrono::{TimeZone, Utc};

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0)
        .single()
        .expect("fixed test time")
}

fn ledger() -> Ledger {
    Ledger::open_in_memory(Box::new(HmacSha256Signer::new(
        "provider-test-key",
        b"provider-test-secret",
    )))
    .expect("in-memory ledger")
}

#[derive(Debug)]
struct MockProvider {
    backend_name: &'static str,
    calls: usize,
}

impl MockProvider {
    fn new(backend_name: &'static str) -> Self {
        Self {
            backend_name,
            calls: 0,
        }
    }
}

impl Provider for MockProvider {
    fn invoke(&mut self, request: ProviderRequest<'_>) -> ProviderProposal {
        self.calls += 1;
        assert!(
            !self.backend_name.is_empty(),
            "the backend identity is injected, not selected by atom-provider"
        );
        let command = match request.perception.mission_state.phase {
            MissionPhase::Created => MissionCommand::Compile,
            MissionPhase::Compiled => MissionCommand::Prepare,
            MissionPhase::Ready => MissionCommand::Start,
            MissionPhase::Running => MissionCommand::Execute,
            MissionPhase::Verifying => MissionCommand::Verify,
            MissionPhase::Terminal => {
                return ProviderProposal::hold_terminal();
            }
        };
        ProviderProposal::activity(command)
    }
}

fn run_with(provider: MockProvider) -> (String, Vec<atom_mission::ActivityKind>) {
    let mut runtime = Runtime::new(
        "provider-agnostic-mission",
        ledger(),
        FixedClock::new(fixed_time()),
        CounterRng::new(100),
        ProviderCognition::new(provider),
    )
    .expect("runtime");
    let mut port = ReferenceActivityPort::default();

    assert!(matches!(
        runtime
            .run_until_terminal(&mut port, 8)
            .expect("provider loop completes"),
        RunStatus::Terminal { .. }
    ));

    (
        runtime
            .ledger()
            .stream_digest("provider-agnostic-mission")
            .expect("mission stream digest")
            .to_string(),
        port.activities().to_vec(),
    )
}

#[test]
fn injected_backends_drive_the_same_loop_without_state_leakage() {
    let perception = Perception {
        mission_id: "provider-agnostic-mission".to_owned(),
        observed_at: fixed_time(),
        mission_state: MissionState::created(),
        pending_effect: None,
    };
    let before = perception.clone();
    let mut backend_a = ProviderCognition::new(MockProvider::new("mock-a"));
    let mut backend_b = ProviderCognition::new(MockProvider::new("mock-b"));

    assert_eq!(
        backend_a.decide(&perception, 7),
        backend_b.decide(&perception, 7),
        "the provider interface has no backend-specific decision path"
    );
    assert_eq!(
        perception, before,
        "providers receive immutable perception, never mutable cognition state"
    );
    assert_eq!(backend_a.provider().calls, 1);
    assert_eq!(backend_b.provider().calls, 1);

    let (digest_a, activities_a) = run_with(MockProvider::new("mock-a"));
    let (digest_b, activities_b) = run_with(MockProvider::new("mock-b"));
    assert_eq!(activities_a, activities_b);
    assert_eq!(digest_a, digest_b, "the provider loop is deterministic");
}
