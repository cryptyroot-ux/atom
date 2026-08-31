//! Acceptance tests for `atom-fault` (ATOM-FLT-001, ATOM-INV-002).
//!
//! These exercise the crate through its public API only, and cover the four
//! properties the task fixes: an exhaustive total recovery mapping, the
//! ATOM-INV-002 sweep, determinism, and conformance of [`FaultClass`] to
//! `spec/enums.yaml`.

use std::fs;
use std::path::PathBuf;

use atom_fault::{
    classify, directive_for, is_plain_retry, recovery_for, AuthorityStatus, CapabilityStatus,
    ConnectorStatus, EnvironmentStatus, EvidenceStatus, FaultClass, FaultSignal, PlanStatus,
    PolicyDecision, RecoveryDirective, ResourceStatus, RetryClass, SandboxStatus, ToolStatus,
    TransportStatus, VerifierStatus,
};

use atom_effect::EffectState;

/// A minimal signal that classifies to exactly `class`.
///
/// Each sets only the single facet that its class occupies on the priority
/// ladder; every higher rung is left benign, so the ladder resolves to `class`.
fn signal_for(class: FaultClass) -> FaultSignal {
    let mut signal = FaultSignal::benign();
    match class {
        FaultClass::EffectUnknown => signal.effect_state = Some(EffectState::UnknownOutcome),
        FaultClass::PolicyDenial => signal.policy = PolicyDecision::Denied,
        FaultClass::AuthorityDrift => signal.authority = AuthorityStatus::Drifted,
        FaultClass::CapabilityMissing => signal.capability = CapabilityStatus::Missing,
        FaultClass::SemanticMisplan => signal.plan = PlanStatus::Misplanned,
        FaultClass::ToolContractError => signal.tool = ToolStatus::ContractError,
        FaultClass::StaleEvidence => signal.evidence = EvidenceStatus::Stale,
        FaultClass::VerifierDisagreement => signal.verifier = VerifierStatus::Disagreement,
        FaultClass::EnvironmentDrift => signal.environment = EnvironmentStatus::Drifted,
        FaultClass::ResourceConflict => signal.resource = ResourceStatus::Conflict,
        FaultClass::SandboxFailure => signal.sandbox = SandboxStatus::Failed,
        FaultClass::ConnectorFailure => signal.connector = ConnectorStatus::Failed,
        FaultClass::RateLimit => signal.transport = TransportStatus::RateLimited,
        FaultClass::ProviderTransient => signal.transport = TransportStatus::Transient,
    }
    signal
}

/// The single expected retry class for each fault class — the full table.
fn expected_retry(class: FaultClass) -> RetryClass {
    match class {
        FaultClass::EffectUnknown => RetryClass::ReconcileBeforeRetry,
        FaultClass::StaleEvidence => RetryClass::ReobserveThenRetry,
        FaultClass::AuthorityDrift => RetryClass::ReauthorizeThenRetry,
        FaultClass::PolicyDenial => RetryClass::Never,
        FaultClass::ProviderTransient => RetryClass::Transient,
        FaultClass::RateLimit => RetryClass::RateLimited,
        FaultClass::ConnectorFailure => RetryClass::ProviderFailoverAllowed,
        FaultClass::ToolContractError => RetryClass::Never,
        FaultClass::CapabilityMissing => RetryClass::Never,
        FaultClass::ResourceConflict => RetryClass::Transient,
        FaultClass::EnvironmentDrift => RetryClass::ReobserveThenRetry,
        FaultClass::SemanticMisplan => RetryClass::Never,
        FaultClass::VerifierDisagreement => RetryClass::ReobserveThenRetry,
        FaultClass::SandboxFailure => RetryClass::Transient,
    }
}

/// `recovery_for` is a total function: every one of the 14 classes maps to
/// exactly the expected retry class, and the mapping is defined for all of them.
#[test]
fn recovery_mapping_is_total_and_exact() {
    assert_eq!(
        FaultClass::ALL.len(),
        14,
        "spec fault_class has 14 variants"
    );
    for class in FaultClass::ALL {
        assert_eq!(
            recovery_for(class),
            expected_retry(class),
            "recovery_for({class}) disagrees with the documented table"
        );
    }
}

/// The seven non-negotiable bindings, asserted by name so a regression is loud.
#[test]
fn non_negotiable_bindings_hold() {
    assert_eq!(
        recovery_for(FaultClass::EffectUnknown),
        RetryClass::ReconcileBeforeRetry
    );
    assert_eq!(
        recovery_for(FaultClass::StaleEvidence),
        RetryClass::ReobserveThenRetry
    );
    assert_eq!(
        recovery_for(FaultClass::AuthorityDrift),
        RetryClass::ReauthorizeThenRetry
    );
    assert_eq!(recovery_for(FaultClass::PolicyDenial), RetryClass::Never);
    assert_eq!(
        recovery_for(FaultClass::ProviderTransient),
        RetryClass::Transient
    );
    assert_eq!(recovery_for(FaultClass::RateLimit), RetryClass::RateLimited);
    assert_eq!(
        recovery_for(FaultClass::ConnectorFailure),
        RetryClass::ProviderFailoverAllowed
    );
}

/// ATOM-INV-002: for an ambiguous effect the result is `ReconcileBeforeRetry`
/// and never a plain retry — swept across every fault class and both ambiguous
/// effect states. Whatever else the signal says, ambiguity must win.
#[test]
fn inv_002_ambiguity_never_plain_retry() {
    // The direct binding.
    let unknown = recovery_for(FaultClass::EffectUnknown);
    assert_eq!(unknown, RetryClass::ReconcileBeforeRetry);
    assert!(
        !is_plain_retry(unknown),
        "EFFECT_UNKNOWN must never be a plain retry"
    );

    // The sweep: take a signal that would otherwise be each class, force the
    // effect ambiguous, and confirm it collapses to EFFECT_UNKNOWN.
    for class in FaultClass::ALL {
        for ambiguous in [EffectState::UnknownOutcome, EffectState::Reconciling] {
            let mut signal = signal_for(class);
            signal.effect_state = Some(ambiguous);

            let classified = classify(signal);
            assert_eq!(
                classified,
                FaultClass::EffectUnknown,
                "ambiguity ({ambiguous}) must dominate the {class} facet"
            );
            let retry = recovery_for(classified);
            assert_eq!(retry, RetryClass::ReconcileBeforeRetry);
            assert!(
                !is_plain_retry(retry),
                "ambiguity ({ambiguous}) over {class} must not be safe-to-retry"
            );
        }
    }

    // No other class may borrow ReconcileBeforeRetry — it is EFFECT_UNKNOWN's
    // alone, so the guarantee cannot be diluted.
    for class in FaultClass::ALL {
        if class != FaultClass::EffectUnknown {
            assert_ne!(
                recovery_for(class),
                RetryClass::ReconcileBeforeRetry,
                "{class} must not claim RECONCILE_BEFORE_RETRY"
            );
        }
    }
}

/// `classify` is deterministic: repeated calls on the same signal agree, for
/// every single-facet signal, the benign signal, and a fully-loaded one.
#[test]
fn classify_is_deterministic() {
    let mut signals: Vec<FaultSignal> = FaultClass::ALL.iter().map(|&c| signal_for(c)).collect();
    signals.push(FaultSignal::benign());
    signals.push(FaultSignal {
        effect_state: Some(EffectState::UnknownOutcome),
        policy: PolicyDecision::Denied,
        authority: AuthorityStatus::Drifted,
        capability: CapabilityStatus::Missing,
        plan: PlanStatus::Misplanned,
        tool: ToolStatus::ContractError,
        evidence: EvidenceStatus::Stale,
        verifier: VerifierStatus::Disagreement,
        environment: EnvironmentStatus::Drifted,
        resource: ResourceStatus::Conflict,
        sandbox: SandboxStatus::Failed,
        connector: ConnectorStatus::Failed,
        transport: TransportStatus::RateLimited,
    });

    for signal in signals {
        let first = classify(signal);
        for _ in 0..8 {
            assert_eq!(classify(signal), first, "classify must be deterministic");
        }
    }
}

/// The ladder can reach every one of the 14 classes: each single-facet signal
/// classifies to its own class, so `classify` is surjective onto `fault_class`.
#[test]
fn classify_reaches_every_class() {
    for class in FaultClass::ALL {
        assert_eq!(
            classify(signal_for(class)),
            class,
            "the minimal signal for {class} should classify to it"
        );
    }
}

/// A benign signal (a reported fault that no facet explains) takes the fail-safe
/// residue: EFFECT_UNKNOWN, never a plain retry.
#[test]
fn benign_signal_is_fail_safe() {
    let class = classify(FaultSignal::benign());
    assert_eq!(class, FaultClass::EffectUnknown);
    assert!(!is_plain_retry(recovery_for(class)));
}

/// The priority ladder: a higher rung dominates a lower one when both are set.
#[test]
fn ladder_priority_is_respected() {
    // Policy denial dominates a transient transport error.
    let signal = FaultSignal {
        policy: PolicyDecision::Denied,
        transport: TransportStatus::Transient,
        ..FaultSignal::benign()
    };
    assert_eq!(classify(signal), FaultClass::PolicyDenial);

    // Authority drift dominates a rate-limit signal.
    let signal = FaultSignal {
        authority: AuthorityStatus::Drifted,
        transport: TransportStatus::RateLimited,
        ..FaultSignal::benign()
    };
    assert_eq!(classify(signal), FaultClass::AuthorityDrift);

    // Rate-limit (specific back-pressure) is only reached when nothing higher
    // fires, but it outranks a generic transient error — modelled as the single
    // RateLimited transport verdict.
    let signal = FaultSignal {
        transport: TransportStatus::RateLimited,
        ..FaultSignal::benign()
    };
    assert_eq!(classify(signal), FaultClass::RateLimit);
}

/// The mission-level directive adds Replan/Stop for exactly the two classes
/// retry cannot help, and wraps `recovery_for` for the rest.
#[test]
fn directive_wraps_retry_and_adds_mission_actions() {
    assert_eq!(
        directive_for(FaultClass::SemanticMisplan),
        RecoveryDirective::Replan
    );
    assert_eq!(
        directive_for(FaultClass::PolicyDenial),
        RecoveryDirective::Stop
    );
    for class in FaultClass::ALL {
        match class {
            FaultClass::SemanticMisplan => {
                assert_eq!(directive_for(class), RecoveryDirective::Replan);
            }
            FaultClass::PolicyDenial => {
                assert_eq!(directive_for(class), RecoveryDirective::Stop);
            }
            other => assert_eq!(
                directive_for(other),
                RecoveryDirective::Retry(recovery_for(other)),
                "{other} should carry its retry class unchanged"
            ),
        }
    }
}

/// `FaultClass` round-trips through its `SCREAMING_SNAKE_CASE` wire form.
#[test]
fn fault_class_serde_roundtrip() {
    for class in FaultClass::ALL {
        let json = serde_json::to_string(&class).expect("serialize");
        assert_eq!(json, format!("\"{}\"", class.as_str()));
        let back: FaultClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, class);
        assert_eq!(class.as_str().parse::<FaultClass>().unwrap(), class);
    }
    assert!("NOT_A_CLASS".parse::<FaultClass>().is_err());
}

/// A `FaultSignal` round-trips through JSON.
#[test]
fn fault_signal_serde_roundtrip() {
    let signal = FaultSignal {
        effect_state: Some(EffectState::Reconciling),
        policy: PolicyDecision::Denied,
        transport: TransportStatus::RateLimited,
        ..FaultSignal::benign()
    };
    let json = serde_json::to_string(&signal).expect("serialize");
    let back: FaultSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, signal);
}

/// `FaultClass::ALL` matches `spec/enums.yaml` `fault_class` name-for-name and
/// in order. The spec is authoritative; drift fails the build.
#[test]
fn fault_class_conforms_to_spec_enum() {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "spec", "enums.yaml"]
        .iter()
        .collect();
    let text = fs::read_to_string(&path).expect("read spec/enums.yaml");
    let spec_variants = parse_yaml_list(&text, "fault_class");

    let ours: Vec<&str> = FaultClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        spec_variants, ours,
        "FaultClass::ALL must match spec/enums.yaml fault_class exactly"
    );
}

/// Every retry class this crate emits is a member of `spec/enums.yaml`
/// `retry_class`.
#[test]
fn emitted_retry_classes_are_in_spec_enum() {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "spec", "enums.yaml"]
        .iter()
        .collect();
    let text = fs::read_to_string(&path).expect("read spec/enums.yaml");
    let spec_retry = parse_yaml_list(&text, "retry_class");

    for class in FaultClass::ALL {
        let wire = recovery_for(class).as_str();
        assert!(
            spec_retry.iter().any(|v| v == wire),
            "retry class {wire} for {class} is not in spec/enums.yaml retry_class"
        );
    }
}

/// Extract a flat `- ITEM` list under a top-level `key:` from the enums YAML.
///
/// Deliberately tiny: it reads the block between `key:` and the next line that
/// begins in column zero, and keeps the `- NAME` entries. Enough to bind the
/// two flat lists this crate cares about without a YAML dependency.
fn parse_yaml_list(text: &str, key: &str) -> Vec<String> {
    let header = format!("{key}:");
    let mut items = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        if !in_block {
            if line.trim_end() == header {
                in_block = true;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            items.push(rest.trim().to_string());
        } else if !line.starts_with(char::is_whitespace) && !line.trim().is_empty() {
            // A new top-level key ends the block.
            break;
        }
    }
    items
}
