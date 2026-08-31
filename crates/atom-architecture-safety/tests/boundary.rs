//! ATOM-VT-012: a regressed canary must be automatically downgraded and the
//! exact prior certified production artifact restored.

use atom_architecture_safety::{
    ChangeOrigin, EvolutionBoundary, EvolutionClass, EvolutionRing, RollbackAction,
};
use atom_artifact::ArtifactId;

fn artifact_id(label: &str) -> ArtifactId {
    ArtifactId::of(label.as_bytes())
}

#[test]
fn vt012_promotes_through_every_ring_then_restores_prior_artifact_on_regression() {
    let stable = artifact_id("stable-certified-artifact");
    let candidate = artifact_id("candidate-artifact");
    let mut boundary = EvolutionBoundary::new();

    boundary
        .register_active(stable.clone())
        .expect("initial certified route");
    boundary
        .register_lab(
            candidate.clone(),
            EvolutionClass::E5HarnessOrTopology,
            ChangeOrigin::ReviewedHuman,
        )
        .expect("candidate begins in LAB");

    for expected in [
        EvolutionRing::Simulation,
        EvolutionRing::Shadow,
        EvolutionRing::Canary,
        EvolutionRing::Active,
    ] {
        let promotion = boundary.promote(&candidate).expect("one legal promotion");
        assert_eq!(promotion.to(), expected);
    }
    assert_eq!(boundary.ring_of(&candidate), Some(EvolutionRing::Active));
    assert_eq!(boundary.active_artifact(), Some(&candidate));

    let rollback = boundary
        .auto_rollback_if_regressed(&candidate, 0.40, 0.80, 0.05)
        .expect("regression automatically rolls back");
    assert_eq!(
        rollback,
        RollbackAction::RolledBack {
            from: EvolutionRing::Active,
            to: EvolutionRing::Canary,
            restored_artifact: stable.clone(),
        }
    );
    assert_eq!(boundary.ring_of(&candidate), Some(EvolutionRing::Canary));
    assert_eq!(boundary.active_artifact(), Some(&stable));
}

#[test]
fn e7_and_e8_changes_from_production_cognition_cannot_self_promote() {
    for class in [
        EvolutionClass::E7TrustedCoreChange,
        EvolutionClass::E8AuthorityOrPolicyExpansion,
    ] {
        let candidate = artifact_id(class.as_str());
        let mut boundary = EvolutionBoundary::new();
        boundary
            .register_lab(candidate.clone(), class, ChangeOrigin::ProductionCognition)
            .expect("a proposal may be recorded in LAB");

        let error = boundary
            .promote(&candidate)
            .expect_err("production cognition cannot self-promote E7/E8");
        assert!(error.is_self_promotion_forbidden());
        assert_eq!(boundary.ring_of(&candidate), Some(EvolutionRing::Lab));
    }
}

#[test]
fn promotion_cannot_skip_a_ring() {
    let candidate = artifact_id("candidate-no-skip");
    let mut boundary = EvolutionBoundary::new();
    boundary
        .register_lab(
            candidate.clone(),
            EvolutionClass::E2Workflow,
            ChangeOrigin::ReviewedHuman,
        )
        .expect("candidate begins in LAB");

    let error = boundary
        .promote_to(&candidate, EvolutionRing::Shadow)
        .expect_err("LAB cannot jump to SHADOW");
    assert!(error.is_invalid_promotion());
    assert_eq!(boundary.ring_of(&candidate), Some(EvolutionRing::Lab));
}
