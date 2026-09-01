//! ATOM-EVO-001: adaptive artifacts move Lab -> Simulation -> Shadow ->
//! Canary -> Active and support automatic rollback on regression.

use atom_evolution::{AdaptiveArtifact, RollbackAction, Stage};

#[test]
fn promotes_one_stage_at_a_time() {
    let lab = AdaptiveArtifact::new("artifact-1");
    assert_eq!(lab.stage, Stage::Lab);

    let sim = lab.promote(Stage::Simulation, "sim ok").unwrap();
    assert_eq!(sim.stage, Stage::Simulation);
    assert_eq!(sim.promoted_from, Some(Stage::Lab));
    assert_eq!(sim.generation, 1);

    let shadow = sim.promote(Stage::Shadow, "shadow ok").unwrap();
    let canary = shadow.promote(Stage::Canary, "canary ok").unwrap();
    let active = canary.promote(Stage::Active, "active ok").unwrap();
    assert_eq!(active.stage, Stage::Active);

    // Active is terminal.
    assert!(active.promote(Stage::Active, "again").is_err());
}

#[test]
fn cannot_skip_stages() {
    let lab = AdaptiveArtifact::new("artifact-2");
    // Try to jump Lab -> Shadow (skipping Simulation).
    let err = lab.promote(Stage::Shadow, "skip").unwrap_err();
    assert!(matches!(
        err,
        atom_evolution::EvolutionError::InvalidPromotion { .. }
    ));
}

#[test]
fn demotes_on_regression() {
    let lab = AdaptiveArtifact::new("artifact-3");
    let sim = lab.promote(Stage::Simulation, "sim").unwrap();
    let shadow = sim.promote(Stage::Shadow, "shadow").unwrap();

    // Regression in shadow -> roll back to simulation.
    let (rolled, action) = shadow.auto_rollback_if_regressed(0.40, 0.80, 0.05);
    assert_eq!(
        action,
        RollbackAction::RolledBack {
            to: Stage::Simulation
        }
    );
    assert_eq!(rolled.stage, Stage::Simulation);
    assert!(rolled.reason.contains("auto-rollback"));
}

#[test]
fn holds_when_no_regression() {
    let lab = AdaptiveArtifact::new("artifact-4");
    let sim = lab.promote(Stage::Simulation, "sim").unwrap();
    let shadow = sim.promote(Stage::Shadow, "shadow").unwrap();

    // Live metric within tolerance of baseline -> no rollback.
    let (held, action) = shadow.auto_rollback_if_regressed(0.79, 0.80, 0.05);
    assert_eq!(action, RollbackAction::Held);
    assert_eq!(held.stage, Stage::Shadow);
}

#[test]
fn demote_requires_lower_stage() {
    let lab = AdaptiveArtifact::new("artifact-5");
    let sim = lab.promote(Stage::Simulation, "sim").unwrap();
    // Demoting to the SAME stage is invalid.
    assert!(sim.demote(Stage::Simulation, "noop").is_err());
    // Demoting to a HIGHER stage is invalid.
    assert!(sim.demote(Stage::Active, "up").is_err());
}
