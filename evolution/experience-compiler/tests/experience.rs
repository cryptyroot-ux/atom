use atom_experience_compiler::{
    CompilerError, CostSnapshot, ExperienceCompiler, ExecutionTrajectory, Polarity, Subtrajectory,
    TaskSignature, TrajectoryStep,
};

/// A recurring, IDENTICAL 2-step trajectory shared by every example in a family.
/// This is what makes subtrajectory mining find a pattern (VT-011: repeated-task learning).
fn recurring_step() -> TrajectoryStep {
    TrajectoryStep {
        tool_id: "tool_a".to_owned(),
        input: serde_json::json!({"op": "read"}),
        output: serde_json::Value::Null,
        is_decision: false,
    }
}

fn recurring_trajectory(i: usize) -> ExecutionTrajectory {
    ExecutionTrajectory {
        task_family: "test".to_owned(),
        steps: vec![
            recurring_step(),
            TrajectoryStep {
                tool_id: "tool_b".to_owned(),
                input: serde_json::json!({"op": "transform"}),
                output: serde_json::Value::Null,
                is_decision: true,
            },
        ],
        success: true,
        cost: CostSnapshot { tokens: 100, latency_ms: 50, cost_cents: 1 },
        timestamp: i as i64,
    }
}

fn family(n: usize) -> Vec<ExecutionTrajectory> {
    (0..n).map(recurring_trajectory).collect()
}

#[test]
fn insufficient_trajectories_is_error() {
    let c = ExperienceCompiler::new();
    let r = c.mine_subtrajectories(&family(3));
    assert!(matches!(r, Err(CompilerError::InsufficientTrajectories { .. })));
}

#[test]
fn mines_recurring_subtrajectory() {
    let c = ExperienceCompiler::new();
    let subs = c.mine_subtrajectories(&family(20)).unwrap();
    assert!(!subs.is_empty(), "expected mined patterns from repeated trajectories");
    for s in &subs {
        assert!(s.frequency >= 3);
    }
}

#[test]
fn synthesized_recommendation_is_non_authoritative() {
    let c = ExperienceCompiler::new();
    let subs = c.mine_subtrajectories(&family(20)).unwrap();
    let rec = c.synthesize_candidate(&subs[0], "test-family").unwrap();
    // INV-016: no authority expansion — target must be None (no CapabilityGrant).
    assert!(rec.target_capability_id.is_none());
    assert!(!rec.proposed_operations.is_empty());
    assert!((0.0..=1.0).contains(&rec.confidence));
    assert!(rec.is_actionable());
}

#[test]
fn holdout_blocks_low_correctness_single_occurrence() {
    let c = ExperienceCompiler::new();
    let _subs = c.mine_subtrajectories(&family(20)).unwrap();
    // A single-occurrence subtrajectory yields low corrected correctness -> rejected.
    let low = Subtrajectory {
        signature: TaskSignature::of(&family(1)[0]),
        steps: vec![recurring_step()],
        frequency: 1,
        avg_cost_savings: CostSnapshot { tokens: 0, latency_ms: 0, cost_cents: 0 },
        polarity: Polarity::Positive,
    };
    let err = c.synthesize_candidate(&low, "test");
    assert!(matches!(err, Err(CompilerError::AuthorityExpansion { .. })));
}

#[test]
fn full_pipeline_compiles_experience() {
    let c = ExperienceCompiler::new();
    let recs = c.compile_experience(&family(20), "test-family").unwrap();
    assert!(!recs.is_empty());
    for r in &recs {
        assert!(r.is_actionable());
    }
}
