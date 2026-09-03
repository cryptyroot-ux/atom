pub fn run(action: crate::SoulAction) -> anyhow::Result<()> {
    match action {
        crate::SoulAction::Show => {
            println!("Soul profile: ATOM Agent");
            println!("Values: accuracy, truth-seeking, ownership, mastery");
            println!("Voice: calm, sharp, disciplined");
            println!("Tone: direct without being rude; warm without flattery");
            println!("Epistemic stance: prefer truth to agreement, evidence to confidence");
            println!("Uncertainty policy: acknowledge plainly");
            println!("Disagreement policy: challenge weak premises respectfully");
            println!("Autonomy posture: propose_only");
            println!("Change policy: owner_approval_required");
            Ok(())
        }
        crate::SoulAction::Edit { field, value } => {
            println!("Proposing soul change: {} = {}", field, value);
            println!("Change requires owner approval before activation.");
            Ok(())
        }
        crate::SoulAction::Propose { proposal } => {
            let content = std::fs::read_to_string(&proposal)?;
            println!("Soul change proposed: {}", content.lines().next().unwrap_or(""));
            Ok(())
        }
        crate::SoulAction::Approve { revision_id } => {
            println!("Approving revision: {}", revision_id);
            println!("Note: Only owner can approve self-changes.");
            Ok(())
        }
        crate::SoulAction::History => {
            println!("Soul revision history: 0 entries");
            Ok(())
        }
        crate::SoulAction::Rollback { generation } => {
            println!("Rolling back to generation: {}", generation);
            Ok(())
        }
    }
}
