pub fn run(action: crate::IdentityAction) -> anyhow::Result<()> {
    match action {
        crate::IdentityAction::Show => {
            println!("Identity profile: ATOM Agent");
            Ok(())
        }
        crate::IdentityAction::Edit { field, value } => {
            println!("Proposing identity change: {} = {}", field, value);
            println!("Change requires owner approval before activation.");
            Ok(())
        }
        crate::IdentityAction::Propose { proposal } => {
            let content = std::fs::read_to_string(&proposal)?;
            println!(
                "Identity change proposed: {}",
                content.lines().next().unwrap_or("")
            );
            Ok(())
        }
        crate::IdentityAction::History => {
            println!("Identity revision history: 0 entries");
            Ok(())
        }
        crate::IdentityAction::Rollback { generation } => {
            println!("Rolling back to generation: {}", generation);
            Ok(())
        }
    }
}
