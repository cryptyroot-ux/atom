pub fn run(action: crate::WorkspaceAction) -> anyhow::Result<()> {
    match action {
        crate::WorkspaceAction::Init { agent_id } => {
            let dir = atom_agent_profile::workspace::workspace_dir(&agent_id);
            std::fs::create_dir_all(&dir)?;
            println!("Workspace initialized at: {}", dir.display());
            println!("Place SOUL.md, IDENTITY.md, USER.md, AGENTS.md in this directory.");
            Ok(())
        }
        crate::WorkspaceAction::Import { from, input } => {
            let content = std::fs::read_to_string(&input)?;
            match from {
                crate::ImportSource::Openclaw => {
                    println!("Importing persona from Openclaw: {}", content.lines().next().unwrap_or(""));
                }
                crate::ImportSource::Hermes => {
                    println!("Importing persona from Hermes: {}", content.lines().next().unwrap_or(""));
                }
            }
            Ok(())
        }
    }
}
