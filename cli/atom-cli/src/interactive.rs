//! Minimal interactive operator session backed by the durable mission API.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::time::Duration;

pub fn run() -> Result<()> {
    let base = std::env::var("ATOM_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8420".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("creating ATOM API client")?;
    println!("ATOM interactive session (type /quit to exit)");
    let stdin = io::stdin();
    loop {
        print!("You> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }
        let goal = line.trim();
        if goal.is_empty() {
            continue;
        }
        if matches!(goal, "/quit" | "/exit") {
            break;
        }
        let payload = json!({
            "goal": goal,
            "success_criteria": ["the mission reaches a terminal state"],
            "constraints": ["follow configured Atom authority and capability policy"],
            "budgets": {"max_steps": 8},
            "authority_profile_ref": "authority/read-only",
            "evidence_requirements": ["durable ledger event"],
            "stopping_rules": ["stop at terminal outcome"]
        });
        let response = client
            .post(format!("{base}/missions"))
            .json(&payload)
            .send()
            .context("submitting mission to ATOM")?;
        if !response.status().is_success() {
            println!(
                "ATOM> mission submission failed (HTTP {})",
                response.status()
            );
            continue;
        }
        let created: serde_json::Value = response.json().context("decoding mission response")?;
        let Some(id) = created["mission_id"].as_str() else {
            println!("ATOM> daemon returned no mission id");
            continue;
        };
        print!("ATOM> mission {id} ");
        io::stdout().flush()?;
        let mut outcome = "timeout".to_owned();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_secs(2));
            let value: serde_json::Value =
                client.get(format!("{base}/missions/{id}")).send()?.json()?;
            if value["phase"].as_str() == Some("TERMINAL") {
                outcome = value["outcome"].as_str().unwrap_or("unknown").to_owned();
                break;
            }
            print!(".");
            io::stdout().flush()?;
        }
        println!(" {outcome}");
    }
    Ok(())
}
