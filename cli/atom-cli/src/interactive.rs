//! Interactive operator session backed by the durable API and model gateway.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::time::Duration;

/// Opens a conversational session. Plain text is sent to `/chat`; mutations
/// are explicit via `/mission`, so a greeting can never silently create a
/// successful mission with no model response.
pub fn run() -> Result<()> {
    let base = std::env::var("ATOM_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8420".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("creating ATOM API client")?;
    let mut history = vec![json!({
        "role": "system",
        "content": "You are ATOM, a careful sovereign assistant. Explain proposed actions clearly. Never claim an external effect happened unless ATOM reports a verified terminal result."
    })];
    println!("ATOM interactive session");
    println!("Connected to {base}");
    println!("Type a message to chat, /mission <goal> to run a governed mission, /model, /help, or /quit.");
    loop {
        print!("You> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        match input {
            "/quit" | "/exit" => break,
            "/help" => {
                println!("ATOM commands: /mission <goal>, /model, /status, /help, /quit");
                continue;
            }
            "/model" => {
                println!(
                    "ATOM> run `sudo atom model` to configure the gateway, model, and API key"
                );
                continue;
            }
            "/status" => {
                let response = client.get(format!("{base}/health")).send()?;
                println!("ATOM> {}", response.text()?);
                continue;
            }
            command if command.starts_with("/mission ") => {
                submit_mission(&client, &base, command.trim_start_matches("/mission "))?;
                continue;
            }
            command if command.starts_with('/') => {
                println!("ATOM> unknown command; use /help");
                continue;
            }
            _ => {}
        }

        history.push(json!({"role": "user", "content": input}));
        if history.len() > 21 {
            history.drain(1..history.len() - 20);
        }
        let response = client
            .post(format!("{base}/chat"))
            .json(&json!({"messages": history}))
            .send()
            .context("sending chat request to ATOM")?;
        let status = response.status();
        let body: Value = response.json().context("decoding ATOM chat response")?;
        if !status.is_success() {
            let detail = body["detail"]
                .as_str()
                .unwrap_or("chat provider unavailable");
            println!("ATOM> {detail}");
            println!("     Configure with: sudo atom setup");
            let _ = history.pop();
            continue;
        }
        let answer = body["content"].as_str().unwrap_or("(empty model response)");
        println!("ATOM> {answer}");
        history.push(json!({"role": "assistant", "content": answer}));
    }
    Ok(())
}

fn submit_mission(client: &reqwest::blocking::Client, base: &str, goal: &str) -> Result<()> {
    if goal.trim().is_empty() {
        println!("ATOM> usage: /mission <goal>");
        return Ok(());
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
        return Ok(());
    }
    let created: Value = response.json().context("decoding mission response")?;
    let Some(id) = created["mission_id"].as_str() else {
        println!("ATOM> daemon returned no mission id");
        return Ok(());
    };
    print!("ATOM> mission {id} ");
    io::stdout().flush()?;
    let mut outcome = "TIMEOUT".to_owned();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_secs(1));
        let value: Value = client.get(format!("{base}/missions/{id}")).send()?.json()?;
        if value["phase"].as_str() == Some("TERMINAL") {
            outcome = value["outcome"].as_str().unwrap_or("UNKNOWN").to_owned();
            break;
        }
        print!(".");
        io::stdout().flush()?;
    }
    println!(" {outcome}");
    Ok(())
}
