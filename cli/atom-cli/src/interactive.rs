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
    let payload = draft_mission_spec(client, base, goal)?;
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
    render_evidence(client, base)?;
    Ok(())
}

/// The safe built-in spec used when no provider can draft one. Mutations stay
/// explicit: the goal is always the caller's, never rewritten by the model.
fn default_mission_spec(goal: &str) -> Value {
    json!({
        "goal": goal.trim(),
        "success_criteria": ["the mission reaches a terminal state"],
        "constraints": ["follow configured Atom authority and capability policy"],
        "budgets": {"max_steps": 8},
        "authority_profile_ref": "authority/read-only",
        "evidence_requirements": ["durable ledger event"],
        "stopping_rules": ["stop at terminal outcome"]
    })
}

/// Parse a model reply into a sanitized mission spec. The caller's goal and the
/// read-only authority profile are always forced, budgets are clamped, and
/// fields the server does not know about are dropped (the API rejects unknown
/// fields). Returns `None` when the reply is unusable so the caller can fall
/// back to the safe built-in spec.
fn parse_mission_spec_content(goal: &str, content: &str) -> Option<Value> {
    let trimmed = content.trim();
    let de_fenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed)
        .trim();
    let de_fenced = de_fenced
        .strip_suffix("```")
        .map(str::trim)
        .unwrap_or(de_fenced);
    let parsed: Value = serde_json::from_str(de_fenced).ok()?;
    let obj = parsed.as_object()?;
    let str_list = |key: &str| -> Vec<String> {
        obj.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .filter(|s| !s.trim().is_empty())
                    .collect::<Vec<String>>()
            })
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_default()
    };
    let success_criteria = str_list("success_criteria");
    let constraints = str_list("constraints");
    let evidence_requirements = str_list("evidence_requirements");
    let stopping_rules = str_list("stopping_rules");
    if success_criteria.is_empty()
        || constraints.is_empty()
        || evidence_requirements.is_empty()
        || stopping_rules.is_empty()
    {
        return None;
    }
    let mut budgets = serde_json::Map::new();
    if let Some(b) = obj.get("budgets").and_then(Value::as_object) {
        for (k, v) in b {
            if let Some(n) = v.as_u64() {
                budgets.insert(k.clone(), json!(n));
            }
        }
    }
    let max_steps = budgets
        .get("max_steps")
        .and_then(Value::as_u64)
        .map(|n| n.clamp(1, 256))
        .unwrap_or(8);
    budgets.insert("max_steps".into(), json!(max_steps));
    let mut payload = serde_json::Map::new();
    payload.insert("goal".into(), json!(goal.trim()));
    payload.insert("success_criteria".into(), json!(success_criteria));
    payload.insert("constraints".into(), json!(constraints));
    payload.insert("budgets".into(), Value::Object(budgets));
    payload.insert("authority_profile_ref".into(), json!("authority/read-only"));
    payload.insert("evidence_requirements".into(), json!(evidence_requirements));
    payload.insert("stopping_rules".into(), json!(stopping_rules));
    Some(Value::Object(payload))
}

/// Ask the model to draft a full mission spec via `/chat`; fall back to the
/// safe built-in spec when no provider is reachable or its reply is unusable.
fn draft_mission_spec(client: &reqwest::blocking::Client, base: &str, goal: &str) -> Result<Value> {
    let prompt = "Return a single JSON object for an ATOM mission spec with exactly these keys: \
goal, success_criteria, constraints, budgets, authority_profile_ref, evidence_requirements, \
stopping_rules. goal is one short present-tense sentence. success_criteria, constraints, \
evidence_requirements and stopping_rules are arrays of short strings. budgets is an object that \
may include \"max_steps\" between 1 and 256. authority_profile_ref must be \"authority/read-only\". \
Reply with the JSON object only; no prose, no markdown.";
    let response = client
        .post(format!("{base}/chat"))
        .json(&json!({
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": goal}
            ]
        }))
        .send()
        .context("drafting mission spec via ATOM chat")?;
    if !response.status().is_success() {
        println!("ATOM> model unavailable; using safe built-in mission spec");
        return Ok(default_mission_spec(goal));
    }
    let body: Value = response.json().context("decoding ATOM chat response")?;
    let Some(content) = body["content"].as_str() else {
        println!("ATOM> empty model reply; using safe built-in mission spec");
        return Ok(default_mission_spec(goal));
    };
    match parse_mission_spec_content(goal, content) {
        Some(spec) => {
            println!("ATOM> mission spec drafted by model, sanitized by ATOM");
            Ok(spec)
        }
        None => {
            println!("ATOM> model reply was not a valid mission spec; using safe built-in spec");
            Ok(default_mission_spec(goal))
        }
    }
}

/// Render the durable evidence recorded after a mission reaches a terminal
/// state. Observations are not yet per-mission, so all recorded evidence is
/// shown honestly.
fn render_evidence(client: &reqwest::blocking::Client, base: &str) -> Result<()> {
    let response = client
        .get(format!("{base}/evidence"))
        .send()
        .context("fetching mission evidence")?;
    if !response.status().is_success() {
        println!(
            "ATOM> could not fetch evidence (HTTP {})",
            response.status()
        );
        return Ok(());
    }
    let body: Value = response.json().context("decoding evidence response")?;
    let observations = body["observations"].as_array().cloned().unwrap_or_default();
    println!(
        "ATOM> evidence: {} observation(s) recorded",
        observations.len()
    );
    for obs in observations {
        let tool = obs["tool"].as_str().unwrap_or("?");
        let path = obs["path"].as_str().unwrap_or("");
        let obs_id = obs["observation_id"].as_str().unwrap_or("");
        println!("ATOM>   - {tool} {path} ({obs_id})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fenced_spec_forces_safe_fields_and_drops_unknown() {
        let content = "```json\n{\"goal\":\"run a demo\",\"success_criteria\":[\"s1\"],\"constraints\":[\"c1\"],\"budgets\":{\"max_steps\":3},\"authority_profile_ref\":\"authority/escape\",\"evidence_requirements\":[\"e1\"],\"stopping_rules\":[\"r1\"],\"sneaky\":true}\n```";
        let spec = parse_mission_spec_content("MY REAL GOAL", content).expect("spec");
        assert_eq!(spec["goal"].as_str(), Some("MY REAL GOAL"));
        assert_eq!(
            spec["authority_profile_ref"].as_str(),
            Some("authority/read-only")
        );
        assert_eq!(spec["budgets"]["max_steps"].as_u64(), Some(3));
        assert!(
            spec.get("sneaky").is_none(),
            "unknown fields must be dropped"
        );
    }

    #[test]
    fn clamps_budget_and_keeps_extra_known_budget() {
        let content = r#"{"goal":"replace","success_criteria":["s"],"constraints":["c"],"budgets":{"max_steps":9999,"other":7},"evidence_requirements":["e"],"stopping_rules":["r"]}"#;
        let spec = parse_mission_spec_content("top goal", content).expect("spec");
        assert_eq!(spec["budgets"]["max_steps"].as_u64(), Some(256));
        assert_eq!(spec["budgets"]["other"].as_u64(), Some(7));
        assert_eq!(spec["goal"].as_str(), Some("top goal"));
    }

    #[test]
    fn default_budget_when_missing_or_garbage() {
        for content in [
            r#"{"goal":"g","success_criteria":["s"],"constraints":["c"],"budgets":{"max_steps":"lots"},"evidence_requirements":["e"],"stopping_rules":["r"]}"#,
            r#"{"goal":"g","success_criteria":["s"],"constraints":["c"],"evidence_requirements":["e"],"stopping_rules":["r"]}"#,
        ] {
            let spec = parse_mission_spec_content("g", content).expect("spec");
            assert_eq!(spec["budgets"]["max_steps"].as_u64(), Some(8));
        }
    }

    #[test]
    fn non_json_reply_is_none() {
        assert!(parse_mission_spec_content("g", "sure, here is a plan!").is_none());
    }

    #[test]
    fn missing_required_list_is_none() {
        let content = r#"{"goal":"g","success_criteria":["s"]}"#;
        assert!(parse_mission_spec_content("g", content).is_none());
    }
}
