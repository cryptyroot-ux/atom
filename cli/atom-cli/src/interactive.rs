//! Interactive operator session backed by the durable API and model gateway.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::time::Duration;

use crate::display::{
    clear_progress, print_atom_prefix, print_banner, print_divider, print_error, print_feed,
    print_info, print_outcome, print_panel, print_phase, print_prompt, print_success,
    print_tool_call, print_warning, render_markdown, Spinner, BOLD, CYAN, DIM, GOLD, GREEN, RESET,
};

/// Opens a conversational session.
pub fn run() -> Result<()> {
    let base = std::env::var("ATOM_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8420".into());

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("creating ATOM API client")?;

    // Print branded banner
    print_banner();
    print_info(&format!("Connected to {base}"));
    print_info("Type a message to chat, /mission <goal>, /status, /help, or /quit.");
    print_divider();

    let mut history = vec![json!({
        "role": "system",
        "content": "You are ATOM, a careful sovereign assistant. Explain proposed actions clearly. Never claim an external effect happened unless ATOM reports a verified terminal result."
    })];

    loop {
        print_prompt();
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        // ── Natural Language Understanding (NLU) ─────────────────────────
        // Detect common intents and route to the right handler instead of
        // sending generic text to the LLM.
        let lower = input.to_lowercase();
        let nlu_status = [
            "check server",
            "ceeck server",
            "cek server",
            "status server",
            "status atom",
            "atom status",
            "health check",
            "check health",
            "server health",
            "is atom running",
            "is the server up",
        ];
        let nlu_version = [
            "show version",
            "which version",
            "atom version",
            "version info",
            "what version",
            "display version",
        ];
        let nlu_model = [
            "which model",
            "what model",
            "show model",
            "current model",
            "model info",
            "what provider",
            "which provider",
        ];
        let nlu_uptime = ["show uptime", "how long", "uptime info", "running time"];

        if nlu_status.iter().any(|p| lower.contains(p)) {
            let response = client.get(format!("{base}/health")).send()?;
            let body: Value = response.json().context("decoding health response")?;
            let status = body["status"].as_str().unwrap_or("unknown");
            let version = body["version"].as_str().unwrap_or("unknown");
            let uptime = body["uptime_seconds"].as_u64().unwrap_or(0);
            let crates = body["crates_loaded"].as_u64().unwrap_or(0);
            println!();
            print_panel("ATOM Status", &format!(
                "Status:  {status}\nVersion: {version}\nUptime:  {uptime}s\nCrates:  {crates} loaded"
            ), CYAN);
            continue;
        }

        if nlu_version.iter().any(|p| lower.contains(p)) {
            let response = client.get(format!("{base}/health")).send()?;
            let body: Value = response.json().context("decoding health response")?;
            let version = body["version"].as_str().unwrap_or("unknown");
            print_info(&format!("ATOM version: {version}"));
            continue;
        }

        if nlu_model.iter().any(|p| lower.contains(p)) {
            let response = client.get(format!("{base}/health")).send()?;
            let body: Value = response.json().context("decoding health response")?;
            let model = body["model"].as_str().unwrap_or("auto");
            print_info(&format!("Current model: {model}"));
            continue;
        }

        if nlu_uptime.iter().any(|p| lower.contains(p)) {
            let response = client.get(format!("{base}/health")).send()?;
            let body: Value = response.json().context("decoding health response")?;
            let uptime = body["uptime_seconds"].as_u64().unwrap_or(0);
            let hours = uptime / 3600;
            let minutes = (uptime % 3600) / 60;
            let seconds = uptime % 60;
            print_info(&format!("Uptime: {hours}h {minutes}m {seconds}s"));
            continue;
        }

        // ── Slash Commands ────────────────────────────────────────────────
        match input {
            "/quit" | "/exit" => break,
            "/help" => {
                println!();
                print_info("ATOM commands:");
                println!("  {GOLD}/mission <goal>{RESET}  Run a governed mission");
                println!("  {GOLD}/tools{RESET}          List available read-only tools");
                println!("  {GOLD}/ls <path>{RESET}      List directory (via tool boundary)");
                println!("  {GOLD}/read <path>{RESET}    Read file (via tool boundary)");
                println!("  {GOLD}/grep <path> <needle>{RESET}  Search file contents");
                println!("  {GOLD}/evidence{RESET}       Show evidence ledger");
                println!("  {GOLD}/caps{RESET}           Show capability grants (authority view)");
                println!("  {GOLD}/ledger{RESET}         Show sealed ledger events + checkpoint");
                println!("  {GOLD}/model{RESET}          Configure gateway/model/key");
                println!("  {GOLD}/status{RESET}         Show service health");
                println!("  {GOLD}/help{RESET}           Show this help");
                println!("  {GOLD}/quit{RESET}           Exit session");
                println!();
                print_info("You can also ask naturally:");
                println!("  {DIM}\"check server\", \"status atom\", \"which model\"{RESET}");
                continue;
            }
            "/model" => {
                print_warning("Run `sudo atom model` to configure the gateway, model, and API key");
                continue;
            }
            "/tools" => {
                print_feed("⚙", CYAN, "tools", "POST /tools/read-only");
                let response = client
                    .post(format!("{base}/tools/read-only"))
                    .json(&json!({"tool": "list_directory", "path": "/var/lib/atom"}))
                    .send()?;
                if response.status().is_success() {
                    let body: Value = response.json()?;
                    if let Some(entries) = body["result"].as_array() {
                        print_info("Available observations from tool boundary:");
                        for entry in entries {
                            if let Some(s) = entry.as_str() {
                                println!("  {CYAN}•{RESET} {s}");
                            }
                        }
                    }
                } else {
                    print_warning("Tool boundary unavailable (daemon not running?)");
                }
                continue;
            }
            "/status" => {
                let response = client.get(format!("{base}/health")).send()?;
                let body: Value = response.json().context("decoding health response")?;
                let status = body["status"].as_str().unwrap_or("unknown");
                let version = body["version"].as_str().unwrap_or("unknown");
                let uptime = body["uptime_seconds"].as_u64().unwrap_or(0);
                let crates = body["crates_loaded"].as_u64().unwrap_or(0);
                println!();
                print_panel("ATOM Status", &format!(
                    "Status:  {status}\nVersion: {version}\nUptime:  {uptime}s\nCrates:  {crates} loaded"
                ), CYAN);
                continue;
            }
            "/evidence" => {
                render_evidence(&client, &base)?;
                continue;
            }
            "/caps" => {
                print_feed("⚙", CYAN, "capabilities", "GET /capabilities");
                match client.get(format!("{base}/capabilities")).send() {
                    Ok(resp) if resp.status().is_success() => {
                        let body: Value = resp.json()?;
                        let grants = body["grants"].as_array().cloned().unwrap_or_default();
                        print_feed(
                            "✓",
                            GREEN,
                            "capabilities",
                            &format!("{} grant(s)", grants.len()),
                        );
                        if grants.is_empty() {
                            println!("  {DIM}no capability grants bound (deny-by-default){RESET}");
                        }
                        for g in grants {
                            let id = g["grant_id"]
                                .as_str()
                                .or_else(|| g["id"].as_str())
                                .unwrap_or("?");
                            let gen = g["generation"].as_u64().unwrap_or(0);
                            let op = g["operation"]
                                .as_str()
                                .or_else(|| g["capability_id"].as_str())
                                .unwrap_or("");
                            println!(
                                "  {CYAN}•{RESET} {BOLD}{id}{RESET} {DIM}gen {gen} {op}{RESET}"
                            );
                        }
                    }
                    _ => print_warning("capabilities unavailable (daemon not running?)"),
                }
                continue;
            }
            "/ledger" => {
                print_feed("⚙", CYAN, "ledger", "GET /ledger/events");
                match client.get(format!("{base}/ledger/events")).send() {
                    Ok(resp) if resp.status().is_success() => {
                        let body: Value = resp.json()?;
                        let checkpoint = body["checkpoint"].as_u64().unwrap_or(0);
                        let events = body["events"].as_array().cloned().unwrap_or_default();
                        print_feed(
                            "✓",
                            GREEN,
                            "ledger",
                            &format!(
                                "{} event(s), checkpoint {checkpoint} (HMAC-SHA256 chained)",
                                events.len()
                            ),
                        );
                        // Show the newest 12 sealed events, most recent last.
                        let tail = events.iter().rev().take(12).collect::<Vec<_>>();
                        for ev in tail.into_iter().rev() {
                            let kind = ev["event_type"].as_str().unwrap_or("?");
                            let hash = ev["payload_hash"].as_str().unwrap_or("");
                            let short = hash.get(..12).unwrap_or(hash);
                            println!("  {GOLD}▪{RESET} {BOLD}{kind}{RESET} {DIM}{short}{RESET}");
                        }
                    }
                    _ => print_warning("ledger unavailable (daemon not running?)"),
                }
                continue;
            }
            command if command.starts_with("/ls ") => {
                let path = command.trim_start_matches("/ls ");
                print_tool_call("list_directory", path);
                let response = client
                    .post(format!("{base}/tools/read-only"))
                    .json(&json!({"tool": "list_directory", "path": path}))
                    .send()?;
                if response.status().is_success() {
                    let body: Value = response.json()?;
                    if let Some(entries) = body["result"].as_array() {
                        let obs_id = body["observation_id"].as_str().unwrap_or("");
                        print_feed(
                            "✓",
                            GREEN,
                            "list_directory",
                            &format!("{} entries, obs={obs_id}", entries.len()),
                        );
                        for entry in entries {
                            if let Some(s) = entry.as_str() {
                                println!("  {DIM}{s}{RESET}");
                            }
                        }
                    } else {
                        let detail = body["detail"].as_str().unwrap_or("unexpected response");
                        print_error(detail);
                    }
                } else {
                    let body: Value = response.json().unwrap_or_default();
                    let detail = body["detail"].as_str().unwrap_or("tool call failed");
                    print_error(detail);
                }
                continue;
            }
            command if command.starts_with("/read ") => {
                let path = command.trim_start_matches("/read ");
                print_tool_call("read_file", path);
                let response = client
                    .post(format!("{base}/tools/read-only"))
                    .json(&json!({"tool": "read_file", "path": path}))
                    .send()?;
                if response.status().is_success() {
                    let body: Value = response.json()?;
                    let content = body["result"].as_str().unwrap_or("");
                    let obs_id = body["observation_id"].as_str().unwrap_or("");
                    print_feed(
                        "✓",
                        GREEN,
                        "read_file",
                        &format!("{} bytes, obs={obs_id}", content.len()),
                    );
                    print!("{}", render_markdown(&format!("```\n{content}\n```")));
                } else {
                    let body: Value = response.json().unwrap_or_default();
                    let detail = body["detail"].as_str().unwrap_or("tool call failed");
                    print_error(detail);
                }
                continue;
            }
            command if command.starts_with("/grep ") => {
                let rest = command.trim_start_matches("/grep ");
                let (path, needle) = match rest.split_once(' ') {
                    Some((p, n)) => (p, n),
                    None => {
                        print_warning("usage: /grep <path> <needle>");
                        continue;
                    }
                };
                print_tool_call("search_text", &format!("{path} needle={needle}"));
                let response = client
                    .post(format!("{base}/tools/read-only"))
                    .json(&json!({"tool": "search_text", "path": path, "needle": needle}))
                    .send()?;
                if response.status().is_success() {
                    let body: Value = response.json()?;
                    let results = body["result"].as_array();
                    let obs_id = body["observation_id"].as_str().unwrap_or("");
                    let count = results.map_or(0, |a| a.len());
                    print_feed(
                        "✓",
                        GREEN,
                        "search_text",
                        &format!("{count} matching lines, obs={obs_id}"),
                    );
                    if let Some(matches) = results {
                        for line in matches {
                            if let Some(text) = line.as_str() {
                                println!("  {CYAN}▎{RESET} {DIM}{text}{RESET}");
                            }
                        }
                    }
                } else {
                    let body: Value = response.json().unwrap_or_default();
                    let detail = body["detail"].as_str().unwrap_or("tool call failed");
                    print_error(detail);
                }
                continue;
            }
            command if command.starts_with("/mission ") => {
                submit_mission(&client, &base, command.trim_start_matches("/mission "))?;
                continue;
            }
            command if command.starts_with('/') => {
                print_warning("Unknown command; use /help");
                continue;
            }
            _ => {}
        }

        // ── Chat with LLM ─────────────────────────────────────────────────
        history.push(json!({"role": "user", "content": input}));
        if history.len() > 21 {
            history.drain(1..history.len() - 20);
        }

        // Show a live spinner while the sovereign daemon works the request.
        print_feed(
            "◐",
            GOLD,
            "cognition",
            "drafting a response via the ATOM daemon",
        );
        let mut spinner = Spinner::new("thinking");
        spinner.tick();

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
            clear_progress();
            print_error(detail);
            print_warning("Configure with: sudo atom setup");
            let _ = history.pop();
            continue;
        }

        let answer = body["content"].as_str().unwrap_or("(empty model response)");
        let model = body["model"].as_str().unwrap_or("");
        clear_progress();
        if !model.is_empty() {
            print_feed("✓", GREEN, "cognition", &format!("model {model}"));
        }
        println!();
        print_atom_prefix();
        println!();
        print!("{}", render_markdown(answer));
        print_divider();
        history.push(json!({"role": "assistant", "content": answer}));
    }
    Ok(())
}

fn submit_mission(client: &reqwest::blocking::Client, base: &str, goal: &str) -> Result<()> {
    if goal.trim().is_empty() {
        print_warning("usage: /mission <goal>");
        return Ok(());
    }
    let payload = draft_mission_spec(client, base, goal)?;
    let response = client
        .post(format!("{base}/missions"))
        .json(&payload)
        .send()
        .context("submitting mission to ATOM")?;
    if !response.status().is_success() {
        print_error(&format!(
            "mission submission failed (HTTP {})",
            response.status()
        ));
        return Ok(());
    }
    let created: Value = response.json().context("decoding mission response")?;
    let Some(id) = created["mission_id"].as_str() else {
        print_warning("daemon returned no mission id");
        return Ok(());
    };
    print_success(&format!("mission {id} submitted"));
    println!();
    print_feed("▸", GOLD, "MISSION", goal.trim());
    print_divider();

    // ── Live activity feed ────────────────────────────────────────────────
    // Poll the durable mission and its ledger and render every *observed*
    // phase transition and tool observation as it lands. This is honest live
    // visibility: we render only what the daemon has actually sealed, never a
    // fabricated step. The initial CREATED/READY phase is shown immediately.
    let mut last_phase = created["phase"].as_str().unwrap_or("CREATED").to_owned();
    print_phase(&last_phase);
    let mut seen_observations = std::collections::HashSet::new();
    let mut outcome = "TIMEOUT".to_owned();

    for _ in 0..120 {
        std::thread::sleep(Duration::from_millis(500));
        let value: Value = client.get(format!("{base}/missions/{id}")).send()?.json()?;

        // Surface any new tool observations sealed on the evidence ledger.
        if let Ok(evidence) = client.get(format!("{base}/evidence")).send() {
            if let Ok(body) = evidence.json::<Value>() {
                if let Some(observations) = body["observations"].as_array() {
                    for obs in observations {
                        let obs_id = obs["observation_id"].as_str().unwrap_or("");
                        if !obs_id.is_empty() && seen_observations.insert(obs_id.to_owned()) {
                            let tool = obs["tool"].as_str().unwrap_or("tool");
                            let path = obs["path"].as_str().unwrap_or("");
                            print_tool_call(tool, path);
                        }
                    }
                }
            }
        }

        // Render a phase transition the moment the daemon records it.
        let phase = value["phase"]
            .as_str()
            .unwrap_or(last_phase.as_str())
            .to_owned();
        if phase != last_phase {
            print_phase(&phase);
            last_phase = phase.clone();
        }

        if phase == "TERMINAL" {
            outcome = value["outcome"].as_str().unwrap_or("UNKNOWN").to_owned();
            break;
        }
    }

    print_divider();
    print_outcome(&outcome);
    render_evidence(client, base)?;
    Ok(())
}

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
        print_warning("model unavailable; using safe built-in mission spec");
        return Ok(default_mission_spec(goal));
    }
    let body: Value = response.json().context("decoding ATOM chat response")?;
    let Some(content) = body["content"].as_str() else {
        print_warning("empty model reply; using safe built-in mission spec");
        return Ok(default_mission_spec(goal));
    };
    match parse_mission_spec_content(goal, content) {
        Some(spec) => {
            print_success("mission spec drafted by model, sanitized by ATOM");
            Ok(spec)
        }
        None => {
            print_warning("model reply was not a valid mission spec; using safe built-in spec");
            Ok(default_mission_spec(goal))
        }
    }
}

fn render_evidence(client: &reqwest::blocking::Client, base: &str) -> Result<()> {
    let response = client
        .get(format!("{base}/evidence"))
        .send()
        .context("fetching mission evidence")?;
    if !response.status().is_success() {
        print_warning(&format!(
            "could not fetch evidence (HTTP {})",
            response.status()
        ));
        return Ok(());
    }
    let body: Value = response.json().context("decoding evidence response")?;
    let observations = body["observations"].as_array().cloned().unwrap_or_default();
    println!();
    print_panel(
        "Evidence",
        &format!("{} observation(s) recorded", observations.len()),
        CYAN,
    );
    for obs in observations {
        let tool = obs["tool"].as_str().unwrap_or("?");
        let path = obs["path"].as_str().unwrap_or("");
        let obs_id = obs["observation_id"].as_str().unwrap_or("");
        println!("  {GOLD}•{RESET} {tool} {path} {DIM}({obs_id}){RESET}");
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
            // Non-numeric max_steps: valid JSON, but the string value can't be
            // read as u64, so the clamp falls back to the default of 8.
            r#"{"goal":"g","success_criteria":["s"],"constraints":["c"],"budgets":{"max_steps":"lots"},"evidence_requirements":["e"],"stopping_rules":["r"]}"#,
            // No budgets object at all: also falls back to the default of 8.
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
