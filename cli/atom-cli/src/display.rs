//! ATOM CLI display layer — panels, markdown, spinners, and skin-aware colors.
//!
//! Modeled after Hermes Agent's ChatConsole + banner system, adapted for Rust.
//! Uses pulldown-cmark for markdown rendering and console for terminal detection.

use std::io::{self, Write};

// ── Skin-aware color palette (ATOM brand: sovereign gold/bronze) ──────────

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const ITALIC: &str = "\x1b[3m";
pub const UNDERLINE: &str = "\x1b[4m";

pub const GOLD: &str = "\x1b[38;2;255;191;0m";       // #FFBF00 - primary accent
pub const GOLD_BRIGHT: &str = "\x1b[38;2;255;215;0m"; // #FFD700 - banner
pub const BRONZE: &str = "\x1b[38;2;205;127;50m";     // #CD7F32 - secondary
pub const AMBER: &str = "\x1b[38;2;184;134;11m";      // #B8860B - dim

pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";
pub const WHITE: &str = "\x1b[37m";

pub const BG_DARK: &str = "\x1b[48;2;8;11;18m";       // ATOM dark background

// ── Terminal detection ─────────────────────────────────────────────────────

pub fn terminal_width() -> usize {
    console::Term::stdout().size().1 as usize
}

pub fn is_terminal() -> bool {
    console::Term::stdout().is_term()
}

// ── Banner ─────────────────────────────────────────────────────────────────

pub const ATOM_BANNER: &str = r#"
  ___ _____ ________  ___
 / _ \_   _|  _  |  \/  |
/ /_\ \| | | | | | .  . |
|  _  || | | | | | |\/| |
| | | || | \ \_/ / |  | |
\_| |_/\_/  \___/\_|  |_/
"#;

pub fn print_banner() {
    let width = terminal_width().min(88);
    let border = "═".repeat(width.saturating_sub(2));
    
    println!("{BOLD}{GOLD_BRIGHT}╔{border}╗{RESET}");
    println!("{BOLD}{GOLD_BRIGHT}║{RESET} {GOLD}ATOM{RESET} {DIM}{AMBER}Sovereign Recursive Agent{RESET}{:>width$}{BOLD}{GOLD_BRIGHT}║{RESET}", 
        "", width = width.saturating_sub(34));
    println!("{BOLD}{GOLD_BRIGHT}║{RESET} {DIM}{BRONZE}Cognition proposes. Authority permits. Reality determines.{RESET}{:>width$}{BOLD}{GOLD_BRIGHT}║{RESET}",
        "", width = width.saturating_sub(58));
    println!("{BOLD}{GOLD_BRIGHT}╚{border}╝{RESET}");
    println!();
}

// ── Panels ─────────────────────────────────────────────────────────────────

pub fn print_panel(title: &str, content: &str, border_color: &str) {
    let width = terminal_width().min(80).max(40);
    let inner_width = width.saturating_sub(4);
    
    let border = "─".repeat(inner_width);
    println!("{border_color}┌{border}┐{RESET}");
    
    if !title.is_empty() {
        println!("{border_color}│{RESET} {BOLD}{GOLD}{title}{RESET}{:>width$}{border_color} │{RESET}",
            "", width = inner_width.saturating_sub(title.len() + 1));
        println!("{border_color}├{border}┤{RESET}");
    }
    
    for line in content.lines() {
        let visible_len = strip_ansi_len(line);
        let padding = inner_width.saturating_sub(visible_len + 1);
        println!("{border_color}│{RESET} {line}{:>width$}{border_color} │{RESET}", 
            "", width = padding);
    }
    
    println!("{border_color}└{border}┘{RESET}");
}

/// Strip ANSI escape sequences to get visible length
fn strip_ansi_len(s: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            count += 1;
        }
    }
    count
}

// ── Markdown rendering (basic) ─────────────────────────────────────────────

pub fn render_markdown(text: &str) -> String {
    let mut output = String::new();
    let mut in_code_block = false;
    let mut code_lang: String;

    for line in text.lines() {
        let trimmed = line.trim();

        // Code blocks
        if trimmed.starts_with("```") {
            if in_code_block {
                output.push_str(&format!("{DIM}{BRONZE}└──────────────────────────────┘{RESET}\n"));
                in_code_block = false;
            } else {
                code_lang = trimmed.trim_start_matches('`').trim().to_string();
                output.push_str(&format!("{DIM}{BRONZE}┌─ {code_lang} ──────────────────────┐{RESET}\n"));
                in_code_block = true;
            }
            continue;
        }
        
        if in_code_block {
            output.push_str(&format!("{DIM}{BRONZE}│{RESET} {WHITE}{line}{RESET}\n"));
            continue;
        }
        
        // Headers
        if trimmed.starts_with("### ") {
            output.push_str(&format!("\n{ITALIC}{CYAN}{}{RESET}\n", trimmed.trim_start_matches('#').trim()));
        } else if trimmed.starts_with("## ") {
            output.push_str(&format!("\n{BOLD}{CYAN}{}{RESET}\n", trimmed.trim_start_matches('#').trim()));
        } else if trimmed.starts_with("# ") {
            output.push_str(&format!("\n{BOLD}{UNDERLINE}{GOLD}{}{RESET}\n", trimmed.trim_start_matches('#').trim()));
        }
        // Bullet points
        else if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            output.push_str(&format!("  {GOLD}•{RESET} {}\n", trimmed[2..].trim()));
        }
        // Numbered lists
        else if trimmed.len() > 2 && trimmed.chars().next().unwrap().is_ascii_digit() 
            && trimmed.chars().nth(1) == Some('.') && trimmed.chars().nth(2) == Some(' ') {
            output.push_str(&format!("  {GOLD}{}{RESET} {}\n", 
                trimmed[..2].trim(), trimmed[3..].trim()));
        }
        // Inline code
        else if trimmed.contains('`') {
            let mut result = String::new();
            let mut chars = trimmed.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '`' {
                    result.push_str(&format!("{DIM}{BRONZE}`"));
                    while let Some(inner) = chars.next() {
                        if inner == '`' {
                            result.push_str(&format!("`{RESET}"));
                            break;
                        }
                        result.push(inner);
                    }
                } else {
                    result.push(c);
                }
            }
            output.push_str(&format!("{result}\n"));
        }
        // Bold
        else if trimmed.contains("**") {
            let mut result = trimmed.to_string();
            while let Some(start) = result.find("**") {
                if let Some(end) = result[start+2..].find("**") {
                    let bold_text = &result[start+2..start+2+end];
                    result = format!("{}{}{}", 
                        &result[..start], 
                        format!("{BOLD}{GOLD}{bold_text}{RESET}"),
                        &result[start+2+end+2..]);
                } else {
                    break;
                }
            }
            output.push_str(&format!("{result}\n"));
        }
        // Regular text
        else if !trimmed.is_empty() {
            output.push_str(&format!("{trimmed}\n"));
        } else {
            output.push('\n');
        }
    }
    
    output
}

// ── Spinner / Progress ─────────────────────────────────────────────────────

pub struct Spinner {
    message: String,
    frames: Vec<&'static str>,
    current: usize,
}

impl Spinner {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current: 0,
        }
    }
    
    pub fn tick(&mut self) {
        let frame = self.frames[self.current % self.frames.len()];
        print!("\r{CYAN}{frame}{RESET} {DIM}{}{RESET}", self.message);
        io::stdout().flush().ok();
        self.current += 1;
    }
    
    pub fn finish(&self, result: &str) {
        print!("\r{GREEN}✓{RESET} {}{DIM} — {}{RESET}\n", self.message, result);
    }
    
    pub fn fail(&self, error: &str) {
        print!("\r{RED}✗{RESET} {}{DIM} — {}{RESET}\n", self.message, error);
    }
}

/// Simple dot progress for long operations
pub fn print_progress(step: &str) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dots = ".".repeat((count as usize % 4) + 1);
    print!("\r{CYAN}⠋{RESET} {step}{DIM}{dots}{RESET}   ");
    io::stdout().flush().ok();
}

pub fn clear_progress() {
    print!("\r{}\r", " ".repeat(80));
    io::stdout().flush().ok();
}

// ── Status indicators ───────────────────────────────────────────────────────

pub fn print_success(msg: &str) {
    println!("{GREEN}✓{RESET} {msg}");
}

pub fn print_error(msg: &str) {
    println!("{RED}✗{RESET} {msg}");
}

pub fn print_warning(msg: &str) {
    println!("{YELLOW}⚠{RESET} {msg}");
}

pub fn print_info(msg: &str) {
    println!("{CYAN}ℹ{RESET} {msg}");
}

pub fn print_divider() {
    let width = terminal_width().min(80);
    println!("{DIM}{AMBER}{}{RESET}", "─".repeat(width));
}

// ── Prompt ─────────────────────────────────────────────────────────────────

pub fn print_prompt() {
    print!("{BOLD}{YELLOW}You>{RESET} ");
    io::stdout().flush().ok();
}

pub fn print_atom_prefix() {
    print!("{BOLD}{CYAN}ATOM>{RESET} ");
}

pub fn print_thinking() {
    print!("{DIM}{ITALIC}thinking...{RESET}");
    io::stdout().flush().ok();
}

// ── Live activity feed (mission execution + tool visibility) ────────────────
//
// Hermes shows every step and tool call as it happens. ATOM's sovereign
// pipeline is phase-driven (CREATED → COMPILED → READY → RUNNING → VERIFYING →
// TERMINAL) and every durable step is sealed on the ledger. These renderers
// surface that real, already-happening work in the terminal instead of a row
// of anonymous dots — the feed reflects ledger truth, never a fabricated step.

/// The glyph and color used to render one mission phase.
///
/// Kept pure (no I/O) so the mapping is unit-testable and stable.
pub fn phase_glyph(phase: &str) -> (&'static str, &'static str) {
    match phase {
        "CREATED" => ("◇", DIM),
        "COMPILED" => ("◈", CYAN),
        "READY" => ("○", CYAN),
        "RUNNING" => ("◐", GOLD),
        "VERIFYING" => ("◑", YELLOW),
        "TERMINAL" => ("●", GREEN),
        _ => ("•", WHITE),
    }
}

/// Renders one phase transition as a live feed line, e.g. `◐ phase RUNNING`.
pub fn print_phase(phase: &str) {
    let (glyph, color) = phase_glyph(phase);
    println!("  {color}{glyph}{RESET} {DIM}phase{RESET} {BOLD}{color}{phase}{RESET}");
    io::stdout().flush().ok();
}

/// Renders one activity line in the feed: an icon, a bold label, and a dim
/// detail. Used for tool calls, ledger seals, and executor steps.
pub fn print_feed(icon: &str, color: &str, label: &str, detail: &str) {
    if detail.is_empty() {
        println!("  {color}{icon}{RESET} {BOLD}{label}{RESET}");
    } else {
        println!("  {color}{icon}{RESET} {BOLD}{label}{RESET} {DIM}{detail}{RESET}");
    }
    io::stdout().flush().ok();
}

/// Renders a tool invocation as it is dispatched (visible tool-use).
pub fn print_tool_call(tool: &str, target: &str) {
    print_feed("⚙", CYAN, tool, target);
}

/// Renders the outcome banner at the end of a mission run.
pub fn print_outcome(outcome: &str) {
    let (glyph, color) = match outcome {
        "SUCCEEDED" => ("✓", GREEN),
        "FAILED" | "UNSATISFIABLE" => ("✗", RED),
        "CANCELLED" => ("⊘", YELLOW),
        "TIMEOUT" => ("⧗", YELLOW),
        _ => ("•", WHITE),
    };
    println!("  {color}{glyph}{RESET} {DIM}outcome{RESET} {BOLD}{color}{outcome}{RESET}");
    io::stdout().flush().ok();
}

/// Renders the `atom run` boot report as a colored subsystem inventory, so a
/// live boot shows every wired crate and the double-gate proof in ATOM's skin
/// instead of flat text.
pub fn render_boot_report(report: &crate::boot::BootReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{BOLD}{GOLD}atom{RESET} {DIM}sovereign process booted{RESET}"
    );
    let _ = writeln!(out, "  {DIM}mission{RESET}        {CYAN}{}{RESET}", report.mission_id);
    let _ = writeln!(out, "  {DIM}signing key id{RESET} {CYAN}{}{RESET}", report.key_id);
    let _ = writeln!(
        out,
        "  {GREEN}✓{RESET} {BOLD}double gate{RESET} {DIM}commit token minted (KRN-001){RESET}"
    );
    let _ = writeln!(out, "      {DIM}effect{RESET}       {}", report.commit_effect_id);
    let _ = writeln!(
        out,
        "      {DIM}grant{RESET}        {} {DIM}(gen {}){RESET}",
        report.commit_grant_id, report.commit_grant_generation
    );
    let _ = writeln!(out, "      {DIM}resource{RESET}     {}", report.commit_resource_id);
    let _ = writeln!(out, "      {DIM}nonce burned{RESET} {}", report.commit_nonce);
    let _ = writeln!(out, "      {DIM}nonces spent{RESET} {}", report.nonces_spent);
    let _ = writeln!(out, "      {DIM}intent state{RESET} {GREEN}{}{RESET}", report.intent_state);
    let _ = writeln!(
        out,
        "  {GREEN}✓{RESET} {BOLD}worker{RESET} {} {DIM}admitted `{}` (WKR-001){RESET}",
        report.worker_id, report.admitted_operation
    );
    let _ = writeln!(
        out,
        "  {BOLD}{GOLD}subsystems{RESET} {DIM}({} wired crates){RESET}",
        report.subsystems.len()
    );
    for subsystem in &report.subsystems {
        let _ = writeln!(
            out,
            "    {GOLD}•{RESET} {BOLD}{:<24}{RESET} {DIM}{}{RESET}",
            subsystem.crate_name, subsystem.status
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_glyph_maps_every_canonical_phase() {
        for phase in [
            "CREATED",
            "COMPILED",
            "READY",
            "RUNNING",
            "VERIFYING",
            "TERMINAL",
        ] {
            let (glyph, color) = phase_glyph(phase);
            assert!(!glyph.is_empty(), "phase {phase} must have a glyph");
            assert!(color.starts_with('\x1b'), "phase {phase} must have a color");
        }
    }

    #[test]
    fn phase_glyph_has_a_fallback_for_unknown_phases() {
        let (glyph, _) = phase_glyph("WAT");
        assert_eq!(glyph, "•");
    }

    #[test]
    fn boot_report_render_includes_every_subsystem_and_gate_proof() {
        let report = crate::boot::BootReport {
            mission_id: "mission-x".into(),
            key_id: "key-x".into(),
            nonces_spent: 1,
            commit_effect_id: "effect-x".into(),
            commit_grant_id: "grant-x".into(),
            commit_grant_generation: 2,
            commit_resource_id: "resource-x".into(),
            commit_nonce: "nonce-x".into(),
            worker_id: "worker-x".into(),
            admitted_operation: "write".into(),
            intent_state: "Dispatching".into(),
            subsystems: vec![
                crate::boot::Subsystem::for_test("atom-kernel", "double gate closed"),
                crate::boot::Subsystem::for_test("atom-ledger", "append-only"),
            ],
        };
        let rendered = render_boot_report(&report);
        assert!(rendered.contains("atom-kernel"));
        assert!(rendered.contains("atom-ledger"));
        assert!(rendered.contains("mission-x"));
        assert!(rendered.contains("KRN-001"));
        assert!(rendered.contains("2 wired crates"));
    }
}
