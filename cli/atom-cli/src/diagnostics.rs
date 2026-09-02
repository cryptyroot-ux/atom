//! Read-only operator diagnostics for installed ATOM deployments.
#![forbid(unsafe_code)]

use anyhow::Result;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

pub fn status(addr: &str) -> Result<()> {
    let service = systemd_state("atom.service");
    let health = probe_health(addr);
    println!("ATOM status");
    println!("  service: {}", service);
    println!("  health:  {}", health);
    if service != "active" || health != "healthy" {
        anyhow::bail!("ATOM is not ready (run `atom doctor` for details)");
    }
    Ok(())
}

pub fn doctor(addr: &str) -> Result<()> {
    let mut failures = 0_u8;
    println!("ATOM doctor");
    failures += check("binary", std::env::current_exe().is_ok());
    failures += check("systemd service", systemd_state("atom.service") == "active");
    failures += check("HTTP health", probe_health(addr) == "healthy");
    let state_db =
        std::env::var("ATOM_STATE_DB").unwrap_or_else(|_| "/var/lib/atom/atom.sqlite".into());
    failures += check(
        "state directory",
        std::path::Path::new(&state_db)
            .parent()
            .is_some_and(std::path::Path::exists),
    );
    let provider = configured_provider();
    println!(
        "  provider: {}",
        provider
            .as_deref()
            .unwrap_or("not configured (native cognition)")
    );
    if failures > 0 {
        anyhow::bail!("doctor found {failures} failing check(s)");
    }
    Ok(())
}

fn configured_provider() -> Option<String> {
    if let Ok(value) = std::env::var("ATOM_PROVIDER_BASE_URL") {
        return Some(value);
    }
    std::fs::read_to_string("/etc/atom/env")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("ATOM_PROVIDER_BASE_URL=")
                    .map(str::to_owned)
            })
        })
}

fn check(name: &str, ok: bool) -> u8 {
    println!("  {name}: {}", if ok { "OK" } else { "FAIL" });
    u8::from(!ok)
}

fn systemd_state(unit: &str) -> String {
    Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn probe_health(addr: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(addr) else {
        return "unreachable".into();
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return "unreachable".into();
    }
    let mut body = String::new();
    if stream.read_to_string(&mut body).is_err() {
        return "unreachable".into();
    }
    if body.starts_with("HTTP/1.1 200") && body.contains("\"status\":\"healthy\"") {
        "healthy".into()
    } else {
        body.lines().next().unwrap_or("unhealthy").to_owned()
    }
}

pub fn default_addr() -> String {
    std::env::var("ATOM_SERVE_ADDR").unwrap_or_else(|_| "127.0.0.1:8420".into())
}
