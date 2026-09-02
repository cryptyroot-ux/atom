//! First-run setup for a system-installed ATOM instance.
#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;

pub struct SetupOptions {
    pub provider_key_file: Option<std::path::PathBuf>,
    pub provider_base_url: Option<String>,
    pub provider_model: Option<String>,
    pub no_provider: bool,
}

pub fn run(options: SetupOptions) -> Result<()> {
    if !is_root() {
        bail!("system setup requires root; run `sudo atom setup ...`");
    }
    let options = if !options.no_provider
        && options.provider_key_file.is_none()
        && options.provider_base_url.is_none()
        && options.provider_model.is_none()
        && interactive_terminal()
    {
        println!("ATOM setup wizard");
        println!("This configures the signing identity, model gateway, API key, and service.");
        println!("Choose native cognition only if you intentionally do not want a model provider.");
        prompt_provider()?
    } else {
        options
    };

    let config_dir = Path::new("/etc/atom");
    std::fs::create_dir_all(config_dir).context("creating /etc/atom")?;
    if !config_dir.join("signing-secret").exists() {
        let output = std::process::Command::new("openssl")
            .args(["rand", "-base64", "32"])
            .output()
            .context("running openssl to generate signing identity")?;
        if !output.status.success() {
            bail!("openssl failed to generate signing identity");
        }
        std::fs::write(config_dir.join("signing-secret"), output.stdout)?;
        restrict(&config_dir.join("signing-secret"))?;
    }
    let key_path = config_dir.join("provider-api-key");
    let has_source = options.provider_key_file.is_some();
    if let Some(source) = options.provider_key_file.as_ref() {
        if !source.is_file() {
            bail!("provider key file does not exist: {}", source.display());
        }
        std::fs::copy(source, &key_path).context("installing provider credential")?;
        restrict(&key_path)?;
        // Interactive setup creates a short-lived root-readable handoff file;
        // remove it immediately after the credential has been staged.
        if source
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("atom-provider-key-"))
        {
            let _ = std::fs::remove_file(source);
        }
    } else if !key_path.exists() {
        std::fs::write(&key_path, [])?;
    }
    let enabled = !options.no_provider && (has_source || key_path.metadata()?.len() > 0);
    let mut env = String::from("ATOM_SERVE_ADDR=127.0.0.1:8420\nATOM_STATE_DB=/var/lib/atom/atom.sqlite\nATOM_SIGNING_KEY_ID=atom-prod-v1\n");
    env.push_str(if enabled {
        "ATOM_NO_PROVIDER=false\n"
    } else {
        "ATOM_NO_PROVIDER=true\n"
    });
    if enabled {
        env.push_str(&format!(
            "ATOM_PROVIDER_BASE_URL={}\n",
            options
                .provider_base_url
                .as_deref()
                .unwrap_or("https://free.pango.fun")
        ));
        env.push_str(&format!(
            "ATOM_PROVIDER_MODEL={}\n",
            options.provider_model.as_deref().unwrap_or("auto")
        ));
    }
    std::fs::write(config_dir.join("env"), env).context("writing Atom configuration")?;
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["enable", "atom.service"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["restart", "atom.service"])
        .status();
    println!("ATOM setup complete");
    println!("  signing:  /etc/atom/signing-secret (managed credential)");
    println!("  endpoint: http://127.0.0.1:8420");
    println!(
        "  provider: {}",
        if enabled { "enabled" } else { "disabled" }
    );
    if enabled {
        println!(
            "  gateway:  {}",
            options
                .provider_base_url
                .as_deref()
                .unwrap_or("https://free.pango.fun")
        );
        println!(
            "  model:    {}",
            options.provider_model.as_deref().unwrap_or("auto")
        );
        println!("  api key:  installed as a systemd credential (hidden)");
    } else {
        println!("  mode:     native cognition (no conversational model)");
    }
    println!("  service: run `atom status` to verify");
    Ok(())
}

fn interactive_terminal() -> bool {
    io::stdin().is_terminal() || Path::new("/dev/tty").exists()
}

/// Collects provider settings from the controlling terminal. The API key is
/// read with terminal echo disabled on Unix and is never included in output.
fn prompt_provider() -> Result<SetupOptions> {
    let use_provider = prompt_line("Use an OpenAI-compatible provider? [Y/n] ", "y")?;
    if matches!(use_provider.to_ascii_lowercase().as_str(), "n" | "no") {
        return Ok(SetupOptions {
            provider_key_file: None,
            provider_base_url: None,
            provider_model: None,
            no_provider: true,
        });
    }
    let base_url = prompt_line(
        "Gateway URL [https://free.pango.fun]: ",
        "https://free.pango.fun",
    )?;
    let model = prompt_line("Model [auto]: ", "auto")?;
    let key = prompt_secret("API key (hidden, required): ")?;
    if key.trim().is_empty() {
        bail!("provider selected but API key is empty; rerun `sudo atom setup` or choose native cognition")
    }
    let key_file = std::env::temp_dir().join(format!("atom-provider-key-{}", std::process::id()));
    std::fs::write(&key_file, key.trim())?;
    restrict(&key_file)?;
    Ok(SetupOptions {
        provider_key_file: Some(key_file),
        provider_base_url: Some(base_url),
        provider_model: Some(model),
        no_provider: false,
    })
}

fn prompt_line(prompt: &str, default: &str) -> Result<String> {
    let mut tty = open_tty()?;
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut line = String::new();
    io::BufReader::new(tty).read_line(&mut line)?;
    let value = line.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

#[cfg(unix)]
fn prompt_secret(prompt: &str) -> Result<String> {
    use std::process::{Command, Stdio};
    let mut tty = open_tty()?;
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut echo = tty.try_clone()?;
    let _ = Command::new("stty")
        .arg("-echo")
        .stdin(Stdio::from(echo.try_clone()?))
        .status();
    let mut line = String::new();
    let result = io::BufReader::new(tty).read_line(&mut line);
    let _ = Command::new("stty")
        .arg("echo")
        .stdin(Stdio::from(echo.try_clone()?))
        .status();
    writeln!(echo)?;
    result.map(|_| line.trim().to_owned()).map_err(Into::into)
}

#[cfg(not(unix))]
fn prompt_secret(prompt: &str) -> Result<String> {
    prompt_line(prompt, "")
}

fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .or_else(|_| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/stdin")
        })
        .context("opening controlling terminal for setup wizard")
}

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|uid| uid.trim() == "0")
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_: &Path) -> Result<()> {
    Ok(())
}
