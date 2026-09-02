//! First-run setup for a system-installed ATOM instance.
#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
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
    println!(
        "  provider: {}",
        if enabled { "enabled" } else { "disabled" }
    );
    println!("  service: run `atom status` to verify");
    Ok(())
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
