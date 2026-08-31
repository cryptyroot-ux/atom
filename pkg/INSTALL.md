# ATOM v4 Installation Guide (G4 Foundry)

This guide documents how to install and run the `atom` sovereign binary on a fresh machine.

## Prerequisites

- **Rust toolchain**: `rustup` with `stable` channel, version **1.80+** (required by workspace).
- **Cargo**: bundled with rustup.
- **System dependencies** (Debian/Ubuntu):
  ```bash
  sudo apt-get update && sudo apt-get install -y \
    pkg-config libssl-dev clang build-essential
  ```
- **System dependencies** (Arch):
  ```bash
  sudo pacman -S --needed base-devel openssl pkgconf
  ```
- **System dependencies** (Fedora/RHEL):
  ```bash
  sudo dnf install -y gcc openssl-devel pkg-config
  ```

## Environment Configuration

`atom` signs and verifies content-addressed artifacts (SUP-001). You **must** provide a signing key via environment variables — **never hardcode secrets**.

```bash
# Required for `atom seal` and `atom verify`
export ATOM_SIGNING_KEY_ID="my-signing-key-v1"     # arbitrary identifier
export ATOM_SIGNING_KEY="base64-or-hex-secret"     # the actual secret bytes
```

> **Tip**: Generate a secret once and store it securely:
> ```bash
> ATOM_SIGNING_KEY="$(openssl rand -base64 32)"
> ```

## Install from Source (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/cryptyroot-ux/atom.git
cd atom

# 2. Build & install the `atom` binary
cargo install --path cli/atom-cli --locked

# 3. Verify installation
atom --version
# → atom 0.0.0-alpha.0 (ATOM v4.0-alpha)
```

The binary is installed to `~/.cargo/bin/atom` (ensure `~/.cargo/bin` is in your `PATH`).

## Alternative: Build Release Binary Only

If you don't want `cargo install` (e.g. for packaging):

```bash
cargo build --release -p atom-cli --locked

# Binary is at:
# target/release/atom
```

## Smoke Test (Seal + Verify)

```bash
# 1. Create a test payload
echo '#!/bin/sh\necho "hello from ATOM"' > test.sh

# 2. Seal it → produces a content-addressed artifact (SUP-001)
atom seal test.sh > test.atom.json

# 3. Inspect the artifact ID (sha256:...)
cat test.atom.json | jq -r .id
# → sha256:a1b2c3...

# 4. Verify it passes
atom verify test.atom.json
# → OK: sha256:a1b2c3...

# 5. Tamper detection
sed -i 's/hello/goodbye/' test.atom.json
atom verify test.atom.json
# → ERROR: SignatureInvalid { key_id: "my-signing-key-v1" }
```

## Running as a Daemon (systemd)

```bash
# 1. Copy the service file
sudo cp atom.service /etc/systemd/system/atom.service

# 2. Set env in service or drop a file at /etc/atom/env
sudo mkdir -p /etc/atom
cat <<'EOF' | sudo tee /etc/atom/env
ATOM_SIGNING_KEY_ID=prod-signing-key
ATOM_SIGNING_KEY=base64-secret-here
EOF
sudo chmod 600 /etc/atom/env

# 3. Enable + start
sudo systemctl daemon-reload
sudo systemctl enable --now atom
```

## Docker (Distroless)

```bash
# Build image
docker build -t atom:v4.0-alpha -f Dockerfile .

# Run (mount signing key env)
docker run --rm \
  -e ATOM_SIGNING_KEY_ID=prod \
  -e ATOM_SIGNING_KEY=base64-secret \
  atom:v4.0-alpha atom --version
```

## Uninstall

```bash
cargo uninstall atom-cli
# or remove ~/.cargo/bin/atom manually
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `atom: command not found` | Add `~/.cargo/bin` to `PATH`, or restart shell. |
| `error: linking with \`cc\` failed` | Install `build-essential` / `base-devel` / `gcc`. |
| `ATOM_SIGNING_KEY not set` | Export both env vars before running `atom seal/verify`. |
| `ContentAddressMismatch` | The artifact bytes were modified after sealing — this is expected tamper detection. |
| `SignatureInvalid` | Wrong signing secret, or artifact was tampered. |

## Verification Checklist (G4 Foundry)

- [ ] `cargo install --path cli/atom-cli --locked` succeeds
- [ ] `atom --version` prints version
- [ ] `atom seal file` produces JSON with `sha256:` ID
- [ ] `atom verify file.atom.json` returns `OK`
- [ ] Tampered artifact is rejected with `SignatureInvalid`
- [ ] `cargo test --workspace` → 374+ tests pass
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` → clean
- [ ] Secret scan: no `sk-` keys, no private keys in source