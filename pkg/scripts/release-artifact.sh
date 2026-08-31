#!/usr/bin/env bash
# release-artifact.sh — Build and seal the `atom` binary as a content-addressed
# artifact (SUP-001). Emits the `sha256:` artifact ID to stdout on success.
#
# Usage:
#   ./release-artifact.sh [--output-dir DIR] [--artifact-name NAME]
#
# Requirements:
#   - ATOM_SIGNING_KEY_ID and ATOM_SIGNING_SECRET must be set in env
#   - Runs from repo root (where Cargo.toml lives)

set -euo pipefail

# ---- Config ----
OUTPUT_DIR="${OUTPUT_DIR:-./release-artifacts}"
ARTIFACT_NAME="${ARTIFACT_NAME:-atom}"
BUILD_PROFILE="${BUILD_PROFILE:-release}"

# ---- Helpers ----
log() { printf '\033[1;32m[%s]\033[0m %s\n' "$(date -Is)" "$*" >&2; }
err() { printf '\033[1;31m[%s] ERROR:\033[0m %s\n' "$(date -Is)" "$*" >&2; }
die() { err "$*"; exit 1; }

# ---- Validate env ----
[[ -n "${ATOM_SIGNING_KEY_ID:-}" ]] || die "ATOM_SIGNING_KEY_ID not set"
[[ -n "${ATOM_SIGNING_SECRET:-}"  ]] || die "ATOM_SIGNING_SECRET not set"

# ---- Ensure we're in the repo root ----
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not in a git repo"
cd "$REPO_ROOT"
log "Repo root: $REPO_ROOT"

# ---- Build the binary ----
log "Building atom-cli ($BUILD_PROFILE)..."
cargo build --locked -p atom-cli --profile "$BUILD_PROFILE" || die "cargo build failed"

BINARY_PATH="$REPO_ROOT/target/$BUILD_PROFILE/atom"
[[ -f "$BINARY_PATH" ]] || die "binary not found at $BINARY_PATH"

log "Binary: $BINARY_PATH"
log "Binary size: $(stat -c%s "$BINARY_PATH") bytes"
log "Binary sha256: $(sha256sum "$BINARY_PATH" | awk '{print $1}')"

# ---- Read binary bytes for sealing ----
BINARY_BYTES="$(cat "$BINARY_PATH" | base64 -w0)"

# ---- Compute provenance ----
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_TAG="$(git describe --tags --exact-match 2>/dev/null || echo "untagged")"
BUILD_RECIPE="cargo-build-${BUILD_PROFILE}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---- Build SBOM from Cargo.lock ----
SBOM_JSON="$(cargo metadata --format-version=1 2>/dev/null | jq -c '
  .packages
  | map({name: .name, version: .version})
  | unique_by(.name + "-" + .version)
  | sort_by(.name)
')"

# ---- Prepare payload for atom-artifact::Artifact::seal ----
# We construct the JSON that matches Artifact::seal's expected input,
# then call a tiny Rust helper to do the sealing (avoids pulling in
# all deps in bash). The helper is compiled on-the-fly.

cat > /tmp/seal_artifact.rs <<'RUST'
use std::collections::BTreeMap;
use std::env;
use atom_artifact::{Artifact, ArtifactId, Provenance, Sbom, SbomComponent, Signature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary_b64 = env::var("BINARY_B64")?;
    let binary = base64::decode(&binary_b64)?;
    let key_id = env::var("KEY_ID")?;
    let secret_b64 = env::var("SECRET_B64")?;
    let secret = base64::decode(&secret_b64)?;

    let provenance = Provenance::new(
        env::var("BUILDER").as_deref().unwrap_or("foundry"),
        &env::var("SOURCE_REF")?,
        &env::var("BUILD_RECIPE")?,
    );

    let sbom_items: Vec<SbomComponent> = serde_json::from_str(&env::var("SBOM_JSON")?)?;
    let sbom = Sbom::new(sbom_items);

    let artifact = Artifact::seal(binary, provenance, sbom, &key_id, &secret);

    // Output JSON for the caller
    let json = serde_json::to_string(&artifact)?;
    println!("{}", json);
    Ok(())
}
RUST

# ---- Compile and run the sealer ----
log "Compiling one-shot sealer..."
cd /tmp
rustc --edition 2021 \
  --extern atom_artifact="$REPO_ROOT/target/debug/deps/libatom_artifact-*.rlib" \
  --extern serde_json="$REPO_ROOT/target/debug/deps/libserde_json-*.rlib" \
  --extern base64="$REPO_ROOT/target/debug/deps/libbase64-*.rlib" \
  seal_artifact.rs -o seal_artifact 2>/dev/null || {
    # Fallback: use cargo run in a minimal workspace
    log "Direct rustc failed; using cargo one-shot..."
    mkdir -p /tmp/sealer/src
    cat > /tmp/sealer/Cargo.toml <<'TOML'
[package]
name = "sealer"
version = "0.1.0"
edition = "2021"

[dependencies]
atom-artifact = { path = "'"$REPO_ROOT"'/crates/atom-artifact" }
serde_json = "1"
base64 = "0.22"
TOML
    cat > /tmp/sealer/src/main.rs <<'RUST'
use std::env;
use atom_artifact::{Artifact, Provenance, Sbom, SbomComponent};

fn main() {
    let binary_b64 = env::var("BINARY_B64").unwrap();
    let binary = base64::decode(&binary_b64).unwrap();
    let key_id = env::var("KEY_ID").unwrap();
    let secret_b64 = env::var("SECRET_B64").unwrap();
    let secret = base64::decode(&secret_b64).unwrap();

    let provenance = Provenance::new(
        env::var("BUILDER").as_deref().unwrap_or("foundry"),
        &env::var("SOURCE_REF").unwrap(),
        &env::var("BUILD_RECIPE").unwrap(),
    );

    let sbom_items: Vec<SbomComponent> = serde_json::from_str(&env::var("SBOM_JSON").unwrap()).unwrap();
    let sbom = Sbom::new(sbom_items);

    let artifact = Artifact::seal(binary, provenance, sbom, &key_id, &secret);
    println!("{}", serde_json::to_string(&artifact).unwrap());
}
RUST
    cd /tmp/sealer
    cargo build --release 2>&1 | tail -5
    SEALER="/tmp/sealer/target/release/sealer"
}

# ---- Run the sealer ----
export BINARY_B64="$BINARY_BYTES"
export KEY_ID="$ATOM_SIGNING_KEY_ID"
export SECRET_B64="$(echo -n "$ATOM_SIGNING_SECRET" | base64 -w0)"
export BUILDER="foundry"
export SOURCE_REF="$GIT_COMMIT"
export BUILD_RECIPE="$BUILD_RECIPE"
export SBOM_JSON="$SBOM_JSON"

log "Sealing artifact..."
ARTIFACT_JSON="$("$SEALER")" || die "sealer failed"

# ---- Extract artifact ID ----
ARTIFACT_ID="$(echo "$ARTIFACT_JSON" | jq -r '.id')"
[[ "$ARTIFACT_ID" =~ ^sha256: ]] || die "invalid artifact ID: $ARTIFACT_ID"

# ---- Write output ----
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/${ARTIFACT_NAME}-${ARTIFACT_ID#sha256:}.json"
echo "$ARTIFACT_JSON" > "$OUTPUT_FILE"
log "Artifact written: $OUTPUT_FILE"
log "Artifact ID: $ARTIFACT_ID"

# ---- Verify the artifact we just created ----
log "Verifying artifact..."
if echo "$ARTIFACT_JSON" | "$REPO_ROOT/target/release/atom" verify /dev/stdin 2>/dev/null; then
    log "✓ Self-verification PASSED"
else
    die "Self-verification FAILED"
fi

# ---- Emit the artifact ID (for CI consumption) ----
echo "$ARTIFACT_ID"