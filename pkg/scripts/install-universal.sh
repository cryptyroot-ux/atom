#!/usr/bin/env bash
# Universal source installer for Linux, macOS, and WSL.
# curl -fsSL https://raw.githubusercontent.com/cryptyroot-ux/atom/atom-v4.1-migration-hardening/pkg/scripts/install-universal.sh | bash
set -euo pipefail

REPO="${ATOM_REPO:-https://github.com/cryptyroot-ux/atom}"
REF="${ATOM_REF:-atom-v4.1-migration-hardening}"
PREFIX="${ATOM_PREFIX:-}"
NO_SERVICE=0
NO_PROVIDER=auto
PROVIDER_KEY_FILE=
PROVIDER_BASE_URL=
PROVIDER_MODEL=
log() { printf '[atom-install] %s\n' "$*" >&2; }
die() { printf '[atom-install] ERROR: %s\n' "$*" >&2; exit 1; }
usage() { cat >&2 <<'EOF'
Install ATOM on Linux, macOS, or WSL.
Options:
  --prefix PATH             Binary directory (default: /usr/local/bin or ~/.local/bin)
  --no-service              Skip Linux systemd setup
  --provider-key-file PATH  OpenAI-compatible bearer key
  --provider-base-url URL   Gateway root URL
  --provider-model MODEL    Provider model identifier (default: auto)
  --no-provider             Disable provider cognition (otherwise onboarding starts)
  -h, --help                Show help
Environment: ATOM_VERSION selects a release tag; ATOM_REF selects the source branch.
ATOM_BINARY_URL may provide an operator-supplied binary only with ATOM_BINARY_SHA256.
EOF
}
while (($#)); do
  case "$1" in
    --prefix) PREFIX="${2:?missing path}"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --provider-key-file) PROVIDER_KEY_FILE="${2:?missing path}"; NO_PROVIDER=0; shift 2 ;;
    --provider-base-url) PROVIDER_BASE_URL="${2:?missing URL}"; NO_PROVIDER=0; shift 2 ;;
    --provider-model) PROVIDER_MODEL="${2:?missing model}"; NO_PROVIDER=0; shift 2 ;;
    --no-provider) NO_PROVIDER=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in Linux|Darwin) ;; *) die "unsupported OS: $OS" ;; esac
case "$ARCH" in x86_64|amd64|aarch64|arm64) ;; *) die "unsupported architecture: $ARCH" ;; esac
command -v curl >/dev/null || die "curl is required"
command -v tar >/dev/null || die "tar is required"
if [[ -z "$PREFIX" ]]; then
  if [[ "$OS" == Linux && "$(id -u)" -eq 0 ]]; then PREFIX=/usr/local/bin
  elif [[ -w /usr/local/bin ]]; then PREFIX=/usr/local/bin
  else PREFIX="${HOME}/.local/bin"; fi
fi
mkdir -p "$PREFIX"
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t atom-install)"; trap 'rm -rf "$TMP_DIR"' EXIT
BINARY="$TMP_DIR/atom"
PLATFORM="$(printf '%s' "$OS" | tr '[:upper:]' '[:lower:]')"
[[ "$PLATFORM" == darwin ]] && PLATFORM=macos
[[ "$ARCH" == amd64 ]] && ARCH=x86_64
[[ "$ARCH" == aarch64 ]] && ARCH=arm64
[[ "$ARCH" == arm64 ]] && ARCH=arm64
ASSET="atom-${PLATFORM}-${ARCH}"
RELEASE_TAG="${ATOM_VERSION:-}"
if [[ -z "$RELEASE_TAG" ]]; then
  RELEASE_TAG="$(curl -fsSL --proto '=https' --tlsv1.2 "$REPO/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 || true)"
fi
if [[ -n "${ATOM_BINARY_URL:-}" ]]; then
  [[ -n "${ATOM_BINARY_SHA256:-}" ]] || die "ATOM_BINARY_SHA256 is required with ATOM_BINARY_URL"
  log "downloading operator-supplied binary for $OS/$ARCH"
  curl --fail --location --proto '=https' --tlsv1.2 "$ATOM_BINARY_URL" -o "$BINARY"
  EXPECTED_SHA256="$ATOM_BINARY_SHA256"
elif [[ -n "$RELEASE_TAG" ]] && curl --fail --location --proto '=https' --tlsv1.2 "$REPO/releases/download/$RELEASE_TAG/$ASSET" -o "$BINARY" 2>/dev/null; then
  log "downloaded release $RELEASE_TAG ($ASSET)"
  EXPECTED_SHA256="$(curl --fail --location --proto '=https' --tlsv1.2 "$REPO/releases/download/$RELEASE_TAG/${ASSET}.sha256" | awk '{print $1}')" || die "release checksum unavailable"
else
  log "no verified binary release found; falling back to pinned source build"
  command -v cargo >/dev/null || die "Cargo is required; install Rust from https://rustup.rs"
  log "building ATOM from $REPO (ref: $REF)"
  curl --fail --location --proto '=https' --tlsv1.2 "$REPO/archive/refs/heads/$REF.tar.gz" -o "$TMP_DIR/source.tar.gz"
  tar -xzf "$TMP_DIR/source.tar.gz" -C "$TMP_DIR"
  SOURCE_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
  [[ -n "$SOURCE_DIR" ]] || die "source archive was empty"
  (cd "$SOURCE_DIR" && cargo build --release --locked -p atom-cli)
  install -m 0755 "$SOURCE_DIR/target/release/atom" "$BINARY"
fi
if [[ -n "${EXPECTED_SHA256:-}" ]]; then
  if command -v sha256sum >/dev/null; then
    ACTUAL_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
  elif command -v shasum >/dev/null; then
    ACTUAL_SHA256="$(shasum -a 256 "$BINARY" | awk '{print $1}')"
  else
    die "sha256sum or shasum is required to verify the binary"
  fi
  [[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || die "binary checksum mismatch"
  log "verified SHA-256: $ACTUAL_SHA256"
fi
install -m 0755 "$BINARY" "$PREFIX/atom"; log "installed $PREFIX/atom"
if [[ "$OS" == Linux && "$NO_SERVICE" -eq 0 && "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null; then
  # A release binary has no checkout. Fetch only the service/config templates;
  # the binary itself remains the checksum-verified artifact above.
  if [[ -z "${SOURCE_DIR:-}" ]]; then
    curl --fail --location --proto '=https' --tlsv1.2 "$REPO/archive/refs/heads/$REF.tar.gz" -o "$TMP_DIR/source.tar.gz"
    tar -xzf "$TMP_DIR/source.tar.gz" -C "$TMP_DIR"
    SOURCE_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
    mkdir -p "$SOURCE_DIR/target/release"
    install -m 0755 "$BINARY" "$SOURCE_DIR/target/release/atom"
  fi
  args=(--no-build)
  [[ "$NO_PROVIDER" == 1 || "$NO_PROVIDER" == auto ]] && args+=(--no-provider)
  [[ -n "$PROVIDER_KEY_FILE" ]] && args+=(--provider-key-file "$PROVIDER_KEY_FILE")
  [[ -n "$PROVIDER_BASE_URL" ]] && args+=(--provider-base-url "$PROVIDER_BASE_URL")
  [[ -n "$PROVIDER_MODEL" ]] && args+=(--provider-model "$PROVIDER_MODEL")
  (cd "$SOURCE_DIR" && ./pkg/scripts/install.sh "${args[@]}")
else
  log "service setup skipped (use Linux root with systemd, or run --no-service)"
fi
case ":${PATH}:" in *":$PREFIX:"*) ;; *) log "add $PREFIX to PATH" ;; esac
log "next: atom --version"
if [[ "$OS" == Linux && "$NO_SERVICE" -eq 0 && "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null; then
  if [[ "$NO_PROVIDER" == auto ]] && [[ -e /dev/tty ]]; then
    log "starting interactive provider onboarding"
    "$PREFIX/atom" setup
  else
    log "then: atom doctor && atom status"
  fi
else
  log "then: atom setup (configure provider/model/API key) or atom --help"
fi
