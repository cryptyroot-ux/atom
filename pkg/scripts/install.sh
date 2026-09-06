#!/usr/bin/env bash
# Install ATOM as a durable systemd service.
# Usage: sudo ./pkg/scripts/install.sh [options]
set -euo pipefail

PREFIX=/usr/local/bin
STATE_DIR=/var/lib/atom
CONFIG_DIR=/etc/atom
LISTEN_ADDR=127.0.0.1:8420
PROVIDER_KEY_FILE=
PROVIDER_BASE_URL=
PROVIDER_MODEL=
NO_BUILD=0
NO_PROVIDER=1

log() { printf '[atom-install] %s\n' "$*" >&2; }
die() { printf '[atom-install] ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
  cat >&2 <<'EOF'
Install ATOM and enable atom.service.

Options:
  --provider-key-file PATH  OpenAI-compatible bearer key (enables provider)
  --provider-base-url URL   Gateway root URL (default: https://free.pango.fun)
  --provider-model MODEL    Model id (default: auto)
  --listen-addr ADDR        Bind address (default: 127.0.0.1:8420)
  --state-dir DIR           Durable state directory (default: /var/lib/atom)
  --no-build                Use target/release/atom already built
  --no-provider              Disable provider cognition (default)
  -h, --help                Show help
EOF
}

while (($#)); do
  case "$1" in
    --provider-key-file) PROVIDER_KEY_FILE="${2:?missing path}"; NO_PROVIDER=0; shift 2 ;;
    --provider-base-url) PROVIDER_BASE_URL="${2:?missing URL}"; NO_PROVIDER=0; shift 2 ;;
    --provider-model) PROVIDER_MODEL="${2:?missing model}"; NO_PROVIDER=0; shift 2 ;;
    --listen-addr) LISTEN_ADDR="${2:?missing address}"; shift 2 ;;
    --state-dir) STATE_DIR="${2:?missing directory}"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    --no-provider) NO_PROVIDER=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root (use sudo)"
command -v systemctl >/dev/null || die "systemd is required"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

if [[ "$NO_PROVIDER" -eq 0 ]]; then
  [[ -r "$PROVIDER_KEY_FILE" ]] || die "provider enabled but key file is missing/readable"
  [[ -n "$PROVIDER_BASE_URL" ]] || PROVIDER_BASE_URL=https://free.pango.fun
  [[ -n "$PROVIDER_MODEL" ]] || PROVIDER_MODEL=auto
fi

if ! id atom >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin atom
fi
install -d -o atom -g atom -m 0750 "$STATE_DIR"
install -d -o root -g atom -m 0750 "$CONFIG_DIR"

if [[ "$NO_BUILD" -eq 0 ]]; then
  command -v cargo >/dev/null || die "cargo is required (or use --no-build)"
  log "building release binary"
  (cd "$REPO_ROOT" && cargo build --release -p atom-cli --locked)
fi
BINARY_SOURCE="$REPO_ROOT/target/release/atom"
[[ -x "$BINARY_SOURCE" ]] || die "missing executable $BINARY_SOURCE"
install -Dm755 "$BINARY_SOURCE" "$PREFIX/atom"

if [[ ! -s "$CONFIG_DIR/signing-secret" ]]; then
  command -v openssl >/dev/null || die "openssl is required"
  tmp_secret="$(mktemp)"
  openssl rand -base64 32 >"$tmp_secret"
  install -o root -g atom -m 0640 "$tmp_secret" "$CONFIG_DIR/signing-secret"
  rm -f "$tmp_secret"
fi

if [[ ! -s "$CONFIG_DIR/api-token" ]]; then
  command -v openssl >/dev/null || die "openssl is required"
  tmp_token="$(mktemp)"
  openssl rand -base64 32 >"$tmp_token"
  install -o root -g atom -m 0640 "$tmp_token" "$CONFIG_DIR/api-token"
  rm -f "$tmp_token"
fi

if [[ -n "$PROVIDER_KEY_FILE" ]]; then
  install -o root -g atom -m 0640 "$PROVIDER_KEY_FILE" "$CONFIG_DIR/provider-api-key"
elif [[ ! -e "$CONFIG_DIR/provider-api-key" ]]; then
  install -o root -g atom -m 0640 /dev/null "$CONFIG_DIR/provider-api-key"
fi

tmp_env="$(mktemp)"
{
  printf 'ATOM_SERVE_ADDR=%s\n' "$LISTEN_ADDR"
  printf 'ATOM_STATE_DB=%s/atom.sqlite\n' "$STATE_DIR"
  printf 'ATOM_SIGNING_KEY_ID=atom-prod-v1\n'
  if [[ "$NO_PROVIDER" -eq 1 ]]; then
    printf 'ATOM_NO_PROVIDER=true\n'
  else
    printf 'ATOM_NO_PROVIDER=false\nATOM_PROVIDER_BASE_URL=%s\nATOM_PROVIDER_MODEL=%s\n' "$PROVIDER_BASE_URL" "$PROVIDER_MODEL"
  fi
} >"$tmp_env"
install -o root -g atom -m 0640 "$tmp_env" "$CONFIG_DIR/env"
rm -f "$tmp_env"

install -Dm644 "$REPO_ROOT/pkg/atom.service" /etc/systemd/system/atom.service
systemctl daemon-reload
systemctl enable atom.service
systemctl restart atom.service
systemctl is-active --quiet atom.service || die "ATOM service did not start"
log "installed /usr/local/bin/atom and enabled atom.service"
log "health endpoint: http://${LISTEN_ADDR}/health"
