#!/usr/bin/env bash
# Fail-closed secret scan. A surviving match exits non-zero: a secret scan that
# finds a secret must FAIL the build, never warn-and-pass (no "|| true"). Obvious
# documentation placeholders are allowlisted, and the scanner excludes itself so
# its own pattern definitions do not self-trip.
set -euo pipefail

ROOT="${1:-.}"

# Matched values that are obvious placeholders, not real secrets.
ALLOW='(-here|<[^>]*>|changeme|change-me|example|redacted|placeholder|dummy|sample|xxxxx|your[-_])'

KEY_PATTERNS='AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----|-----BEGIN PRIVATE KEY-----'
ENV_PATTERNS='^[A-Z_]*SECRET|^[A-Z_]*PASSWORD|^[A-Z_]*TOKEN|^[A-Z_]*KEY[[:space:]]*=[[:space:]]*.{6,}'

hits=0

run_scan() {
  local label="$1" patterns="$2"; shift 2
  local matches
  # grep exit 1 (no match) must not abort the script under `set -e`.
  matches="$(grep -RInE "$patterns" "$ROOT" \
      --exclude-dir=target --exclude-dir=.git --exclude=secret_scan.sh "$@" || true)"
  matches="$(printf '%s\n' "$matches" | grep -vE "$ALLOW" || true)"
  matches="$(printf '%s\n' "$matches" | grep -v '^$' || true)"
  if [ -n "$matches" ]; then
    echo "::error::secret scan matched ($label):"
    printf '%s\n' "$matches"
    hits=1
  fi
}

echo "== high-entropy / key patterns =="
run_scan "keys" "$KEY_PATTERNS"
echo "== env / credential leakage =="
run_scan "env-leakage" "$ENV_PATTERNS" \
  --include='*.rs' --include='*.toml' --include='*.md' \
  --include='*.json' --include='*.yaml' --include='*.yml' --include='*.sh'

echo "== .env / secret files =="
files="$(find "$ROOT" -maxdepth 3 \
  \( -name '.env' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \) \
  -not -path '*/target/*' -not -path '*/.git/*' || true)"
if [ -n "$files" ]; then
  echo "::error::secret file(s) present:"; printf '%s\n' "$files"; hits=1
fi

if [ "$hits" -eq 0 ]; then echo "secret scan clean"; fi
exit "$hits"
