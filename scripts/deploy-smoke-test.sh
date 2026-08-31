#!/usr/bin/env bash
# ATOM deployment smoke test — runs every verification step live.
# Usage: bash scripts/deploy-smoke-test.sh
set -euo pipefail

BINARY="${1:-./target/release/atom}"
PASS=0; FAIL=0; TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✅ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ❌ $1"; }

echo "═══ ATOM Deployment Smoke Test ═══"
echo "binary: $BINARY"
echo "date:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# --- 1. Binary exists and runs ---
echo "1. Binary"
if [ -x "$BINARY" ]; then
  pass "binary exists and is executable"
else
  fail "binary not found or not executable: $BINARY"
  echo ""; echo "RESULT: $PASS/$TOTAL passed, $FAIL failed"; exit 1
fi

# --- 2. Version ---
echo "2. Version"
VER=$("$BINARY" --version 2>&1) && pass "version: $VER" || fail "--version failed"

# --- 3. Help ---
echo "3. Help"
"$BINARY" --help >/dev/null 2>&1 && pass "--help exits 0" || fail "--help failed"

# --- 4. Seal (with signing key) ---
echo "4. Seal"
export ATOM_SIGNING_KEY_ID="smoke-test-$(date +%s)"
export ATOM_SIGNING_SECRET="$(openssl rand -hex 32)"
TMPDIR=$(mktemp -d)
echo "hello sovereignty" > "$TMPDIR/input.txt"

SEAL_OUT=$("$BINARY" seal --input "$TMPDIR/input.txt" --out "$TMPDIR/artifact.json" 2>&1) \
  && pass "seal exits 0: $SEAL_OUT" \
  || fail "seal failed: $SEAL_OUT"

# --- 5. Artifact structure ---
echo "5. Artifact structure"
if [ -f "$TMPDIR/artifact.json" ]; then
  ART_ID=$(python3 -c "import json; print(json.load(open('$TMPDIR/artifact.json'))['id'])" 2>/dev/null || echo "")
  if echo "$ART_ID" | grep -q "^sha256:"; then
    pass "artifact has sha256 ID: $ART_ID"
  else
    fail "artifact missing sha256 ID (got: $ART_ID)"
  fi
else
  fail "artifact.json not created"
fi

# --- 6. Verify (clean) ---
echo "6. Verify (clean)"
VERIFY_OUT=$("$BINARY" verify "$TMPDIR/artifact.json" 2>&1) \
  && pass "verify exits 0: $VERIFY_OUT" \
  || fail "verify failed: $VERIFY_OUT"

# --- 7. Tamper detection ---
echo "7. Tamper detection"
cp "$TMPDIR/artifact.json" "$TMPDIR/tampered.json"
python3 -c "
import json
d=json.load(open('$TMPDIR/tampered.json'))
d['content']=[99,97,116]  # 'cat' instead of 'hello sovereignty'
json.dump(d,open('$TMPDIR/tampered.json','w'))
"
if "$BINARY" verify "$TMPDIR/tampered.json" >/dev/null 2>&1; then
  fail "tampered artifact SHOULD have been rejected"
else
  pass "tampered artifact correctly rejected (exit non-zero)"
fi

# --- 8. Run (boot runtime, drive one mutation) ---
echo "8. Run (boot runtime)"
RUN_OUT=$("$BINARY" run 2>&1) \
  && pass "run exits 0" \
  || fail "run failed: $RUN_OUT"

# --- 9. Full test suite ---
echo "9. Test suite"
TEST_OUT=$(cargo test --workspace 2>&1 | grep -oE "[0-9]+ passed" | awk '{s+=$1} END{print s}')
if [ "$TEST_OUT" -ge 374 ] 2>/dev/null; then
  pass "cargo test: $TEST_OUT passed"
else
  fail "cargo test: expected ≥374, got $TEST_OUT"
fi

# --- 10. Clippy strict ---
echo "10. Clippy strict"
if cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1; then
  pass "clippy: 0 warnings"
else
  fail "clippy: warnings found"
fi

# --- Summary ---
echo ""
echo "═══ RESULT: $PASS/$TOTAL passed, $FAIL failed ═══"
rm -rf "$TMPDIR"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
