#!/usr/bin/env bash
# E2E durability recovery kill-test.
#
# Proves P1: a daemon SIGKILLed mid-run must not strand the mission. On restart
# the executor reclaims the crashed claim (with or without a snapshot), replays
# it deterministically, seals TERMINAL, and deletes the snapshot.
#
# Scenario exercised here: the daemon is killed while the mission is RUNNING
# (inside a slow provider propose), i.e. in the window between `claim` and
# `recovery.put` where no snapshot exists yet. The restart path must reset that
# snapshotless claim and drive the mission to a fresh TERMINAL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/atom"
WORK="$(mktemp -d /tmp/atom-kill-test.XXXXXX)"
STATE_DB="$WORK/state.db"
RECOVERY_DIR="$WORK/recovery"
SERVE_ADDR="127.0.0.1:18420"
MOCK_ADDR="127.0.0.1:18555"
MOCK_URL="http://$MOCK_ADDR"
export ATOM_SIGNING_KEY_ID="durability-kill-test"
export ATOM_SIGNING_SECRET="$(openssl rand -hex 32)"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill -9 "$DAEMON_PID" 2>/dev/null || true
  [[ -n "${MOCK_PID:-}" ]] && kill -9 "$MOCK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

log() { printf '[kill-test] %s\n' "$*"; }

# --- slow mock provider -----------------------------------------------
# Sleeps so the mission stays RUNNING long enough for a reliable SIGKILL,
# then answers with a valid full-lifecycle plan (CREATED -> TERMINAL).
cat > "$WORK/mock_provider.py" <<'PY'
import http.server, json, time

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        time.sleep(3.0)
        body = json.dumps({
            "choices": [
                {"message": {"content":
                    '["COMPILE","PREPARE","START","EXECUTE","VERIFY"]'}}
            ]
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", 18555), H).serve_forever()
PY
python3 "$WORK/mock_provider.py" & MOCK_PID=$!
sleep 0.4
log "mock provider up on $MOCK_URL"

start_daemon() {
  "$BIN" serve \
    --addr "$SERVE_ADDR" \
    --state-db "$STATE_DB" \
    --provider-base-url "$MOCK_URL" \
    --provider-model "mock-slomo" \
    --provider-timeout-ms 9000 \
    --provider-max-retries 0 \
    "$@" > "$WORK/daemon.log" 2>&1 &
  DAEMON_PID=$!
}

phase_of() {
  curl -s --max-time 2 "http://$SERVE_ADDR/missions/$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("phase",""))'
}

wait_for_phase() {
  local id="$1" want="$2" tries="${3:-80}"
  for _ in $(seq 1 "$tries"); do
    local cur
    cur="$(phase_of "$id")"
    if [[ "$cur" == "$want" ]]; then return 0; fi
    sleep 0.1
  done
  return 1
}

# --- run 1: claim, RUNNING, SIGKILL -----------------------------------
start_daemon
for _ in $(seq 1 60); do
  curl -sf --max-time 1 "http://$SERVE_ADDR/health" > /dev/null && break
  sleep 0.2
done

log "creating mission"
MISSION_JSON="$(curl -s --max-time 3 -X POST "http://$SERVE_ADDR/missions" \
  -H 'Content-Type: application/json' \
  -d '{
    "goal": "complete the durability kill-test",
    "success_criteria": ["mission reaches TERMINAL across a daemon crash"],
    "constraints": ["deterministic replay only"],
    "budgets": {"steps": 100, "time_ms": 60000},
    "authority_profile_ref": "kill-test-profile",
    "evidence_requirements": ["recovery snapshot"],
    "stopping_rules": ["stop on crash recovery"]
  }')"
MISSION_ID="$(echo "$MISSION_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["mission_id"])')"
log "mission $MISSION_ID"

if ! wait_for_phase "$MISSION_ID" "RUNNING" 60; then
  log "FAIL: mission never reached RUNNING"; cat "$WORK/daemon.log"; exit 1
fi
log "mission RUNNING observed (crashed window = claim without snapshot)"

kill -9 "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
log "daemon SIGKILLed in RUNNING state"

# --- run 2: restart must recover + replay to TERMINAL ------------------
start_daemon
for _ in $(seq 1 60); do
  curl -sf --max-time 1 "http://$SERVE_ADDR/health" > /dev/null && break
  sleep 0.2
done
log "daemon restarted with same state db"

if ! wait_for_phase "$MISSION_ID" "TERMINAL" 120; then
  log "FAIL: mission did not reach TERMINAL after restart"
  log "final phase: $(phase_of "$MISSION_ID")"
  tail -30 "$WORK/daemon.log"
  exit 1
fi

OUTCOME="$(curl -s --max-time 3 "http://$SERVE_ADDR/missions/$MISSION_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("outcome") or "")')"
log "mission TERMINAL after crash recovery (outcome=${OUTCOME:-none})"

if [[ -d "$RECOVERY_DIR" ]]; then
  STALE="$(ls -A "$RECOVERY_DIR" 2>/dev/null || true)"
  if [[ -n "$STALE" ]]; then
    log "FAIL: stale recovery snapshot left behind"; ls -la "$RECOVERY_DIR"; exit 1
  fi
fi
log "no stale recovery snapshot remains"

mkdir -p "$ROOT/evidence"
OUT="$(curl -s --max-time 3 "http://$SERVE_ADDR/missions/$MISSION_ID")"
python3 - "$MISSION_ID" "$MISSION_JSON" "$OUT" <<'PY' > "$ROOT/evidence/durability-kill-e2e.json"
import json, sys, time
mission_id, created, terminal = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
record = {
    "scenario": "daemon SIGKILLed while mission RUNNING (claim-without-snapshot window)",
    "mission_id": mission_id,
    "created_phase": created.get("phase"),
    "terminal_phase": terminal.get("phase"),
    "terminal_outcome": terminal.get("outcome"),
    "killed_after_claim_before_snapshot": True,
    "recovered": terminal.get("phase") == "TERMINAL",
    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
}
print(json.dumps(record, indent=2))
PY
log "evidence written to evidence/durability-kill-e2e.json"
log "PASS: durable recovery survived SIGKILL and sealed TERMINAL"
exit 0