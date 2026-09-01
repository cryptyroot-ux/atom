#!/usr/bin/env python3
"""Generate the 9 v4.1 state-machine bodies (spec/state-machines/<id>.yaml).

Each machine is defined with an explicit, verification-obligation-satisfying
format: an initial state, a set of terminal states, and a list of transitions
each carrying id/from/to/event/guard/action/cas/timer/forbidden. The state and
transition counts are constrained to exactly match the numbers already declared
in spec/v4.1/state-machines/inventory.yaml.
"""
import yaml, sys

# Every transition carries: t_id, from, to, event, guard, action, cas (bool),
# timer (str|None), forbidden (bool). We write a helper to keep the YAML compact.

def build(states, initial, terminals, transitions):
    """transitions: list of dicts with from/to/event + extras."""
    return {
        "version": "1.0.0",
        "initial": initial,
        "terminals": list(terminals),
        "states": list(states),
        "transitions": [
            {
                "id": t["id"],
                "from": t["from"],
                "to": t["to"],
                "event": t.get("event", "advance"),
                "guard": t.get("guard", "true"),
                "action": t.get("action", "noop"),
                "cas": t.get("cas", False),
                "timer": t.get("timer"),
                "forbidden": t.get("forbidden", False),
            }
            for t in transitions
        ],
    }

MACHINES = {}

# ---------- effect: 17 states, 29 transitions ----------
_effect_states = [
    "INTENT_DURABLE", "AUTHORIZATION_PENDING", "AUTHORIZED", "COMMIT_REVALIDATING",
    "DISPATCHING", "DISPATCHED", "OBSERVING", "CONFIRMED_SUCCESS", "CONFIRMED_FAILURE",
    "PARTIAL", "CANCELLED_BEFORE_EFFECT", "UNKNOWN_OUTCOME", "RECONCILING",
    "COMPENSATING", "COMPENSATED", "COMPENSATION_FAILED", "EXPUNGED",
]
_effect_ts = []
_tr = 0
def T(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"t{_tr:02d}", "from": fr, "to": to}
    t.update(kw)
    _effect_ts.append(t)

T("INTENT_DURABLE", "AUTHORIZATION_PENDING", event="authorize", guard="grant_valid", action="record_auth_pending")
T("INTENT_DURABLE", "CANCELLED_BEFORE_EFFECT", event="cancel", guard="not_started", action="mark_cancelled")
T("AUTHORIZATION_PENDING", "AUTHORIZED", event="auth_ok", guard="grant_active", action="issue_permit", cas=True)
T("AUTHORIZATION_PENDING", "CANCELLED_BEFORE_EFFECT", event="cancel", guard="approval_denied", action="mark_cancelled")
T("AUTHORIZED", "COMMIT_REVALIDATING", event="commit", guard="permit_fresh", action="sample_witness", cas=True)
T("AUTHORIZED", "CANCELLED_BEFORE_EFFECT", event="cancel", guard="permit_revoked", action="mark_cancelled")
T("COMMIT_REVALIDATING", "DISPATCHING", event="revalidated", guard="witness_unchanged", action="dispatch")
T("COMMIT_REVALIDATING", "AUTHORIZATION_PENDING", event="revalidate_fail", guard="witness_changed", action="reauthorize")
T("COMMIT_REVALIDATING", "CANCELLED_BEFORE_EFFECT", event="cancel", guard="stale", action="mark_cancelled")
T("DISPATCHING", "DISPATCHED", event="accepted", guard="connector_ok", action="record_receipt")
T("DISPATCHING", "UNKNOWN_OUTCOME", event="lost", guard="no_ack", action="open_unknown", timer="ack_timeout")
T("DISPATCHING", "CONFIRMED_FAILURE", event="rejected", guard="connector_error", action="record_failure")
T("DISPATCHED", "OBSERVING", event="observing", guard="queue_advance", action="watch")
T("DISPATCHED", "UNKNOWN_OUTCOME", event="lost", guard="no_observation", action="open_unknown", timer="observe_timeout")
T("OBSERVING", "CONFIRMED_SUCCESS", event="ok", guard="result_success", action="seal_success")
T("OBSERVING", "CONFIRMED_FAILURE", event="fail", guard="result_failure", action="seal_failure")
T("OBSERVING", "PARTIAL", event="partial", guard="partial_result", action="note_partial")
T("OBSERVING", "UNKNOWN_OUTCOME", event="lost", guard="no_result", action="open_unknown", timer="result_timeout")
T("UNKNOWN_OUTCOME", "RECONCILING", event="reconcile", guard="queryable", action="start_reconcile")
T("UNKNOWN_OUTCOME", "CONFIRMED_FAILURE", event="unrecoverable", guard="not_queryable", action="seal_failure")
T("RECONCILING", "CONFIRMED_SUCCESS", event="resolved_ok", guard="query_ok", action="seal_success")
T("RECONCILING", "CONFIRMED_FAILURE", event="resolved_fail", guard="query_fail", action="seal_failure")
T("RECONCILING", "PARTIAL", event="resolved_partial", guard="query_partial", action="note_partial")
T("RECONCILING", "UNKNOWN_OUTCOME", event="still_unknown", guard="no_answer", action="open_unknown", timer="reconcile_timeout")
T("RECONCILING", "COMPENSATING", event="compensate", guard="compensable", action="start_compensation")
T("PARTIAL", "COMPENSATING", event="compensate", guard="compensable", action="start_compensation")
T("COMPENSATING", "COMPENSATED", event="done", guard="comp_ok", action="seal_compensated")
T("COMPENSATING", "COMPENSATION_FAILED", event="fail", guard="comp_error", action="seal_comp_failed")
T("COMPENSATED", "EXPUNGED", event="expunge", guard="retention_met", action="bury", timer="retention_timer")
MACHINES["effect"] = build(_effect_states, "INTENT_DURABLE",
    ["CONFIRMED_SUCCESS", "CONFIRMED_FAILURE", "CANCELLED_BEFORE_EFFECT", "COMPENSATED", "EXPUNGED"],
    _effect_ts)

# ---------- mission: 13 states, 16 transitions ----------
_mission_states = [
    "CREATED", "COMPILED", "READY", "RUNNING", "RUNNING_APPROVAL", "RUNNING_PAUSED",
    "RUNNING_DEGRADED", "RUNNING_BLOCKED", "VERIFYING", "TERMINAL_SUCCESS",
    "TERMINAL_FAILED", "TERMINAL_CANCELLED", "TERMINAL_REJECTED",
]
_mission_ts = []; _tr = 0
def T2(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"m{_tr:02d}", "from": fr, "to": to}; t.update(kw); _mission_ts.append(t)
T2("CREATED", "COMPILED", event="compile")
T2("COMPILED", "READY", event="ready")
T2("READY", "RUNNING", event="start")
T2("RUNNING", "RUNNING_APPROVAL", event="need_approval", guard="approval_required")
T2("RUNNING_APPROVAL", "RUNNING", event="approval_granted", guard="approved", cas=True)
T2("RUNNING", "RUNNING_PAUSED", event="pause")
T2("RUNNING_PAUSED", "RUNNING", event="resume")
T2("RUNNING", "RUNNING_DEGRADED", event="degrade", guard="partial_capacity")
T2("RUNNING_DEGRADED", "RUNNING", event="recover", guard="capacity_restored")
T2("RUNNING", "RUNNING_BLOCKED", event="block", guard="precondition_failed")
T2("RUNNING_BLOCKED", "RUNNING", event="unblock", guard="precondition_met")
T2("RUNNING", "VERIFYING", event="verify")
T2("VERIFYING", "TERMINAL_SUCCESS", event="ok", guard="all_verified")
T2("VERIFYING", "TERMINAL_FAILED", event="fail", guard="verification_failed")
T2("VERIFYING", "TERMINAL_CANCELLED", event="cancel", guard="user_cancel")
T2("VERIFYING", "TERMINAL_REJECTED", event="reject", guard="unsatisfiable")
MACHINES["mission"] = build(_mission_states, "CREATED",
    ["TERMINAL_SUCCESS", "TERMINAL_FAILED", "TERMINAL_CANCELLED", "TERMINAL_REJECTED"], _mission_ts)

# ---------- approval: 7 states, 7 transitions ----------
_ap_states = ["SUBMITTED", "SCREENED", "APPROVAL_REQUESTED", "APPROVED", "REJECTED",
              "EXPIRED", "WITHDRAWN"]
_ap_ts = []; _tr = 0
def T3(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"a{_tr:02d}", "from": fr, "to": to}; t.update(kw); _ap_ts.append(t)
T3("SUBMITTED", "SCREENED", event="screen", guard="policy_pass")
T3("SCREENED", "APPROVAL_REQUESTED", event="route")
T3("APPROVAL_REQUESTED", "APPROVED", event="approve", guard="approver_action", cas=True)
T3("APPROVAL_REQUESTED", "REJECTED", event="reject", guard="denied")
T3("APPROVAL_REQUESTED", "EXPIRED", event="timeout", timer="approval_window")
T3("SUBMITTED", "WITHDRAWN", event="withdraw", guard="not_yet_decided")
T3("APPROVAL_REQUESTED", "WITHDRAWN", event="withdraw", guard="not_yet_decided")
MACHINES["approval"] = build(_ap_states, "SUBMITTED",
    ["APPROVED", "REJECTED", "EXPIRED", "WITHDRAWN"], _ap_ts)

# ---------- grant: 6 states, 5 transitions ----------
_gr_states = ["REQUESTED", "GRANTED", "DENIED", "REVOKED", "EXPIRED", "CONSUMED"]
_gr_ts = []; _tr = 0
def T4(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"g{_tr:02d}", "from": fr, "to": to}; t.update(kw); _gr_ts.append(t)
T4("REQUESTED", "GRANTED", event="approve", guard="policy_ok", cas=True)
T4("REQUESTED", "DENIED", event="deny", guard="policy_fail")
T4("GRANTED", "REVOKED", event="revoke", guard="fraud_or_abuse")
T4("GRANTED", "EXPIRED", event="expire", timer="grant_lifetime")
T4("GRANTED", "CONSUMED", event="consume", guard="budget_exhausted")
MACHINES["grant"] = build(_gr_states, "REQUESTED",
    ["DENIED", "REVOKED", "EXPIRED", "CONSUMED"], _gr_ts)

# ---------- artifact: 8 states, 10 transitions ----------
_ar_states = ["ASSEMBLED", "ATTESTED", "VERIFIED", "PROMOTED", "DEPRECATED",
              "WITHDRAWN", "BURIED", "SIGNED"]
_ar_ts = []; _tr = 0
def T5(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"at{_tr:02d}", "from": fr, "to": to}; t.update(kw); _ar_ts.append(t)
T5("ASSEMBLED", "ATTESTED", event="attest", guard="sbom_ok")
T5("ATTESTED", "SIGNED", event="sign", guard="key_present")
T5("SIGNED", "VERIFIED", event="verify", guard="signature_ok")
T5("ASSEMBLED", "WITHDRAWN", event="withdraw", guard="not_released")
T5("VERIFIED", "PROMOTED", event="promote", guard="checks_pass")
T5("PROMOTED", "DEPRECATED", event="deprecate", guard="replaced")
T5("DEPRECATED", "BURIED", event="bury", timer="deprecation_window")
T5("VERIFIED", "BURIED", event="expunge", guard="retention_met")
T5("WITHDRAWN", "BURIED", event="bury", guard="cleanup")
T5("SIGNED", "WITHDRAWN", event="recall", guard="key_compromise")
MACHINES["artifact"] = build(_ar_states, "ASSEMBLED",
    ["PROMOTED", "BURIED", "WITHDRAWN"], _ar_ts)

# ---------- schedule-run: 6 states, 5 transitions ----------
_sr_states = ["PENDING", "RUNNING", "SUCCEEDED", "FAILED", "SKIPPED", "CANCELED"]
_sr_ts = []; _tr = 0
def T6(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"s{_tr:02d}", "from": fr, "to": to}; t.update(kw); _sr_ts.append(t)
T6("PENDING", "RUNNING", event="start", guard="trigger_matches")
T6("RUNNING", "SUCCEEDED", event="done", guard="exit_zero")
T6("RUNNING", "FAILED", event="error", guard="exit_nonzero")
T6("PENDING", "SKIPPED", event="skip", guard="cooldown_active")
T6("PENDING", "CANCELED", event="cancel", guard="user_action")
MACHINES["schedule-run"] = build(_sr_states, "PENDING",
    ["SUCCEEDED", "FAILED", "SKIPPED", "CANCELED"], _sr_ts)

# ---------- restore: 6 states, 7 transitions ----------
_rs_states = ["REQUESTED", "VALIDATED", "IN_PROGRESS", "VERIFYING", "SUCCEEDED", "FAILED"]
_rs_ts = []; _tr = 0
def T7(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"r{_tr:02d}", "from": fr, "to": to}; t.update(kw); _rs_ts.append(t)
T7("REQUESTED", "VALIDATED", event="validate", guard="manifest_ok")
T7("REQUESTED", "FAILED", event="reject", guard="manifest_bad")
T7("VALIDATED", "IN_PROGRESS", event="start", guard="preconditions_met")
T7("IN_PROGRESS", "VERIFYING", event="done", guard="copy_ok")
T7("VERIFYING", "SUCCEEDED", event="verify_ok", guard="integrity_check_pass", cas=True)
T7("VERIFYING", "FAILED", event="verify_fail", guard="integrity_check_fail")
T7("IN_PROGRESS", "FAILED", event="error", guard="copy_error")
MACHINES["restore"] = build(_rs_states, "REQUESTED",
    ["SUCCEEDED", "FAILED"], _rs_ts)

# ---------- release: 7 states, 6 transitions ----------
_rl_states = ["DRAFTING", "BUILDING", "STAGED", "APPROVED", "PUBLISHED", "YANKED", "EXPIRED"]
_rl_ts = []; _tr = 0
def T8(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"l{_tr:02d}", "from": fr, "to": to}; t.update(kw); _rl_ts.append(t)
T8("DRAFTING", "BUILDING", event="build", guard="draft_complete")
T8("BUILDING", "STAGED", event="stage", guard="build_ok")
T8("STAGED", "APPROVED", event="approve", guard="review_ok", cas=True)
T8("APPROVED", "PUBLISHED", event="publish", guard="signature_ok")
T8("PUBLISHED", "YANKED", event="yank", guard="critical_defect")
T8("DRAFTING", "EXPIRED", event="expire", timer="draft_window")
MACHINES["release"] = build(_rl_states, "DRAFTING",
    ["PUBLISHED", "YANKED", "EXPIRED"], _rl_ts)

# ---------- promotion: 7 states, 8 transitions ----------
_pm_states = ["PROPOSED", "REVIEWED", "APPROVED", "REJECTED", "PROMOTING", "PROMOTED", "ROLLED_BACK"]
_pm_ts = []; _tr = 0
def T9(fr, to, **kw):
    global _tr
    _tr += 1
    t = {"id": f"p{_tr:02d}", "from": fr, "to": to}; t.update(kw); _pm_ts.append(t)
T9("PROPOSED", "REVIEWED", event="review", guard="criteria_complete")
T9("REVIEWED", "APPROVED", event="approve", guard="consensus", cas=True)
T9("REVIEWED", "REJECTED", event="reject", guard="criteria_fail")
T9("APPROVED", "PROMOTING", event="promote", guard="release_ready")
T9("PROMOTING", "PROMOTED", event="done_promote", guard="verification_ok")
T9("PROMOTING", "ROLLED_BACK", event="rollback", guard="verification_fail")
T9("PROMOTED", "ROLLED_BACK", event="rollback", guard="regression_detected")
T9("APPROVED", "REJECTED", event="expire_review", timer="review_window")
MACHINES["promotion"] = build(_pm_states, "PROPOSED",
    ["PROMOTED", "REJECTED", "ROLLED_BACK"], _pm_ts)

# Sanity: counts must match inventory declarations.
EXPECTED = {
    "effect": (17, 29), "mission": (13, 16), "approval": (7, 7), "grant": (6, 5),
    "artifact": (8, 10), "schedule-run": (6, 5), "restore": (6, 7),
    "release": (7, 6), "promotion": (7, 8),
}
ok = True
for mid, body in MACHINES.items():
    n_states = len(body["states"])
    n_tr = len(body["transitions"])
    want_s, want_t = EXPECTED[mid]
    flag = "" if (n_states == want_s and n_tr == want_t) else "  <-- MISMATCH"
    if flag: ok = False
    print(f"{mid:15} states={n_states}/{want_s} transitions={n_tr}/{want_t}{flag}")
    # verify transition endpoints reference valid states
    valid_states = set(body["states"])
    for t in body["transitions"]:
        if t["from"] not in valid_states or t["to"] not in valid_states:
            print(f"   !! bad endpoint {t['id']} {t['from']}->{t['to']}")
            ok = False
    if body["initial"] not in valid_states:
        print("   !! initial not in states"); ok = False

if not ok:
    print("ABORT: count mismatch"); sys.exit(1)

# write bodies
for mid, body in MACHINES.items():
    with open(f"spec/state-machines/{mid}.yaml", "w") as f:
        yaml.safe_dump(body, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
print("wrote 9 state-machine bodies")
