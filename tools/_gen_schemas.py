#!/usr/bin/env python3
"""Generate the remaining 33 v4.1 schema bodies + their valid/invalid fixtures.

Each schema is a Draft-2020-12 JSON Schema. Fixtures are conformance-checked
against the schema via jsonschema: valid fixtures must produce 0 errors, invalid
fixtures must produce >= 1 error.
"""
import json, os
from jsonschema import Draft202012Validator

BASE = "https://atom.run/spec/v4/schemas"
SCHEMA_DIR = "spec/schemas"
FIX_DIR = "spec/fixtures"
DIG = "sha256:" + "a" * 64
DIGB = "sha256:" + "b" * 64


def schema(name, title, body):
    s = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE}/{name}.schema.json",
        "title": title,
        "type": "object",
        "additionalProperties": False,
    }
    s.update(body)
    return s


# Each entry: name -> (schema_body, valid_fixture, invalid_fixture)
SPECS = {}

SPECS["context-item"] = (
    {
        "required": ["item_id", "code", "toml", "digest", "sources"],
        "properties": {
            "item_id": {"type": "string"},
            "code": {"type": "string"},
            "toml": {"type": "string"},
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "sources": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        },
    },
    {"item_id": "ctx-item/001", "code": "println", "toml": "[meta]\\nname='x'", "digest": DIG, "sources": ["spec/mission"]},
    {"item_id": "ctx-item/001", "code": "println", "toml": "[meta]\\nname='x'", "digest": "bad", "sources": []},
)

SPECS["data-policy"] = (
    {
        "required": ["policy_id", "classifications", "retention", "purposes", "activated_at"],
        "properties": {
            "policy_id": {"type": "string"},
            "classifications": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "retention": {"type": "object"},
            "purposes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "activated_at": {"type": "string", "format": "date-time"},
            "override": {"type": ["object", "null"]},
        },
    },
    {"policy_id": "dp-0001", "classifications": ["PII"], "retention": {"days": 90}, "purposes": ["billing"], "activated_at": "2026-08-31T12:00:00Z", "override": None},
    {"policy_id": "dp-0001", "classifications": [], "retention": {"days": 90}, "purposes": ["billing"], "activated_at": "2026-08-31T12:00:00Z"},
)

SPECS["decision-record"] = (
    {
        "required": ["record_id", "decision", "subject", "decided_by", "decided_at", "binding"],
        "properties": {
            "record_id": {"type": "string"},
            "decision": {"type": "string"},
            "subject": {"type": "string"},
            "decided_by": {"type": "string"},
            "decided_at": {"type": "string", "format": "date-time"},
            "binding": {"type": "boolean"},
            "rationale": {"type": ["string", "null"]},
            "supersedes_record_id": {"type": ["string", "null"]},
        },
    },
    {"record_id": "dec-0001", "decision": "approve", "subject": "mission/alpha", "decided_by": "svc/approval", "decided_at": "2026-08-31T12:00:00Z", "binding": True, "rationale": "all checks pass", "supersedes_record_id": None},
    {"record_id": "dec-0001", "decision": "approve", "subject": "mission/alpha", "decided_by": "svc/approval", "decided_at": "2026-08-31T12:00:00Z", "binding": "yes"},
)

SPECS["deletion-receipt"] = (
    {
        "required": ["receipt_id", "target_digest", "requester", "completed_at", "buried"],
        "properties": {
            "receipt_id": {"type": "string"},
            "target_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "requester": {"type": "string"},
            "completed_at": {"type": "string", "format": "date-time"},
            "buried": {"type": "boolean"},
            "reclaimed_at": {"type": ["string", "null"], "format": "date-time"},
        },
    },
    {"receipt_id": "del-0001", "target_digest": DIG, "requester": "svc/gc", "completed_at": "2026-08-31T12:00:00Z", "buried": True, "reclaimed_at": None},
    {"receipt_id": "del-0001", "target_digest": "x", "requester": "svc/gc", "completed_at": "2026-08-31T12:00:00Z", "buried": True},
)

SPECS["evidence"] = (
    {
        "required": ["evidence_id", "kind", "digest", "produced_by", "produced_at"],
        "properties": {
            "evidence_id": {"type": "string"},
            "kind": {"enum": ["TEST", "AUDIT", "OBSERVATION", "ATTESTATION", "MEASUREMENT"]},
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "produced_by": {"type": "string"},
            "produced_at": {"type": "string", "format": "date-time"},
            "verdict": {"enum": ["PASS", "FAIL", "INCONCLUSIVE"]},
            "refs": {"type": "array", "items": {"type": "string"}},
        },
    },
    {"evidence_id": "ev/001", "kind": "TEST", "digest": DIG, "produced_by": "unit-suite", "produced_at": "2026-08-31T12:00:00Z", "verdict": "PASS", "refs": ["test/foo"]},
    {"evidence_id": "ev/001", "kind": "TEST", "digest": "bad", "produced_by": "unit-suite", "produced_at": "2026-08-31T12:00:00Z", "verdict": "PASS"},
)

SPECS["extension-manifest"] = (
    {
        "required": ["manifest_id", "extension_id", "version", "entrypoint", "apis", "capabilities"],
        "properties": {
            "manifest_id": {"type": "string"},
            "extension_id": {"type": "string"},
            "version": {"type": "string"},
            "entrypoint": {"type": "string"},
            "apis": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "capabilities": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        },
    },
    {"manifest_id": "em-0001", "extension_id": "ext-fs", "version": "1.0.0", "entrypoint": "ext-fs:main", "apis": ["fs"], "capabilities": ["fs.read"]},
    {"manifest_id": "em-0001", "extension_id": "ext-fs", "version": "1.0.0", "entrypoint": "ext-fs:main", "apis": [], "capabilities": ["fs.read"]},
)

SPECS["fault-record"] = (
    {
        "required": ["fault_id", "kind", "injected_at", "target", "status"],
        "properties": {
            "fault_id": {"type": "string"},
            "kind": {"enum": ["PARTITION", "LATENCY", "EXCEPTION", "CRASH", "RESOURCE_EXHAUSTION"]},
            "injected_at": {"type": "string", "format": "date-time"},
            "target": {"type": "string"},
            "status": {"enum": ["ARMED", "INJECTED", "RECOVERED", "CANCELED"]},
            "recovered_at": {"type": ["string", "null"], "format": "date-time"},
        },
    },
    {"fault_id": "ft-0001", "kind": "PARTITION", "injected_at": "2026-08-31T12:00:00Z", "target": "conn/aws-s3", "status": "INJECTED", "recovered_at": None},
    {"fault_id": "ft-0001", "kind": "PARTITION", "injected_at": "2026-08-31T12:00:00Z", "target": "conn/aws-s3", "status": "BOGUS"},
)

SPECS["lease-epoch"] = (
    {
        "required": ["lease_id", "epoch", "holder", "acquired_at", "expires_at", "renewable"],
        "properties": {
            "lease_id": {"type": "string"},
            "epoch": {"type": "integer", "minimum": 0},
            "holder": {"type": "string"},
            "acquired_at": {"type": "string", "format": "date-time"},
            "expires_at": {"type": "string", "format": "date-time"},
            "renewable": {"type": "boolean"},
        },
    },
    {"lease_id": "ls-0001", "epoch": 3, "holder": "svc/leader", "acquired_at": "2026-08-31T12:00:00Z", "expires_at": "2026-08-31T12:30:00Z", "renewable": True},
    {"lease_id": "ls-0001", "epoch": -1, "holder": "svc/leader", "acquired_at": "2026-08-31T12:00:00Z", "expires_at": "2026-08-31T12:30:00Z", "renewable": True},
)

SPECS["ledger-checkpoint"] = (
    {
        "required": ["checkpoint_id", "ledger_digest", "at_event", "sealed_at", "signature"],
        "properties": {
            "checkpoint_id": {"type": "string"},
            "ledger_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "at_event": {"type": "integer", "minimum": 0},
            "sealed_at": {"type": "string", "format": "date-time"},
            "signature": {"type": "string"},
        },
    },
    {"checkpoint_id": "chk-0001", "ledger_digest": DIG, "at_event": 1000, "sealed_at": "2026-08-31T12:00:00Z", "signature": "sig:v1"},
    {"checkpoint_id": "chk-0001", "ledger_digest": DIG, "at_event": -2, "sealed_at": "2026-08-31T12:00:00Z", "signature": "sig:v1"},
)

SPECS["ledger-event"] = (
    {
        "required": ["event_id", "seq", "event_type", "payload_digest", "emitted_at"],
        "properties": {
            "event_id": {"type": "string"},
            "seq": {"type": "integer", "minimum": 0},
            "event_type": {"type": "string"},
            "payload_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "emitted_at": {"type": "string", "format": "date-time"},
            "cause_event_id": {"type": ["string", "null"]},
        },
    },
    {"event_id": "evt-0001", "seq": 42, "event_type": "EFFECT_APPLIED", "payload_digest": DIG, "emitted_at": "2026-08-31T12:00:00Z", "cause_event_id": None},
    {"event_id": "evt-0001", "seq": 42, "event_type": "EFFECT_APPLIED", "payload_digest": "x", "emitted_at": "2026-08-31T12:00:00Z"},
)

SPECS["mission-graph"] = (
    {
        "required": ["graph_id", "mission_id", "nodes", "edges", "digest"],
        "properties": {
            "graph_id": {"type": "string"},
            "mission_id": {"type": "string"},
            "nodes": {"type": "array", "items": {"type": "object"}, "minItems": 1},
            "edges": {"type": "array", "items": {"type": "object"}, "minItems": 1},
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        },
    },
    {"graph_id": "mg-0001", "mission_id": "mission/alpha", "nodes": [{"id": "n1"}], "edges": [{"from": "n1", "to": "n2"}], "digest": DIG},
    {"graph_id": "mg-0001", "mission_id": "mission/alpha", "nodes": [], "edges": [], "digest": DIG},
)

SPECS["mission-snapshot"] = (
    {
        "required": ["snapshot_id", "mission_id", "state_digest", "captured_at", "replay_offset"],
        "properties": {
            "snapshot_id": {"type": "string"},
            "mission_id": {"type": "string"},
            "state_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "captured_at": {"type": "string", "format": "date-time"},
            "replay_offset": {"type": "integer", "minimum": 0},
        },
    },
    {"snapshot_id": "snap-0001", "mission_id": "mission/alpha", "state_digest": DIG, "captured_at": "2026-08-31T12:00:00Z", "replay_offset": 100},
    {"snapshot_id": "snap-0001", "mission_id": "mission/alpha", "state_digest": "x", "captured_at": "2026-08-31T12:00:00Z", "replay_offset": 100},
)

SPECS["mission-spec"] = (
    {
        "required": ["mission_id", "goal", "capacity_grant_ids", "task_signatures", "epoch", "revision"],
        "properties": {
            "mission_id": {"type": "string"},
            "goal": {"type": "string"},
            "capacity_grant_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "task_signatures": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "epoch": {"type": "integer", "minimum": 0},
            "revision": {"type": "integer", "minimum": 0},
            "parent_mission_id": {"type": ["string", "null"]},
        },
    },
    {"mission_id": "mission/alpha", "goal": "summarize findings", "capacity_grant_ids": ["cap-0001"], "task_signatures": ["tsk-0001"], "epoch": 0, "revision": 1, "parent_mission_id": None},
    {"mission_id": "mission/alpha", "goal": "summarize findings", "capacity_grant_ids": [], "task_signatures": ["tsk-0001"], "epoch": 0, "revision": 1},
)

SPECS["obligation"] = (
    {
        "required": ["obligation_id", "kind", "subject", "deadline", "status"],
        "properties": {
            "obligation_id": {"type": "string"},
            "kind": {"enum": ["REPORT", "RETENTION", "NOTICE", "COMPENSATION"]},
            "subject": {"type": "string"},
            "deadline": {"type": "string", "format": "date-time"},
            "status": {"enum": ["PENDING", "FULFILLED", "OVERDUE", "WAIVED"]},
            "waived_by": {"type": ["string", "null"]},
        },
    },
    {"obligation_id": "ob-0001", "kind": "RETENTION", "subject": "ledger/alpha", "deadline": "2026-12-31T00:00:00Z", "status": "PENDING", "waived_by": None},
    {"obligation_id": "ob-0001", "kind": "RETENTION", "subject": "ledger/alpha", "deadline": "2026-12-31T00:00:00Z", "status": "BOGUS"},
)

SPECS["observation"] = (
    {
        "required": ["obs_id", "observed_at", "subject_digest", "measurements", "source"],
        "properties": {
            "obs_id": {"type": "string"},
            "observed_at": {"type": "string", "format": "date-time"},
            "subject_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "measurements": {"type": "object"},
            "source": {"type": "string"},
        },
    },
    {"obs_id": "obs-0001", "observed_at": "2026-08-31T12:00:00Z", "subject_digest": DIG, "measurements": {"cpu_ms": 12}, "source": "telemetry"},
    {"obs_id": "obs-0001", "observed_at": "2026-08-31T12:00:00Z", "subject_digest": "bad", "measurements": {}, "source": "telemetry"},
)

SPECS["operation-status"] = (
    {
        "required": ["operation_id", "phase", "updated_at", "attempt"],
        "properties": {
            "operation_id": {"type": "string"},
            "phase": {"enum": ["SCHEDULED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELED", "UNKNOWN"]},
            "updated_at": {"type": "string", "format": "date-time"},
            "attempt": {"type": "integer", "minimum": 1},
            "message": {"type": ["string", "null"]},
        },
    },
    {"operation_id": "op-0001", "phase": "RUNNING", "updated_at": "2026-08-31T12:00:00Z", "attempt": 1, "message": None},
    {"operation_id": "op-0001", "phase": "RUNNING", "updated_at": "2026-08-31T12:00:00Z", "attempt": 0},
)

SPECS["policy-decision"] = (
    {
        "required": ["decision_id", "policy", "input_refs", "decision", "rendered_at", "evaluator"],
        "properties": {
            "decision_id": {"type": "string"},
            "policy": {"type": "string"},
            "input_refs": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "decision": {"enum": ["ALLOW", "DENY", "REQUIRE_APPROVAL", "UNEVALUABLE"]},
            "rendered_at": {"type": "string", "format": "date-time"},
            "evaluator": {"type": "string"},
            "reason": {"type": ["string", "null"]},
        },
    },
    {"decision_id": "pd-0001", "policy": "policy/approval", "input_refs": ["req/001"], "decision": "ALLOW", "rendered_at": "2026-08-31T12:00:00Z", "evaluator": "opa", "reason": None},
    {"decision_id": "pd-0001", "policy": "policy/approval", "input_refs": [], "decision": "ALLOW", "rendered_at": "2026-08-31T12:00:00Z", "evaluator": "opa"},
)

SPECS["problem-detail"] = (
    {
        "required": ["type", "title", "status", "detail", "instance"],
        "properties": {
            "type": {"type": "string"},
            "title": {"type": "string"},
            "status": {"type": "integer", "minimum": 100, "maximum": 599},
            "detail": {"type": "string"},
            "instance": {"type": "string"},
            "extensions": {"type": "object"},
        },
    },
    {"type": "https://atom.run/probs/denied", "title": "Access denied", "status": 403, "detail": "no grant", "instance": "op/001", "extensions": {}},
    {"type": "https://atom.run/probs/denied", "title": "Access denied", "status": 42, "detail": "no grant", "instance": "op/001"},
)

SPECS["promotion-decision"] = (
    {
        "required": ["decision_id", "from_release", "to_release", "approved_by", "decided_at", "outcome"],
        "properties": {
            "decision_id": {"type": "string"},
            "from_release": {"type": "string"},
            "to_release": {"type": "string"},
            "approved_by": {"type": "string"},
            "decided_at": {"type": "string", "format": "date-time"},
            "outcome": {"enum": ["PROMOTE", "HOLD", "REJECT"]},
            "review_ref": {"type": ["string", "null"]},
        },
    },
    {"decision_id": "prom-0001", "from_release": "0.0.0-alpha.0", "to_release": "0.0.0", "approved_by": "svc/release", "decided_at": "2026-08-31T12:00:00Z", "outcome": "PROMOTE", "review_ref": None},
    {"decision_id": "prom-0001", "from_release": "0.0.0-alpha.0", "to_release": "0.0.0", "approved_by": "svc/release", "decided_at": "2026-08-31T12:00:00Z", "outcome": "BOGUS"},
)
SPECS["provider-call"] = (
    {
        "required": ["call_id", "provider_id", "operation", "request_digest", "response_digest", "duration_ms", "status"],
        "properties": {
            "call_id": {"type": "string"},
            "provider_id": {"type": "string"},
            "operation": {"type": "string"},
            "request_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "response_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "duration_ms": {"type": "integer", "minimum": 0},
            "status": {"enum": ["OK", "ERROR", "TIMEOUT", "CANCELED"]},
            "started_at": {"type": ["string", "null"], "format": "date-time"},
        },
    },
    {"call_id": "pc-0001", "provider_id": "provider/llm", "operation": "completion", "request_digest": DIG, "response_digest": DIGB, "duration_ms": 250, "status": "OK", "started_at": None},
    {"call_id": "pc-0001", "provider_id": "provider/llm", "operation": "completion", "request_digest": "x", "response_digest": DIGB, "duration_ms": -1, "status": "OK"},
)
SPECS["provider-profile"] = (
    {
        "required": ["provider_id", "name", "endpoint", "auth_kind", "model_ids", "asserted_capabilities"],
        "properties": {
            "provider_id": {"type": "string"},
            "name": {"type": "string"},
            "endpoint": {"type": "string"},
            "auth_kind": {"enum": ["API_KEY", "OAUTH", "NONE"]},
            "model_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "asserted_capabilities": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "salt": {"type": ["string", "null"]},
        },
    },
    {"provider_id": "provider/llm", "name": "rootlabs-llm", "endpoint": "https://free.pango.fun/v1", "auth_kind": "API_KEY", "model_ids": ["claude-opus-4-8"], "asserted_capabilities": ["completion"], "salt": None},
    {"provider_id": "provider/llm", "name": "rootlabs-llm", "endpoint": "https://free.pango.fun/v1", "auth_kind": "API_KEY", "model_ids": [], "asserted_capabilities": ["completion"]},
)
SPECS["recovery-plan"] = (
    {
        "required": ["plan_id", "scenario", "steps", "computed_at"],
        "properties": {
            "plan_id": {"type": "string"},
            "scenario": {"type": "string"},
            "steps": {"type": "array", "items": {"type": "object"}, "minItems": 1},
            "computed_at": {"type": "string", "format": "date-time"},
            "responsible": {"type": ["string", "null"]},
        },
    },
    {"plan_id": "rp-0001", "scenario": "ledger-corruption", "steps": [{"order": 1, "action": "restore"}], "computed_at": "2026-08-31T12:00:00Z", "responsible": None},
    {"plan_id": "rp-0001", "scenario": "ledger-corruption", "steps": [], "computed_at": "2026-08-31T12:00:00Z"},
)
SPECS["release-manifest"] = (
    {
        "required": ["manifest_id", "release_id", "version", "artifacts", "created_at", "signatures"],
        "properties": {
            "manifest_id": {"type": "string"},
            "release_id": {"type": "string"},
            "version": {"type": "string"},
            "artifacts": {"type": "array", "items": {"type": "object"}, "minItems": 1},
            "created_at": {"type": "string", "format": "date-time"},
            "signatures": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "notes": {"type": ["string", "null"]},
        },
    },
    {"manifest_id": "rm-0001", "release_id": "rel-0001", "version": "0.0.0-alpha.0", "artifacts": [{"name": "atom-core", "digest": DIG}], "created_at": "2026-08-31T12:00:00Z", "signatures": ["sig:v1"], "notes": None},
    {"manifest_id": "rm-0001", "release_id": "rel-0001", "version": "0.0.0-alpha.0", "artifacts": [{"name": "atom-core", "digest": DIG}], "created_at": "2026-08-31T12:00:00Z", "signatures": []},
)
SPECS["replay-request"] = (
    {
        "required": ["request_id", "subject_digest", "from_offset", "to_offset", "requested_at", "mode"],
        "properties": {
            "request_id": {"type": "string"},
            "subject_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "from_offset": {"type": "integer", "minimum": 0},
            "to_offset": {"type": "integer", "minimum": 0},
            "requested_at": {"type": "string", "format": "date-time"},
            "mode": {"enum": ["FULL", "INCREMENTAL", "CHECKPOINT"]},
        },
    },
    {"request_id": "rp-0001", "subject_digest": DIG, "from_offset": 0, "to_offset": 100, "requested_at": "2026-08-31T12:00:00Z", "mode": "FULL"},
    {"request_id": "rp-0001", "subject_digest": DIG, "from_offset": -1, "to_offset": 100, "requested_at": "2026-08-31T12:00:00Z", "mode": "FULL"},
)
SPECS["resource-precondition"] = (
    {
        "required": ["precondition_id", "resource_id", "expectation", "expected_witness", "checked_at"],
        "properties": {
            "precondition_id": {"type": "string"},
            "resource_id": {"type": "string"},
            "expectation": {"type": "string"},
            "expected_witness": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "checked_at": {"type": "string", "format": "date-time"},
        },
    },
    {"precondition_id": "pre-0001", "resource_id": "ledger/alpha", "expectation": "exists", "expected_witness": DIG, "checked_at": "2026-08-31T12:00:00Z"},
    {"precondition_id": "pre-0001", "resource_id": "ledger/alpha", "expectation": "exists", "expected_witness": "bad", "checked_at": "2026-08-31T12:00:00Z"},
)
SPECS["schedule-run"] = (
    {
        "required": ["run_id", "schedule_id", "scheduled_at", "trigger", "status"],
        "properties": {
            "run_id": {"type": "string"},
            "schedule_id": {"type": "string"},
            "scheduled_at": {"type": "string", "format": "date-time"},
            "trigger": {"type": "string"},
            "status": {"enum": ["PENDING", "RUNNING", "SUCCEEDED", "FAILED", "SKIPPED"]},
            "attempt": {"type": "integer", "minimum": 0},
        },
    },
    {"run_id": "run-0001", "schedule_id": "sch-0001", "scheduled_at": "2026-08-31T12:00:00Z", "trigger": "cron", "status": "PENDING", "attempt": 0},
    {"run_id": "run-0001", "schedule_id": "sch-0001", "scheduled_at": "2026-08-31T12:00:00Z", "trigger": "cron", "status": "BOGUS"},
)
SPECS["schedule-spec"] = (
    {
        "required": ["schedule_id", "cron", "mission_template_id", "timezone", "enabled"],
        "properties": {
            "schedule_id": {"type": "string"},
            "cron": {"type": "string"},
            "mission_template_id": {"type": "string"},
            "timezone": {"type": "string"},
            "enabled": {"type": "boolean"},
            "max_attempts": {"type": "integer", "minimum": 1},
        },
    },
    {"schedule_id": "sch-0001", "cron": "0 3 * * *", "mission_template_id": "mission/daily", "timezone": "UTC", "enabled": True, "max_attempts": 3},
    {"schedule_id": "sch-0001", "cron": "0 3 * * *", "mission_template_id": "mission/daily", "timezone": "UTC", "enabled": True, "max_attempts": 0},
)
SPECS["schema-inventory"] = (
    {
        "required": ["inventory_id", "pack_version", "schemas", "generated_at"],
        "properties": {
            "inventory_id": {"type": "string"},
            "pack_version": {"type": "string"},
            "schemas": {"type": "array", "items": {"type": "object"}, "minItems": 1},
            "generated_at": {"type": "string", "format": "date-time"},
        },
    },
    {"inventory_id": "inv-schema", "pack_version": "4.1", "schemas": [{"id": "effect-intent"}], "generated_at": "2026-08-31T12:00:00Z"},
    {"inventory_id": "inv-schema", "pack_version": "4.1", "schemas": [], "generated_at": "2026-08-31T12:00:00Z"},
)
SPECS["secret-handle"] = (
    {
        "required": ["handle_id", "secret_id", "reference", "generation", "scope"],
        "properties": {
            "handle_id": {"type": "string"},
            "secret_id": {"type": "string"},
            "reference": {"type": "string"},
            "generation": {"type": "integer", "minimum": 0},
            "scope": {"type": "string"},
        },
    },
    {"handle_id": "sh-0001", "secret_id": "secret/0123", "reference": "sr:1", "generation": 1, "scope": "effect-kernel"},
    {"handle_id": "sh-0001", "secret_id": "secret/0123", "reference": "sr:1", "generation": -1, "scope": "effect-kernel"},
)
SPECS["slo-definition"] = (
    {
        "required": ["slo_id", "metric", "target", "window_seconds", "compliance", "owned_by"],
        "properties": {
            "slo_id": {"type": "string"},
            "metric": {"type": "string"},
            "target": {"type": "number", "minimum": 0, "maximum": 1},
            "window_seconds": {"type": "integer", "minimum": 1},
            "compliance": {"enum": ["SLI", "SLA", "WARNING"]},
            "owned_by": {"type": "string"},
        },
    },
    {"slo_id": "slo-0001", "metric": "availability", "target": 0.999, "window_seconds": 86400, "compliance": "SLA", "owned_by": "platform"},
    {"slo_id": "slo-0001", "metric": "availability", "target": 1.5, "window_seconds": 86400, "compliance": "SLA", "owned_by": "platform"},
)
SPECS["telemetry-envelope"] = (
    {
        "required": ["envelope_id", "source", "metric", "value", "sampled_at", "labels"],
        "properties": {
            "envelope_id": {"type": "string"},
            "source": {"type": "string"},
            "metric": {"type": "string"},
            "value": {"type": "number"},
            "sampled_at": {"type": "string", "format": "date-time"},
            "labels": {"type": "object"},
        },
    },
    {"envelope_id": "tel-0001", "source": "effect-kernel", "metric": "latency_ms", "value": 12.5, "sampled_at": "2026-08-31T12:00:00Z", "labels": {"op": "append"}},
    {"envelope_id": "tel-0001", "source": "effect-kernel", "metric": "latency_ms", "value": "fast", "sampled_at": "2026-08-31T12:00:00Z", "labels": {}},
)
SPECS["test-evidence"] = (
    {
        "required": ["evidence_id", "test_id", "outcome", "ran_at", "runner", "logs_digest"],
        "properties": {
            "evidence_id": {"type": "string"},
            "test_id": {"type": "string"},
            "outcome": {"enum": ["PASS", "FAIL", "SKIPPED", "FLAKY"]},
            "ran_at": {"type": "string", "format": "date-time"},
            "runner": {"type": "string"},
            "logs_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        },
    },
    {"evidence_id": "te-0001", "test_id": "ATOM-VT41-001", "outcome": "PASS", "ran_at": "2026-08-31T12:00:00Z", "runner": "pytest", "logs_digest": DIG},
    {"evidence_id": "te-0001", "test_id": "ATOM-VT41-001", "outcome": "PASS", "ran_at": "2026-08-31T12:00:00Z", "runner": "pytest", "logs_digest": "bad"},
)
SPECS["trace-link"] = (
    {
        "required": ["link_id", "source", "target", "relation", "recorded_at"],
        "properties": {
            "link_id": {"type": "string"},
            "source": {"type": "string"},
            "target": {"type": "string"},
            "relation": {"type": "string"},
            "recorded_at": {"type": "string", "format": "date-time"},
        },
    },
    {"link_id": "tl-0001", "source": "REQ-001", "target": "ATOM-VT41-001", "relation": "validated_by", "recorded_at": "2026-08-31T12:00:00Z"},
    {"link_id": "tl-0001", "source": "REQ-001", "target": "", "relation": "validated_by", "recorded_at": "2026-08-31T12:00:00Z"},
)

# Write schemas + fixtures, then conformance-check
errors = []
written = []
for name, (body, valid, invalid) in SPECS.items():
    # schema with $id set
    s = schema(name, name.replace("-", " ").title(), body)
    with open(os.path.join(SCHEMA_DIR, f"{name}.schema.json"), "w") as f:
        json.dump(s, f, indent=2)
        f.write("\n")
    with open(os.path.join(FIX_DIR, f"{name}.valid.json"), "w") as f:
        json.dump(valid, f, indent=2)
        f.write("\n")
    with open(os.path.join(FIX_DIR, f"{name}.invalid.json"), "w") as f:
        json.dump(invalid, f, indent=2)
        f.write("\n")
    written.append(name)

    # conformance
    v = Draft202012Validator(s)
    nv = sum(1 for _ in v.iter_errors(valid))
    ni = sum(1 for _ in v.iter_errors(invalid))
    if nv != 0 or not ni:
        errors.append(f"{name}: valid_errors={nv} invalid_errors={ni}")

print(f"wrote {len(written)} schemas + {len(written)*2} fixtures")
if errors:
    print("CONFORMANCE FAILURES:")
    for e in errors:
        print("  ", e)
else:
    print("CONFORMANCE OK: all valid=0 err, all invalid>=1 err")
