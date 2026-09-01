#!/usr/bin/env python3
"""ATOM v4.1 G0 release validator (executable, fail-closed).

G0 is the entry gate: the machine-readable canonical pack must be internally
consistent, fully traceable, and honest about body/fixture coverage before any
downstream gate may run. This tool is the single source of the *repository* G0
decision. It NEVER warns-and-passes: any FAIL or BLOCKED check makes the overall
decision non-PASS and the process exit non-zero (INV-030 deterministic gate).

Two distinct claims — do not conflate:
  * document-package G0 (manifest.yaml `g0: PASS_AT_DOCUMENT_PACKAGE`) — a weaker
    claim about the DOCX pack only.
  * repository G0 (this tool) — the full pack plus body/fixture coverage. It is
    expected to BLOCK until all 51 schema bodies + 102 fixtures and 9
    state-machine bodies are authored and v4.1-reviewed. Blocking is the honest
    state, not a bug (INV-021 release truthfulness).

Usage:
    python tools/validate_release.py --root . [--emit evidence/g0/gate-result.json]

Exit 0 iff the overall decision is PASS.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # fail-closed: cannot validate without a parser
    print("FATAL: pyyaml is required (uv run --with pyyaml ...)", file=sys.stderr)
    sys.exit(2)

# Controlled totals — the verified v4.1 baseline. Drift from any of these is a
# FAIL, never a silent re-baseline.
CONTROLLED = {
    "requirements": 142,
    "invariants": 30,
    "trace_rows": 142,
    "acceptance_tests": 142,
    "legacy_dispositions": 184,
    "semantic_rules": 12,
    "schemas": 51,
    "state_machines": 9,
}
SCHEMA_BODIES_REQUIRED = 51
SCHEMA_FIXTURES_REQUIRED = 102  # one valid + one invalid per schema
SM_BODIES_REQUIRED = 9

PASS, FAIL, BLOCKED = "PASS", "FAIL", "BLOCKED"

# spec/v4.1 file -> the top-level key holding its list of records.
LIST_KEY = {
    "requirements.yaml": "requirements",
    "invariants.yaml": "invariants",
    "traceability.yaml": "traceability",
    "acceptance-catalog.yaml": "tests",
    "legacy-disposition.yaml": "legacy",
    "semantic-rules.yaml": "rules",
    "schemas/inventory.yaml": "schemas",
    "state-machines/inventory.yaml": "machines",
}


@dataclass
class Check:
    """One G0 obligation and how it resolved."""

    id: str
    status: str  # PASS | FAIL | BLOCKED
    summary: str
    detail: str = ""


class G0Validator:
    """Runs every G0 obligation over the landed spec/v4.1 pack."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.spec = root / "spec" / "v4.1"
        self.checks: list[Check] = []
        self.docs: dict[str, object] = {}

    def add(self, cid: str, status: str, summary: str, detail: str = "") -> None:
        self.checks.append(Check(cid, status, summary, detail))

    def _list(self, fname: str) -> list:
        """The record list from a loaded doc, or [] if it failed to load."""
        doc = self.docs.get(fname)
        if not isinstance(doc, dict):
            return []
        got = doc.get(LIST_KEY[fname])
        return got if isinstance(got, list) else []

    # ── loading ──────────────────────────────────────────────────────────────
    def load(self) -> bool:
        """Loads every pack file. A missing/unparseable file is a FAIL."""
        ok = True
        for fname in LIST_KEY:
            path = self.spec / fname
            if not path.exists():
                self.add(f"G0-FILE::{fname}", FAIL, f"{fname} is missing")
                ok = False
                continue
            try:
                self.docs[fname] = yaml.safe_load(path.read_text())
            except yaml.YAMLError as exc:
                self.add(f"G0-FILE::{fname}", FAIL, f"{fname} is not valid YAML", str(exc))
                ok = False
        man = self.spec / "manifest.yaml"
        if man.exists():
            try:
                self.docs["manifest.yaml"] = yaml.safe_load(man.read_text())
            except yaml.YAMLError as exc:
                self.add("G0-FILE::manifest.yaml", FAIL, "manifest.yaml is not valid YAML", str(exc))
                ok = False
        else:
            self.add("G0-FILE::manifest.yaml", FAIL, "manifest.yaml is missing")
            ok = False
        return ok

    # ── counts ───────────────────────────────────────────────────────────────
    def check_counts(self) -> None:
        actual = {
            "requirements": len(self._list("requirements.yaml")),
            "invariants": len(self._list("invariants.yaml")),
            "trace_rows": len(self._list("traceability.yaml")),
            "acceptance_tests": len(self._list("acceptance-catalog.yaml")),
            "legacy_dispositions": len(self._list("legacy-disposition.yaml")),
            "semantic_rules": len(self._list("semantic-rules.yaml")),
            "schemas": len(self._list("schemas/inventory.yaml")),
            "state_machines": len(self._list("state-machines/inventory.yaml")),
        }
        for key, want in CONTROLLED.items():
            got = actual[key]
            status = PASS if got == want else FAIL
            self.add(f"G0-COUNT::{key}", status, f"{key}: {got} (controlled {want})")

    # ── unique identifiers ─────────────────────────────────────────────────────
    def _unique(self, cid: str, fname: str, key: str) -> set[str]:
        ids = [str(r.get(key)) for r in self._list(fname) if isinstance(r, dict)]
        seen: set[str] = set()
        dupes: set[str] = set()
        for i in ids:
            (dupes if i in seen else seen).add(i)
        if dupes:
            self.add(cid, FAIL, f"{len(dupes)} duplicate id(s) in {fname}", ", ".join(sorted(dupes)))
        else:
            self.add(cid, PASS, f"{len(seen)} unique id(s) in {fname}")
        return seen

    def check_unique_ids(self) -> None:
        self.req_ids = self._unique("G0-UNIQUE::requirements", "requirements.yaml", "id")
        self.acc_ids = self._unique("G0-UNIQUE::acceptance", "acceptance-catalog.yaml", "id")
        self.inv_ids = self._unique("G0-UNIQUE::invariants", "invariants.yaml", "id")
        self.sem_ids = self._unique("G0-UNIQUE::semantic", "semantic-rules.yaml", "id")
        self.leg_ids = self._unique("G0-UNIQUE::legacy", "legacy-disposition.yaml", "legacy_id")

    # ── bidirectional traceability ──────────────────────────────────────────────
    def check_traceability(self) -> None:
        trace = self._list("traceability.yaml")
        traced_reqs = {str(r.get("requirement")) for r in trace if isinstance(r, dict)}
        # Every requirement is traced, and every trace row names a real requirement.
        reqs_without_trace = self.req_ids - traced_reqs
        dangling_trace = traced_reqs - self.req_ids
        if reqs_without_trace or dangling_trace:
            self.add(
                "G0-TRACE::bidirectional", FAIL,
                "requirement <-> traceability is not bijective",
                f"reqs_without_trace={sorted(reqs_without_trace)[:5]} "
                f"dangling_trace_reqs={sorted(dangling_trace)[:5]}",
            )
        else:
            self.add("G0-TRACE::bidirectional", PASS,
                     f"all {len(self.req_ids)} requirements traced, no dangling rows")
        # Each trace row's test must exist in the acceptance catalog.
        bad_tests = {str(r.get("test")) for r in trace if isinstance(r, dict)} - self.acc_ids
        status = FAIL if bad_tests else PASS
        self.add("G0-TRACE::test-refs", status,
                 "trace.test references resolve to acceptance ids",
                 "" if not bad_tests else f"dangling={sorted(bad_tests)[:5]}")
        # Each acceptance test must name a real requirement.
        acc = self._list("acceptance-catalog.yaml")
        bad_acc = {str(a.get("requirement")) for a in acc if isinstance(a, dict)} - self.req_ids
        status = FAIL if bad_acc else PASS
        self.add("G0-TRACE::acceptance-refs", status,
                 "acceptance.requirement references resolve to requirement ids",
                 "" if not bad_acc else f"dangling={sorted(bad_acc)[:5]}")

    # ── invariants: presence, referencing, class discipline ─────────────────────
    def check_invariants(self) -> None:
        want = {f"ATOM-INV-{n:03d}" for n in range(1, 31)}
        missing = want - self.inv_ids
        self.add("G0-INV::present", FAIL if missing else PASS,
                 f"30 invariants present ({len(self.inv_ids)} found)",
                 "" if not missing else f"missing={sorted(missing)}")
        trace = self._list("traceability.yaml")
        referenced: set[str] = set()
        for r in trace:
            if isinstance(r, dict):
                referenced.update(str(i) for i in r.get("invariants", []))
        cls = {str(i.get("id")): str(i.get("class")) for i in self._list("invariants.yaml")}
        bad = []
        for iid, klass in cls.items():
            is_ref = iid in referenced
            if is_ref and klass != "requirement-linked":
                bad.append(f"{iid}:referenced-but-{klass}")
            if not is_ref and klass != "global-meta":
                bad.append(f"{iid}:unreferenced-but-{klass}")
        self.add("G0-INV::class-discipline", FAIL if bad else PASS,
                 f"{len(referenced)} requirement-linked, {30 - len(referenced)} global-meta",
                 "" if not bad else "; ".join(bad[:6]))

    # ── every referenced contract is inventoried ────────────────────────────────
    def check_contract_coverage(self) -> None:
        trace = self._list("traceability.yaml")
        ref_schema: set[str] = set()
        ref_sm: set[str] = set()
        for r in trace:
            if not isinstance(r, dict):
                continue
            for c in r.get("contracts", []):
                c = str(c)
                if c.endswith(".schema.json"):
                    ref_schema.add(c)
                elif "state-machines" in c:
                    ref_sm.add(c)
        inv_schema = {str(s.get("contract")) for s in self._list("schemas/inventory.yaml")}
        inv_sm = {str(s.get("contract")) for s in self._list("state-machines/inventory.yaml")}
        miss_s = ref_schema - inv_schema
        self.add("G0-CONTRACT::schema-inventory", FAIL if miss_s else PASS,
                 f"{len(ref_schema)} referenced schema contracts inventoried",
                 "" if not miss_s else f"uninventoried={sorted(miss_s)[:5]}")
        miss_m = ref_sm - inv_sm
        self.add("G0-CONTRACT::sm-inventory", FAIL if miss_m else PASS,
                 f"{len(ref_sm)} referenced state-machine contracts inventoried",
                 "" if not miss_m else f"uninventoried={sorted(miss_m)[:5]}")

    # ── legacy disposition discipline ────────────────────────────────────────────
    def check_legacy(self) -> None:
        allowed = {
            "RETAINED_OR_STRENGTHENED", "SUPERSEDED", "SPLIT", "MERGED",
            "DEFERRED", "WITHDRAWN", "REPLACED", "ABSORBED",
        }
        leg = self._list("legacy-disposition.yaml")
        bad = sorted({str(r.get("disposition")) for r in leg if isinstance(r, dict)} - allowed)
        # Report unknown dispositions as informational-but-not-fatal only if the
        # vocabulary genuinely differs; a missing disposition field is a FAIL.
        missing = [str(r.get("legacy_id")) for r in leg
                   if isinstance(r, dict) and not r.get("disposition")]
        if missing:
            self.add("G0-LEGACY::disposition", FAIL,
                     f"{len(missing)} legacy rows without a disposition",
                     f"{missing[:5]}")
        else:
            self.add("G0-LEGACY::disposition", PASS,
                     f"all {len(leg)} legacy rows carry a disposition",
                     "" if not bad else f"note: extra-vocab dispositions {bad}")

    # ── manifest counts must equal the files on disk ─────────────────────────────
    def check_manifest(self) -> None:
        man = self.docs.get("manifest.yaml")
        counts = man.get("counts", {}) if isinstance(man, dict) else {}
        actual = {
            "requirements": len(self._list("requirements.yaml")),
            "invariants": len(self._list("invariants.yaml")),
            "trace_rows": len(self._list("traceability.yaml")),
            "acceptance_tests": len(self._list("acceptance-catalog.yaml")),
            "legacy_dispositions": len(self._list("legacy-disposition.yaml")),
            "semantic_rules": len(self._list("semantic-rules.yaml")),
            "schemas": len(self._list("schemas/inventory.yaml")),
            "state_machines": len(self._list("state-machines/inventory.yaml")),
        }
        drift = {k: (counts.get(k), v) for k, v in actual.items() if counts.get(k) != v}
        self.add("G0-MANIFEST::counts", FAIL if drift else PASS,
                 "manifest counts equal files on disk",
                 "" if not drift else f"drift(manifest,actual)={drift}")

    # ── body & fixture coverage (honest BLOCKED until authored) ──────────────────
    def _v41_final(self, item: dict) -> bool:
        return str(item.get("body_status", "")) == "authored_v41"

    def check_schema_bodies(self) -> None:
        schemas = self._list("schemas/inventory.yaml")
        on_disk = sum(1 for s in schemas if (self.root / str(s.get("contract"))).exists())
        final = sum(1 for s in schemas if self._v41_final(s))
        status = PASS if final >= SCHEMA_BODIES_REQUIRED else BLOCKED
        self.add("G0-COVERAGE::schema-bodies", status,
                 f"{final}/{SCHEMA_BODIES_REQUIRED} schema bodies v4.1-authored",
                 f"{on_disk} exist on disk (v4.0-era, pending v4.1 review)")

    def check_schema_fixtures(self) -> None:
        schemas = self._list("schemas/inventory.yaml")
        authored = 0
        for s in schemas:
            fx = s.get("fixtures", {}) if isinstance(s, dict) else {}
            for kind in ("valid", "invalid"):
                if str(fx.get(kind, "")).startswith("spec/") and (self.root / str(fx[kind])).exists():
                    authored += 1
        status = PASS if authored >= SCHEMA_FIXTURES_REQUIRED else BLOCKED
        self.add("G0-COVERAGE::schema-fixtures", status,
                 f"{authored}/{SCHEMA_FIXTURES_REQUIRED} schema fixtures authored",
                 "one valid + one invalid per schema required")

    def check_sm_bodies(self) -> None:
        machines = self._list("state-machines/inventory.yaml")
        on_disk = sum(1 for m in machines if (self.root / str(m.get("contract"))).exists())
        final = sum(1 for m in machines if self._v41_final(m))
        status = PASS if final >= SM_BODIES_REQUIRED else BLOCKED
        self.add("G0-COVERAGE::sm-bodies", status,
                 f"{final}/{SM_BODIES_REQUIRED} state-machine bodies v4.1-authored",
                 f"{on_disk} exist on disk (v4.0-era, pending v4.1 review)")

    # ── semantic rules: hooks enforce contract text over fixtures (G0-SEM) ────────
    # Each rule in spec/v4.1/semantic-rules.yaml names a `reference_hook` method
    # on this validator. A rule is only PASS when BOTH hold:
    #   * its valid fixture satisfies the contract (no violation), and
    #   * a deterministic mutation that breaks the contract is caught (fails
    #     closed). A rule without any walkable fixture stays honeshly BLOCKED.
    #
    # The checks below are *semantic*: cross-field relations, ordering, digest
    # tagging, and reference integrity that JSON Schema cannot express. They are
    # intentionally mechanical and never warns-and-passes.
    _MUTATIONS = {
        "ATOM-SEM-001": {"expires_at": lambda r: r.get("not_before")},
        "ATOM-SEM-002": {"expires_at": lambda r: r.get("not_before")},
        "ATOM-SEM-003": {"canonical_request_digest": lambda r: "not-a-canonical-digest"},
        "ATOM-SEM-004": {"expires_at": lambda r: r.get("issued_at")},
        "ATOM-SEM-005": {"payload_digest": lambda r: "tampered", "ledger_digest": lambda r: "tampered"},
        "ATOM-SEM-006": {"edges": lambda r: list(r.get("edges") or []) + [{"from": "ghost", "to": "n1"}]},
        "ATOM-SEM-007": {"from_offset": lambda r: (r.get("to_offset") or 0) + 1},
        "ATOM-SEM-008": {"model_ids": lambda r: []},
        "ATOM-SEM-009": {"digest": lambda r: "tampered", "logs_digest": lambda r: "tampered"},
        "ATOM-SEM-010": {"system_prompt_digest": lambda r: "tampered", "subject_digest": lambda r: "tampered"},
        "ATOM-SEM-011": {"max_attempts": lambda r: 0, "status": lambda r: "BOGUS"},
        "ATOM-SEM-012": {"artifacts": lambda r: []},
    }

    def _iso(self, value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _digest_violation(self, value: object) -> str:
        if isinstance(value, str) and value.startswith("sha256:"):
            return ""
        return f"{value!r} is not a sha256-tagged digest"

    def _empty_violation(self, value: object, field: str) -> str:
        if value is None or value == "" or value == [] or value == {}:
            return f"{field} must be non-empty"
        return ""

    def _stamp_order(self, record: dict, then: str, now: str) -> str:
        a = self._iso(record.get(then))
        b = self._iso(record.get(now))
        if a is not None and b is not None and a >= b:
            return f"{then} ({record.get(then)}) is not before {now} ({record.get(now)})"
        return ""

    def semantic_grant(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        if bad := self._stamp_order(record, "not_before", "expires_at"):
            out.append(bad)
        for field in ("generation", "delegation_depth"):
            v = record.get(field)
            if isinstance(v, int) and v < 0:
                out.append(f"{field} {v} is negative")
        rs = record.get("revocation_state")
        if rs not in (None, "ACTIVE", "REVOKED", "EXPIRED"):
            out.append(f"revocation_state {rs!r} not in ACTIVE/REVOKED/EXPIRED")
        for field in ("operations", "resources"):
            v = record.get(field)
            if isinstance(v, list) and not v:
                out.append(f"{field} must be non-empty")
        return out

    def semantic_approval(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        if bad := self._stamp_order(record, "not_before", "expires_at"):
            out.append(bad)
        gen = record.get("generation")
        if isinstance(gen, int) and gen < 0:
            out.append(f"generation {gen} is negative")
        for field in ("granted_operations", "granted_resources"):
            v = record.get(field)
            if isinstance(v, list) and not v:
                out.append(f"{field} must be non-empty")
        return out

    def semantic_effect(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        if v := self._digest_violation(record.get("canonical_request_digest")):
            out.append(f"canonical_request_digest {v}")
        for field in ("effect_class", "risk_class"):
            if self._empty_violation(record.get(field), field):
                out.append(f"{field} must be present")
        idem = record.get("idempotency")
        strategy = idem.get("strategy") if isinstance(idem, dict) else idem
        if self._empty_violation(strategy, "idempotency.strategy"):
            out.append("idempotency.strategy must be present")
        rec = record.get("reconciliation")
        rstrategy = rec.get("strategy") if isinstance(rec, dict) else rec
        if self._empty_violation(rstrategy, "reconciliation.strategy"):
            out.append("reconciliation.strategy must be present")
        return out

    def semantic_permit(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        if bad := self._stamp_order(record, "issued_at", "expires_at"):
            out.append(bad)
        if v := self._digest_violation(record.get("effect_digest")):
            out.append(f"effect_digest {v}")
        gen = record.get("grant_generation")
        if isinstance(gen, int) and gen < 0:
            out.append(f"grant_generation {gen} is negative")
        for field in ("principal_id", "capability_grant_id", "resource_id",
                      "one_shot_nonce", "audience", "workload_id"):
            if bad := self._empty_violation(record.get(field), field):
                out.append(bad)
        witness = record.get("resource_version_witness")
        if not isinstance(witness, dict) or not witness:
            out.append("resource_version_witness must be a non-empty object")
        return out

    def semantic_ledger(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        if "seq" in record:  # ledger-event
            seq = record.get("seq")
            if isinstance(seq, int) and seq < 0:
                out.append(f"seq {seq} is negative")
            if v := self._digest_violation(record.get("payload_digest")):
                out.append(f"payload_digest {v}")
            if self._iso(record.get("emitted_at")) is None:
                out.append("emitted_at must be an ISO-8601 instant")
        if "at_event" in record:  # ledger-checkpoint
            at = record.get("at_event")
            if isinstance(at, int) and at < 0:
                out.append(f"at_event {at} is negative")
            if v := self._digest_violation(record.get("ledger_digest")):
                out.append(f"ledger_digest {v}")
            if self._iso(record.get("sealed_at")) is None:
                out.append("sealed_at must be an ISO-8601 instant")
            if bad := self._empty_violation(record.get("signature"), "signature"):
                out.append(bad)
        return out

    def semantic_graph(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        nodes = record.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            out.append("graph must declare at least one node")
            return out
        ids = {str(n.get("id")) for n in nodes if isinstance(n, dict) and n.get("id") is not None}
        edges = record.get("edges")
        for edge in edges or []:
            if not isinstance(edge, dict):
                out.append(f"edge {edge!r} is not an object")
                continue
            for end in ("from", "to"):
                ref = str(edge.get(end))
                if ref not in ids:
                    out.append(f"edge references node {ref!r} which is not declared")
        return out

    def semantic_replay(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        fo, to = record.get("from_offset"), record.get("to_offset")
        if isinstance(fo, int) and fo < 0:
            out.append(f"from_offset {fo} is negative")
        if isinstance(to, int) and to < 0:
            out.append(f"to_offset {to} is negative")
        if isinstance(fo, int) and isinstance(to, int) and to < fo:
            out.append(f"to_offset {to} is before from_offset {fo}")
        if v := self._digest_violation(record.get("subject_digest")):
            out.append(f"subject_digest {v}")
        if self._iso(record.get("requested_at")) is None:
            out.append("requested_at must be an ISO-8601 instant")
        return out

    def semantic_provider(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        ep = str(record.get("endpoint", ""))
        if not ep.startswith(("http://", "https://")):
            out.append(f"endpoint {record.get('endpoint')!r} is not an http(s) URL")
        for field in ("model_ids", "asserted_capabilities"):
            v = record.get(field)
            if isinstance(v, list) and not v:
                out.append(f"{field} must be non-empty")
        for field in ("provider_id", "name", "auth_kind"):
            if bad := self._empty_violation(record.get(field), field):
                out.append(bad)
        return out

    def semantic_evidence(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        for field in ("digest", "logs_digest"):
            if field in record:
                if v := self._digest_violation(record.get(field)):
                    out.append(f"{field} {v}")
        for field in ("ran_at", "produced_at"):
            if field in record and self._iso(record.get(field)) is None:
                out.append(f"{field} must be an ISO-8601 instant")
        verdict = record.get("verdict")
        if verdict is not None and verdict not in ("PASS", "FAIL", "INCONCLUSIVE"):
            out.append(f"verdict {verdict!r} not in PASS/FAIL/INCONCLUSIVE")
        if bad := self._empty_violation(record.get("evidence_id"), "evidence_id"):
            out.append(bad)
        if "logs_digest" in record and self._empty_violation(record.get("runner"), "runner"):
            out.append("runner must be non-empty (test-evidence)")
        if ("produced_at" in record or "verdict" in record) and \
                self._empty_violation(record.get("produced_by"), "produced_by"):
            out.append("produced_by must be non-empty (evidence)")
        refs = record.get("refs")
        if isinstance(refs, list) and not refs:
            out.append("refs must be non-empty")
        return out

    def semantic_behavior(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        for field in ("system_prompt_digest", "instruction_bundle_digest",
                      "context_snapshot_digest", "policy_bundle_digest",
                      "subject_digest", "behavior_manifest_digest",
                      "evaluation_suite_digest"):
            if field in record:
                if v := self._digest_violation(record.get(field)):
                    out.append(f"{field} {v}")
        for field in ("capability_contract_digests", "tool_schema_digests"):
            for item in record.get(field, []) or []:
                if v := self._digest_violation(item):
                    out.append(f"{field} entry {v}")
        ver = record.get("schema_version")
        if ver is not None and str(ver) != "4.1":
            out.append(f"schema_version {ver!r} is not 4.1")
        samples = record.get("sampling_parameters")
        if isinstance(samples, dict):
            temp = samples.get("temperature")
            if temp is not None and not isinstance(temp, (int, float)):
                out.append("sampling_parameters.temperature must be numeric")
        if bad := self._stamp_order(record, "issued_at", "valid_until"):
            out.append(bad)
        return out

    def semantic_schedule(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        if "max_attempts" in record:  # schedule-spec
            attempts = record.get("max_attempts")
            if not isinstance(attempts, int) or attempts < 1:
                out.append(f"max_attempts must be a positive integer (got {attempts!r})")
            for field in ("schedule_id", "cron", "timezone"):
                if bad := self._empty_violation(record.get(field), field):
                    out.append(bad)
        else:  # schedule-run
            status = record.get("status")
            if status is not None and status not in ("PENDING", "RUNNING", "SUCCEEDED", "FAILED", "SKIPPED"):
                out.append(f"status {status!r} not in PENDING/RUNNING/SUCCEEDED/FAILED/SKIPPED")
            attempt = record.get("attempt")
            if isinstance(attempt, int) and attempt < 0:
                out.append(f"attempt {attempt} is negative")
            for field in ("run_id", "schedule_id", "trigger"):
                if bad := self._empty_violation(record.get(field), field):
                    out.append(bad)
            if "scheduled_at" in record and self._iso(record.get("scheduled_at")) is None:
                out.append("scheduled_at must be an ISO-8601 instant")
        return out

    def semantic_release(self, record: dict) -> list[str]:
        if not isinstance(record, dict):
            return []
        out = []
        for field in ("artifacts", "signatures"):
            v = record.get(field)
            if isinstance(v, list) and not v:
                out.append(f"{field} must be non-empty")
        intro = record.get("notes")
        for field in ("manifest_id", "release_id", "version"):
            if bad := self._empty_violation(record.get(field), field):
                out.append(bad)
        if self._iso(record.get("created_at")) is None:
            out.append("created_at must be an ISO-8601 instant")
        return out

    def _semantic_mutation(self, rid: str, record: dict) -> dict:
        out = dict(record)
        applied = 0
        for field, fn in self._MUTATIONS.get(rid, {}).items():
            if field in out:
                out[field] = fn(record)
                applied += 1
        if not applied:
            key = next((k for k in record if k.endswith(("_digest", "_ids", "_at"))), None)
            if key:
                out[key] = "tampered"
        return out

    def check_semantic_rules(self) -> None:
        rules = [r for r in self._list("semantic-rules.yaml") if isinstance(r, dict)]
        for rule in rules:
            rid = str(rule.get("id"))
            ref = rule.get("reference_hook")
            hook_name = ""
            if isinstance(ref, str) and "::" in ref:
                hook_name = ref.rsplit("::", 1)[-1]
            hook = getattr(self, hook_name, None)
            if not callable(hook):
                self.add(f"G0-SEM-HOOK::{rid}", FAIL,
                         f"reference_hook {ref!r} does not resolve to a callable on tools/validate_release.py")
                continue
            self.add(f"G0-SEM-HOOK::{rid}", PASS, f"hook {hook_name} resolves")
            stems = [t.strip() for t in str(rule.get("applies_to", "")).split(",") if t.strip()]
            walked = 0
            for stem in stems:
                path = self.root / "spec" / "fixtures" / f"{stem}.valid.json"
                if not path.exists():
                    continue
                try:
                    record = json.loads(path.read_text())
                except json.JSONDecodeError as exc:
                    self.add(f"G0-SEM::{rid}::{stem}", FAIL,
                             f"{stem}.valid.json is not parseable JSON", str(exc))
                    continue
                violations = list(hook(record) or [])
                if violations:
                    self.add(f"G0-SEM::{rid}::{stem}", FAIL,
                             f"valid fixture violates {rid}", "; ".join(violations[:3]))
                    continue
                self.add(f"G0-SEM::{rid}::{stem}", PASS,
                         f"{stem}.valid.json satisfies {rid}")
                walked += 1
                mutated = self._semantic_mutation(rid, record)
                caught = list(hook(mutated) or [])
                if caught:
                    self.add(f"G0-SEM::{rid}::{stem}::fails-closed", PASS,
                             f"mutation of {stem}.valid.json is caught")
                else:
                    self.add(f"G0-SEM::{rid}::{stem}::fails-closed", FAIL,
                             f"mutation of {stem}.valid.json passes {rid} undetected")
                walked += 1
            if not walked:
                self.add(f"G0-SEM::{rid}", BLOCKED,
                         "no fixture walked for this rule (fixtures not authored)")

    # ── run + decide ─────────────────────────────────────────────────────────────
    def run(self) -> dict:
        if self.load():
            self.check_counts()
            self.check_unique_ids()
            self.check_traceability()
            self.check_invariants()
            self.check_contract_coverage()
            self.check_legacy()
            self.check_manifest()
            self.check_schema_bodies()
            self.check_schema_fixtures()
            self.check_sm_bodies()
            self.check_semantic_rules()
        fails = [c for c in self.checks if c.status == FAIL]
        blocks = [c for c in self.checks if c.status == BLOCKED]
        overall = FAIL if fails else (BLOCKED if blocks else PASS)
        return {
            "gate": "G0",
            "scope": "repository",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall": overall,
            "summary": {
                "total": len(self.checks),
                "pass": sum(1 for c in self.checks if c.status == PASS),
                "fail": len(fails),
                "blocked": len(blocks),
            },
            "checks": [asdict(c) for c in self.checks],
        }


_ICON = {PASS: "PASS ", FAIL: "FAIL ", BLOCKED: "BLOCK"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ATOM v4.1 repository G0 validator (fail-closed)")
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--emit", default=None, help="write the gate-result JSON to this path")
    parser.add_argument("--quiet", action="store_true", help="print only the overall decision")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not (root / "spec" / "v4.1").is_dir():
        print(f"FATAL: {root}/spec/v4.1 not found — run from the repo root", file=sys.stderr)
        return 2

    result = G0Validator(root).run()

    if not args.quiet:
        for c in result["checks"]:
            line = f"  [{_ICON[c['status']]}] {c['id']}: {c['summary']}"
            if c["detail"]:
                line += f"\n           {c['detail']}"
            print(line)
    s = result["summary"]
    print(f"\nG0 (repository) = {result['overall']}  "
          f"[{s['pass']} pass / {s['fail']} fail / {s['blocked']} blocked of {s['total']}]")

    if args.emit:
        out = Path(args.emit)
        if not out.is_absolute():
            out = root / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n")
        print(f"evidence written: {out}")

    return 0 if result["overall"] == PASS else 1


if __name__ == "__main__":
    sys.exit(main())
