#!/usr/bin/env python3
"""Emit honest G2 conformance evidence from real cargo test runs.

For each acceptance test this tool knows how to exercise, it runs the mapped
adversarial Rust test(s), parses libtest's own summary line, and writes the
evidence record the v4.1 catalog declares — but ONLY reflecting what actually
happened. It never hardcodes a pass:

  * a mapped cargo run fails, errors, or runs zero tests -> outcome=fail
  * every mapped run passes with >=1 test               -> outcome=pass

The record embeds the exact commands and a sha256 over the test sources that
produced it, so a reviewer can reproduce and audit the claim (INV-021). It is
the honest counterpart to tools/gate.py, which only *reads* evidence.

Usage:
  python tools/emit_g2_evidence.py --root .            # emit all mapped ids
  python tools/emit_g2_evidence.py --test ATOM-VT41-001
  python tools/emit_g2_evidence.py --check             # run, report, write nothing
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("FATAL: pyyaml is required (uv run --with pyyaml ...)", file=sys.stderr)
    sys.exit(2)

# Acceptance-test id -> the adversarial cargo runs that substantiate it.
# Each run is (package, test_binary, name_filter|None). A binary named for a
# requirement's own suite runs whole; a cross-cutting proof drawn from a shared
# binary uses a name filter, so the evidence attributes only the relevant cases.
MAPPING: dict[str, list[tuple[str, str, str | None]]] = {
    # KRN-001: every mutation path traverses authorization + commit revalidation.
    "ATOM-VT41-001": [("atom-kernel", "kernel_gate", None)],
    # KRN-002: runtime unprivileged; host admin only via atom-privd + valid permit.
    "ATOM-VT41-002": [
        ("atom-privd", "vt_privilege_boundary", None),
        ("atom-privd", "deny_by_default", None),
        ("atom-privd", "property_no_admit_without_permit", None),
        ("atom-runtime", "native_loop", "host_operation_crosses_only_the_atom_privd_permit_gate"),
    ],
    # AUT-001: CapabilityGrant binds identity/op/resource/generation/revocation.
    "ATOM-VT41-003": [
        ("atom-capability", "inv012_no_authority_escalation", None),
        ("atom-kernel", "kernel_gate", "wrong_"),
    ],
    # AUT-002: delegation is subset-only (attenuation + lattice property).
    "ATOM-VT41-004": [
        ("atom-capability", "vt005_capability_attenuation", None),
        ("atom-capability", "lattice_property", None),
    ],
    # AUT-003: approvals are durable, exact/bounded-scope grants.
    "ATOM-VT41-005": [("atom-approval", "lifecycle", None)],
    # EFX-001: EffectIntent ledger-sealed durable before any dispatch.
    "ATOM-VT41-006": [
        ("atom-kernel", "kernel_gate", "no_permit_non_durable_intent_denies_commit"),
        ("atom-effect", "vt003_toctou_authority_drift", "never_made_durable"),
        ("atom-runtime", "native_loop", None),
    ],
    # EFX-004: CommitPermit short-lived, one-shot, bound to digest/witness/etc.
    "ATOM-VT41-009": [("atom-effect", "vt003_toctou_authority_drift", None)],
}

RESULT_RE = re.compile(r"test result:\s+(\w+)\.\s+(\d+)\s+passed;\s+(\d+)\s+failed")


def _rustc_version(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["rustc", "--version"], cwd=root, capture_output=True, text=True
        )
        return proc.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def _run(pkg: str, test_bin: str, name_filter: str | None, root: Path) -> dict:
    """Run one test binary (optionally name-filtered) and report the truth."""
    cmd = ["cargo", "test", "-p", pkg, "--test", test_bin]
    if name_filter:
        cmd.append(name_filter)
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    passed = failed = 0
    saw_ok = False
    for m in RESULT_RE.finditer(proc.stdout):
        saw_ok = m.group(1) == "ok"
        passed += int(m.group(2))
        failed += int(m.group(3))
    ok = bool(saw_ok and proc.returncode == 0 and failed == 0 and passed >= 1)
    return {
        "command": " ".join(cmd),
        "package": pkg,
        "test_binary": test_bin,
        "name_filter": name_filter,
        "exit_code": proc.returncode,
        "passed": passed,
        "failed": failed,
        "ok": ok,
    }


def _source_digest(runs_spec: list[tuple[str, str, str | None]], root: Path) -> str:
    """A sha256 over the distinct test sources that produced this evidence."""
    h = hashlib.sha256()
    for pkg, test_bin in sorted({(p, t) for p, t, _ in runs_spec}):
        src = root / "crates" / pkg / "tests" / f"{test_bin}.rs"
        if src.exists():
            h.update(f"{pkg}/{test_bin}\0".encode())
            h.update(src.read_bytes())
    return "sha256:" + h.hexdigest()


def _catalog(root: Path) -> dict[str, dict]:
    path = root / "spec" / "v4.1" / "acceptance-catalog.yaml"
    if not path.exists():
        print(f"FATAL: {path} not found", file=sys.stderr)
        sys.exit(2)
    tests = yaml.safe_load(path.read_text()).get("tests", [])
    return {str(t.get("id")): t for t in tests if isinstance(t, dict)}


def emit(test_id: str, root: Path, check: bool) -> bool:
    """Run the mapped tests for `test_id` and (unless --check) seal the record."""
    entry = _catalog(root).get(test_id)
    if entry is None:
        print(f"FATAL: {test_id} not in catalog", file=sys.stderr)
        sys.exit(2)
    runs_spec = MAPPING[test_id]
    runs = [_run(pkg, test_bin, flt, root) for pkg, test_bin, flt in runs_spec]
    outcome = "pass" if runs and all(r["ok"] for r in runs) else "fail"
    total_passed = sum(r["passed"] for r in runs)
    record = {
        "test": test_id,
        "requirement": entry["requirement"],
        "gate": entry.get("gate", "G2"),
        "outcome": outcome,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "harness": "tools/emit_g2_evidence.py",
        "toolchain": _rustc_version(root),
        "test_source_digest": _source_digest(runs_spec, root),
        "total_passed": total_passed,
        "runs": runs,
    }
    label = outcome.upper()
    if check:
        print(f"[{label}] {test_id}: {total_passed} passed across {len(runs)} run(s)")
        return outcome == "pass"
    ev_path = root / str(entry["evidence"])
    ev_path.parent.mkdir(parents=True, exist_ok=True)
    ev_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"[{label}] {test_id} -> {entry['evidence']} ({total_passed} passed)")
    return outcome == "pass"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Emit honest G2 evidence from real cargo test runs"
    )
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--test", default=None, help="one acceptance id; omit for all mapped")
    ap.add_argument(
        "--check", action="store_true", help="run tests and report; write nothing"
    )
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    ids = [args.test] if args.test else list(MAPPING)
    all_ok = True
    for tid in ids:
        if tid not in MAPPING:
            print(f"FATAL: no run mapping for {tid}", file=sys.stderr)
            return 2
        all_ok = emit(tid, root, args.check) and all_ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
