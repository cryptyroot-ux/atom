#!/usr/bin/env python3
"""ATOM conformance evidence checker (honest, fail-closed).

`gate.py verify-evidence --test <ID>` resolves an acceptance test's declared
evidence path and reports its true state. It NEVER fabricates a pass:

  * evidence file absent            -> NOT_RUN (exit 1)
  * present but malformed / wrong   -> FAIL    (exit 1)
  * well-formed with outcome=pass   -> PASS    (exit 0)

This is the command the v4.1 acceptance catalog invokes
(`python tools/gate.py verify-evidence --test ATOM-VT41-001 --root .`). Until
real test evidence is produced and sealed, every test is honestly NOT_RUN — a
blocked conformance run, not a green one (INV-021 release truthfulness).

An evidence record is a JSON object with at least:
    {"test": "<id>", "requirement": "<id>", "outcome": "pass|fail|unknown"}
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("FATAL: pyyaml is required (uv run --with pyyaml ...)", file=sys.stderr)
    sys.exit(2)

NOT_RUN, PASS, FAIL = "NOT_RUN", "PASS", "FAIL"


def _load_catalog(root: Path) -> dict[str, dict]:
    path = root / "spec" / "v4.1" / "acceptance-catalog.yaml"
    if not path.exists():
        print(f"FATAL: {path} not found", file=sys.stderr)
        sys.exit(2)
    tests = yaml.safe_load(path.read_text()).get("tests", [])
    return {str(t.get("id")): t for t in tests if isinstance(t, dict)}


def _check_one(root: Path, test_id: str, test: dict) -> tuple[str, str]:
    """Returns (status, detail) for one acceptance test's evidence."""
    ev = str(test.get("evidence", "")).strip()
    if not ev:
        return NOT_RUN, "no evidence path declared"
    path = root / ev
    if not path.exists():
        return NOT_RUN, f"evidence absent: {ev}"
    try:
        rec = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return FAIL, f"evidence is not valid JSON: {exc}"
    if not isinstance(rec, dict):
        return FAIL, "evidence is not a JSON object"
    if str(rec.get("test")) != test_id:
        return FAIL, f"evidence.test={rec.get('test')!r} != {test_id!r}"
    if str(rec.get("requirement")) != str(test.get("requirement")):
        return FAIL, "evidence.requirement does not match the catalog"
    outcome = str(rec.get("outcome", "")).lower()
    if outcome == "pass":
        return PASS, f"outcome=pass ({ev})"
    if outcome == "fail":
        return FAIL, f"outcome=fail ({ev})"
    return NOT_RUN, f"outcome={outcome or 'unknown'} ({ev})"


def cmd_verify_evidence(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    catalog = _load_catalog(root)

    if args.test:
        test = catalog.get(args.test)
        if test is None:
            print(f"FATAL: unknown test id {args.test!r}", file=sys.stderr)
            return 2
        status, detail = _check_one(root, args.test, test)
        print(f"[{status}] {args.test}: {detail}")
        return 0 if status == PASS else 1

    # --all (or no --test): summarise the whole catalog, honestly.
    counts = {PASS: 0, FAIL: 0, NOT_RUN: 0}
    for tid, test in catalog.items():
        status, detail = _check_one(root, tid, test)
        counts[status] += 1
        if not args.quiet:
            print(f"[{status}] {tid}: {detail}")
    total = sum(counts.values())
    print(f"\nconformance: {counts[PASS]}/{total} PASS, "
          f"{counts[FAIL]} FAIL, {counts[NOT_RUN]} NOT_RUN")
    return 0 if counts[PASS] == total and total > 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ATOM conformance evidence checker (fail-closed)")
    sub = parser.add_subparsers(dest="command", required=True)
    ve = sub.add_parser("verify-evidence", help="check declared evidence for a test (or all)")
    ve.add_argument("--test", default=None, help="acceptance test id; omit to check all")
    ve.add_argument("--root", default=".", help="repository root (default: .)")
    ve.add_argument("--quiet", action="store_true", help="print only the summary")
    ve.set_defaults(func=cmd_verify_evidence)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
