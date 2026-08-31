# Conformance

Executable acceptance-conformance harness. The `atom-conformance` crate binds
`spec/acceptance/catalog.yaml` to **real crate logic** for the three acceptance
tests below, so passing means the production code behaved as the spec requires —
not that a check was rubber-stamped.

| Acceptance id | Name | Crate under test |
|---|---|---|
| `ATOM-VT-011` | Repeated-task learning | `atom-experience-compiler` |
| `ATOM-VT-012` | Evolution rollback | `atom-restore` |
| `ATOM-VT-015` | 2G benchmark reproducibility | `atom-benchmark` + `atom-benchmark-runtime` |

## Files

- `coverage.json` — the declared coverage contract (schema `ATOM-CONF-COVERAGE-v1`).
  Each entry names the covered acceptance id, its normative catalog name, the
  crate it exercises, and the pass criterion. A test cross-checks that every
  covered id exists in the catalog with a matching name, and that this file's
  covered set equals the harness registry (`atom_conformance::COVERED_TESTS`).

## Running

```sh
cargo test -p atom-conformance
```

The suite:

- pins the catalog to its 15 entries with known names;
- runs each check against real crate logic and requires it to pass;
- proves the report is reproducible via its content-addressed digest;
- includes **control** tests that make a check genuinely fail on wrong behavior
  (a VT-011 holdout with no measurable cost drop; a tampered VT-012 expectation),
  so a green suite cannot be a false positive.

## Freeze

This harness verifies **reproducibility**, which is necessary but not sufficient
for a 2G superiority claim. It does not open the frozen INV-020 gate (spec H-14:
"no 2G claim until reproducible"). The checked-in VT-015 benchmark artifact stays
single-track and evidence-unpublished, so `evaluate_superiority` still refuses.
