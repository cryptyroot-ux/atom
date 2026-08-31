# VT-015 native-runtime same-model suite

This is a file-backed `ATOM-VT-015` suite.  Each task is a real
provider-free `atom-runtime` lifecycle scenario.  The runtime adapter must
create the scenario, call `Runtime::run_until_terminal`, and derive the result
from the returned `RunStatus`; it must not return a fabricated score.

The task suite contains the following expected classifications:

- `orchestrate-clean` → `SUCCEEDED`
- `fail-on-compile` and `fail-on-execute` → `FAILED`
- `cancel-on-prepare` → `CANCELLED`
- `block-on-start` and `degrade-on-verify` → `BLOCKED`

`manifest.json` deliberately contains one same-model ATOM runtime track only.
It is a reproducibility/conformance baseline, not a comparison against Hermes
or OpenClaw.  Both publication flags are `false`; consequently the
`ATOM-INV-020` gate remains closed even when this suite is reproducible.

The raw bytes of `tasks.json` are pinned by `task_set_digest`.  The loader
rejects a digest mismatch, empty suite, duplicate task identifier, malformed
task, or task whose token charge exceeds the declared per-task budget.
