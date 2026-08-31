# ATOM benchmark artifacts

This directory contains versioned benchmark inputs, not benchmark claims.

`vt015-native-runtime/` is the first checked-in, file-backed suite for
`ATOM-VT-015`.  It exercises six deterministic, provider-free
`atom-runtime` mission outcomes via the same-model track.  The manifest is
deliberately frozen: it does not publish evidence or failure traces, and it
cannot open the `ATOM-INV-020` superiority-claim gate.

The suite's `tasks.json` is content-addressed by the `task_set_digest` in
`manifest.json`.  A loader must verify that digest before executing the tasks;
editing a task requires a new digest and therefore a new manifest identity.

The current suite is a runtime conformance/reproducibility baseline, not a
competitive result.  It contains no competitor result and makes no "2G"
claim.
