# Chaos

Checked-in fault descriptors for conformance checks whose scenario is **data,
not a clock**. Each descriptor names the exact expected outcome so the check
verifies observed behavior against a declared expectation.

## Files

- `vt012-canary-regression.json` (schema `ATOM-CHAOS-VT012-v1`) — the VT-012
  ("Evolution rollback") scenario. A certified baseline route is live at
  `ACTIVE`; a canary candidate is promoted `CANARY -> ACTIVE` and then regresses.
  The descriptor declares the prior and candidate routes plus the expected
  rollback: observed ring `ACTIVE`, downgrade to `CANARY`, and restoration of the
  prior certified route. The check drives the real `atom-restore` `ArtifactRouter`
  and compares its transition to this expectation field-for-field.

Tampering with the declared `expected` (for instance the restored route id) makes
the check fail — a property a control test exercises.
