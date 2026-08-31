# TASK — G4 Foundry: atom-cli (Claude · Architect)

Worktree: `feat/foundry-cli` · Edit ONLY `cli/atom-cli/`

## Objective
Turn ATOM from a library collection into a real, installable executable. The `atom`
binary is the sovereign process that boots the runtime and lets an operator drive
ATOM from a terminal / as a daemon.

## Deliverables (all MUST land, all tests MUST pass)
1. `cli/atom-cli/src/main.rs` — REAL binary (replace the G0 skeleton stub).
2. Wire these crates into the CLI as a coherent process:
   atom-kernel, atom-runtime, atom-scheduler, atom-worker, atom-identity,
   atom-capability, atom-policy, atom-approval, atom-secret, atom-mission,
   atom-ledger, atom-effect, atom-context, atom-claim, atom-evidence,
   atom-fault, atom-replay, atom-restore, atom-provider, atom-target,
   atom-connector, atom-adapter, atom-memory, atom-artifact.
3. CLI surface (at minimum):
   - `atom --version` and `atom --help`
   - `atom run`          — boot runtime + scheduler + worker in-process
   - `atom verify <file>`— verify a sealed artifact via atom-artifact (SUP-001)
   - `atom seal <bytes>` — produce a content-addressed signed artifact
   - `--config <path>` or env-based config for signing key id + secret
4. `cli/atom-cli/Cargo.toml` already declares deps — extend if needed.
5. `#![forbid(unsafe_code)]` in main.rs.

## Acceptance (you must DEMONSTRATE, not claim)
- `cargo build -p atom-cli` produces `atom` binary.
- `./target/debug/atom --version` and `--help` print.
- `atom seal` then `atom verify` round-trips; tamper is caught
  (reuse atom-artifact::Artifact::seal / verify).
- `cargo test -p atom-cli` passes (CLI parses, seal+verify round-trip,
  wrong-secret/forged-bundle rejected).
- `cargo clippy -p atom-cli --all-targets` clean (0 warnings).

## Constraints
- Do NOT modify any crate in `crates/` — only `cli/atom-cli/`.
- Reuse existing types: atom_artifact::Artifact, atom_kernel::CommitToken.
- No API key/secret hardcoded — signing secret from env/file only.
- Commit to `feat/foundry-cli` when tests pass. Then STOP (wait for merge gate).
