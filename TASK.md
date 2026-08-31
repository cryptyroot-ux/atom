# TASK — G4 Foundry: packaging + install verification (OpenCode · Challenger/Verifier)

Worktree: `feat/foundry-pkg` · Edit ONLY `pkg/` (new dir, untracked)

## Objective
Prove ATOM is actually installable and runnable end-to-end, and package it so a
user can install it. You VERIFY the other two workers (Claude's CLI, Codex's SDK)
and add packaging glue.

## Deliverables
1. `pkg/INSTALL.md` — exact, copy-pasteable steps for a fresh machine:
   - prerequisites (rust toolchain, version)
   - `cargo install --path cli/atom-cli` (or `cargo build --release`)
   - how to set signing key id + secret (env vars, NOT hardcoded)
   - `atom --version`, `atom seal`, `atom verify` smoke test
2. Release wrapper using `atom-artifact::Artifact::seal` (SUP-001): build the
   binary, hash it, seal with provenance + SBOM, emit `sha256:` id. Provide
   `pkg/scripts/release-artifact.sh` (or .rs) that does this.
3. Optional: `pkg/Dockerfile` (distroless/static) + `pkg/atom.service` (systemd).
4. Verify the other two workers' output actually compiles + tests + clippy and
   report any gap. If Claude/Codex left something red, either fix it (say what)
   or file a precise blocking note — do NOT silently pass.

## Acceptance (you must DEMONSTRATE, not claim)
- `cargo install --path cli/atom-cli` succeeds, OR you document exact
  `cargo build --release` + binary path alternative.
- Built `atom` runs `--version`, `seal`, `verify`; tamper detected (reuse atom-artifact).
- `cargo test --workspace` GREEN after all three Foundry branches merge.
- `cargo clippy --workspace --all-targets` 0 warnings.
- Secret scan over push range: 0 hits (no key in source).
- Sealed release artifact verifies with `atom verify` after `git fetch`.

## Constraints
- Never hardcode keys — signing secret from env/file only.
- `#![forbid(unsafe_code)]` in any Rust you add.
- Do NOT modify cli/ or sdk/ crates directly — verify them, fix via note or
  coordinate with Luna if blocking.
- Commit to `feat/foundry-pkg` when INSTALL.md + script ready. Then STOP.
