# Contributing to ATOM

Thank you for your interest in contributing to ATOM — the sovereign recursive agent runtime.

## Quick Start

```bash
# Clone
git clone https://github.com/cryptyroot-ux/atom.git
cd atom

# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo clippy --workspace
```

## Development Workflow

### 1. Find or Create an Issue

- Check [existing issues](https://github.com/cryptyroot-ux/atom/issues)
- For new features, create an issue describing the change
- Reference requirement IDs from `spec/requirements.yaml` (e.g., `ATOM-V4-KRN-001`)

### 2. Branch

```bash
git checkout -b feat/your-feature-name
```

Branch naming:
- `feat/` — new feature
- `fix/` — bug fix
- `refactor/` — code improvement
- `docs/` — documentation
- `test/` — test additions

### 3. Implement

- Follow existing code style
- Add tests for new functionality
- Update documentation if behavior changes
- Reference requirement/invariant IDs in doc-comments:

```rust
/// Implements ATOM-V4-KRN-001: sovereign kernel boundary.
///
/// INV-001: Probabilistic cognition cannot directly mutate authoritative state.
pub fn authorize_proposal(...) -> Result<CommitPermit, KernelError> {
    // ...
}
```

### 4. Test

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p atom-kernel

# Run with output
cargo test --workspace -- --nocapture
```

### 5. Lint

```bash
cargo clippy --workspace -- -D warnings
```

Zero warnings required. Fix all clippy suggestions before submitting PR.

### 6. Commit

```bash
git commit -m "feat(kernel): add capability revalidation gate

Implements ATOM-V4-KRN-001. Adds commit-time revalidation
against capability grant before effect dispatch.

Closes #42"
```

Commit message format:
- `type(scope): description`
- Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`
- Scope: crate name (e.g., `kernel`, `effect`, `ledger`)
- Reference requirement ID and issue number

### 7. Pull Request

- PR title matches commit message format
- Description includes:
  - What changed and why
  - Requirement ID(s) addressed
  - Test evidence (paste `cargo test` output)
  - Breaking changes (if any)
- CI must pass (build, test, clippy)
- At least 1 Trusted Core approval required

## Code Standards

### Rust Style

- Edition 2021
- `#![forbid(unsafe_code)]` in all crates
- `#[must_use]` on pure functions
- `thiserror` for error types
- `serde` for serialization
- No `unwrap()` in library code (use `?` or explicit handling)

### Testing

- Unit tests in `src/lib.rs` or `src/*.rs`
- Integration tests in `tests/` directory
- Property tests preferred for invariant verification
- Test names should describe behavior, not implementation

### Documentation

- Public API must have doc-comments
- Include examples in doc-comments where helpful
- Reference requirement/invariant IDs for normative behavior

## Architecture

See:
- `spec/requirements.yaml` — 40 requirements (P0/P1)
- `spec/invariants.yaml` — 20 invariants
- `spec/acceptance/catalog.yaml` — 15 acceptance tests
- `spec/traceability.yaml` — requirement ↔ test ↔ crate mapping
- `spec/security/owasp-crosswalk.yaml` — security controls

## Crate Structure

```
crates/
├── atom-kernel/      # Sovereign kernel (authorize→commit boundary)
├── atom-ledger/      # Tamper-evident event store
├── atom-mission/     # Mission lifecycle state machine
├── atom-capability/  # Authority attenuation (grants, delegation)
├── atom-effect/      # Effect intent, commit permit, reconciliation
├── atom-secret/      # Brokered secret handles
├── atom-privd/       # Privilege daemon (typed host operations)
├── atom-scheduler/   # Mission scheduling
├── atom-approval/    # Durable approval grants
├── atom-claim/       # Epistemic claims with provenance
├── atom-evidence/    # Observations and evidence lifecycle
├── atom-fault/       # Fault classification and recovery
├── atom-replay/      # Replay honesty (R0-R4 classes)
├── atom-context/     # Taint labels and governed declassify
├── atom-runtime/     # Native cognition loop
├── atom-identity/    # Content-addressed identity binding
├── atom-cert/        # Behavior certificates
├── atom-provider/    # Provider-agnostic loop
├── atom-restore/     # Deterministic restore fencing
├── atom-target/      # Target resolution
├── atom-connector/   # Connector conformance suite
├── atom-memory/      # Memory lifecycle (write/execute/forget)
├── atom-worker/      # Worker isolation
├── atom-adapter/     # Protocol adapters
├── atom-artifact/    # Supply chain artifact verification
└── atom-ui/          # Mission Control (PWA, not in Rust workspace)
```

## Security

- Never commit secrets, API keys, or credentials
- Report security vulnerabilities per [SECURITY.md](SECURITY.md)
- Security-impacting changes require 2 Trusted Core reviews

## Questions?

- Open a [discussion](https://github.com/cryptyroot-ux/atom/discussions)
- Tag `@cryptyroot-ux` for architecture questions
