# HTTP Provider (Cognition Backend) — Design Spec

> **Status:** Approved (Tahap 3). Implements a real model-provider HTTP cognition
> backend for the executor while keeping external-effect execution **proposal-only**.

## Goal

Replace (selectively) the built-in `NativeCognition` decision loop of the
mission executor with a **real HTTP provider** that consults a model gateway
(e.g. an OpenAI-compatible LLM endpoint) to propose the next mission command.
The provider is advisory: it proposes `MissionCommand`s, never mutates
authoritative state, and never executes an external effect. Externally
consequential effects remain intents that the runtime observes; actual external
mutation stays deferred (proposal-only) exactly as in Tahap 2.

## Background

- `Runtime<C, R, N>` (atom-runtime) is generic over cognition `N: Cognition`.
  `Runtime::new(..., cognition)` accepts `ProviderCognition<P>` from
  `atom-provider`, so no atom-runtime change is needed.
- `Cognition::decide` and `atom_provider::Provider::invoke` are **synchronous**
  and are called inside the `run_until_terminal`/`tick` loop. A real HTTP call
  is asynchronous and non-deterministic. This is the core tension.
- Resolution (agreed in Tahap 3): perform the HTTP call **asynchronously outside
  the daemon loop** — once per mission, before starting the runtime loop — and
  cache its result as an ordered plan of `ProviderProposal`s. A synchronous
  `CachedProvider` replays that cache during the runtime loop. The reducer /
  commit / effect path stays deterministic with respect to the cached plan.
- `atom-provider` is intentionally pure (sovereign core semantics) and is **not
  modified**. The HTTP client and cached provider live in `atom-executor`, the
  crate that already runs async and owns `run_mission`.

## Architecture

```
executor::run_mission (async)
  │
  ├─ Provider disabled (default) ──► Runtime::native(...)  [NativeCognition]
  │
  └─ Provider enabled ──► HttpProposalClient::propose(...)  (async HTTP → gateway)
                             │
                             ▼
                        ProviderPlan (VecDeque<ProviderProposal>, cached)
                             │
                             ▼
              CachedProvider (sync, impl atom_provider::Provider)
                             │
                             ▼
     Runtime::new(..., ProviderCognition::new(CachedProvider))
                             │
                             ▼
                   run_until_terminal(port, max_steps)
```

- The HTTP call happens once per mission, before the runtime loop starts, and
  is fully async (`reqwest`, rustls-tls) — it never blocks the daemon pump.
- The cached plan maps directly to `ProviderProposal`s. When the cache is
  exhausted mid-loop, `CachedProvider` returns `hold_terminal()`, so a plan
  shorter than the mission lifecycle yields a deterministic, safe hold.
- A failed HTTP call (connect/timeout/non-2xx) does **not** fabricate a success:
  the mission is sealed `VERIFYING` / `UNSATISFIABLE` with the honest reason,
  matching Tahap 2 failure semantics.

## Determinism trade-off

- LLM output is non-deterministic, so the *choice of next command* is not
  reproducible across two runs.
- What stays deterministic and sovereign: mission/effect/ledger state is only
  advanced through the runtime reducer, which is validated against the same
  `atom-mission` / `atom-effect` state machines as the native path. The provider
  never writes state; it only proposes.
- Replay safety (a mission runs at most once) is unchanged: claiming is
  idempotent in the queue and the HTTP call is performed only for a `READY`
  claim.

## New components (all in `crates/atom-executor`)

### `src/provider.rs`

- `ProviderConfig` — `base_url: String`, `model: String`, `api_key: String`,
  `enabled: bool`, with `Default` = disabled.
- `ProviderError` — `thiserror` error: `Http { source }`, `NonSuccess { status }`,
  `MalformedResponse { detail }`, `PointlessPlan`.
- `HttpProposalClient` — owns a `reqwest::Client`;
  `async fn propose(&self, mission_id: &str, phase: &str) -> Result<ProviderPlan>`.
  POSTs to `{base_url}/v1/chat/completions` (OpenAI-compatible shape) with a
  deterministic system prompt describing the `ProviderProposal` contract
  (commands + optional effect intent), parses `choices[0].message.content`
  as JSON lines into a sequence of `ProviderProposal`s.
- `ProviderPlan` — ordered cache of `ProviderProposal` plus `mission_id`.
- `CachedProvider` — `impl atom_provider::Provider`; `invoke` pops the next
  cached proposal (falling back to `hold_terminal()` when empty).

### `src/executor.rs`

- `ExecutorConfig` gains `pub provider: ProviderConfig` (`Default` = disabled).
- `run_mission` branches: provider enabled → build plan, wrap in
  `CachedProvider` + `ProviderCognition`, spawn `Runtime::new(...)`; else the
  existing `Runtime::native(...)` path. An HTTP failure returns the honest
  `VERIFYING`/no-outcome `RunResult`.

### `cli/atom-cli/src/lib.rs`

- `Serve` gains `--no-provider` (`env = "ATOM_NO_PROVIDER"`) and optional
  `--provider-base-url` / `--provider-model` / `--provider-api-key`
  (`env = "ATOM_PROVIDER_BASE_URL"` / `ATOM_PROVIDER_MODEL` / `ATOM_PROVIDER_API_KEY`).
  The API key is taken from the environment only, never hardcoded.
- When `ATOM_PROVIDER_BASE_URL`/`MODEL` are set and `--no-provider` is absent,
  provider is enabled and wired into `ExecutorConfig`.

## Tests

- `crates/atom-executor/tests/http_provider_loop.rs`:
  - Use `httpmock` (dev-dep) to serve a deterministic `/v1/chat/completions`
    returning a fixed JSON plan.
  - E2E: boot a real `AtomExecutor` against the store with the mock URL, enqueue
    a mission, drive it, assert it reaches `TERMINAL` with the provider-proposed
    outcome and that the HTTP endpoint was hit exactly once.
  - Failure path: mock returns 500 → mission sealed `VERIFYING`/`UNSATISFIABLE`
    with a non-empty reason, and no fabricate-success.
  - Existing Tahap 2 tests (`queue.rs` unit tests) must stay green; the default
    config keeps provider disabled so behavior is unchanged.

## Verifying

1. `cargo test -p atom-executor` — new provider tests + existing queue tests.
2. `cargo test -p atom-provider` — unchanged, still green.
3. `cargo clippy --workspace --all-targets -- -D warnings` — clean.
4. `cargo test` (full workspace) — no regression.

## Non-objectives

- Do **not** modify `atom-runtime`, `atom-provider`, `atom-server/store`
  (Tahap 1), `spec/openapi.yaml`, `spec/state-machines/effect.yaml`, or the
  Codex-owned tests.
- Do **not** execute external effects — provider output stays proposal-only.
- Do **not** commit/push unless explicitly asked.