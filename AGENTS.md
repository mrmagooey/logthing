# Agent Operations Guide

This document explains how automated or semi-automated agents should interact with the repository, which helper scripts to use, and the required git workflow.

## 1. Purpose & Scope

- Agents assist with routine engineering tasks: running builds/tests, executing the Dockerized end-to-end suite, generating coverage reports, and updating documentation/configuration.
- Anything involving production secrets, credentials, billing, or infrastructure changes **must** be escalated to a human maintainer.

## 2. Build, Test & Lint Commands

| Task | Command |
|------|---------|
| Build release | `cargo build --release` |
| Build debug | `cargo build` |
| Run all tests | `cargo test` |
| Run single test | `cargo test <test_name>` |
| Run module tests | `cargo test <module_name>::` |
| Check only | `cargo check` |
| Format code | `cargo fmt` |
| Lint check | `cargo clippy -- -D warnings` |
| Coverage report | `scripts/run_coverage.sh` |
| E2E tests | `tests/e2e/simulation-environment/run.sh` (requires Docker) |
| Fuzz (nightly) | `scripts/fuzz.sh <target|all> [secs]` |
| Harness real-server test | `cargo build --release --bin logthing && cargo build --release -p loadgen && cargo test --test max_ingest_rate_harness_integration -- --ignored --test-threads=1` |
| Committer tests | `committer/.venv/bin/pytest committer/tests --ignore=committer/tests/e2e` |
| Committer E2E test | `committer/tests/e2e/run.sh` (requires Docker) |
| Object Lock integration test | `MINIO_ENDPOINT=http://host:9000 [MINIO_ACCESS_KEY=.. MINIO_SECRET_KEY=..] cargo test --test object_lock_integration` (skips when `MINIO_ENDPOINT` is unset) |
| Analytics unit tests | `deploy/analytics/.venv/bin/pytest -c deploy/analytics/tests/pytest.ini deploy/analytics/tests/unit` |
| Analytics integration test | `deploy/analytics/.venv/bin/pytest -c deploy/analytics/tests/pytest.ini deploy/analytics/tests/integration -m integration` (requires Docker; Trino tests need AVX2 or `TRINO_IMAGE`) |
| Analytics E2E (compose) | `deploy/analytics/tests/e2e/compose.sh` (requires Docker + AVX2 CPU, or `TRINO_IMAGE=trinodb/trino:470`) |
| Analytics dbt build | `deploy/analytics/.venv/bin/dbt build --project-dir deploy/analytics/dbt --profiles-dir deploy/analytics/dbt` (needs `TRINO_PASSWORD`, `TRINO_CA_CERT`; see `deploy/analytics/dbt/README.md`) |
| Analytics E2E (Helm) | `deploy/analytics/tests/e2e/helm-minikube.sh` (requires minikube + AVX2 CPU) |

**Example - run a specific test:**
```bash
cargo test test_event_4624_logon
cargo test parser::tests::test_event_4624_logon
```

**Example - run tests for a module:**
```bash
cargo test parser::
cargo test models::
```

## 3. Code Style Guidelines

### General
- **Edition**: Rust 2024
- **Line length**: 100 characters max
- **Indent**: 4 spaces (no tabs)
- **Trailing whitespace**: Remove
- **Final newline**: Required

### Imports Ordering
```rust
// 1. Standard library
use std::collections::HashMap;
use std::path::Path;

// 2. External crates (alphabetical)
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// 3. Internal modules
use crate::config::Config;
use crate::models::WindowsEvent;
```

### Naming Conventions
- **Structs/Enums**: PascalCase (e.g., `WindowsEvent`, `EventLevel`)
- **Functions/methods**: snake_case (e.g., `parse_event`, `extract_field`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., `ADMIN_OVERRIDE_FILE`)
- **Variables**: snake_case (e.g., `event_id`, `source_host`)
- **Type parameters**: PascalCase, single letter preferred (e.g., `T`, `P`)
- **Acronyms**: Treat as words (e.g., `TlsConfig`, not `TLSConfig`)

### Error Handling
- Use `anyhow::Result<T>` for functions that can fail
- Use `thiserror` for custom error types
- Propagate errors with `?` operator
- Add context with `.with_context(|| "message")`
- Log errors at appropriate level before returning

### Types & Documentation
- Prefer explicit types for public APIs
- Use `Option<T>` for optional fields
- Document all public items with `///`
- Include examples in doc comments when helpful
- Use `#[derive(Debug)]` for all structs/enums

### Async & Concurrency
- Use `tokio` runtime
- Prefer `tokio::spawn` for concurrent tasks
- Use channels for communication between tasks
- Prefer `Arc<RwLock<T>>` for shared mutable state

### Testing
- Tests live in `#[cfg(test)]` module at end of file
- Use `tempfile` crate for temp files in tests
- Name tests descriptively: `test_<what>_<condition>`
- Use `assert_eq!`, `assert!`, `assert_matches!` appropriately

## 4. Git Workflow

- After each discrete change, stage files and commit
- Do not batch unrelated modifications
- Use conventional commit style: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- Never amend or force-push without explicit approval
- Keep working tree clean before new tasks
- Release checklist: tag and publish the images BEFORE anyone runs the analytics stack from
  master (compose and Helm default to the `:<crate version>` tag, e.g. `:0.22.0`); run
  `deploy/analytics/tests/e2e/helm-minikube.sh` on a host with a normal inotify limit
  before and after tagging

## 5. Safety & Guardrails

- Do not introduce or expose secrets in code
- Use environment variables for configuration
- Prefer ASCII unless UTF-8 is required
- The E2E suite requires Docker; skip if unavailable

## 5a. Fuzzing

- Targets live in `fuzz/fuzz_targets/` and are thin shims over `src/fuzz_harness.rs`,
  which replays each ingestor's production receive path. Priority: `ipfix`, `sflow`,
  `syslog`, `wef_event`, `wef_envelope`, then `zeek`, `suricata`, `hec`, `otlp`.
- Needs nightly + `cargo install cargo-fuzz`; the root crate stays stable-only.
- On a crash in `fuzz/artifacts/<t>/crash-*`: minimize with
  `cargo +nightly fuzz tmin <t> <file>`, commit the result to `fuzz/regressions/<t>/`,
  and fix the root cause with a unit test at the parser. `cargo test` replays every
  file under `fuzz/seeds/` and `fuzz/regressions/` on stable.
- `fuzz/target/` grows large; `cargo clean --manifest-path fuzz/Cargo.toml` when done.

## 6. Project Structure

```
src/
  admin/        # Read-only admin UI and effective-config API (config is restart-only)
  config/       # Configuration loading
  forwarding/   # Parquet/S3 and local-disk sinks (incl. otlp_s3.rs typed OTLP sink)
  ingest/       # HEC / NDJSON ingest, event_uuid assignment, gzip request decoding
  ipfix/        # IPFIX / NetFlow flow ingestion
  middleware/   # HTTP middleware
  models/       # Data structures
  parser/       # Event parsing logic
  protocol/     # WEF protocol handlers
  redaction/    # HEC/OTLP drop/hash/mask rules
  server/       # HTTP server implementation (OTLP handler + mapper in otlp.rs)
  stats/        # Metrics and statistics
  syslog/       # Syslog listener
  zeek/         # Zeek NDJSON ingestion
committer/  # Python Iceberg committer (separate image)
deploy/analytics/  # Compose + Helm analytics stack (Garage, Lakekeeper, Trino, Metabase)
deploy/analytics/dbt/  # dbt-trino project: staging, OCSF views, detection analyses
```

Delivery guarantees per source (spool, shutdown, fsync) are documented in `docs/delivery-semantics.md`.

Note: `src/lib.rs` is the crate's module root (the crate is both a library and a binary); `src/main.rs` is the binary entry point only.

## 7. Extending Capabilities

- Add helper scripts under `scripts/` with usage comments
- Update AGENTS.md and README when adding features
- Provide example commands for new capabilities

## 8. Support & Contacts

- Tag repository owners in issues labeled `automation` for help
- Attach relevant output/logs to CI/CD failure discussions
