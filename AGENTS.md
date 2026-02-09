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

## 5. Safety & Guardrails

- Do not introduce or expose secrets in code
- Use environment variables for configuration
- Prefer ASCII unless UTF-8 is required
- The E2E suite requires Docker; skip if unavailable

## 6. Project Structure

```
src/
  admin/        # Admin API and hot-reload
  config/       # Configuration loading
  forwarding/   # Event forwarding to destinations
  middleware/   # HTTP middleware
  models/       # Data structures
  parser/       # Event parsing logic
  protocol/     # WEF protocol handlers
  server/       # HTTP server implementation
  stats/        # Metrics and statistics
  syslog/       # Syslog listener
```

## 7. Extending Capabilities

- Add helper scripts under `scripts/` with usage comments
- Update AGENTS.md and README when adding features
- Provide example commands for new capabilities

## 8. Support & Contacts

- Tag repository owners in issues labeled `automation` for help
- Attach relevant output/logs to CI/CD failure discussions
