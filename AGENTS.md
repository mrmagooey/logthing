# Agent Operations Guide

This document explains how automated or semi-automated agents should interact with the repository, which helper scripts to use, and the required git workflow.

## 1. Purpose & Scope

- Agents assist with routine engineering tasks: running builds/tests, executing the Dockerized end-to-end suite, generating coverage reports, and updating documentation/configuration.
- Anything involving production secrets, credentials, billing, or infrastructure changes **must** be escalated to a human maintainer.

## 2. Available Agent Tasks

| Agent Role | Responsibilities | Key Commands |
| --- | --- | --- |
| Build/Test Agent | Run `cargo test`, lint, or targeted component checks. | `cargo test`, `cargo check`, custom commands as needed. |
| Coverage Agent | Produce Rust code coverage reports. | `scripts/run_coverage.sh` (uses `cargo tarpaulin`). |
| E2E Agent | Execute the full Docker-based integration suite (WEF generator, syslog generator, S3 verifier). | `tests/e2e/run.sh` (requires Docker + Compose). |
| Docs Agent | Update Markdown/docs when workflows change; ensure README/AGENTS reflect new procedures. | Edit relevant `.md` files. |

## 3. Workflow & Invocation

1. **Preparation**
   - Ensure dependencies are installed (Rust toolchain, cargo-tarpaulin, Docker/Compose if running e2e tests).
   - Confirm no local uncommitted changes conflict with the intended work.
2. **Execution**
   - Use the provided scripts/commands rather than reimplementing functionality.
   - Capture relevant output (summaries) for PR or issue comments.
3. **Post-Run Actions**
   - Review generated artifacts (e.g., coverage HTML under `target/coverage/`, e2e logs) for failures.
   - Document any deviations or manual steps needed.

## 4. Git & Commit Requirements

- **Mandatory Rule:** After each discrete change is made, the agent must stage the affected files and create a git commit with an appropriate, descriptive message. Do not batch unrelated modifications into a single commit.
- Use conventional-style messages when possible (e.g., `feat: …`, `fix: …`, `docs: …`, `test: …`).
- Never amend or force-push without explicit human approval.
- Keep the working tree clean before starting a new task.

## 5. Safety & Guardrails

- Do not introduce or expose secrets. Configuration files with credentials should reference environment variables or example placeholders.
- The Docker-based e2e suite (`tests/e2e/run.sh`) requires a local Docker daemon; skip running it if the host cannot provide `/var/run/docker.sock` and report the limitation.
- When editing files, prefer ASCII unless the file already uses UTF-8 symbols and there is a clear reason to add more.

## 6. Extending Agent Capabilities

- Add new helper scripts under `scripts/` or `tests/` with clear usage comments.
- Update this `AGENTS.md` plus README sections so humans know how to invoke the new functionality.
- Provide at least one example command or workflow for every new automated capability.

## 7. Support & Contacts

- Maintainers: tag the repository owners in issues labeled `automation` for help.
- For CI/CD-related agent failures, attach the relevant command output and log excerpts to the issue or PR discussion.
