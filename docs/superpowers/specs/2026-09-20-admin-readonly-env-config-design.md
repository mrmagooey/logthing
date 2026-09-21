# Read-only admin console; configuration changes via environment variables

Date: 2026-09-20
Status: approved (user-negotiated scope; coherence-reviewed)
Branch: `feat/admin-readonly-env-config`

## Problem

The admin interface can write configuration. `PUT`/`PATCH /config` and
`POST /config/{validate,diff,export,import,reload}` mutate the running
config and persist it to `logthing.admin.toml`, which `Config::load()`
then reads back as a config layer on the next start. A web form is
therefore a first-class way to reconfigure the service, competing with
the file and environment-variable paths, and `logthing.admin.toml` —
tracked in git — silently outranks `logthing.toml` for anyone running
from the repo root.

The goal is to make environment variables the way an operator *changes*
configuration, and reduce the admin interface to a read-only view.

## What this change is, stated honestly

This removes **the config-editing UI and the admin-written file layer**.
It does *not* make environment variables the sole input to `Config`:

- `logthing.toml` and `/etc/logthing/config` remain live base layers for
  the entire config schema.
- `LOGTHING__*` environment variables override them, as they already do
  today.
- Two fields stay **file-only, with no environment equivalent**:
  `security.allowed_ips` (a `Vec<String>`; the loader sets no
  `list_separator`, so no single variable can produce a list) and
  `aggregate.rules` (a `Vec<AggregateRule>` with nested `Vec<String>`
  fields, not expressible as environment variables at all).

The user was offered the stricter alternative — rip every file source
out of `Config::load()`, making `LOGTHING__*` the only input — and chose
this scope instead, because the stricter version breaks those two
fields. Any documentation produced by this change must describe it in
these terms and must not claim "configuration is via environment
variables only."

## Background: environment-variable support already exists

`Config::load()` (`src/config/mod.rs:1602`) layers sources through the
`config` crate, last source winning:

```
defaults → logthing.toml → logthing.admin.toml → /etc/logthing/config → LOGTHING__* env
```

`config::Environment::with_prefix("LOGTHING").separator("__")` is
already installed and already tested by
`env_vars_override_bind_ports_for_all_log_types`
(`src/config/mod.rs:2123`). This change therefore **builds no new
configuration capability**. It is a deletion, plus one new startup
validation and one new diagnostic view.

## Design

### 1. Configuration loading (`src/config/mod.rs`)

- Remove the `logthing.admin.toml` source from `Config::load()`.
- Delete the `ADMIN_OVERRIDE_FILE` constant (`src/config/mod.rs:5`).
- Delete the tracked `logthing.admin.toml` from the repository. It
  currently sets `bind_address = "127.0.0.1:9999"`, `tls.enabled =
  false` and `logging.level = "debug"`; with it gone, running from the
  repo root falls back to `logthing.toml`'s `0.0.0.0:5985` and `info`.
- Move `validate_config_invariants` out of `src/admin/config_api.rs:366`
  into `src/config/mod.rs` and call it at the end of `Config::load()`.

  This is **new behaviour for every deployment**, not deletion. Today
  the function is reachable only from the admin write endpoints, so a
  config that enables TLS without a certificate, or sets a port to 0,
  is accepted at startup and fails later. With the write endpoints
  gone the function would otherwise become dead code, and there would
  be nothing validating those invariants at all.

  Two notes for the implementer. First, its doc comment references
  `apply_live_security_settings` and "before persist" — both concepts
  disappear in this change, so the comment must be rewritten rather
  than moved verbatim. Second, its `parse_allowed_ips` check duplicates
  a fail-fast that already exists at `src/main.rs:48`, where
  `IpWhitelist::new` rejects a bad CIDR. The duplication is harmless
  (both fail fast and agree), and `main.rs` keeps its call because it
  must build the whitelist anyway. Do not attempt to unify them.

- On startup, if `logthing.admin.toml` still exists on disk, log a WARN
  naming the file and stating it is no longer read. An operator whose
  effective configuration came from that file would otherwise see
  settings change with no explanation. A hard failure was rejected: it
  would break upgrades for no safety gain.

### 2. Admin routes (`src/admin/routes.rs`)

Keep: `GET /`, `GET /config`, `GET /health`, `GET /audit-log`,
`GET /stats`, `GET /stats.json`.

Delete: `PUT /config`, `PATCH /config`, and
`POST /config/{validate,diff,export,import,reload}`.

`GET /config` keeps its existing JSON response and its existing
secret-redaction behaviour — a working contract with passing tests, and
nothing about this change requires altering it.

`src/admin/config_api.rs` (1,413 lines) shrinks to the read path:
`redacted_config`, `redact_s3_connection`, and the `REDACTED`
constant. Everything else in the file is deleted — `persist_config`,
`write_config_to_path`, `merge_redacted_secrets`,
`apply_live_security_settings`, `apply_flush_intervals`, the five
endpoint handlers, `ValidationResult`, and the
`LOGTHING_ADMIN_OVERRIDE_FILE` test sandbox that existed solely to keep
the write tests off the real file.

### 3. Orphaned plumbing

Every surviving route is a `GET`, so:

- Delete `csrf_middleware` and `generate_csrf_token`
  (`src/admin/middleware.rs`, `src/admin/auth.rs`), the
  `AdminState.csrf_tokens` field, and the `{{CSRF_TOKEN}}` template
  substitution. There is no state-changing request left to forge.
- Delete `AdminState.ip_whitelist` and `AdminState.flush_registry`;
  each had exactly one reader, and both were the live-apply helpers.
  `spawn_admin_server` loses the matching parameters and `src/main.rs`
  updates at the call site.
- Delete `IpWhitelist::set_networks` (`src/middleware/mod.rs`) and
  `FlushIntervalRegistry::set_secs`. `FlushIntervalRegistry::register`
  is used throughout `main.rs` for every sink and stays.
- `Arc<RwLock<Config>>` stays exactly as it is. Collapsing it to
  `Arc<Config>` would touch `server/mod.rs`, `ingest/handlers.rs`,
  `AppState`, and every test that builds a router, for no behaviour
  change. Explicitly out of scope.

`security_middleware` is untouched. It gates the admin server on
`LOGTHING_ADMIN_ALLOWED_IPS`, a separate admin-only allowlist unrelated
to `security.allowed_ips`.

### 4. The page (`src/admin/templates/admin.html`)

663 lines to roughly 140. The form, its seven buttons, and the ~350
lines of JavaScript driving the config endpoints are deleted. What
replaces them, rendered server-side the way `stats.html` already is:

- A read-only table of the effective configuration, built from
  `redacted_config`. Server-side rendering keeps even redacted secrets
  out of browser JavaScript and removes the last reason for the page to
  call an API.
- The list of `LOGTHING__*` variable **names** currently set in the
  process, beside the resolved configuration. Names only, never values:
  `LOGTHING__HEC__TOKEN` and the S3 credentials would otherwise leak
  into the page.

  This is a deliberate approximation. The `config` crate exposes no
  per-field source attribution, so showing which layer actually won
  would mean building a parallel resolver. The known limitation: a
  typo'd variable (`LOGTHING__SYSLOG__UDP_PRT`) still appears in the
  list looking legitimate. What disambiguates it is the resolved value
  displayed alongside — the variable is listed, but the field it was
  meant to set still shows the old value. The page copy should say so.
- A note that configuration comes from `LOGTHING__*` variables layered
  over `logthing.toml`, and that changes require a restart.
- An explicit line marking `security.allowed_ips` and
  `aggregate.rules` as file-only with no environment equivalent.
  Without it, an operator follows the general note, sets
  `LOGTHING__SECURITY__ALLOWED_IPS`, and it silently does nothing.
- The audit-log section and a link to `/stats`, both retained.
- The stale subtitle claiming changes persist to `wef-server.admin.toml`
  is removed along with the rest of the form.

### 5. Behaviour removed, deliberately

`security.allowed_ips`, `hec.token`, and the S3 flush intervals stop
applying live; all three become restart-only. This reverses commits
`1401447` and `4fcf618` from two weeks ago and must be recorded in
`CHANGELOG.md` as a breaking change. Operators relying on live
allowlist or token updates need to know before they upgrade.

The audit log also becomes much quieter: its `CONFIG_UPDATED` and
`CONFIG_UPDATE_FAILED` entries disappear, leaving read access and
authentication failures. It remains useful as an auth trail but stops
being a change record.

### 6. Testing

The project requires unit, integration, and end-to-end coverage for
changed behaviour.

**Unit**
- `Config::load()` ignores a `logthing.admin.toml` sitting in the
  working directory.
- `Config::load()` rejects TLS-enabled-without-certificate, and a
  `bind_address` port of 0, via the relocated
  `validate_config_invariants`.
- The stale-`logthing.admin.toml` WARN fires when the file is present
  and not otherwise.
- The environment-variable lister returns variable names and never
  values.

**Integration**
- The admin router returns 405 for `PUT` and `PATCH /config`, and 404
  for the five deleted `POST /config/*` routes.
- `GET /config` still returns secret-redacted configuration under
  authentication.
- The existing authentication, rate-limit, and trusted-header tests
  still pass with the CSRF layer removed.

**End-to-end**
- Delete `tests/admin_flush_interval_e2e.rs`. It drives a real
  `PUT /config` to prove flush intervals apply live — a feature this
  change removes.
- Keep `tests/admin_trusted_header_e2e.rs`. It already uses only
  `GET /config`; it needs its `LOGTHING_ADMIN_ENABLE_CSRF` setup line
  and its `PERSIST_CONFIG_ENV_LOCK` reference removed.
- Add an end-to-end test that starts a real server with
  `LOGTHING__SYSLOG__UDP_PORT` set, scrapes `GET /config` and `GET /`
  over real HTTP, and asserts the environment value is what the running
  process reports and that the variable name appears on the page.

### 7. Documentation

- `README.md` and `docs/admin-security.md`. The CSRF section of the
  latter goes; its TLS, authentication, IP-allowlist, rate-limit and
  audit sections stay.
- `logthing.toml` is the environment-variable reference. It already
  annotates most fields with `env: LOGTHING__*`; fill in the gaps, and
  mark `security.allowed_ips` and `aggregate.rules` as file-only with
  no environment equivalent. A separate `docs/configuration.md` was
  rejected: `logthing.toml` remains a live config source, and two
  references drift apart.
- `CHANGELOG.md` records the breaking change from section 5.
- Files under `docs/performance/` and `docs/superpowers/` are records
  of past work and are left alone.

## Out of scope

- Collapsing `Arc<RwLock<Config>>` to `Arc<Config>`.
- Adding a `list_separator` so `security.allowed_ips` becomes
  environment-settable.
- Any new mechanism for `aggregate.rules`.
- Removing `logthing.toml` or `/etc/logthing/config` as config sources.
- Rewriting historical documents under `docs/`.

## Decision log

| # | Decision | Chosen | Decided by |
|---|---|---|---|
| 1 | Fate of the TOML files | Drop `logthing.admin.toml` only; `logthing.toml` and `/etc/logthing/config` stay | user |
| 2 | What admin still serves | Read-only console: `GET /config`, `/stats`, `/stats.json`, `/audit-log`, `/health` | user |
| 3 | Cleanup depth | Admin-local dead code only; keep `Arc<RwLock<Config>>` | user |
| 4 | `validate_config_invariants` | Move to `Config::load()`; new startup behaviour | assistant |
| 5 | Stale `logthing.admin.toml` | WARN at startup, not silent, not fatal | assistant |
| 6 | Read-only page | Server-side table from `redacted_config` | assistant |
| 7 | `GET /config` format | JSON, unchanged | assistant |
| 8 | How the change is described | Honest framing; no "env vars only" claim | assistant |
| 9 | Env-var reference location | Annotate `logthing.toml`, mark the two file-only fields | assistant |
| 10 | Branch | `feat/admin-readonly-env-config`; merge decision left to the user | assistant |
| 11 | "Did my env var land?" | List set `LOGTHING__*` names beside resolved values; document the typo limitation | assistant |

Rows 1-3 were answered directly by the user. Rows 4-11 were chosen by
the assistant under the `auto-develop` skill and cleared by an
independent coherence review (round 2: `coherent: true`), whose
remaining concerns are folded into sections 1, 4 and 7 above.
