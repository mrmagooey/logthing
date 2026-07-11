# Bind-port env-var configurability: regression tests & documentation

**Date:** 2026-07-10
**Process:** `auto-develop` (autonomous brainstorming, reviewer-gated, no human Q&A)
**Status:** approved by independent coherence reviewer

## Request (verbatim)

> Make the bind ports configurable via environment variable for each type of log

## Finding

This is already implemented. `Config::load()` (`src/config/mod.rs`) layers
`config::Environment::with_prefix("WEF").separator("__")` over the TOML file
sources, so any config field — including every listener's port and bind
address — can be overridden with a `WEF__<SECTION>__<FIELD>` environment
variable. This was verified two ways:

1. **Isolated verification** — a throwaway `cargo run --example` set
   `WEF__SYSLOG__UDP_PORT`, `WEF__ZEEK__TCP_PORT`, `WEF__IPFIX__UDP_PORT`,
   `WEF__SFLOW__UDP_PORT`, `WEF__SURICATA__TCP_PORT`, and `WEF__BIND_ADDRESS`,
   called `Config::load()`, and confirmed every field reflected the override.
2. **End-to-end trace** — read `src/main.rs` and `src/server/mod.rs`
   directly and confirmed the *same* `Config::load()` result flows, with no
   re-parsing or CLI-arg shadowing, into every listener's start call and the
   main HTTP/TLS/metrics binds:
   - `main.rs:37` — the one `Config::load()` call.
   - `main.rs:173-178` (syslog), `243-246` (ipfix), `311-314` (zeek),
     `382-385` (suricata), `451-454` (sflow) — each listener's
     `*ListenerConfig` built from that same config.
   - `main.rs:467` → `server/mod.rs:345,348` (HTTP bind), `353` (metrics
     bind), `465` (TLS bind).
   - All five listeners (`src/{syslog,ipfix,zeek,suricata,sflow}/listener.rs`)
     use the identical `format!("{bind}:{port}").parse() -> UdpSocket::bind`
     / `TcpListener::bind` wiring (confirmed by direct grep of each file).

So env-var port configuration for every log type already works, end to end,
today. What's actually missing:

- **Zero test coverage.** No unit, integration, or e2e test in the repo
  directly asserts that `Config::load()` honors these overrides, or that an
  override reaches a real OS-level bind. A future refactor of the config
  loader could silently break this with nothing to catch it.
- **Thin documentation.** `README.md`'s env-var section shows examples only
  for `WEF__BIND_ADDRESS`, `WEF__TLS__ENABLED`, `WEF__SECURITY__MAX_CONNECTIONS`,
  `WEF__METRICS__PORT` — never the per-log-type listener ports, which is
  presumably why this looked unimplemented.
- **A real, minor asymmetry worth documenting (not fixing):**
  `SyslogConfig` has no `bind_address` field — the syslog listener's bind
  address is hardcoded to `"0.0.0.0"` in `main.rs:176`, unlike
  `IpfixConfig`/`ZeekConfig`/`SuricataConfig`/`SflowConfig`, which all have a
  `bind_address` field that *is* env-var overridable. Adding that field to
  `SyslogConfig` is out of scope — the request was about ports, not bind
  interfaces — but leaving it undocumented would surprise a user who expects
  parity across listener types.

## Scope

No new runtime/production code paths. This closes the coverage and
discoverability gap on already-working behavior.

### 1. Config-level regression test (unit tier)

One consolidated test in `src/config/mod.rs`'s existing `#[cfg(test)] mod
tests`, following the file's existing `load_reads_configuration_file`
pattern (env mutation wrapped in `catch_unwind` with guaranteed cleanup, so a
failed assertion can't leak `WEF__*` env state into other tests sharing the
process). It sets every overridable bind-related field via env var and
asserts `Config::load()` reflects each:

- `WEF__BIND_ADDRESS`
- `WEF__TLS__PORT`
- `WEF__METRICS__PORT`
- `WEF__SYSLOG__UDP_PORT`, `WEF__SYSLOG__TCP_PORT`
- `WEF__IPFIX__UDP_PORT`, `WEF__IPFIX__BIND_ADDRESS`
- `WEF__ZEEK__TCP_PORT`, `WEF__ZEEK__BIND_ADDRESS`
- `WEF__SURICATA__TCP_PORT`, `WEF__SURICATA__BIND_ADDRESS`
- `WEF__SFLOW__UDP_PORT`, `WEF__SFLOW__BIND_ADDRESS`

One test, not thirteen near-duplicates — same rationale as the existing file
conventions (three similar lines beat a premature abstraction; thirteen
near-identical one-liners are noise, not clarity).

### 2. Live-bind regression test (integration tier)

One new integration test (new file, e.g.
`tests/ipfix_env_var_bind_integration.rs`, no external services required) that:

1. Sets `WEF__IPFIX__UDP_PORT` and `WEF__IPFIX__BIND_ADDRESS` (to
   `127.0.0.1` and a fixed high test port) as env vars.
2. Calls `Config::load()`.
3. Builds a real `IpfixListener` from the resulting `ipfix.udp_port` /
   `ipfix.bind_address` and starts it with `start_with_shutdown`.
4. Confirms the override reached a live OS socket: attempting a second
   `UdpSocket::bind` on the exact same `127.0.0.1:<port>` fails with
   `AddrInUse` while the listener holds it.
5. Triggers shutdown and confirms the port is released afterward.

Ipfix is the representative listener (not syslog) specifically because it
has *both* `udp_port` and `bind_address` fields, so one live-bind test
proves both override paths reach a real socket. The other four listeners
share byte-for-byte identical `format!("{bind}:{port}").parse() -> bind()`
wiring (verified by direct inspection), so duplicating this test across all
five would be redundant coverage of an identical pattern.

Existing e2e coverage (`tests/e2e/simulation-environment/docker-compose.yml`,
which already runs the full system with `WEF__SYSLOG__UDP_PORT=5514` /
`WEF__SYSLOG__TCP_PORT=5601`) already exercises this at the e2e tier for
syslog; no new e2e artifact is added.

### 3. Documentation

- **`README.md`** — extend the existing "environment variables" example
  block (currently only `WEF__BIND_ADDRESS`, `WEF__TLS__ENABLED`,
  `WEF__SECURITY__MAX_CONNECTIONS`, `WEF__METRICS__PORT`) with one example
  per log type's port (and bind address, where applicable), plus an explicit
  note that syslog's bind address is fixed at `0.0.0.0` and not
  configurable (unlike ipfix/zeek/suricata/sflow).
- **`logthing.toml`** — add a one-line inline comment next to each port /
  `bind_address` field naming its override env var, matching the file's
  existing habit of inline comments (e.g. `# Standard syslog UDP port`).
  Add a comment on the `[syslog]` section noting the bind-address
  limitation.

## Non-goals

- Adding a `bind_address` field to `SyslogConfig`.
- Introducing a second/bespoke env-var naming scheme (e.g. dedicated
  `LOGTHING_*` vars) — the existing `WEF__<SECTION>__<FIELD>` convention is
  already used throughout tests, `docker-compose.yml`, and
  `scripts/run-with-profiling.sh`; a parallel mechanism would be pure
  duplication.
- Expanding e2e docker-compose coverage to ipfix/zeek/suricata/sflow.

## Review record

Independent reviewer (fresh subagent, full context passed inline, no shared
history with the implementer) issued `coherent: false` on first pass with
three concerns:

1. Unverified premise that `Config::load()`'s output actually reaches the
   real server startup path.
2. Silent asymmetry (syslog `bind_address` not configurable) not flagged to
   users.
3. "Identical wiring across all five listeners" asserted without evidence.

All three were closed with direct code evidence (full `main.rs` /
`server/mod.rs` trace; explicit doc callout added for the asymmetry; grep
confirmation of identical bind wiring across all five listener files). On
re-review: `coherent: true`, with one non-blocking note (now folded into
scope item 2 above: use ipfix, which has a `bind_address` field, as the
live-bind integration test's representative listener instead of syslog).
