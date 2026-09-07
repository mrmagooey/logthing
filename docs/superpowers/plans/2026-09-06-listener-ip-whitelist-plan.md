# Plan: listener IP whitelist + empty-HEC-token warning

Spec: `docs/superpowers/specs/2026-09-06-listener-ip-whitelist-design.md`
Branch: `feat/listener-ip-whitelist` (worktree `/home/dev/projects/logthing-wt-ipwl`)

## Task 1 — enforcement in the 5 listener modules

- [ ] Add private `allowed_ips: IpWhitelist` to `SyslogListener`, `IpfixListener`,
      `SflowListener`, `ZeekListener`, `SuricataListener`; init to
      `IpWhitelist::empty()` in each `new()`; add
      `pub fn with_allowed_ips(mut self, w: IpWhitelist) -> Self`.
- [ ] Insert the guard at all 12 sites, before any `*_received` counter
      increment and before parsing. UDP → `debug!`, TCP → `warn!`. Counter
      `listener_source_rejected` with `protocol` label
      (`syslog_udp`, `syslog_tcp`, `ipfix`, `sflow`, `zeek`, `suricata`).
- [ ] One `ponytail:` comment per module: new recv/accept arms need the check.
- [ ] Unit tests per module: blocked source never reaches the handler; allowed
      source does. Reuse each module's real-socket + recording-handler pattern.

## Task 2 — main.rs wiring

- [ ] Build `IpWhitelist` once after config load (empty → `empty()`, else
      `new(...)?`), clone into all 5 listener constructions via
      `.with_allowed_ips(...)`.

## Task 3 — empty-HEC-token warning

- [ ] `pub fn insecure_config_warnings(cfg: &Config) -> Vec<String>` in
      `src/config/mod.rs`; one warning when `cfg.hec.enabled && cfg.hec.token.is_empty()`.
- [ ] main.rs logs each at `warn!`, **immediately after the subscriber `.init()`
      match block (src/main.rs:47)** — not after `Config::load()` at L37.
- [ ] Unit tests: enabled+empty warns; enabled+token silent; disabled silent.

## Task 4 — integration test

- [ ] `tests/listener_ip_whitelist_integration.rs`: allow and block cases over
      real sockets for one UDP listener and one TCP listener.

## Task 5 — e2e test

- [ ] `tests/listener_ip_whitelist_e2e.rs`: spawn `env!("CARGO_BIN_EXE_logthing")`
      with `current_dir` = temp dir holding a `logthing.toml` (all 5 listeners on
      collision-safe high ports, metrics enabled, `security.allowed_ips` excluding
      127.0.0.1). Retry-connect readiness loop, no fixed sleep. Probe all 5 ports,
      **sending a payload on the TCP ones**. Scrape `/metrics`; assert
      `listener_source_rejected` fired for every protocol label.
- [ ] Kill the child process on both success and failure paths.

## Task 6 — docs

- [ ] `CHANGELOG.md` — new Unreleased section; note the widened scope of
      `security.allowed_ips` as a behaviour change for anyone who already set it.
- [ ] `README.md` `[security]` block (~L54) and `logthing.toml` (~L11) — state
      that `allowed_ips` covers HTTP *and* the wire-protocol listeners.

## Verification

- [ ] `cargo test --all-targets` green.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
