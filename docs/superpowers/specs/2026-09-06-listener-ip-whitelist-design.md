# Design: apply `security.allowed_ips` to non-HTTP listeners + warn on empty HEC token

Date: 2026-09-06
Status: approved (auto-develop; independent coherence review round 2)

## Problem

Two gaps found while auditing what stops logthing accepting logs from
unauthorised systems.

1. **`security.allowed_ips` silently applies to nothing outside HTTP.**
   `IpWhitelist` (`src/middleware/mod.rs:11`) is wired only into the axum
   router (`src/server/mod.rs:423`). The syslog UDP+TCP, IPFIX UDP, sFlow UDP,
   Zeek TCP and Suricata TCP listeners perform no source filtering at all.
   An operator who sets `allowed_ips` reasonably believes their collectors are
   restricted; in reality every wire-protocol listener accepts from anyone who
   can reach the port.
2. **Empty `hec.token` means "accept any token".** `src/ingest/handlers.rs`
   guards with `!cfg_token.is_empty() && !check_hec_token(...)`, so a HEC
   deployment that never sets a token is unauthenticated with no signal.

Out of scope, explicitly not authorised: adding auth to the `/wsman` and
`/syslog` HTTP routes.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Check at the `recv_from`/`accept` site, not via a handler decorator | Drops before parse; ~1 line per site vs 5 decorator structs across 5 trait signatures |
| 2 | Plumb via `with_allowed_ips(mut self, IpWhitelist) -> Self` setter on each listener struct, field defaulting to `IpWhitelist::empty()` in `new()` | Putting it on `XListenerConfig` forces edits at all 29 explicit construction sites incl. 5 files under `tests/`, and needs a `Debug` derive on `IpWhitelist` since those config structs derive `Debug` |
| 3 | Reuse the existing `security.allowed_ips`; no per-protocol lists | Exactly what was asked; per-protocol is YAGNI and reversible |
| 4 | Metric always; `debug!` on UDP datagram drops, `warn!` on TCP connection drops | A `warn!` per rejected UDP datagram is a self-inflicted log flood under packet flood. TCP accept rate is bounded, and the codebase already warns per rejected connection (`syslog_tcp_connections_rejected`) |
| 5 | One counter `listener_source_rejected` with a `protocol` label | Labels are established here (`syslog_payload_parsed`, `zeek_records_by_path`, `aggregate_records_consumed`); one name to document |
| 6 | `insecure_config_warnings(&Config) -> Vec<String>` in `src/config/mod.rs`; main logs each **after** the tracing subscriber `.init()` | An inline `warn!` in main is unreachable from a unit test. Placement is load-bearing: `Config::load()` is `src/main.rs:37` but `.init()` is lines 45-47 — anything logged between them is silently discarded |
| 7 | Warn for HEC only, not the identical OTLP `bearer_token` footgun | Not requested; scope creep. Surfaced to the user as a follow-up |
| 8 | Build the `IpWhitelist` once in main after config load | One parse, fails fast on invalid CIDR, mirrors `run`/`run_tls` |
| 9 | E2E spawns the real binary once and probes all 5 listener ports | `with_allowed_ips` defaults to allow-all, so a forgotten call at any of the 5 `main.rs` sites is a *silent* bypass. Testing 2 of 5 leaves that unguarded while the changelog claims all five are protected. Rejected alternative: making the whitelist a required `new()` parameter — compiler-enforced, but re-introduces the 29-site churn |
| 10 | Guard goes **before** the existing `*_received` counter increments | Rejected traffic must not inflate received counts, and it makes the e2e assertion unambiguous |
| 11 | One `ponytail:` comment per listener module | Drift marker for 12 scattered sites. Restructuring to collapse the `start_with_shutdown` / `run_with_*` pairs was tried before in this repo and made the code longer — do not re-propose |

## The change

Private `allowed_ips: IpWhitelist` field on each of the 5 listener structs,
initialised to `IpWhitelist::empty()` in `new()`, set via `with_allowed_ips`.

At each of the **12 guard sites**, immediately after obtaining `(len, src)`
from `recv_from` or `(stream, src)` from `accept()`, and **before** any
received-counter increment or parsing:

```rust
if !self.allowed_ips.is_allowed(&src) {
    metrics::counter!("listener_source_rejected", "protocol" => "<proto>").increment(1);
    // UDP: debug!   TCP: warn!
    continue;
}
```

For TCP the accepted stream is dropped immediately, closing the connection.
Rejecting pre-accept is not possible without firewall/eBPF.

The 12 sites (line numbers as of `0bfe714`, expect small drift):

| Module | Sites |
|---|---|
| `src/syslog/listener.rs` | UDP arm ~L248 and TCP accept arm ~L271 of `start_with_shutdown`; `start_udp_listener` ~L324; `run_with_listener` ~L369 |
| `src/ipfix/listener.rs` | `start_with_shutdown` L89; `run_with_socket` L139 |
| `src/sflow/listener.rs` | `start_with_shutdown` L80; `run_with_socket` L126 |
| `src/zeek/listener.rs` | `start_with_shutdown` L104; `run_with_listener` L152 |
| `src/suricata/listener.rs` | `start_with_shutdown` L104; `run_with_listener` L152 |

Confirmed complete: no `recv_from`/`accept()` sites exist outside these five
modules, the HTTP server (already covered by `ip_whitelist_middleware`) and the
admin server (independent gate, out of scope).

`src/main.rs`: build the `IpWhitelist` once after config load; append
`.with_allowed_ips(w.clone())` at each of the 5 listener constructions
(~326 syslog, ~414 ipfix, ~500 zeek, ~589 suricata, ~676 sflow); iterate
`insecure_config_warnings(&config)` and `warn!` each, after subscriber init.

## Compatibility

Empty `security.allowed_ips` yields `IpWhitelist::empty()`, which allows all,
so a deployment that never set it sees **zero** behaviour change.

**Documented behaviour change**: a deployment that set `security.allowed_ips`
for HTTP will now *also* filter syslog/IPFIX/sFlow/Zeek/Suricata. Goes in
`CHANGELOG.md`, `README.md` (the `[security]` block at L54) and `logthing.toml`.

## Testing

- **Unit** — per listener module, a non-whitelisted source never reaches the
  handler, plus the matching allow case, using each module's existing
  real-socket + recording-handler pattern. Plus `insecure_config_warnings`:
  enabled+empty warns, enabled+token silent, disabled silent.
- **Integration** — allow and block, end to end over real sockets, for one UDP
  and one TCP listener.
- **E2E** — one test spawning `env!("CARGO_BIN_EXE_logthing")` with
  `current_dir` set to a temp dir holding a `logthing.toml` that enables all 5
  listeners on high ports, enables metrics, and sets `security.allowed_ips` to
  a range excluding 127.0.0.1. Probe all 5 ports from localhost, scrape
  `/metrics`, assert `listener_source_rejected` fired for each protocol label.
  Feasible: all 5 listeners fall back to their `Default*Handler` when no sink
  is configured (no AWS credentials needed), TLS defaults off, and the metrics
  endpoint is served by a *separate* router with no IP-whitelist layer, so it
  stays scrapable while 127.0.0.1 is blocked.

  Two constraints from review, both load-bearing:
  - Use a **retry-connect readiness loop**, never a fixed sleep — the binary
    binds 5 listeners plus HTTP plus metrics non-deterministically. This is the
    first process-spawn test in the suite; there is no precedent to copy and no
    `serial_test`/port-picker crate available. Choose collision-safe high ports
    and retry on bind failure.
  - TCP probes must **send a payload after connecting**. With connect-only,
    "the `*_received` counter stayed at zero" is trivially true whether or not
    the guard works, so it would prove nothing for the 3 TCP protocols.

## Delivery

Feature branch `feat/listener-ip-whitelist` off `0bfe714`. Not merged — the
merge/PR decision is the user's.
