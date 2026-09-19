# Security Review Remediation — Design

**Date:** 2026-09-19
**Base commit:** `67db818`
**Integration branch:** `security/review-remediation`
**Origin:** a five-agent security review of the repository, one agent per trust
boundary (auth/admin, HTTP ingest/TLS, binary decoders, text decoders,
sinks/secrets/config). Every finding below was independently spot-verified
against the code before being accepted into this spec.

This design was produced via the `auto-develop` skill: the clarifying questions
were self-answered and recorded in the decision log, then an independent
reviewer subagent checked coherence. It took three review rounds; rounds 1 and 2
rejected, round 3 returned `coherent: true`.

---

## 1. Scope

Nine findings, remediated **sequentially** — one unit at a time, each merged
into the integration branch before the next begins.

| ID | Sev | Summary |
|----|-----|---------|
| F1 | CRITICAL | Nine raw-byte-offset slices of wire strings panic mid-UTF-8-char; in syslog UDP the panic permanently kills a receive task, and the death is silent |
| F2 | HIGH | Stored XSS: unauthenticated attacker writes an audit entry; admin UI renders it via `innerHTML` |
| F3 | HIGH | `redacted_config()` masks S3 credentials for 3 of 10 config sections |
| F4 | HIGH | Wire-supplied `sourcetype` used verbatim as an S3 object-key path segment |
| F5 | MEDIUM | IPFIX template cache has no eviction path; never recovers from a spoofed fill |
| F6 | MEDIUM | No idle timeout on the three TCP listeners; no accept-level bound on HTTP |
| F7 | MEDIUM | Metrics server binds `0.0.0.0` with no whitelist and no auth; TLS ignores `bind_address` |
| F8 | LOW | Raw `\n` from the wire reaches the log under the default plain-text format |
| F9 | LOW | Admin rate-limit map never evicts; a fully-malformed admin allowlist silently means allow-all |

**Explicitly out of scope** (decision log row 13): any broader audit of the
receive path for other latent panics. F1 fixes the confirmed trigger and its
amplifier; a speculative hunt is unbounded and unrequested.

---

## 2. Decision log

| # | Question | Options considered | Chosen | Rationale | Conf |
|---|----------|--------------------|--------|-----------|------|
| 1 | Which findings? | All 9 / high+ only / critical+high | All 9 | User said "each finding"; the lows are ~5 lines each | High |
| 2 | Branch strategy | One integration branch / branch-per-finding / 9 off master | One `security/review-remediation` branch; each unit in its own worktree off the branch's **current tip**, merged back before the next starts | User said "sequentially". File overlap (F1+F8 in listeners, F2+F3+F9 in `admin/*`, F1+F7 in `server/mod.rs`) is a secondary reason that admittedly does not apply to the independent F4/F5 pair | High |
| 3 | Panic-class fix | Inline per site / one shared helper / `get().unwrap_or()` | One `pub(crate) fn truncate_for_log(s: &str, max_bytes: usize) -> &str` — byte-budget with char-boundary walk-back, generalizing `protocol/mod.rs:58-60` — called from all 9 sites **and** from `protocol/mod.rs` | Same root cause in 9 places: one guard beats nine. Byte-budget preserves current max log-line length (a `chars().take(N)` would silently 4x it). Reuses the in-repo algorithm rather than forking it | High |
| 4 | F6 idle-timeout value | Hardcoded const / new config knob / reuse `security.connection_timeout_secs` | Hardcoded `const` beside the existing `MAX_*_TCP_CONNECTIONS` consts | The three listeners never receive `SecurityConfig`, so reuse needs plumbing through 3 structs; the existing connection caps are themselves hardcoded consts | High |
| 5 | F7 exposure | Inherit bind_address / new config knob / add whitelist middleware | **Both**: metrics gets `metrics.bind_address: Option<String>` (None = inherit) **and** the existing IP-whitelist middleware. TLS inherits `bind_address` with no new knob | Inheriting alone leaves metrics open whenever `bind_address` is `0.0.0.0`. The `Option` is the opt-back path for operators scraping remotely — a release note is not a rollout mechanism. TLS needs no knob: it already carries whitelist + auth | Medium |
| 6 | F4 sanitizing | Reuse `sanitize_log_path` / new sanitizer / reject record | Reuse `sanitize_log_path`, hoisted from `zeek_s3.rs` to the shared sink module | Already implements the needed semantics (`[a-z0-9_]`, 64 chars, `"unknown"` fallback) and is already proven for zeek/suricata | High |
| 6b | F4's HEC empty-token fail-open | Hard error / startup warn / leave | Startup warn only | Empty-token dev mode is documented deliberate behaviour; hard-erroring breaks it. Row 6 removes the dangerous consequence | Medium |
| 7 | F5 eviction | `lru` crate / TTL sweep / periodic clear | TTL = 1 hour, no new dep. Map value becomes `TemplateEntry { fields, last_seen: AtomicU64 }`, refreshed by a **`Relaxed` store under the existing `.read()` lock**; sweep only on insert-into-full-cache; metric on eviction | Refresh-on-use keeps any actively-sending exporter alive indefinitely. Sweep-only-when-full means non-attacked deployments never evict. The atomic preserves the read-mostly invariant documented at `decoder.rs:113-116` — a plain field would force the IPFIX hot path onto a write lock | High |
| 8 | F2 XSS fix | Escape in template / server-side / CSP | Build DOM nodes with `textContent` at the render site | Server-side escaping would corrupt the JSON API's data. CSP noted as defence-in-depth, not built (scope creep) | High |
| 9 | F3 redaction | 7 more `if let` lines / macro / serde attribute | The 7 lines, plus a test enumerating all 10 S3-bearing sections | A serde attribute would also alter the config **write** path and TOML round-trips. Boring beats clever; the enumerating test is the real guard against a future 11th section | High |
| 10 | Test levels | All three always / unit+integration with e2e where cheap | Unit + integration + e2e for every finding via the repo's existing `tests/*_e2e.rs` cargo-test pattern. **F2 excepted** — see §5 | `tests/*_e2e.rs` are ~20 plain cargo tests over real sockets, not Docker, so e2e is cheap here and CLAUDE.md's three-level rule is met rather than exempted | High |
| 11 | Order | Severity / dependency-aware | F1 → F2 → F3 → F4 → F5 → F6 → F7 → F8 → F9 | F8 layers on F1's helper so F1 must land first; the critical fix lands first in a small, backportable commit | High |
| 12 | Recv-task death visibility | In F1 / separate unit / ignore | In F1's scope: replace `let _ = task.await` at `syslog/listener.rs:557-559` with a match that logs an error and increments a metric on `JoinError` | F1's CRITICAL rating derives **entirely** from this amplifier. Fixing the trigger while leaving death silent would misrepresent the fix | High |
| 13 | Broader recv-path panic audit | In scope / out of scope | Out of scope, explicitly | F1 covers the confirmed trigger plus its amplifier; a speculative hunt is unbounded | Medium |

---

## 3. Per-finding design

### F1 — char-boundary panic class (CRITICAL)

Two defects, one unit, because the second is what makes the first critical.

**Trigger.** Add to `src/lib.rs`:

```rust
pub(crate) fn truncate_for_log(s: &str, max_bytes: usize) -> &str
```

Byte-budget truncation that walks back to a char boundary — the algorithm
already at `src/protocol/mod.rs:58-60`, hoisted. Returns `&str`; round 2
verified all 9 sites bind a value that outlives the `warn!` call, so no site
needs an owned `String`. Call sites, preserving each one's current budget:

- `src/syslog/listener.rs` — 334, 427, 607, 747, 794, 847 (budget 100)
- `src/zeek/listener.rs:267`, `src/suricata/listener.rs:266` (budget 120)
- `src/server/mod.rs:889` (budget 100)
- `src/protocol/mod.rs:58-60` refactored to call the helper (budget 2000)

**Amplifier.** `src/syslog/listener.rs:557-559` currently reads
`for task in tasks { let _ = task.await; }`. The `let _ =` discards the
`JoinError`, so a panicking receive task is silently ignored: the parent
listener handle stays alive and `supervise_listener_handles`
(`src/main.rs:777`) never fires. Replace with a match that logs at `error!`
and increments a counter on `Err`.

Scoped to syslog deliberately — round 2 verified this fan-out/join/discard
pattern exists only there, because only syslog fans multiple `SO_REUSEPORT`
receive tasks plus a TCP accept loop under one parent handle. zeek/suricata are
TCP-only with legitimately fire-and-forget per-connection tasks.

### F2 — admin audit-log XSS (HIGH)

Fix at the render site in `src/admin/templates/admin.html:595-599`: build the
audit entry with DOM nodes and `textContent` rather than an `innerHTML`
template literal. The server keeps storing and serving the raw string — that is
the correct JSON API contract, and escaping belongs at render time.

### F3 — incomplete S3 credential redaction (HIGH)

`redacted_config()` (`src/admin/config_api.rs:148-162`) gains the 7 missing
sections: `syslog.structured_s3`, `suricata.s3`, `wef.s3`, `hec.s3`,
`sflow.s3`, `aggregate.s3`, `iceberg.s3`. All 10 share
`#[serde(flatten)] connection: S3ConnectionConfig`.

### F4 — `sourcetype` path injection (HIGH)

Hoist `sanitize_log_path` from `src/forwarding/zeek_s3.rs:35` into the shared
sink module and call it from `GenericSink::partition`
(`src/forwarding/generic_s3.rs:166-170`). Update the stale
"operator-controlled" comment. Add a startup warning when `hec.enabled` is true
and `hec.token` is empty (row 6b — warn, not error).

### F5 — IPFIX template cache eviction (MEDIUM)

In `src/ipfix/decoder.rs`, the map value becomes:

```rust
struct TemplateEntry { fields: Vec<FieldSpecifier>, last_seen: AtomicU64 }
```

- `cache_get` keeps `.read()` and refreshes `last_seen` with a `Relaxed` store
  through the shared reference. `AtomicU64::store` takes `&self`, so this needs
  no write lock — the documented read-mostly invariant survives intact.
- `try_insert_template` already takes `.write()`; when an insert arrives at a
  full cache, first sweep entries older than the TTL, then retry.
- TTL: 1 hour. Re-inserting an existing key replaces the whole entry, so a
  periodic template re-send refreshes `last_seen` naturally.
- Emit a metric on eviction.

Public signatures of `cache_get`/`try_insert_template` are unchanged, so none
of the 20+ call sites move.

Note: the cross-exporter template poisoning in the same finding (spoofed source
IP overwrites another exporter's template) is **inherent to unauthenticated UDP
IPFIX** and is not fixed here. Document it and the `allowed_ips` mitigation.

### F6 — TCP idle timeout (MEDIUM)

Wrap the per-line `read_until` in `tokio::time::timeout` in the three listeners'
`handle_tcp_connection`, closing the connection on expiry. Timeout is a
hardcoded `const` beside each file's existing `MAX_*_TCP_CONNECTIONS`.

The HTTP half of this finding (tower layers only bound post-routing work) is
noted but **not** fixed here — it needs a hyper-level header-read timeout,
which is a different change from the listener fix. Flagged as a follow-up.

### F7 — metrics/TLS bind exposure (MEDIUM)

- New `metrics.bind_address: Option<String>`; `None` inherits the main
  `bind_address`. `src/server/mod.rs:386` uses it instead of hardcoded
  `0.0.0.0`.
- Apply the existing IP-whitelist middleware to the metrics router
  (`start_metrics_server`, 3229-3252).
- `src/server/mod.rs:551` uses the `bind_address` IP with `tls.port`.

This is a deliberate breaking change for anyone scraping metrics from another
host while binding the main server narrowly; `metrics.bind_address = "0.0.0.0"`
is the documented opt-back.

### F8 — log injection (LOW)

Layer control-character sanitizing on top of F1's helper for the syslog UDP
`warn!` sites, where a raw `\n` from a datagram can forge an operator log line
under the default `Pretty` format. Returns `Cow<str>` so the common
(clean) path does not allocate.

### F9 — admin housekeeping (LOW)

- `src/admin/middleware.rs:56`: sweep stale entries from `request_counts`.
- `src/admin/state.rs:491-497`: distinguish "no allowlist configured" from "all
  N entries failed to parse" and warn distinctly for the latter.

---

## 4. Execution model

One integration branch. Nine sequential units. For each:

1. A Sonnet implementer subagent works in its own git worktree, branched from
   the integration branch's **current tip** (verified with `git rev-parse HEAD`,
   not remembered).
2. Regression tests first: each must fail before the fix and pass after.
3. A spec-compliance reviewer subagent — does it match this spec? Anything
   missing, anything extra?
4. Once that is clean, a code-quality reviewer subagent.
5. Reviewer findings go back to the implementer and are re-reviewed by the same
   reviewer. No unit advances with open findings.
6. `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` all pass, then the
   unit merges into the integration branch as one conventional commit.

**The run stops at the merge-to-master decision.** No merge to master, no push,
no PR without explicit user consent.

---

## 5. Testing

Unit + integration + e2e for every finding, using the repo's existing
`tests/*_e2e.rs` pattern (plain cargo tests over real sockets and spawned
binaries — not the Docker harness).

**F2 is the one exception, stated explicitly per CLAUDE.md's escape clause:**

- **Unit** — assert the `admin.html` source (available as a Rust string literal
  via `include_str!`, `src/admin/routes.rs:263`) no longer interpolates audit
  fields into `innerHTML`.
- **Integration** — assert `/audit-log` still serves a script-payload username
  verbatim in its JSON, confirming the API contract is deliberately unchanged.
- **E2E — not delivered.** Browser-level proof that the payload does not execute
  is out of reach of `cargo test`: there is no DOM in the Rust harness, no JS
  test tooling in the repo, and the Docker harness contains only protocol
  generators/verifiers. Adding Playwright for a single template fix is judged
  scope creep and is surfaced to the user as a follow-up decision rather than
  built.

---

## 6. Known follow-ups (not built here)

- Browser-level e2e for the admin UI (F2).
- HTTP accept-level/header-read timeout (F6's HTTP half).
- CSP header on the admin server (F2 defence-in-depth).
- Cross-exporter IPFIX template poisoning — inherent to unauthenticated UDP;
  mitigation is a tight per-exporter `allowed_ips`.
