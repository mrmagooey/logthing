# Security Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate the nine findings from the five-agent security review of `67db818`, one sequential unit at a time.

**Architecture:** Each finding is one task producing one conventional commit on the `security/review-remediation` integration branch. Tasks are ordered by severity except that Task 8 depends on the helper Task 1 introduces. Every task is TDD: regression test first, confirmed failing, then the minimal fix.

**Tech Stack:** Rust 2024, tokio, axum, rustls, metrics/Prometheus, serde. No new dependencies are introduced by any task in this plan.

**Spec:** `docs/superpowers/specs/2026-09-19-security-review-remediation-design.md`

## Global Constraints

- Rust 2024 edition; 100-character line limit; 4-space indent; trailing newline required.
- `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` must all pass before any commit.
- Conventional commit style: `fix:`, `feat:`, `test:`, `docs:`, `refactor:`.
- Tests live in a `#[cfg(test)]` module at the end of the file they cover; integration and e2e tests live in `tests/`.
- **No new crate dependencies.** Every task is solvable with std, tokio, and what `Cargo.toml` already lists.
- Document all new public items with `///`.
- Never work on `master`. Never merge to `master`, push, or open a PR — the run stops at the merge decision.
- `tests/*_e2e.rs` in this repo are plain `cargo test` end-to-end tests over real sockets and spawned binaries, **not** Docker. Follow that existing pattern (see `tests/listener_ip_whitelist_e2e.rs`, `tests/syslog_payload_e2e.rs`).

---

### Task 1: F1 — char-boundary panic class + silent recv-task death (CRITICAL)

**Files:**
- Modify: `src/lib.rs` (add helper + its unit tests)
- Modify: `src/syslog/listener.rs:334,427,607,747,794,847` (call sites), `:557-559` (JoinError)
- Modify: `src/zeek/listener.rs:267`, `src/suricata/listener.rs:266`
- Modify: `src/server/mod.rs:889`
- Modify: `src/protocol/mod.rs:58-62` (refactor to use the helper)
- Test: `tests/syslog_panic_resilience_e2e.rs` (create)

**Interfaces:**
- Produces: `pub(crate) fn truncate_for_log(s: &str, max_bytes: usize) -> &str` in `crate` root. Task 8 extends this call site set — do not change this signature there, layer on top of it.

- [ ] **Step 1: Write the failing unit tests for the helper**

Append to `src/lib.rs`:

```rust
/// Truncate `s` to at most `max_bytes` bytes, walking back to the nearest
/// UTF-8 character boundary so the result is always a valid `&str`.
///
/// Slicing a wire-derived string with a raw byte index (`&s[..100]`) panics
/// when the cut lands inside a multi-byte character. Every log site that
/// truncates untrusted input must use this instead.
pub(crate) fn truncate_for_log(s: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod truncate_for_log_tests {
    use super::truncate_for_log;

    #[test]
    fn returns_whole_string_when_under_budget() {
        assert_eq!(truncate_for_log("hello", 100), "hello");
    }

    #[test]
    fn truncates_ascii_at_exact_byte_budget() {
        assert_eq!(truncate_for_log("aaaaaaaaaa", 4), "aaaa");
    }

    #[test]
    fn walks_back_off_a_multibyte_boundary_instead_of_panicking() {
        // 98 ASCII bytes then a 4-byte char straddling byte 100.
        let s = format!("{}{}", "x".repeat(98), '\u{1F600}');
        let out = truncate_for_log(&s, 100);
        assert_eq!(out.len(), 98, "must cut back to the boundary at 98");
        assert!(out.chars().all(|c| c == 'x'));
    }

    #[test]
    fn handles_budget_of_zero_and_empty_input() {
        assert_eq!(truncate_for_log("hello", 0), "");
        assert_eq!(truncate_for_log("", 10), "");
    }

    #[test]
    fn handles_a_string_that_is_entirely_one_multibyte_char() {
        assert_eq!(truncate_for_log("\u{1F600}", 2), "");
    }
}
```

- [ ] **Step 2: Run the unit tests to verify they fail**

Run: `cargo test truncate_for_log_tests`
Expected: FAIL to compile — `truncate_for_log` is referenced by the test module before you add it, or if added together, the tests pass immediately. If they pass immediately, that is fine for the helper itself; the *regression* proof is Step 3's e2e test, which must fail against the unfixed call sites.

- [ ] **Step 3: Write the failing e2e regression test**

Create `tests/syslog_panic_resilience_e2e.rs`. This proves the real defect: a
single malformed UDP datagram must not permanently kill the receive task.

```rust
//! E2E regression: a syslog UDP datagram whose 100th byte falls inside a
//! multi-byte UTF-8 character must not panic the receive task.
//!
//! Before the fix, `&msg[..100.min(msg.len())]` in the parse-error `warn!`
//! arm panicked on a non-char-boundary index. The panicking task was one of
//! N SO_REUSEPORT receive tasks, and its parent discarded the JoinError, so
//! the socket was silently never drained again.

use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;

/// 98 ASCII bytes then a 4-byte emoji: byte index 100 lands mid-character.
/// The content parses as neither RFC3164 nor RFC5424, so it reaches the
/// parse-error `warn!` arm.
fn boundary_straddling_datagram() -> Vec<u8> {
    let mut v = vec![b'x'; 98];
    v.extend_from_slice("\u{1F600}".as_bytes());
    v
}

/// A well-formed RFC3164 message used as the liveness probe.
const GOOD: &[u8] = b"<34>Oct 11 22:14:15 testhost app: liveness probe";

#[tokio::test]
async fn malformed_datagram_does_not_kill_the_receive_task() {
    // Bind the listener under test on an ephemeral port, send the hostile
    // datagram, then send a good one and assert the listener still counts it.
    //
    // IMPLEMENTER: wire this to the same in-process listener harness used by
    // tests/listener_ip_whitelist_e2e.rs — spawn SyslogListener with
    // recv_batch_size = 1 and a counting handler, capture the port, then:
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");

    // 1. hostile datagram — must not panic the task
    sock.send_to(&boundary_straddling_datagram(), LISTENER_ADDR)
        .await
        .expect("send hostile");
    sleep(Duration::from_millis(200)).await;

    // 2. liveness probe — proves the task is still draining the socket
    sock.send_to(GOOD, LISTENER_ADDR).await.expect("send good");
    sleep(Duration::from_millis(200)).await;

    assert_eq!(
        handler.count(),
        1,
        "receive task died on the malformed datagram; the good message that \
         followed was never processed"
    );
}
```

**IMPLEMENTER NOTE:** `LISTENER_ADDR` and `handler` above are placeholders for
the harness wiring. Read `tests/listener_ip_whitelist_e2e.rs` first and mirror
its setup exactly — it already spawns a real `SyslogListener` with a test
handler and an ephemeral port. Do not invent a new harness shape.

- [ ] **Step 4: Run the e2e test to verify it fails**

Run: `cargo test --test syslog_panic_resilience_e2e`
Expected: FAIL — the liveness assertion sees `0`, and the captured output
contains `byte index 100 is not a char boundary`.

- [ ] **Step 5: Fix all nine call sites**

Replace the raw slice at each site with the helper. Preserve each site's
current byte budget exactly — do not unify them.

`src/syslog/listener.rs` at 334, 427, 607, 747, 794, 847 — each currently
`&msg[..100.min(msg.len())]` or `&line[..100.min(line.len())]`:

```rust
crate::truncate_for_log(&msg, 100)
```

`src/zeek/listener.rs:267` and `src/suricata/listener.rs:266` — each currently
`&line[..line.len().min(120)]`:

```rust
crate::truncate_for_log(line, 120)
```

`src/server/mod.rs:889` — currently `&content[..100.min(content.len())]`:

```rust
crate::truncate_for_log(&content, 100)
```

- [ ] **Step 6: Refactor `protocol/mod.rs` to use the helper**

`src/protocol/mod.rs:58-62` currently hand-rolls the same walk-back:

```rust
let mut check_len = body.len().min(2000);
while check_len > 0 && !body.is_char_boundary(check_len) {
    check_len -= 1;
}
let check_body = &body[..check_len];
```

Replace with:

```rust
let check_body = crate::truncate_for_log(body, 2000);
```

- [ ] **Step 7: Make recv-task death loud**

`src/syslog/listener.rs:557-559` currently discards the `JoinError`:

```rust
for task in tasks {
    let _ = task.await;
}
```

Replace with:

```rust
for task in tasks {
    if let Err(e) = task.await {
        // A receive task that panics stops draining its socket for the
        // lifetime of the process. Discarding this JoinError made that
        // failure completely silent: the parent handle stays alive, so
        // main.rs's `supervise_listener_handles` never fires either.
        metrics::counter!("syslog_recv_task_failed").increment(1);
        error!("syslog: a receive task terminated abnormally: {e}");
    }
}
```

- [ ] **Step 8: Run all tests**

Run: `cargo test`
Expected: PASS, including `syslog_panic_resilience_e2e`.

- [ ] **Step 9: Verify fmt and clippy**

Run: `cargo fmt --check && cargo clippy -- -D warnings`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add src/lib.rs src/syslog/listener.rs src/zeek/listener.rs \
        src/suricata/listener.rs src/server/mod.rs src/protocol/mod.rs \
        tests/syslog_panic_resilience_e2e.rs
git commit -m "fix: prevent char-boundary panic killing listener receive tasks

Nine log sites sliced wire-derived strings by raw byte offset, panicking
when the cut landed inside a multi-byte UTF-8 character. In syslog UDP the
panicking task was one of N SO_REUSEPORT receive tasks whose parent
discarded the JoinError, so the socket was silently never drained again.

Adds truncate_for_log (byte budget, char-boundary walk-back), generalizing
the algorithm already in protocol/mod.rs, and makes receive-task death log
an error and increment a counter."
```

---

### Task 2: F2 — admin audit-log stored XSS (HIGH)

**Files:**
- Modify: `src/admin/templates/admin.html:589-605`
- Test: `src/admin/routes.rs` (`#[cfg(test)]` module — unit + integration)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing unit + integration tests**

Add to the `#[cfg(test)]` module at the end of `src/admin/routes.rs`:

```rust
/// The audit-log viewer must not interpolate attacker-controlled fields into
/// innerHTML. An unauthenticated attacker can write an audit entry by failing
/// a Basic-Auth login with a payload as the username; it then executes in the
/// admin's browser, same-origin, with cached credentials.
#[test]
fn admin_template_does_not_interpolate_audit_fields_into_inner_html() {
    let template = include_str!("templates/admin.html");
    for field in ["${entry.username}", "${entry.action}", "${entry.details}", "${entry.client_ip}"] {
        assert!(
            !template.contains(field),
            "admin.html still interpolates {field} into a template literal; \
             audit entries must be rendered with textContent"
        );
    }
}

/// The API contract is deliberately unchanged: /audit-log serves the raw
/// stored string. Escaping is a render-time concern, so the JSON must NOT be
/// pre-escaped (that would corrupt the data for any other consumer).
#[tokio::test]
async fn audit_log_api_still_serves_the_payload_verbatim() {
    let payload = "<img src=x onerror=alert(1)>";
    let state = test_state().await;
    state
        .audit_logger
        .log("AUTH_FAILED", payload, "127.0.0.1", None)
        .await;

    let entries = state.audit_logger.get_entries(100).await;
    assert!(
        entries.iter().any(|e| e.username == payload),
        "the audit API must store and serve the raw username unescaped"
    );
}
```

**IMPLEMENTER NOTE:** `test_state()` is a placeholder for whatever helper the
existing tests in `src/admin/routes.rs` use to build an `AdminState` (look for
`create_request_with_auth` around line 749 and follow what it constructs).
Reuse it; do not build a new one.

- [ ] **Step 2: Run to verify the first test fails**

Run: `cargo test admin_template_does_not_interpolate_audit_fields_into_inner_html`
Expected: FAIL — the template still contains `${entry.username}`.

- [ ] **Step 3: Fix the render site**

In `src/admin/templates/admin.html`, replace the `loadAuditLog` rendering
block (currently `auditEntries.innerHTML = entries.map(entry => \`...\`)`) with
DOM construction:

```javascript
auditEntries.replaceChildren(...entries.map(entry => {
    const div = document.createElement('div');
    div.className = 'audit-entry';

    const ts = document.createElement('span');
    ts.className = 'timestamp';
    ts.textContent = new Date(entry.timestamp).toLocaleString();
    div.append(ts, ' ');

    const action = document.createElement('strong');
    action.textContent = entry.action;
    div.append(action, ` by ${''}`);
    div.append(document.createTextNode(entry.username));
    div.append(document.createTextNode(' from '));
    div.append(document.createTextNode(entry.client_ip));

    if (entry.details) {
        div.append(document.createElement('br'));
        const details = document.createElement('span');
        details.textContent = entry.details;
        div.append(details);
    }
    return div;
}));
```

Every attacker-controlled field goes through `textContent` or
`createTextNode`, never a template literal.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib admin::`
Expected: PASS.

- [ ] **Step 5: Verify fmt and clippy, then commit**

```bash
cargo fmt --check && cargo clippy -- -D warnings
git add src/admin/templates/admin.html src/admin/routes.rs
git commit -m "fix: render admin audit entries with textContent, not innerHTML

An unauthenticated attacker could write an audit entry by failing a
Basic-Auth login with a script payload as the username; the audit viewer
interpolated it into innerHTML, executing it in the admin's browser
same-origin with cached credentials.

The API deliberately still serves the raw string — escaping belongs at
render time, and pre-escaping would corrupt the JSON for other consumers.

E2E note: browser-level proof that the payload no longer executes is out of
reach of cargo test (no DOM, no JS tooling in the repo). Tracked as a
follow-up in the design doc."
```

---

### Task 3: F3 — incomplete S3 credential redaction (HIGH)

**Files:**
- Modify: `src/admin/config_api.rs:148-162`
- Test: `src/admin/config_api.rs` (`#[cfg(test)]` module)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)]` module in `src/admin/config_api.rs`:

```rust
/// Every S3-bearing config section must be redacted, not just the three that
/// were originally covered. This test enumerates all ten so that adding an
/// eleventh section without redacting it fails here.
#[test]
fn redacted_config_masks_every_s3_section() {
    const SENTINEL_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SENTINEL_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    let mut cfg = Config::default();
    // IMPLEMENTER: populate all ten sections with the sentinels:
    //   syslog.s3, syslog.structured_s3, ipfix.s3, zeek.s3, suricata.s3,
    //   wef.s3, hec.s3, sflow.s3, aggregate.s3, iceberg.s3
    // Each is an Option<...S3Config> whose `connection: S3ConnectionConfig`
    // is #[serde(flatten)] and carries access_key / secret_key.
    populate_all_s3_sections(&mut cfg, SENTINEL_KEY, SENTINEL_SECRET);

    let redacted = redacted_config(&cfg);
    let json = serde_json::to_string(&redacted).expect("serialize redacted config");

    assert!(
        !json.contains(SENTINEL_KEY),
        "a plaintext access_key survived redaction: {json}"
    );
    assert!(
        !json.contains(SENTINEL_SECRET),
        "a plaintext secret_key survived redaction: {json}"
    );
}
```

**IMPLEMENTER NOTE:** write `populate_all_s3_sections` as a small test helper
in the same module. It must set all ten sections — that exhaustiveness is the
entire point of the test.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test redacted_config_masks_every_s3_section`
Expected: FAIL — the sentinel appears in the JSON via the seven unredacted
sections.

- [ ] **Step 3: Add the seven missing sections**

In `redacted_config` (`src/admin/config_api.rs:148-162`), after the existing
three, add the same treatment for each remaining section:

```rust
    if let Some(ref mut s3) = out.syslog.structured_s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.suricata.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.wef.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.hec.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.sflow.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.aggregate.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.iceberg.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
```

**IMPLEMENTER NOTE:** verify each field path against `src/config/mod.rs` before
writing it — the `Option<...S3Config>` fields are at lines 255, 260, 355, 409,
523, 693, 786, 857, 1205, 1345. If a path differs from the above, the config
is authoritative, not this plan.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test redacted_config_masks_every_s3_section`
Expected: PASS.

- [ ] **Step 5: Run the full suite, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/admin/config_api.rs
git commit -m "fix: redact S3 credentials in all ten config sections

redacted_config masked only syslog.s3, ipfix.s3 and zeek.s3. The other
seven sections flatten the same S3ConnectionConfig, so plaintext access and
secret keys were served by GET/PUT/PATCH /config and by /config/export —
against that function's own documented invariant that a security export
must never contain live credentials.

The new test enumerates all ten sections so an eleventh cannot be added
without redacting it."
```

---

### Task 4: F4 — `sourcetype` path injection into S3 keys (HIGH)

**Files:**
- Modify: `src/forwarding/zeek_s3.rs:35` (hoist `sanitize_log_path`)
- Modify: `src/forwarding/buffered_writer.rs` (new shared home for it)
- Modify: `src/forwarding/generic_s3.rs:166-170`
- Modify: `src/server/mod.rs` (HEC empty-token startup warning)
- Test: `src/forwarding/generic_s3.rs` (`#[cfg(test)]`), `tests/hec_local_integration.rs`

- [ ] **Step 1: Write the failing unit test**

Add to the `#[cfg(test)]` module in `src/forwarding/generic_s3.rs`:

```rust
/// `sourcetype` arrives from an HTTP query parameter or JSON body field and
/// becomes an S3 object-key path segment. It must be sanitized exactly as the
/// zeek and suricata sinks sanitize their wire-derived partition keys.
#[test]
fn partition_key_sanitizes_traversal_and_control_characters() {
    let sink = test_sink();

    for (raw, expected) in [
        ("../zeek/conn", "___zeek_conn"),
        ("/absolute", "_absolute"),
        ("normal_type", "normal_type"),
        ("UPPER", "upper"),
        ("", "unknown"),
    ] {
        let record = GenericRecord {
            sourcetype: raw.to_string(),
            ..test_record()
        };
        assert_eq!(
            sink.partition(&record).as_deref(),
            Some(expected),
            "sourcetype {raw:?} was not sanitized"
        );
    }
}

#[test]
fn partition_key_is_length_capped() {
    let sink = test_sink();
    let record = GenericRecord {
        sourcetype: "a".repeat(500),
        ..test_record()
    };
    assert_eq!(sink.partition(&record).map(|p| p.len()), Some(64));
}
```

**IMPLEMENTER NOTE:** `test_sink()` / `test_record()` are placeholders — reuse
whatever constructors the existing tests in `generic_s3.rs` already use. The
expected strings above assume `sanitize_log_path`'s exact semantics
(lowercase, non-`[a-z0-9_]` → `_`, truncate to 64, empty → `"unknown"`);
confirm against `src/forwarding/zeek_s3.rs:35-51` and correct the expectations
if they differ.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test partition_key_sanitizes_traversal_and_control_characters`
Expected: FAIL — `partition` returns `"../zeek/conn"` verbatim.

- [ ] **Step 3: Hoist the sanitizer and use it**

Move `sanitize_log_path` from `src/forwarding/zeek_s3.rs` into
`src/forwarding/buffered_writer.rs` (the shared sink module), keeping it
`pub(crate)`. Update `zeek_s3.rs` and `suricata_s3.rs` to import it from the
new home rather than defining or re-defining it.

Then in `src/forwarding/generic_s3.rs`, replace:

```rust
    /// Partition key = `sourcetype`.  Invalid characters are preserved as-is
    /// because sourcetypes are operator-controlled (admin-set token required).
    fn partition(&self, record: &GenericRecord) -> Option<String> {
        Some(record.sourcetype.clone())
    }
```

with:

```rust
    /// Partition key = sanitized `sourcetype`.
    ///
    /// `sourcetype` is wire-supplied (an HTTP query parameter or a JSON body
    /// field) and becomes a path segment in the S3 object key, so it is
    /// sanitized exactly as the zeek and suricata sinks sanitize theirs. The
    /// previous comment claimed it was operator-controlled; that does not
    /// hold — the HEC token is optional, and even when set, any token holder
    /// controls the string.
    fn partition(&self, record: &GenericRecord) -> Option<String> {
        Some(crate::forwarding::buffered_writer::sanitize_log_path(
            &record.sourcetype,
        ))
    }
```

- [ ] **Step 4: Add the HEC empty-token startup warning**

In `src/server/mod.rs`, near where `cfg_token` is built (line ~443), warn when
HEC is enabled with no token — matching the existing startup-warning style
used for other optional auth:

```rust
if self.config.hec.enabled && self.config.hec.token.is_empty() {
    warn!(
        "[hec] enabled with an empty token — all HEC ingest endpoints accept \
         unauthenticated writes. Set hec.token to require a bearer token."
    );
}
```

Deliberately a warning, not a hard error: the empty-token dev mode is
documented existing behaviour, and Step 3 removes the dangerous consequence.

- [ ] **Step 5: Add the integration test**

In `tests/hec_local_integration.rs`, add a test that posts an event with
`sourcetype = "../escape"` through the real HEC route and asserts the written
object key contains no `..` segment. Follow the file's existing pattern for
standing up the sink and locating written files.

- [ ] **Step 6: Run everything, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/forwarding/generic_s3.rs src/forwarding/buffered_writer.rs \
        src/forwarding/zeek_s3.rs src/forwarding/suricata_s3.rs \
        src/server/mod.rs tests/hec_local_integration.rs
git commit -m "fix: sanitize wire-supplied sourcetype before it enters S3 keys

GenericSink::partition returned the HEC sourcetype verbatim as an object-key
path segment, so a posted sourcetype of '../zeek/conn' produced the key
hec/../zeek/conn/... — S3 does not collapse '..', letting a prefix-trusting
consumer file forged HEC records under another source's partition.

Hoists sanitize_log_path to the shared sink module and applies it, matching
the zeek and suricata sinks. Also warns at startup when HEC is enabled with
an empty token, which is what made the endpoint reachable unauthenticated."
```

---

### Task 5: F5 — IPFIX template cache eviction (MEDIUM)

**Files:**
- Modify: `src/ipfix/decoder.rs:107-192`
- Test: `src/ipfix/decoder.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces: `TemplateEntry { fields: Vec<FieldSpecifier>, last_seen: AtomicU64 }` — internal to `decoder.rs`. The public signatures of `cache_get` and `try_insert_template` must NOT change; all 20+ existing call sites stay untouched.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)]` module in `src/ipfix/decoder.rs`:

```rust
/// A full cache must self-heal. Before the fix there was no eviction path at
/// all, so once an attacker filled the cache with 100k spoofed templates,
/// every new legitimate exporter template was refused until process restart.
#[test]
fn full_cache_evicts_expired_entries_and_admits_a_new_template() {
    let dec = IpfixDecoder::new();

    // Fill to capacity with entries stamped as already expired.
    for i in 0u32..MAX_CACHED_TEMPLATES as u32 {
        let key = (
            IpAddr::V4(Ipv4Addr::from(i)),
            i,
            256u16,
        );
        dec.try_insert_template(key, vec![test_field()]);
    }
    assert_eq!(dec.cache_len(), MAX_CACHED_TEMPLATES);
    dec.force_expire_all_for_test();

    // A new template from a legitimate exporter must now be admitted.
    let fresh = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7, 999);
    dec.try_insert_template(fresh, vec![test_field()]);
    assert!(
        dec.cache_contains_key(&fresh),
        "a full cache of expired entries must evict to admit a new template"
    );
}

/// An exporter that is still sending data keeps its template alive
/// indefinitely, even if it never re-sends the template itself.
#[test]
fn lookup_refreshes_last_seen() {
    let dec = IpfixDecoder::new();
    let key = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1, 256);
    dec.try_insert_template(key, vec![test_field()]);

    dec.force_expire_all_for_test();
    let _ = dec.cache_get(&key); // refreshes last_seen

    // Fill the rest of the cache and trigger a sweep; the refreshed entry
    // must survive it.
    for i in 0u32..MAX_CACHED_TEMPLATES as u32 {
        dec.try_insert_template((IpAddr::V4(Ipv4Addr::from(i)), i, 512), vec![test_field()]);
    }
    assert!(
        dec.cache_contains_key(&key),
        "an entry refreshed by a successful lookup must not be evicted"
    );
}
```

**IMPLEMENTER NOTE:** add `force_expire_all_for_test` as a `#[cfg(test)]`
method that stores `0` into every entry's `last_seen`. `test_field()` is a
placeholder — reuse the existing `FieldSpecifier` constructor already used by
the tests in this file.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test full_cache_evicts_expired_entries_and_admits_a_new_template`
Expected: FAIL to compile (`force_expire_all_for_test` missing), then once the
harness compiles, FAIL on the assertion — no eviction path exists.

- [ ] **Step 3: Introduce `TemplateEntry`**

In `src/ipfix/decoder.rs`, change the cache value type:

```rust
/// How long a template survives without being re-sent or used before it
/// becomes eligible for eviction. Only consulted when the cache is full, so
/// a healthy deployment never evicts anything.
const TEMPLATE_TTL_SECS: u64 = 3600;

#[derive(Debug)]
pub(crate) struct TemplateEntry {
    fields: Vec<FieldSpecifier>,
    /// Unix seconds. Refreshed on insert and on every successful lookup via a
    /// `Relaxed` store through a shared reference, so the read-mostly
    /// invariant documented on `IpfixDecoder` is preserved — no write lock on
    /// the decode hot path.
    last_seen: AtomicU64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Default)]
pub(crate) struct TemplateCache {
    map: HashMap<TemplateKey, TemplateEntry>,
    limit_warned: bool,
}
```

- [ ] **Step 4: Refresh on lookup without changing the lock mode**

```rust
    pub(crate) fn cache_get(&self, key: &TemplateKey) -> Option<Vec<FieldSpecifier>> {
        let guard = self.cache.read().expect("template cache lock poisoned");
        let entry = guard.map.get(key)?;
        // AtomicU64::store takes &self, so this needs no write lock.
        entry.last_seen.store(now_secs(), Ordering::Relaxed);
        Some(entry.fields.clone())
    }
```

- [ ] **Step 5: Sweep on insert-into-full-cache**

In `try_insert_template`, before the capacity refusal, sweep expired entries:

```rust
        let mut guard = self.cache.write().expect("template cache lock poisoned");

        if !guard.map.contains_key(&key) && guard.map.len() >= MAX_CACHED_TEMPLATES {
            // Only sweep when full: a healthy deployment never reaches this
            // branch, so templates are never evicted in normal operation.
            let cutoff = now_secs().saturating_sub(TEMPLATE_TTL_SECS);
            let before = guard.map.len();
            guard
                .map
                .retain(|_, e| e.last_seen.load(Ordering::Relaxed) > cutoff);
            let evicted = before - guard.map.len();
            if evicted > 0 {
                metrics::counter!("ipfix_templates_evicted").increment(evicted as u64);
            }
        }

        if !guard.map.contains_key(&key) && guard.map.len() >= MAX_CACHED_TEMPLATES {
            // ... existing refusal: counter, one-shot warning, return
        }
```

Then the insert stores a fresh entry (which naturally refreshes `last_seen`
for a re-sent template):

```rust
        guard.map.insert(
            key,
            TemplateEntry {
                fields,
                last_seen: AtomicU64::new(now_secs()),
            },
        );
```

- [ ] **Step 6: Document the residual poisoning risk**

Add to the `IpfixDecoder` doc comment: the cache key includes the UDP source
address, which is spoofable, and inserts overwrite unconditionally — so one
exporter can poison another's templates. This is inherent to unauthenticated
UDP IPFIX (RFC 7011 §11 transport security is the real fix); the available
mitigation is a tight per-exporter `security.allowed_ips` rather than a broad
CIDR.

- [ ] **Step 7: Run everything, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/ipfix/decoder.rs
git commit -m "fix: give the IPFIX template cache a TTL eviction path

The cache was bounded at 100k entries but had no eviction, TTL or LRU of any
kind. Once an attacker filled it with spoofed templates it stayed full until
process restart, silently refusing every new legitimate exporter template.

Entries now carry a last_seen stamp refreshed on insert and on successful
lookup. The refresh is a Relaxed atomic store through the existing read lock,
so the decode hot path keeps its read-mostly lock behaviour. The sweep runs
only when an insert arrives at a full cache, so healthy deployments never
evict anything."
```

---

### Task 6: F6 — TCP listener idle timeout (MEDIUM)

**Files:**
- Modify: `src/syslog/listener.rs` (`handle_tcp_connection`, ~690)
- Modify: `src/zeek/listener.rs`, `src/suricata/listener.rs` (same function)
- Test: `tests/tcp_idle_timeout_integration.rs` (create)

- [ ] **Step 1: Write the failing integration test**

Create `tests/tcp_idle_timeout_integration.rs`:

```rust
//! A TCP client that connects and then sends nothing must be disconnected
//! rather than holding a connection-semaphore permit indefinitely. Without a
//! timeout, 1024 silent sockets exhaust any of the three listeners.

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn idle_tcp_connection_is_closed_by_the_listener() {
    // IMPLEMENTER: start the syslog listener on an ephemeral TCP port using
    // the same harness as tests/listener_ip_whitelist_e2e.rs.
    let mut stream = TcpStream::connect(LISTENER_ADDR).await.expect("connect");

    // Send nothing. The listener must close the connection on idle timeout.
    // read() returning Ok(0) means the peer closed.
    let mut buf = [0u8; 1];
    let closed = timeout(
        Duration::from_secs(TEST_IDLE_TIMEOUT_SECS + 5),
        stream.read(&mut buf),
    )
    .await;

    match closed {
        Ok(Ok(0)) => {} // listener closed it — correct
        Ok(other) => panic!("expected the listener to close the idle connection, got {other:?}"),
        Err(_) => panic!("listener never closed an idle connection within the timeout"),
    }
}
```

**IMPLEMENTER NOTE:** a 1-hour production timeout cannot be tested directly.
Make the constant `pub(crate)` and give the test a short override, or gate the
value behind `#[cfg(test)]`. Do NOT make the test sleep for the production
duration.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --test tcp_idle_timeout_integration`
Expected: FAIL — the connection stays open; the outer timeout fires.

- [ ] **Step 3: Add the constant and wrap the read**

In each of the three listeners, beside the existing `MAX_*_TCP_CONNECTIONS`:

```rust
/// Maximum time a TCP connection may sit without delivering a complete line
/// before it is closed. Without this, a client that connects and sends
/// nothing holds a connection-semaphore permit for the process's lifetime,
/// so 1024 silent sockets exhaust the listener.
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
```

Then wrap the existing `read_until` in `handle_tcp_connection`:

```rust
            let n = match tokio::time::timeout(
                TCP_IDLE_TIMEOUT,
                limited.read_until(b'\n', &mut buf),
            )
            .await
            {
                Err(_elapsed) => {
                    metrics::counter!("syslog_tcp_idle_timeouts").increment(1);
                    debug!("TCP connection from {} idle past timeout; closing", src);
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    error!("TCP read error from {}: {}", src, e);
                    break;
                }
            };
```

Use the matching metric name per listener (`zeek_tcp_idle_timeouts`,
`suricata_tcp_idle_timeouts`).

- [ ] **Step 4: Run everything, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/syslog/listener.rs src/zeek/listener.rs src/suricata/listener.rs \
        tests/tcp_idle_timeout_integration.rs
git commit -m "fix: close idle TCP connections on the syslog/zeek/suricata listeners

All three listeners bounded concurrency with a 1024-permit semaphore but
wrapped read_until in no timeout, so a client that connected and sent
nothing held its permit forever. 1024 silent sockets exhausted the listener
and legitimate senders were rejected until the attacker disconnected.

Note: the HTTP half of this finding (tower's concurrency and timeout layers
only wrap Service::call, so neither bounds a connection that never completes
a request head) needs a hyper-level header-read timeout and is tracked as a
follow-up in the design doc."
```

---

### Task 7: F7 — metrics and TLS bind exposure (MEDIUM)

**Files:**
- Modify: `src/config/mod.rs:171-177` (`MetricsConfig`)
- Modify: `src/server/mod.rs:386` (metrics bind), `:551` (TLS bind), `:3229-3252` (metrics router)
- Test: `src/config/mod.rs` (`#[cfg(test)]`), `tests/metrics_bind_integration.rs` (create)

- [ ] **Step 1: Write the failing tests**

In `src/config/mod.rs` tests:

```rust
#[test]
fn metrics_bind_address_defaults_to_none_and_parses_from_toml() {
    let cfg: Config = toml::from_str("").expect("empty config must parse");
    assert_eq!(cfg.metrics.bind_address, None, "default must inherit bind_address");

    let cfg: Config = toml::from_str("[metrics]\nbind_address = \"0.0.0.0\"\n")
        .expect("explicit bind_address must parse");
    assert_eq!(cfg.metrics.bind_address.as_deref(), Some("0.0.0.0"));
}
```

Create `tests/metrics_bind_integration.rs` asserting that with
`bind_address = "127.0.0.1"` and no `metrics.bind_address`, the metrics
listener is NOT reachable on a non-loopback local address.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test metrics_bind_address_defaults_to_none_and_parses_from_toml`
Expected: FAIL — no such field.

- [ ] **Step 3: Add the config field**

```rust
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    #[serde(default = "default_metrics_port")]
    pub port: u16,

    /// Interface for the metrics listener. `None` (the default) inherits the
    /// main server's `bind_address`.
    ///
    /// This listener has no authentication, so it previously binding
    /// `0.0.0.0` unconditionally exposed it on every interface regardless of
    /// `bind_address`. Set this explicitly to `"0.0.0.0"` to restore that
    /// behaviour when scraping from another host.
    #[serde(default)]
    pub bind_address: Option<String>,
}
```

- [ ] **Step 4: Use it, and stop hardcoding `0.0.0.0`**

`src/server/mod.rs:386`:

```rust
            let metrics_host = self
                .config
                .metrics
                .bind_address
                .clone()
                .unwrap_or_else(|| self.config.bind_address.ip().to_string());
            let metrics_addr: SocketAddr =
                format!("{}:{}", metrics_host, self.config.metrics.port).parse()?;
```

`src/server/mod.rs:551`:

```rust
        let tls_addr: SocketAddr =
            format!("{}:{}", self.config.bind_address.ip(), self.config.tls.port).parse()?;
```

- [ ] **Step 5: Put the whitelist middleware on the metrics router**

`start_metrics_server` must take the `IpWhitelist` and apply the same
`ip_whitelist_middleware` the main router uses, so that a `0.0.0.0` metrics
bind is still gated by `security.allowed_ips`. Update its signature and its
call site accordingly.

- [ ] **Step 6: Document the breaking change**

Add a note to `README.md` (or the config reference it points at): the metrics
and TLS listeners now follow `bind_address`; operators scraping metrics from
another host while binding the main server narrowly must set
`metrics.bind_address = "0.0.0.0"` explicitly.

- [ ] **Step 7: Run everything, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/config/mod.rs src/server/mod.rs README.md tests/metrics_bind_integration.rs
git commit -m "fix: stop binding the metrics and TLS listeners to 0.0.0.0 unconditionally

Both ignored bind_address entirely. The metrics listener additionally had no
IP whitelist and no auth, so an operator who set bind_address to a narrow
interface still exposed /metrics on every one.

Metrics now inherits bind_address, is gated by the existing allowed_ips
middleware, and gains an explicit metrics.bind_address escape hatch for
remote scraping. TLS inherits bind_address with no new knob since it already
carries the whitelist and auth layers.

BREAKING: set metrics.bind_address = \"0.0.0.0\" to restore the old
behaviour."
```

---

### Task 8: F8 — log injection via raw control characters (LOW)

**Files:**
- Modify: `src/lib.rs` (add sanitizer beside `truncate_for_log`)
- Modify: `src/syslog/listener.rs` (the UDP `warn!` sites from Task 1)
- Test: `src/lib.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `truncate_for_log(&str, usize) -> &str` from Task 1. Do not modify that function — layer on it.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod sanitize_for_log_tests {
    use super::sanitize_for_log;

    #[test]
    fn passes_clean_input_through_without_allocating() {
        assert!(matches!(
            sanitize_for_log("clean message", 100),
            std::borrow::Cow::Borrowed("clean message")
        ));
    }

    #[test]
    fn replaces_newlines_that_would_forge_a_log_line() {
        let forged = "ok\nERROR fake entry";
        assert_eq!(sanitize_for_log(forged, 100), "ok\u{fffd}ERROR fake entry");
    }

    #[test]
    fn replaces_ansi_escape_sequences() {
        assert_eq!(sanitize_for_log("a\u{1b}[31mred", 100), "a\u{fffd}[31mred");
    }

    #[test]
    fn still_truncates_on_a_char_boundary() {
        let s = format!("{}{}", "x".repeat(98), '\u{1F600}');
        assert_eq!(sanitize_for_log(&s, 100).len(), 98);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test sanitize_for_log_tests`
Expected: FAIL — `sanitize_for_log` does not exist.

- [ ] **Step 3: Implement the sanitizer**

```rust
/// Truncate for logging like [`truncate_for_log`], additionally replacing
/// control characters with U+FFFD.
///
/// A syslog UDP datagram is an opaque blob: an embedded newline makes the
/// envelope parse fail, so the raw bytes reach the parse-error log site with
/// the newline intact. Under the default plain-text log format that lets an
/// unauthenticated sender forge what looks like a separate operator log
/// entry, or inject ANSI escapes into an operator's terminal.
///
/// Returns `Cow::Borrowed` when there is nothing to replace.
pub(crate) fn sanitize_for_log(s: &str, max_bytes: usize) -> std::borrow::Cow<'_, str> {
    let truncated = truncate_for_log(s, max_bytes);
    if truncated.chars().any(|c| c.is_control()) {
        std::borrow::Cow::Owned(
            truncated
                .chars()
                .map(|c| if c.is_control() { '\u{fffd}' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(truncated)
    }
}
```

- [ ] **Step 4: Switch the syslog UDP sites to it**

At `src/syslog/listener.rs` lines 334, 427, 607, 794, 847 (the UDP datagram
sites — **not** 747, which is the TCP path where the reader has already split
on `\n`), replace `crate::truncate_for_log(&msg, 100)` with
`crate::sanitize_for_log(&msg, 100)`.

- [ ] **Step 5: Run everything, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/lib.rs src/syslog/listener.rs
git commit -m "fix: strip control characters from wire text before logging it

A syslog UDP datagram containing a raw newline fails envelope parsing and
reaches the parse-error log site with the newline intact. Under the default
Pretty format that let an unauthenticated, spoofable sender forge an
apparently separate operator log entry, or inject ANSI escapes into a
terminal.

Applies to the UDP sites only — the TCP path already splits on newline
before this point."
```

---

### Task 9: F9 — admin rate-limit map growth and silent allowlist degradation (LOW)

**Files:**
- Modify: `src/admin/middleware.rs:51-70`
- Modify: `src/admin/state.rs:491-500`
- Test: `src/admin/middleware.rs`, `src/admin/state.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing tests**

```rust
// in src/admin/middleware.rs tests
#[tokio::test]
async fn rate_limit_map_evicts_entries_outside_the_window() {
    let state = test_admin_state().await;
    {
        let mut counts = state.request_counts.write().await;
        let stale = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        for i in 0..1000u32 {
            counts.insert(format!("10.0.{}.{}", i / 256, i % 256), (stale, 1));
        }
    }
    // One fresh request must sweep the stale entries.
    let _ = security_middleware_for_test(&state, "127.0.0.1").await;
    let counts = state.request_counts.read().await;
    assert!(
        counts.len() < 100,
        "stale rate-limit entries were never evicted: {} remain",
        counts.len()
    );
}
```

```rust
// in src/admin/state.rs tests
#[test]
fn all_allowlist_entries_failing_to_parse_is_distinguished_from_unset() {
    let parsed = parse_admin_allowed_ips(Some("not-an-ip,also-bad"));
    assert!(
        parsed.is_err(),
        "an allowlist where every entry is malformed must not silently \
         degrade to the allow-all empty list"
    );
    assert!(parse_admin_allowed_ips(None).expect("unset is valid").is_empty());
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test rate_limit_map_evicts_entries_outside_the_window`
Expected: FAIL — entries are never removed.

- [ ] **Step 3: Sweep the rate-limit map**

In `src/admin/middleware.rs`, inside the existing `request_counts.write()`
block, drop entries whose window has fully elapsed before inserting:

```rust
            let mut counts = state.request_counts.write().await;
            // Entries are reset in place when their window expires but were
            // never removed, so a client rotating source IPs grew this map
            // without bound.
            counts.retain(|_, (started, _)| now.duration_since(*started) <= rate_limit_window);
            let entry = counts.entry(client_ip.clone()).or_insert((now, 0));
```

- [ ] **Step 4: Distinguish a broken allowlist from an unset one**

In `src/admin/state.rs`, replace the silent `filter_map(...).ok()` with a
parse that counts failures:

```rust
    let allowed_ips: Vec<IpNet> = match allowed_ips_str {
        Some(s) => {
            let provided: Vec<&str> = s.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
            let parsed: Vec<IpNet> = provided.iter().filter_map(|ip| ip.parse().ok()).collect();
            if !provided.is_empty() && parsed.is_empty() {
                anyhow::bail!(
                    "LOGTHING_ADMIN_ALLOWED_IPS was set but none of its {} entries parsed as an \
                     IP or CIDR; refusing to start with what would silently be an allow-all \
                     admin interface",
                    provided.len()
                );
            }
            if parsed.len() < provided.len() {
                tracing::warn!(
                    "LOGTHING_ADMIN_ALLOWED_IPS: {} of {} entries failed to parse and were \
                     ignored",
                    provided.len() - parsed.len(),
                    provided.len()
                );
            }
            parsed
        }
        None => vec![],
    };
```

**IMPLEMENTER NOTE:** the parsing above currently lives inline inside a larger
function in `state.rs`. Extract it into a testable
`fn parse_admin_allowed_ips(raw: Option<&str>) -> anyhow::Result<Vec<IpNet>>`
first — Step 1's test calls it by that name — then have the original call site
use it.

**IMPLEMENTER NOTE:** this makes a fully-malformed allowlist a startup error.
That is deliberate — failing closed is correct when the alternative is an
unintended allow-all admin interface. A *partially* malformed list still
starts, with a loud warning.

- [ ] **Step 5: Run everything, verify fmt/clippy, commit**

```bash
cargo test && cargo fmt --check && cargo clippy -- -D warnings
git add src/admin/middleware.rs src/admin/state.rs
git commit -m "fix: bound the admin rate-limit map and fail closed on a broken allowlist

request_counts reset entries in place when their window expired but never
removed them, so a client rotating source IPs grew the map without bound.

A LOGTHING_ADMIN_ALLOWED_IPS value whose entries all failed to parse silently
produced an empty list, which the deliberate empty-means-allow-all semantics
then treated as no restriction — warning identically to the never-configured
case. That is now a startup error; a partially malformed list still starts
with a warning naming the count."
```

---

## Completion

After Task 9, the integration branch holds ten commits (the design doc plus
nine fixes). **Stop there.** Report status and hand the merge-to-master
decision to the user — do not merge, push, or open a PR.

Carry these forward as known follow-ups, none of them built here:

- Browser-level e2e for the admin UI (Task 2's stated e2e gap).
- HTTP accept-level / header-read timeout (Task 6's HTTP half).
- CSP header on the admin server.
- Cross-exporter IPFIX template poisoning — inherent to unauthenticated UDP;
  the mitigation is a tight per-exporter `allowed_ips`.
