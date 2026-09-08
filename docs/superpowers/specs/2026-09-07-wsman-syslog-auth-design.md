# Design: real Kerberos for /wsman, opt-in token for /syslog, OTLP token warning

Date: 2026-09-07
Status: approved (auto-develop; 2 coherence-review rounds; residual risk accepted by the user)

## Problem

Two auth gaps deferred from the `feat/listener-ip-whitelist` change:

1. `/wsman` and `/syslog` HTTP routes have no credential check. Their only gate
   is the IP allowlist plus optional mTLS. `/wsman`'s intended control is
   Kerberos (`README.md:167,194`, and a real-AD test range), but
   `kerberos_auth_middleware` (`src/server/mod.rs:613`) is an unimplemented
   stub that fail-closes with 501 on every request.
2. An empty `otlp.bearer_token` disables OTLP auth silently, unlike its HEC
   twin which now warns at startup.

User decisions when asked: implement **real GSSAPI/SPNEGO** for `/wsman`; add an
**opt-in token** for `/syslog`.

## Unit 1 — OTLP empty-bearer_token warning

Add a second entry to `insecure_config_warnings` (`src/config/mod.rs`) when
`otlp.enabled` and `bearer_token` is `None`/empty, wording mirroring the HEC
entry. **Also update the stale `ponytail:` comment at `src/config/mod.rs:780`**,
which currently says the OTLP footgun is "out of scope here" — this unit puts it
in scope, so that comment becomes wrong the moment this lands.

## Unit 2 — /syslog HTTP opt-in token

| # | Decision | Rationale |
|---|---|---|
| 2.1 | New `syslog.http_token: String`, `#[serde(default)]`, empty = disabled | Empty-means-off keeps every existing deployment byte-identical |
| 2.2 | `Authorization: Bearer <token>` | Generic HTTP receiver, no Splunk client to satisfy; matches the OTLP precedent already in tree |
| 2.3 | Constant-time compare, length-gated, copying `check_hec_token` (`src/ingest/mod.rs:65`) | Same idiom as the two existing token checks |
| 2.4 | No runtime warning when empty; README callout instead | The `/syslog` route is mounted unconditionally, so a warning would fire on every default deployment. Asymmetric with HEC/OTLP by necessity, not oversight |
| 2.5 | Updating the ~5 existing unit tests that call `handle_syslog_http` directly is in scope | Its signature must gain `HeaderMap` + config access. Mandatory work, not optional |

## Unit 3 — /wsman real Kerberos SPNEGO

| # | Decision | Rationale |
|---|---|---|
| 3.1 | Implement against **`libgssapi` (MIT)** directly, not `axum-negotiate` | logthing is MIT (`Cargo.toml:5`) and ships **static musl** binaries (`binaries.yml`); statically linking LGPL-3.0-or-later makes the relinking right impossible to honour. `axum-negotiate` is a 241-LOC pass-through wrapper over the same GSS calls, so this is not reimplementing protocol or crypto logic |
| 3.2 | **Remove** the `axum-negotiate` dependency; point `kerberos-auth` at `libgssapi` | Declared at `Cargo.toml:29` but referenced nowhere in `src/` or `tests/`. Dropping it removes the licence exposure outright |
| 3.3 | RFC 4559 **two-pass only**; multi-leg/NTLM unsupported | Genuine Kerberos-over-HTTP is inherently two-legged — the client already holds a ticket from the KDC. Same limitation `axum-negotiate` documents. **Document that NTLM fallback on a misconfigured client will not work** |
| 3.4 | **CORRECTED after implementation attempt.** Acquire a `Cred` once at startup *purely to validate* the SPN/keytab (then drop it) so a bad config fails fast; acquire a **fresh `Cred` per request** inside `spawn_blocking`, backing exactly one `ServerCtx`. | The original decision — share one long-lived `Cred` — is **unimplementable** against this crate's safe API, and the obvious workaround is an auth bypass. Verified in `libgssapi-0.7.2`: `Cred` has no `Clone` and its `Drop` calls `gss_release_cred` (`credential.rs:81,83`); `ServerCtx::new(cred: Cred)` takes it **by value** (`context.rs:506`), so the first request to complete releases the shared credential and every later request runs against a freed handle. Reusing one completed `ServerCtx` instead is worse: `step()` short-circuits on `ServerCtxState::Complete => return Ok(None)` **without inspecting the token** (`context.rs:523`), silently authenticating any subsequent caller. Per-request acquisition reads the local keytab and does **not** contact a KDC; `/wsman` is a batched, low-QPS endpoint, so this is the right trade. Rejected alternatives: forging duplicate handles via `pub(crate)` internals (double-release — there is no `gss_duplicate_cred`), forking the MIT crate, and switching to `cross-krb5` (not cached locally; crates.io returned 403 from this sandbox) |
| 3.5 | Middleware stays **fail-closed**: real validation replaces "501 always"; 401 + `WWW-Authenticate: Negotiate` on any failure | It is already fail-closed; this preserves that property while making success possible |
| 3.6 | **No `Upn` extractor.** Log the authenticated principal at `debug!` from the middleware, and reword `README.md:170` | The README currently promises `axum_negotiate::Upn`. A first-party replacement would be an abstraction with *zero* consumers. The middleware already holds the value |
| 3.7 | Rewrite `test_wsman_with_auth` (`kerberos-test/entrypoint.py:187`) so a garbage token expects **401** | It sends `Negotiate dGVzdA==` (base64 `"test"`) and today asserts NOT-401, which only passes because the stub returns 501. Real validation inverts it |
| 3.8 | **Generate a keytab offline** (`ktutil`, no live KDC) in `Dockerfile.kerberos`, and fix the path mismatch | Decisive, and easy to miss: the fixture sets `keytab = "/etc/wef-server/keytabs/wef.keytab"`, the Dockerfile creates `/etc/logthing/keytabs`, and no keytab is ever created or mounted. Harmless today because nothing calls `gss_acquire_cred` — but under 3.4 startup fails, the health check never passes, and **all six** existing sim tests break, not just 3.7's. `gss_acquire_cred` for a *server* credential reads key material from the keytab and does not contact a KDC, so an offline-generated keytab suffices |

### The SPNEGO flow (RFC 4559)

1. No `Authorization` header → 401 + bare `WWW-Authenticate: Negotiate`.
2. `Authorization: Negotiate <base64>` → decode, `ServerCtx::step(token)`:
   - `Ok(None)` → authenticated; run the request.
   - `Ok(Some(tok))` with the context complete → authenticated; attach
     `WWW-Authenticate: Negotiate <base64 tok>` to the response.
   - continue-needed → 401 (multi-leg unsupported, see 3.3).
   - `Err` → 401.
3. Malformed base64 or a non-Negotiate scheme → 401.

`apply_kerberos_layer` switches from `middleware::from_fn` to
`from_fn_with_state` carrying the acquired `Cred`, and drops the "NOT
implemented / rejects all requests" SECURITY error log.

## Testing, and its honest limits

- Units 1 and 2: unit + integration + e2e in the normal Rust suite.
- Unit 3 under `cargo test`: only what needs no KDC — missing header → 401 +
  challenge; malformed base64 → 401; wrong scheme → 401; `Cred` acquisition
  failure surfacing at startup.
- Unit 3 success path (a valid ticket being accepted): **not covered anywhere,
  by explicit user decision.** A full KDC harness was considered and cut as
  disproportionate — it would gate nothing, since the sim environment is a
  manual `run.sh` that no CI workflow invokes.

  **Accepted risk, stated plainly:** after this change, no automated check —
  gating or manual — proves that a *valid* Kerberos ticket is accepted. The
  negative-path tests prove bad input is rejected; they cannot catch a
  regression that breaks or bypasses real validation. The user was asked
  directly and accepted this in favour of the cheaper offline-keytab option.

## Delivery

Branch `feat/wsman-syslog-auth` off `c937bb6`, one commit per unit, delivered in
order 1 → 2 → 3. Two-stage review (spec compliance, then code quality) before
hand-off. Not merged — that is the user's call.
