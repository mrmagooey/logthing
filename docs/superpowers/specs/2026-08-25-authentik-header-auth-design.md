# Trusted-Header Auth for Authentik Forward-Proxy — Design

**Date:** 2026-08-25
**Status:** Approved (autonomous design via `auto-develop`; coherence-reviewed, 3 rounds — round 1 and round 2 each found a real gap, closed before round 3 approved)

## Goal

Let an Authentik reverse-proxy (forward-auth pattern) sit in front of logthing's
admin web interface (`src/admin/`) and authenticate operators via SSO, instead
of (or in addition to) the interface's existing HTTP Basic Auth. Authentik
injects trusted headers into the proxied request after a successful login;
logthing must verify those headers are genuinely proxy-supplied (not
client-forged) and gate access by group membership before treating the
request as authenticated.

## Fixed constraints

Decided by the user and prior research, not open for revision during
implementation:

- **C1 — Scope is `src/admin/` only.** The HEC ingest endpoints and the
  Kerberos-gated WEF data-plane server are machine-to-machine traffic with no
  browser auth flow; Authentik forward-auth does not apply to them.
- **C2 — Groups gate access (non-negotiable).** `X-authentik-groups` must be
  checked against a configured allowlist before granting admin access. "Any
  successfully-proxied user is admin" is explicitly rejected.
- **C3 — Basic Auth remains a working fallback.** `WEF_ADMIN_USER`/
  `WEF_ADMIN_PASS`/`WEF_ADMIN_PASS_HASH` are not removed or weakened.
- **C4 — Trust boundary is loopback bind + shared secret, not headers alone.**
  Authentik does not itself guarantee a reverse proxy strips client-forged
  copies of its headers — that's the proxy config's job, and is not something
  logthing can verify. A shared secret header, verified constant-time, closes
  the gap for anyone who reaches logthing directly (including a co-resident
  process on a loopback-bound host, which a loopback bind alone does not
  stop).
- **C5 — JWT verification of `X-authentik-jwt` is out of scope for this
  pass.** Flagged as a stronger future mitigation; needs JWKS fetch/cache
  infrastructure this codebase doesn't have yet.
- **C6 — Unit + integration + end-to-end test coverage required** for all new
  and modified behavior (repo-wide CLAUDE.md policy).

## Why headers alone aren't enough

Authentik's outpost computes `X-authentik-username`, `X-authentik-groups`,
etc. and returns them from an auth-subrequest; the reverse proxy (nginx
`auth_request_set`, Traefik `authResponseHeaders`, Caddy `copy_headers`) is
responsible for overwriting any client-supplied header of the same name with
that computed value. If the proxy config is wrong, or a request reaches
logthing by any path that bypasses the proxy, forged headers pass straight
through. logthing therefore requires, in addition to the headers themselves:
a loopback/internal-only bind (`WEF_ADMIN_BIND`, already supported) **and** a
shared secret in a separate header that only the trusted proxy and logthing
know, checked with the existing constant-time-compare primitive
(`ct_str_eq`, `src/admin/auth.rs`).

## Architecture

```
Request → trusted_header_middleware (NEW, middleware.rs)
            ├─ trust_proxy_headers off, or secret missing/mismatched,
            │  or groups don't match allowlist
            │      → no Extension inserted, request proceeds unauthenticated
            └─ secret matches AND ≥1 group matches allowlist
                   → Extension(TrustedIdentity { username }) inserted
          → security_middleware (unchanged: IP allowlist, rate limit)
          → csrf_middleware (unchanged)
          → handler (routes.rs × 7, config_api.rs × 5 — all 12)
                extracts trusted: Option<Extension<TrustedIdentity>>
                → ensure_authorized(state, trusted, auth, client_ip)
                     trusted.is_some() → Ok(username), Basic Auth not checked
                     else              → today's unmodified Basic Auth check
```

`verify_trusted_header()` (the header/secret/group logic) lives in `auth.rs`,
alongside the existing `ct_str_eq`/Basic-Auth/CSRF-token logic it reuses.
`trusted_header_middleware` (the Axum wiring) lives in `middleware.rs`,
alongside `security_middleware`/`csrf_middleware` — the same split already
used for CSRF (`verify_csrf_token` in auth.rs, `csrf_middleware` in
middleware.rs).

Every handler continues to call `ensure_authorized()` itself, individually —
this is deliberate: the codebase's existing pattern is that CSRF/rate-limit/
IP-allowlist are middleware-enforced, but identity checks are independently
made in every handler as defense-in-depth. This design preserves that
invariant rather than replacing it with a single middleware gate.

## New types (`src/admin/state.rs`)

```rust
pub struct TrustedHeaderConfig {
    pub username_header: http::HeaderName,   // parsed once at startup
    pub groups_header: http::HeaderName,
    pub secret_header: http::HeaderName,
    pub secret: String,                       // required non-empty
    pub allowed_groups: Vec<String>,           // required non-empty
}
```

`AdminServerConfig` gains one new field: `trusted_header: Option<TrustedHeaderConfig>`
(`None` = feature disabled), mirroring the existing `tls_config: Option<AdminTlsConfig>`
field on the same struct.

```rust
#[derive(Clone)]
pub struct TrustedIdentity { pub username: String }
```

Used as an Axum `Extension`.

## Config surface (env vars)

| Var | Default | Notes |
|---|---|---|
| `WEF_ADMIN_TRUST_PROXY_HEADERS` | `false` | master on/off switch |
| `WEF_ADMIN_TRUSTED_HEADER` | `X-authentik-username` | |
| `WEF_ADMIN_TRUSTED_GROUPS_HEADER` | `X-authentik-groups` | split on `,` or `\|` — see caveat below |
| `WEF_ADMIN_TRUSTED_SECRET_HEADER` | `X-Admin-Proxy-Secret` | header the shared secret arrives in |
| `WEF_ADMIN_TRUSTED_HEADER_SECRET` | — | **required**, non-empty, when trust-mode is on |
| `WEF_ADMIN_TRUSTED_GROUPS` | — | comma-separated allowlist; **required**, non-empty, when trust-mode is on |

**Fail-closed startup validation** (`build_admin_config_from_parts`,
unconditional — any bind address, not just non-loopback): if
`WEF_ADMIN_TRUST_PROXY_HEADERS=true` and either the secret or the allowed-groups
list is empty, `load_admin_config()` returns `Err` and the admin server does not
start. This is stricter than "only guard non-loopback binds" (the literal
suggestion in the originating research) because a co-resident process on a
loopback-bound host can still forge headers directly — the loopback bind stops
remote attackers, not local ones, so the secret/group requirement must not be
conditional on bind address.

The 6 new raw env-string inputs are bundled into one new params struct passed
to `build_admin_config_from_parts` (rather than 6 more flat positional
params) — that function already takes 11 positional args behind
`#[allow(clippy::too_many_arguments)]`; 17 raw `Option<&str>`/`bool` params
would be a real mis-ordering hazard at the call site.

## Runtime verification logic (`auth.rs`)

```rust
pub fn verify_trusted_header(state: &AdminState, headers: &HeaderMap) -> Option<TrustedIdentity> {
    let cfg = state.server_config.trusted_header.as_ref()?;
    let secret = headers.get(&cfg.secret_header)?.to_str().ok()?;
    if !ct_str_eq(secret, &cfg.secret) { return None; }          // constant-time: secret only

    let username = headers.get(&cfg.username_header)?.to_str().ok()?.trim();
    if username.is_empty() { return None; }

    let groups_raw = headers.get(&cfg.groups_header)?.to_str().ok()?;
    let groups = groups_raw.split(|c| c == ',' || c == '|').map(str::trim);
    let matched = groups.filter(|g| !g.is_empty())
        .any(|g| cfg.allowed_groups.iter().any(|a| a == g));      // plain equality: not secret
    if !matched { return None; }

    Some(TrustedIdentity { username: username.to_string() })
}
```

Notes:
- Constant-time comparison (`ct_str_eq`) is used **only** for the shared
  secret. Group-name and username comparisons use plain equality — they
  aren't secret values, and applying `ct_str_eq` there would be
  cargo-culting the mitigation somewhere it adds nothing.
- **Header-name caveat, flagged low-confidence**: Authentik's actual
  delimiter for `X-authentik-groups` was not confirmed with certainty against
  live docs during design. Splitting on both `,` and `\|` is a best-effort
  default that costs nothing; `docs/admin-security.md` must carry an explicit
  operator-facing warning to verify this against their deployed Authentik
  version before relying on it in production.
- Header values that fail UTF-8 decoding are treated identically to a
  missing header (`None`) — same fail-safe posture, no separate error path.
- Header *names* (not values) are parsed once into `http::HeaderName` at
  config-build time (`build_admin_config_from_parts`), not per-request — a
  malformed env var fails loudly at startup instead of silently failing on
  every request.

## Middleware wiring (`middleware.rs`, `routes.rs`)

New `trusted_header_middleware(State(state), request, next)`: calls
`verify_trusted_header`; if `Some`, inserts `Extension(identity)` into the
request before calling `next.run(request)`; if `None`, calls
`next.run(request)` unchanged (does **not** short-circuit/reject — a request
with no or invalid trusted headers must still be able to fall through to
Basic Auth). Layered into the existing stack in `routes.rs` alongside
`security_middleware`/`csrf_middleware`.

## Handler and `ensure_authorized` changes — exhaustive call-site inventory

This is the part two of three coherence-review rounds found incomplete.
Verified by direct `grep` (not enumerated from memory) immediately before
this spec was finalized:

**`ensure_authorized()` signature change** — gains a new second parameter:
`ensure_authorized(state, trusted: Option<TrustedIdentity>, auth, client_ip)`.
Checks `trusted` first; falls through to the existing, unmodified Basic Auth
logic otherwise.

**All 15 references to `ensure_authorized(` in `src/admin/` must be updated**
(verified via `grep -rn "ensure_authorized(" src/admin/`):

- 12 handler call sites gain a new `trusted: Option<Extension<TrustedIdentity>>`
  parameter on the handler itself, unwrapped and passed through:
  - `routes.rs`: `get_config` (:165), `admin_page` (:184), `update_config` (:210),
    `patch_config` (:273), `get_audit_log` (:370), `get_stats` (:389),
    `get_stats_json` (:444)
  - `config_api.rs`: `validate_config` (:224), `diff_config` (:307),
    `export_config` (:392), `import_config` (:443), `reload_config` (:517)
- 3 direct calls in `mod.rs`'s `ensure_authorized_checks_credentials` test
  (lines 77, 82, 87) — bypass the router/extractors entirely, calling the
  function directly. Updated to pass `None` as the new argument, preserving
  their existing assertions unchanged. A **new 4th case** is added to this
  same test: calls `ensure_authorized(&state, Some(TrustedIdentity {
  username: "proxied-user".into() }), None, client_ip)` and asserts
  `Ok("proxied-user")` — proving the trusted-identity branch short-circuits
  Basic Auth entirely, as a genuine unit test in the same style as the
  existing direct-call tests (not solely covered by router-level tests).

**All 9 `AdminServerConfig { .. }` struct literals must gain the new
`trusted_header: Option<TrustedHeaderConfig>` field** (verified via
`grep -rn "AdminServerConfig {" src/admin/`; the struct has no
`#[derive(Default)]` and no site uses `..Default::default()`, so every
literal spells out all fields and breaks compilation until updated):

- Production: `state.rs:410` (`build_admin_config_from_parts`)
- Test literals (all set `trusted_header: None` unless the test specifically
  targets this feature, in which case it constructs its own
  `Some(TrustedHeaderConfig { .. })` inline): `mod.rs:26`, `mod.rs:429`,
  `mod.rs:639`, `routes.rs:468`, `routes.rs:808`, `routes.rs:1002`,
  `middleware.rs:126`, `config_api.rs:620`

`AdminState { .. }` construction sites do **not** need a separate field —
confirmed every `AdminState` literal builds `server_config` from a preceding
`AdminServerConfig` variable (or `.clone()`/a parameter chain rooted in one),
never re-spelling `AdminServerConfig`'s fields inline. Fixing the 9 sites
above is complete.

Confirmed via repo-wide grep: no `AdminServerConfig`, `AdminState`,
`ensure_authorized`, or `TypedHeader<Authorization<Basic>>` reference exists
outside `src/admin/`. `main.rs` and `tests/admin_flush_interval_e2e.rs` only
go through the stable public `spawn_admin_server(...)` entry point and are
unaffected (new env vars default off).

**Fourth inventory, found while writing the implementation plan (same
verification discipline applied prospectively this time, not after a review
round caught it)**: `build_admin_config_from_parts` itself — the function
gaining the new `trusted_header_env: TrustedHeaderEnvArgs` parameter — has
**18** references, verified via `grep -rn "build_admin_config_from_parts("
src/admin/`: the definition (`state.rs:322`), the one production call inside
`load_admin_config` (`state.rs:441`), and **16 test call sites**, all
confined to `state.rs`'s own test module (lines 568, 594, 614, 637, 663, 684,
704, 714, 743, 763, 793, 816, 838, 866, 877, 888, 898). Adding a required
positional parameter breaks compilation at all 16 until each passes
`TrustedHeaderEnvArgs::default()` (trust-mode off) as the new last argument —
except the handful of tests written specifically to exercise the new
validation branches, which construct a real `TrustedHeaderEnvArgs` inline.
Unlike the `AdminServerConfig`/`ensure_authorized` sprawl across 4-5 files,
this one is entirely contained within `state.rs`.

## Documentation

New numbered section in `docs/admin-security.md` (matches the file's existing
per-feature structure: short prose + env var code block), covering:
- The 6 new env vars and their defaults.
- That header names must be proxy-injected, never client-settable — the
  trust boundary depends entirely on correct reverse-proxy configuration.
- The explicit, named caveat: verify the `X-authentik-groups` delimiter
  against your deployed Authentik version; this implementation accepts both
  `,` and `\|` as a best-effort default, unconfirmed against live Authentik
  docs at design time.

## Explicitly out of scope (YAGNI cuts made during design)

- **JWT verification** of `X-authentik-jwt` (C5).
- **Audit-log auth-method tagging** — `ensure_authorized` keeps returning
  just the username string; no `auth_method` field added to `AuditEntry`.
  Not requested; would touch all 12 call sites' `.log()` invocations for an
  unrequested feature.
- **Audit logging of failed/rejected trusted-header attempts** (bad/missing
  secret) — `verify_trusted_header` stays a pure function
  (`headers → Option<TrustedIdentity>`); giving it audit-logger/client-IP
  access is a real interface change for a nice-to-have. Good follow-up, not
  blocking.
- **Group-header delimiter as a config knob** — hardcoded to accept both `,`
  and `\|` rather than adding a 7th env var to configure it.

## Test plan (three levels, per CLAUDE.md)

**Unit** (`auth.rs`): `verify_trusted_header` — secret match/mismatch/missing;
username header missing/empty; group match/no-match; both delimiters;
multiple configured groups with only one incoming group matching; non-UTF8
header value treated as absent. Plus the new 4th case in
`ensure_authorized_checks_credentials` (above).
**Unit** (`state.rs`): `build_admin_config_from_parts`/`load_admin_config` —
trust-mode on + missing secret → `Err`; trust-mode on + empty groups → `Err`;
trust-mode on + valid inputs → `Ok` with correct defaulted/overridden header
names; invalid header-name string → `Err` at build time.

**Integration** (`tower::oneshot` router tests): `middleware.rs` —
`trusted_header_middleware` sets the extension on secret+group match, does
not set it on mismatch, does not block/short-circuit either way (request
still reaches the next layer). `routes.rs`/`config_api.rs` — at least one
handler from **each** module (e.g. `get_config` from `routes.rs`,
`export_config` from `config_api.rs`) exercised end-to-end via the full
router with trusted headers alone (no `Authorization` header) → 200; Basic
Auth still works when trusted headers are absent (fallback preserved); 401
when neither is present; audit log records the header-derived username.

**End-to-end**: new real-socket test mirroring the existing
`e2e_shared_source_stats_reach_stats_json_over_real_socket` pattern in
`routes.rs` — real admin server on a real loopback socket with trust-mode
configured, real `reqwest` HTTP call carrying the three trusted headers and
no `Authorization` header → 200 + correct body; second case with a
wrong/missing secret → 401.

## Implementation checklist (process commitment from round-3 review)

Before this is reported complete, re-run and diff against the exhaustive
inventories above:
```
grep -rn "AdminServerConfig {" src/admin/
grep -rn "ensure_authorized(" src/admin/
grep -rn "build_admin_config_from_parts(" src/admin/
```
plus a clean `cargo build` and `cargo test` for the whole `admin` module —
verified mechanically, not re-enumerated from memory. This closes the actual
failure pattern found across coherence-review rounds 1–2 (confident-but-incomplete
file inventories), not just its two specific instances.
