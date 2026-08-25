# Trusted-Header Auth for Authentik Forward-Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an Authentik reverse-proxy authenticate admin operators via
trusted headers (verified by shared secret + group allowlist), while keeping
Basic Auth as a working fallback, in logthing's `src/admin/` interface.

**Architecture:** A new `trusted_header_middleware` (Axum layer) validates a
shared secret and group membership on every request and, if valid, stashes a
`TrustedIdentity` in request extensions. `ensure_authorized()` (called
independently by every one of the 12 existing admin handlers, unchanged
invariant) checks for that identity first, falling back to today's unmodified
Basic Auth check. All new config follows the existing `WEF_ADMIN_*` /
`AdminServerConfig` / `build_admin_config_from_parts` pattern.

**Tech Stack:** Rust, Axum, `subtle` (constant-time compare, already a dep),
`http::HeaderName`/`HeaderMap` (via axum's re-export).

## Global Constraints

- **C1** — Scope is `src/admin/` only (no changes to HEC ingest or the WEF
  data-plane server).
- **C2** — Groups gate access: `X-authentik-groups` must intersect a
  configured allowlist before granting access. Never "any proxied user is
  admin."
- **C3** — Basic Auth (`WEF_ADMIN_USER`/`WEF_ADMIN_PASS`/`WEF_ADMIN_PASS_HASH`)
  remains a fully working fallback, unmodified.
- **C4** — Trust boundary is loopback bind + constant-time-verified shared
  secret, not headers alone. Validation is **unconditional** (any bind
  address) — enabling trust-mode without a secret or without allowed groups
  is a hard startup error via `anyhow::Result::Err`, not just a warning.
- **C5** — JWT verification of `X-authentik-jwt` is explicitly out of scope.
- **C6** — Every new/modified behavior needs unit + integration + end-to-end
  test coverage (repo-wide CLAUDE.md policy).
- **Full spec**: `docs/superpowers/specs/2026-08-25-authentik-header-auth-design.md`
  — read it before starting; it contains the exhaustive, grep-verified
  call-site inventories this plan's tasks are built from.

---

## Task 1: Add `TrustedHeaderConfig`/`TrustedIdentity` types, wire `trusted_header: None` into all 9 `AdminServerConfig` construction sites

This task only adds the new field with a disabled (`None`) default everywhere
— zero behavior change. Its purpose is to unblock compilation for every later
task without those tasks needing to touch 9 files each. Reviewer note: this
task is intentionally "boring" — the whole point is that after it lands, the
crate compiles and every existing test still passes unchanged.

**Files:**
- Modify: `src/admin/state.rs` (add types + field)
- Modify: `src/admin/mod.rs:26`, `src/admin/mod.rs:429`, `src/admin/mod.rs:639`
- Modify: `src/admin/routes.rs:468`, `src/admin/routes.rs:808`, `src/admin/routes.rs:1002`
- Modify: `src/admin/middleware.rs:126`
- Modify: `src/admin/config_api.rs:620`

**Interfaces:**
- Produces: `pub struct TrustedHeaderConfig { username_header: HeaderName, groups_header: HeaderName, secret_header: HeaderName, secret: String, allowed_groups: Vec<String> }` and `pub struct TrustedIdentity { pub username: String }` (both `#[derive(Clone)]`, in `src/admin/state.rs`). `AdminServerConfig.trusted_header: Option<TrustedHeaderConfig>`.

- [ ] **Step 1: Add the `HeaderName` import and the two new types to `state.rs`**

In `src/admin/state.rs`, change the top-of-file import block:

```rust
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use chrono::Utc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::RwLock};
use tracing::info;

use crate::config::Config;
```

to:

```rust
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use axum::http::HeaderName;
use chrono::Utc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::RwLock};
use tracing::info;

use crate::config::Config;
```

Then, immediately after the `AdminTlsConfig` struct definition (right before
`/// Hashed password using Argon2`), insert:

```rust
/// Configuration for trusting reverse-proxy-injected identity headers (e.g.
/// from an Authentik forward-auth outpost). Headers are only trusted when a
/// shared secret (verified constant-time) accompanies them and the resolved
/// group list intersects `allowed_groups` — presence of the identity headers
/// alone is never sufficient, since a reverse-proxy config error (or a
/// request that bypasses the proxy entirely) can forge them.
#[derive(Clone)]
pub struct TrustedHeaderConfig {
    pub username_header: HeaderName,
    pub groups_header: HeaderName,
    pub secret_header: HeaderName,
    pub secret: String,
    pub allowed_groups: Vec<String>,
}

/// A caller identity resolved from trusted reverse-proxy headers, inserted
/// into request extensions by `trusted_header_middleware` when verification
/// succeeds.
#[derive(Clone)]
pub struct TrustedIdentity {
    pub username: String,
}
```

- [ ] **Step 2: Add the field to `AdminServerConfig`**

Change:

```rust
/// Admin server configuration
#[derive(Clone)]
pub struct AdminServerConfig {
    pub bind_address: SocketAddr,
    pub username: String,
    pub password_hash: PasswordHash,
    pub allowed_ips: Vec<IpNet>,
    pub tls_config: Option<AdminTlsConfig>,
    pub enable_csrf: bool,
    pub enable_rate_limiting: bool,
}
```

to:

```rust
/// Admin server configuration
#[derive(Clone)]
pub struct AdminServerConfig {
    pub bind_address: SocketAddr,
    pub username: String,
    pub password_hash: PasswordHash,
    pub allowed_ips: Vec<IpNet>,
    pub tls_config: Option<AdminTlsConfig>,
    pub enable_csrf: bool,
    pub enable_rate_limiting: bool,
    /// `None` disables trusted reverse-proxy-header auth entirely (default).
    pub trusted_header: Option<TrustedHeaderConfig>,
}
```

- [ ] **Step 3: Add `trusted_header: None,` to the production constructor**

In `src/admin/state.rs`, the `Ok(AdminServerConfig { ... })` inside
`build_admin_config_from_parts` (around line 410):

```rust
    Ok(AdminServerConfig {
        bind_address,
        username: username.to_string(),
        password_hash,
        allowed_ips,
        tls_config,
        enable_csrf,
        enable_rate_limiting,
    })
```

becomes:

```rust
    Ok(AdminServerConfig {
        bind_address,
        username: username.to_string(),
        password_hash,
        allowed_ips,
        tls_config,
        enable_csrf,
        enable_rate_limiting,
        trusted_header: None,
    })
```

(Task 2 replaces this `None` with real logic — this step only needs to compile.)

- [ ] **Step 4: Add `trusted_header: None,` to all 8 test-literal construction sites**

Each site below is an `AdminServerConfig { ... }` struct literal inside a
`#[test]`/`#[tokio::test]` helper. Add the line `trusted_header: None,`
as a new final field in each (exact current text shown so you can locate it
unambiguously; some structs differ slightly in other field values but all
currently end with an `enable_csrf`/`enable_rate_limiting` pair):

`src/admin/mod.rs:26` (inside `async fn test_state()`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "user".to_string(),
            password_hash: PasswordHash::hash("pass").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };
```

`src/admin/mod.rs:429` (inside `admin_server_config_is_cloneable`):
```rust
            let config = AdminServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                username: "admin".to_string(),
                password_hash: PasswordHash::hash("test").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_csrf: true,
                enable_rate_limiting: true,
                trusted_header: None,
            };
```

`src/admin/mod.rs:639` (inside `async fn create_test_app()`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "user".to_string(),
            password_hash: PasswordHash::hash("pass").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };
```

`src/admin/routes.rs:468` (inside `async fn test_state()` in `routes::tests`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };
```

`src/admin/routes.rs:808` (inside `e2e_shared_source_stats_reach_stats_json_over_real_socket`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };
```

`src/admin/routes.rs:1002` (inside `admin_page_with_csrf_enabled_generates_token`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: true,
            enable_rate_limiting: false,
            trusted_header: None,
        };
```

`src/admin/middleware.rs:126` (inside `async fn test_state_with_config(...)`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "user".to_string(),
            password_hash: PasswordHash::hash("pass").unwrap(),
            allowed_ips,
            tls_config: None,
            enable_csrf,
            enable_rate_limiting,
            trusted_header: None,
        };
```

`src/admin/config_api.rs:620` (inside `async fn make_state_with_s3_secrets()`):
```rust
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };
```

- [ ] **Step 5: Compile and run the full existing test suite — must be 100% green with zero behavior change**

Run: `cargo build --lib && cargo test --lib admin::`
Expected: builds clean, every pre-existing admin test still passes (this task
adds no new tests of its own — Task 2 does — it only proves the new field
didn't silently change anything).

- [ ] **Step 6: Commit**

```bash
git add src/admin/state.rs src/admin/mod.rs src/admin/routes.rs src/admin/middleware.rs src/admin/config_api.rs
git commit -m "feat(admin): add TrustedHeaderConfig/TrustedIdentity types (disabled by default)"
```

---

## Task 2: `build_admin_config_from_parts`/`load_admin_config` — parse and validate the 6 new env vars

**Files:**
- Modify: `src/admin/state.rs`

**Interfaces:**
- Consumes: `TrustedHeaderConfig`, `TrustedIdentity` (Task 1, `state.rs`)
- Produces: `pub struct TrustedHeaderEnvArgs<'a> { trust_proxy_headers: bool, username_header: Option<&'a str>, groups_header: Option<&'a str>, secret_header: Option<&'a str>, secret: Option<&'a str>, allowed_groups: Option<&'a str> }` (derives `Default`). `build_admin_config_from_parts(..., trusted_header_env: TrustedHeaderEnvArgs) -> anyhow::Result<AdminServerConfig>` (one new trailing parameter). Later tasks (3, 4) read `state.server_config.trusted_header` — unchanged from Task 1's shape.

- [ ] **Step 1: Add `TrustedHeaderEnvArgs` and the validation helper**

In `src/admin/state.rs`, immediately before `pub fn build_admin_config_from_parts(`, insert:

```rust
/// Raw, unvalidated env-var inputs for trusted reverse-proxy-header auth.
/// Bundled into one struct so `build_admin_config_from_parts` doesn't grow
/// past its already-long positional-argument list.
#[derive(Default)]
pub struct TrustedHeaderEnvArgs<'a> {
    pub trust_proxy_headers: bool,
    pub username_header: Option<&'a str>,
    pub groups_header: Option<&'a str>,
    pub secret_header: Option<&'a str>,
    pub secret: Option<&'a str>,
    pub allowed_groups: Option<&'a str>,
}

/// Validates and builds `TrustedHeaderConfig` from raw env-derived inputs.
///
/// Fails closed, unconditionally (regardless of bind address): if
/// `trust_proxy_headers` is true, both a non-empty secret and a non-empty
/// allowed-groups list are required. A missing secret would let anyone who
/// reaches this server forge identity headers; a missing groups list would
/// silently turn "groups gate access" into "any proxied user is admin,"
/// which defeats the entire point of the feature.
fn build_trusted_header_config(
    args: TrustedHeaderEnvArgs,
) -> anyhow::Result<Option<TrustedHeaderConfig>> {
    if !args.trust_proxy_headers {
        return Ok(None);
    }

    let secret = args.secret.unwrap_or("").to_string();
    if secret.is_empty() {
        anyhow::bail!(
            "WEF_ADMIN_TRUST_PROXY_HEADERS is true but WEF_ADMIN_TRUSTED_HEADER_SECRET is \
             not set. A shared secret is required whenever trusted-header auth is enabled \
             (regardless of bind address) — without it, any request that reaches this \
             server can forge the identity headers."
        );
    }

    let allowed_groups: Vec<String> = args
        .allowed_groups
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if allowed_groups.is_empty() {
        anyhow::bail!(
            "WEF_ADMIN_TRUST_PROXY_HEADERS is true but WEF_ADMIN_TRUSTED_GROUPS is empty. \
             At least one allowed group is required — trusted-header auth must not grant \
             access to every successfully-proxied user."
        );
    }

    let username_header =
        HeaderName::from_bytes(args.username_header.unwrap_or("X-authentik-username").as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid WEF_ADMIN_TRUSTED_HEADER value: {e}"))?;
    let groups_header = HeaderName::from_bytes(
        args.groups_header.unwrap_or("X-authentik-groups").as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("invalid WEF_ADMIN_TRUSTED_GROUPS_HEADER value: {e}"))?;
    let secret_header = HeaderName::from_bytes(
        args.secret_header.unwrap_or("X-Admin-Proxy-Secret").as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("invalid WEF_ADMIN_TRUSTED_SECRET_HEADER value: {e}"))?;

    Ok(Some(TrustedHeaderConfig {
        username_header,
        groups_header,
        secret_header,
        secret,
        allowed_groups,
    }))
}
```

- [ ] **Step 2: Add the 12th parameter to `build_admin_config_from_parts` and use it**

Change the function signature (currently ends `enable_rate_limiting: bool,\n) -> anyhow::Result<AdminServerConfig> {`):

```rust
pub fn build_admin_config_from_parts(
    bind_str: Option<&str>,
    username: &str,
    plain_pass: &str,
    pass_hash: Option<&str>,
    allowed_ips_str: Option<&str>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    require_client_cert: bool,
    enable_csrf: bool,
    enable_rate_limiting: bool,
) -> anyhow::Result<AdminServerConfig> {
```

to:

```rust
pub fn build_admin_config_from_parts(
    bind_str: Option<&str>,
    username: &str,
    plain_pass: &str,
    pass_hash: Option<&str>,
    allowed_ips_str: Option<&str>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    require_client_cert: bool,
    enable_csrf: bool,
    enable_rate_limiting: bool,
    trusted_header_env: TrustedHeaderEnvArgs,
) -> anyhow::Result<AdminServerConfig> {
```

And replace the `trusted_header: None,` placeholder from Task 1 Step 3:

```rust
    Ok(AdminServerConfig {
        bind_address,
        username: username.to_string(),
        password_hash,
        allowed_ips,
        tls_config,
        enable_csrf,
        enable_rate_limiting,
        trusted_header: None,
    })
```

with:

```rust
    let trusted_header = build_trusted_header_config(trusted_header_env)?;

    Ok(AdminServerConfig {
        bind_address,
        username: username.to_string(),
        password_hash,
        allowed_ips,
        tls_config,
        enable_csrf,
        enable_rate_limiting,
        trusted_header,
    })
```

- [ ] **Step 3: Read the 6 new env vars in `load_admin_config` and pass them through**

Change the body of `load_admin_config()` (currently ends by calling
`build_admin_config_from_parts(...)` with 11 args) — add before that call:

```rust
    let trust_proxy_headers = std::env::var("WEF_ADMIN_TRUST_PROXY_HEADERS")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(false);
    let trusted_username_header = std::env::var("WEF_ADMIN_TRUSTED_HEADER").ok();
    let trusted_groups_header = std::env::var("WEF_ADMIN_TRUSTED_GROUPS_HEADER").ok();
    let trusted_secret_header = std::env::var("WEF_ADMIN_TRUSTED_SECRET_HEADER").ok();
    let trusted_header_secret = std::env::var("WEF_ADMIN_TRUSTED_HEADER_SECRET").ok();
    let trusted_groups = std::env::var("WEF_ADMIN_TRUSTED_GROUPS").ok();
```

and change the trailing call from:

```rust
    build_admin_config_from_parts(
        bind_str.as_deref(),
        &username,
        &plain_pass,
        pass_hash.as_deref(),
        allowed_ips_str.as_deref(),
        tls_cert.as_deref(),
        tls_key.as_deref(),
        tls_ca.as_deref(),
        require_client_cert,
        enable_csrf,
        enable_rate_limiting,
    )
```

to:

```rust
    build_admin_config_from_parts(
        bind_str.as_deref(),
        &username,
        &plain_pass,
        pass_hash.as_deref(),
        allowed_ips_str.as_deref(),
        tls_cert.as_deref(),
        tls_key.as_deref(),
        tls_ca.as_deref(),
        require_client_cert,
        enable_csrf,
        enable_rate_limiting,
        TrustedHeaderEnvArgs {
            trust_proxy_headers,
            username_header: trusted_username_header.as_deref(),
            groups_header: trusted_groups_header.as_deref(),
            secret_header: trusted_secret_header.as_deref(),
            secret: trusted_header_secret.as_deref(),
            allowed_groups: trusted_groups.as_deref(),
        },
    )
```

- [ ] **Step 4: Fix the 16 pre-existing test call sites in `state.rs`'s test module**

Every one of these currently ends its argument list with `enable_rate_limiting`
(a `bool` literal, `true` or `false`) as the last argument, at line numbers
322 (definition, not a call), 441 (already handled in Step 3), 568, 594, 614,
637, 663, 684, 704, 714, 743, 763, 793, 816, 838, 866, 877, 888, 898 (16 test
calls). For **every one of these 16**, add `TrustedHeaderEnvArgs::default()`
as a new final argument after the existing last argument. Example — the
`default_parts()` helper (around line 568) changes from:

```rust
    fn default_parts() -> anyhow::Result<AdminServerConfig> {
        build_admin_config_from_parts(
            None,    // bind_str  → 127.0.0.1:8080
            "admin", // username
            "admin", // plain_pass
            None,    // pass_hash
            None,    // allowed_ips_str
            None,    // tls_cert
            None,    // tls_key
            None,    // tls_ca
            false,   // require_client_cert
            true,    // enable_csrf
            true,    // enable_rate_limiting
        )
    }
```

to:

```rust
    fn default_parts() -> anyhow::Result<AdminServerConfig> {
        build_admin_config_from_parts(
            None,    // bind_str  → 127.0.0.1:8080
            "admin", // username
            "admin", // plain_pass
            None,    // pass_hash
            None,    // allowed_ips_str
            None,    // tls_cert
            None,    // tls_key
            None,    // tls_ca
            false,   // require_client_cert
            true,    // enable_csrf
            true,    // enable_rate_limiting
            TrustedHeaderEnvArgs::default(),
        )
    }
```

Apply the identical mechanical change (append `TrustedHeaderEnvArgs::default(),`
as the new last argument, on its own line, matching the existing trailing-comma
style) at every one of the other 15 call sites (lines 594, 614, 637, 663, 684,
704, 714, 743, 763, 793, 816, 838, 866, 877, 888, 898). None of these tests
are about trusted-header behavior — they all keep testing exactly what they
tested before, with the feature explicitly disabled via `::default()`
(`trust_proxy_headers: false`).

Run `cargo build --lib 2>&1 | grep "state.rs"` after this step — any
remaining "missing argument" errors point at a call site this step missed.

- [ ] **Step 5: Write the new validation-branch unit tests**

Add to `src/admin/state.rs`'s existing `#[cfg(test)] mod tests` block (near
the other `build_config_*` tests):

```rust
    // ── TrustedHeaderConfig / build_trusted_header_config coverage ────────────

    #[test]
    fn trusted_header_disabled_by_default() {
        let cfg = default_parts().unwrap();
        assert!(cfg.trusted_header.is_none());
    }

    #[test]
    fn trusted_header_enabled_without_secret_errs() {
        let result = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true, true,
            TrustedHeaderEnvArgs {
                trust_proxy_headers: true,
                allowed_groups: Some("admins"),
                ..Default::default()
            },
        );
        assert!(result.is_err(), "trust mode on with no secret must be refused");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("WEF_ADMIN_TRUSTED_HEADER_SECRET"), "{msg}");
    }

    #[test]
    fn trusted_header_enabled_with_empty_groups_errs() {
        let result = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true, true,
            TrustedHeaderEnvArgs {
                trust_proxy_headers: true,
                secret: Some("shhh"),
                allowed_groups: Some("   , ,  "), // parses to zero non-empty entries
                ..Default::default()
            },
        );
        assert!(result.is_err(), "trust mode on with no usable group must be refused");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("WEF_ADMIN_TRUSTED_GROUPS"), "{msg}");
    }

    #[test]
    fn trusted_header_enabled_valid_inputs_uses_defaults() {
        let cfg = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true, true,
            TrustedHeaderEnvArgs {
                trust_proxy_headers: true,
                secret: Some("shhh"),
                allowed_groups: Some("admins, ops"),
                ..Default::default()
            },
        )
        .unwrap();
        let th = cfg.trusted_header.expect("trusted_header should be Some");
        assert_eq!(th.username_header, "x-authentik-username");
        assert_eq!(th.groups_header, "x-authentik-groups");
        assert_eq!(th.secret_header, "x-admin-proxy-secret");
        assert_eq!(th.secret, "shhh");
        assert_eq!(th.allowed_groups, vec!["admins", "ops"]);
    }

    #[test]
    fn trusted_header_custom_header_names_override_defaults() {
        let cfg = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true, true,
            TrustedHeaderEnvArgs {
                trust_proxy_headers: true,
                username_header: Some("X-Custom-User"),
                groups_header: Some("X-Custom-Groups"),
                secret_header: Some("X-Custom-Secret"),
                secret: Some("shhh"),
                allowed_groups: Some("admins"),
            },
        )
        .unwrap();
        let th = cfg.trusted_header.expect("trusted_header should be Some");
        assert_eq!(th.username_header, "x-custom-user");
        assert_eq!(th.groups_header, "x-custom-groups");
        assert_eq!(th.secret_header, "x-custom-secret");
    }

    #[test]
    fn trusted_header_invalid_header_name_errs() {
        let result = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true, true,
            TrustedHeaderEnvArgs {
                trust_proxy_headers: true,
                username_header: Some("not a valid header name!!"),
                secret: Some("shhh"),
                allowed_groups: Some("admins"),
                ..Default::default()
            },
        );
        assert!(result.is_err(), "an invalid header-name string must be refused at build time");
    }
```

(`HeaderName`'s `PartialEq<&str>` impl lower-cases for comparison, matching
HTTP header-name case-insensitivity — the `assert_eq!(th.username_header, "x-authentik-username")`
style above is the standard way to compare an `http::HeaderName` against a
string literal.)

- [ ] **Step 6: Run tests**

Run: `cargo test --lib admin::state:: -- --nocapture`
Expected: all pre-existing `state.rs` tests plus the 6 new ones pass.

- [ ] **Step 7: Commit**

```bash
git add src/admin/state.rs
git commit -m "feat(admin): parse and validate trusted-header-auth env vars"
```

---

## Task 3: `verify_trusted_header()` in `auth.rs` + unit tests

**Files:**
- Modify: `src/admin/auth.rs`

**Interfaces:**
- Consumes: `TrustedHeaderConfig`, `TrustedIdentity` (Task 1), `AdminState.server_config.trusted_header` (Task 2)
- Produces: `pub fn verify_trusted_header(state: &AdminState, headers: &HeaderMap) -> Option<TrustedIdentity>` — consumed by Task 5's middleware.

- [ ] **Step 1: Add the function**

In `src/admin/auth.rs`, change the import block:

```rust
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use subtle::ConstantTimeEq;

use crate::admin::state::AdminState;
```

to:

```rust
use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use subtle::ConstantTimeEq;

use crate::admin::state::{AdminState, TrustedIdentity};
```

Then, after the existing `ct_str_eq` function and before `ensure_authorized`,
add:

```rust
/// Resolve a caller identity from trusted reverse-proxy headers, or `None`
/// if trusted-header auth is disabled, the shared secret is missing/wrong,
/// the username header is missing/empty, or no incoming group matches the
/// configured allowlist.
///
/// The secret comparison is constant-time (`ct_str_eq`) since it's the one
/// value here that's actually sensitive. Username/group comparisons use
/// plain equality — group and user names aren't secrets, so a constant-time
/// compare there would add no security benefit.
///
/// Header values that aren't valid UTF-8 are treated identically to a
/// missing header (`None`) — same fail-safe posture, no separate error path.
pub fn verify_trusted_header(state: &AdminState, headers: &HeaderMap) -> Option<TrustedIdentity> {
    let cfg = state.server_config.trusted_header.as_ref()?;

    let secret = headers.get(&cfg.secret_header)?.to_str().ok()?;
    if !ct_str_eq(secret, &cfg.secret) {
        return None;
    }

    let username = headers.get(&cfg.username_header)?.to_str().ok()?.trim();
    if username.is_empty() {
        return None;
    }

    let groups_raw = headers.get(&cfg.groups_header)?.to_str().ok()?;
    // Authentik's exact delimiter for this header was not confirmed against
    // live docs at design time — accept both `,` and `|` as a best-effort
    // default (see docs/admin-security.md for the operator-facing caveat).
    let matched = groups_raw
        .split(|c| c == ',' || c == '|')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .any(|g| cfg.allowed_groups.iter().any(|allowed| allowed == g));
    if !matched {
        return None;
    }

    Some(TrustedIdentity {
        username: username.to_string(),
    })
}
```

- [ ] **Step 2: Write unit tests**

Add to `src/admin/auth.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
    mod verify_trusted_header_tests {
        use super::super::verify_trusted_header;
        use crate::admin::state::{
            AdminServerConfig, AdminState, AuditLogger, PasswordHash, TrustedHeaderConfig,
        };
        use axum::http::{HeaderMap, HeaderName, HeaderValue};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        fn trusted_cfg() -> TrustedHeaderConfig {
            TrustedHeaderConfig {
                username_header: HeaderName::from_static("x-authentik-username"),
                groups_header: HeaderName::from_static("x-authentik-groups"),
                secret_header: HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string(), "ops".to_string()],
            }
        }

        async fn state_with(trusted_header: Option<TrustedHeaderConfig>) -> AdminState {
            let server_config = AdminServerConfig {
                bind_address: "127.0.0.1:8080".parse().unwrap(),
                username: "admin".to_string(),
                password_hash: PasswordHash::hash("admin").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_csrf: false,
                enable_rate_limiting: false,
                trusted_header,
            };
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config,
                audit_logger: AuditLogger::new(10).await,
                csrf_tokens: Arc::new(RwLock::new(Vec::new())),
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
                flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            }
        }

        fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            h
        }

        #[tokio::test]
        async fn disabled_returns_none_even_with_valid_headers() {
            let state = state_with(None).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn wrong_secret_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "wrong"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn missing_secret_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn missing_username_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn empty_username_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "   "),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn no_matching_group_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "guests,visitors"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn matching_group_comma_delimited_returns_identity() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "guests,admins,visitors"),
            ]);
            let identity = verify_trusted_header(&state, &h).expect("should match");
            assert_eq!(identity.username, "alice");
        }

        #[tokio::test]
        async fn matching_group_pipe_delimited_returns_identity() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "bob"),
                ("x-authentik-groups", "guests|ops|visitors"),
            ]);
            let identity = verify_trusted_header(&state, &h).expect("should match");
            assert_eq!(identity.username, "bob");
        }

        #[tokio::test]
        async fn non_utf8_header_value_treated_as_absent() {
            let state = state_with(Some(trusted_cfg())).await;
            let mut h = headers(&[
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            h.insert(
                HeaderName::from_static("x-admin-proxy-secret"),
                HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap(),
            );
            assert!(verify_trusted_header(&state, &h).is_none());
        }
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test --lib admin::auth:: -- --nocapture`
Expected: all pre-existing `auth.rs` tests plus the 9 new ones pass.

- [ ] **Step 4: Commit**

```bash
git add src/admin/auth.rs
git commit -m "feat(admin): verify_trusted_header — secret + group-gated identity resolution"
```

---

## Task 4: `ensure_authorized()` signature change + update all 15 references

**Files:**
- Modify: `src/admin/auth.rs`
- Modify: `src/admin/routes.rs` (7 handlers)
- Modify: `src/admin/config_api.rs` (5 handlers)
- Modify: `src/admin/mod.rs` (3 direct test calls + 1 new test case)

**Interfaces:**
- Consumes: `TrustedIdentity` (Task 1)
- Produces: `ensure_authorized(state: &AdminState, trusted: Option<TrustedIdentity>, auth: Option<TypedHeader<Authorization<Basic>>>, client_ip: &str) -> Result<String, Response>` — consumed by Task 5's router wiring (no further change needed there; the middleware only needs to *insert* the extension, not call this function).

This task intentionally lands *before* Task 5's middleware exists.
`Option<Extension<TrustedIdentity>>` is a standard Axum extractor that
resolves to `None` when no such extension was inserted into the request —
so every handler here compiles and behaves exactly as before (Basic Auth
only) until Task 5 adds the middleware that can actually populate it.

- [ ] **Step 1: Change `ensure_authorized`'s signature**

In `src/admin/auth.rs`, change:

```rust
/// Verify authentication and authorize access
pub async fn ensure_authorized(
    state: &AdminState,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    client_ip: &str,
) -> Result<String, Response> {
    let Some(auth) = auth else {
        return Err(unauthorized());
    };

    let creds = auth.0;
    let username = creds.username();
    let password = creds.password();

    if ct_str_eq(username, &state.server_config.username)
        && state.server_config.password_hash.verify(password)
    {
        Ok(username.to_string())
    } else {
        state
            .audit_logger
            .log("AUTH_FAILED", username, client_ip, None)
            .await;
        Err(unauthorized())
    }
}
```

to:

```rust
/// Verify authentication and authorize access.
///
/// Checks a trusted reverse-proxy identity first (if present — see
/// `verify_trusted_header`), and only falls back to Basic Auth if none was
/// resolved. This keeps Basic Auth fully working as a fallback for direct/
/// local access when the trusted-header proxy isn't in the request path.
pub async fn ensure_authorized(
    state: &AdminState,
    trusted: Option<TrustedIdentity>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    client_ip: &str,
) -> Result<String, Response> {
    if let Some(identity) = trusted {
        return Ok(identity.username);
    }

    let Some(auth) = auth else {
        return Err(unauthorized());
    };

    let creds = auth.0;
    let username = creds.username();
    let password = creds.password();

    if ct_str_eq(username, &state.server_config.username)
        && state.server_config.password_hash.verify(password)
    {
        Ok(username.to_string())
    } else {
        state
            .audit_logger
            .log("AUTH_FAILED", username, client_ip, None)
            .await;
        Err(unauthorized())
    }
}
```

- [ ] **Step 2: Update `mod.rs`'s 3 direct calls + add a 4th case**

In `src/admin/mod.rs`, change:

```rust
    #[tokio::test]
    async fn ensure_authorized_checks_credentials() {
        use axum_extra::extract::TypedHeader;
        use headers::Authorization;

        let state = test_state().await;
        let client_ip = "127.0.0.1";

        let good = Some(TypedHeader(Authorization::basic("user", "pass")));
        let bad = Some(TypedHeader(Authorization::basic("user", "nope")));

        assert!(
            auth::ensure_authorized(&state, good, client_ip)
                .await
                .is_ok()
        );
        assert!(
            auth::ensure_authorized(&state, bad, client_ip)
                .await
                .is_err()
        );
        assert!(
            auth::ensure_authorized(&state, None, client_ip)
                .await
                .is_err()
        );
    }
```

to:

```rust
    #[tokio::test]
    async fn ensure_authorized_checks_credentials() {
        use axum_extra::extract::TypedHeader;
        use headers::Authorization;

        let state = test_state().await;
        let client_ip = "127.0.0.1";

        let good = Some(TypedHeader(Authorization::basic("user", "pass")));
        let bad = Some(TypedHeader(Authorization::basic("user", "nope")));

        assert!(
            auth::ensure_authorized(&state, None, good, client_ip)
                .await
                .is_ok()
        );
        assert!(
            auth::ensure_authorized(&state, None, bad, client_ip)
                .await
                .is_err()
        );
        assert!(
            auth::ensure_authorized(&state, None, None, client_ip)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ensure_authorized_trusted_identity_short_circuits_basic_auth() {
        let state = test_state().await;
        let client_ip = "127.0.0.1";
        let trusted = Some(crate::admin::state::TrustedIdentity {
            username: "proxied-user".to_string(),
        });

        // No Authorization header at all — must still succeed via the
        // trusted identity, proving Basic Auth is not consulted when a
        // trusted identity is already present.
        let result = auth::ensure_authorized(&state, trusted, None, client_ip).await;
        assert_eq!(result.unwrap(), "proxied-user");
    }
```

- [ ] **Step 3: Update the 7 handlers in `routes.rs`**

First, add `Extension` to the import block and `TrustedIdentity` to the
state import:

```rust
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    response::{Html, IntoResponse, Response},
};
```
→
```rust
use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, State},
    response::{Html, IntoResponse, Response},
};
```

```rust
use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, load_admin_config};
```
→
```rust
use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, TrustedIdentity, load_admin_config};
```

Then, for **each** of the 7 handlers below, add
`trusted: Option<Extension<TrustedIdentity>>` as a new parameter immediately
after `ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,` (before `auth`,
and before any body extractor like `Json(..)`/`body: Bytes` which must stay
last), and change the `ensure_authorized(&state, auth, &client_ip)` call to
`ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip)`.

`get_config` (line 159):
```rust
async fn get_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`admin_page` (line 178):
```rust
async fn admin_page(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Html<String>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`update_config` (line 203):
```rust
async fn update_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(new_config): Json<Config>,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`patch_config` (line 266):
```rust
async fn patch_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(partial): Json<PartialConfigUpdate>,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`get_audit_log` (line 364):
```rust
async fn get_audit_log(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Vec<crate::admin::state::AuditEntry>>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`get_stats` (line 383):
```rust
async fn get_stats(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Html<String>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`get_stats_json` (line 438):
```rust
async fn get_stats_json(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Vec<crate::stats::SourceHourlySnapshot>>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

(Only the signature line and the `ensure_authorized` call line change in
each — the rest of every handler body is untouched.)

- [ ] **Step 4: Update the 5 handlers in `config_api.rs`**

Add `Extension` and `TrustedIdentity` to the imports:

```rust
use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
```
→
```rust
use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Extension, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
```

```rust
use crate::admin::state::AdminState;
```
→
```rust
use crate::admin::state::{AdminState, TrustedIdentity};
```

Same transformation as Step 3, applied to each of these 5:

`validate_config` (line 217):
```rust
pub async fn validate_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(config_to_validate): Json<Config>,
) -> Result<Json<ValidationResult>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`diff_config` (line 300):
```rust
pub async fn diff_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(proposed_config): Json<Config>,
) -> Result<Json<ConfigDiff>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`export_config` (line 386):
```rust
pub async fn export_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Response, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`import_config` (line 436):
```rust
pub async fn import_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    body: Bytes,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

`reload_config` (line 511):
```rust
pub async fn reload_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;
```

- [ ] **Step 5: Verify no call site was missed**

Run: `grep -rn "ensure_authorized(" src/admin/`
Expected: exactly the same 15 reference lines as the spec's inventory (plus
the `pub async fn ensure_authorized(` definition line), each now passing the
new `trusted`/`None` argument — if `cargo build` (next step) fails with a
wrong-arg-count error, it names the missed site directly.

- [ ] **Step 6: Build and run every existing test — must still be 100% green (still no new runtime behavior; the middleware that populates `trusted` doesn't exist until Task 5)**

Run: `cargo build --lib && cargo test --lib admin::`
Expected: builds clean, all pre-existing tests pass, plus the new
`ensure_authorized_trusted_identity_short_circuits_basic_auth` test passes.

- [ ] **Step 7: Commit**

```bash
git add src/admin/auth.rs src/admin/routes.rs src/admin/config_api.rs src/admin/mod.rs
git commit -m "feat(admin): thread trusted identity through ensure_authorized and all 12 handlers"
```

---

## Task 5: `trusted_header_middleware` + router wiring + integration tests

**Files:**
- Modify: `src/admin/middleware.rs`
- Modify: `src/admin/routes.rs` (router construction only)

**Interfaces:**
- Consumes: `verify_trusted_header` (Task 3), `TrustedIdentity` (Task 1)
- Produces: `pub async fn trusted_header_middleware(...)` — an Axum
  `from_fn_with_state` layer, wired into `run_admin_server`'s router.

- [ ] **Step 1: Add the middleware function**

In `src/admin/middleware.rs`, add `verify_trusted_header` to the auth import:

```rust
use crate::admin::auth::verify_csrf_token;
use crate::admin::state::{AdminState, RateLimitError};
```
→
```rust
use crate::admin::auth::{verify_csrf_token, verify_trusted_header};
use crate::admin::state::{AdminState, RateLimitError};
```

Then, after `csrf_middleware` and before the `#[cfg(test)]` block, add:

```rust
/// Resolves a trusted reverse-proxy identity (if any) and, when present,
/// inserts it into the request's extensions for downstream handlers to pick
/// up via `Option<Extension<TrustedIdentity>>`.
///
/// Never rejects the request itself — a request with no or invalid trusted
/// headers must still be able to reach the handler and fall back to Basic
/// Auth there (`ensure_authorized` handles that fallback).
pub async fn trusted_header_middleware(
    State(state): State<AdminState>,
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    if let Some(identity) = verify_trusted_header(&state, request.headers()) {
        request.extensions_mut().insert(identity);
    }
    next.run(request).await
}
```

- [ ] **Step 2: Write integration tests**

Add to `src/admin/middleware.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
    mod trusted_header_middleware_tests {
        use super::*;
        use crate::admin::state::TrustedHeaderConfig;
        use axum::http::HeaderName;
        use axum::routing::get;

        fn trusted_cfg() -> TrustedHeaderConfig {
            TrustedHeaderConfig {
                username_header: HeaderName::from_static("x-authentik-username"),
                groups_header: HeaderName::from_static("x-authentik-groups"),
                secret_header: HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string()],
            }
        }

        async fn state_with_trust(trusted_header: Option<TrustedHeaderConfig>) -> AdminState {
            let server_config = AdminServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                username: "user".to_string(),
                password_hash: PasswordHash::hash("pass").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_csrf: false,
                enable_rate_limiting: false,
                trusted_header,
            };
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config,
                audit_logger: AuditLogger::new(100).await,
                csrf_tokens: Arc::new(RwLock::new(Vec::new())),
                request_counts: Arc::new(RwLock::new(HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
                flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            }
        }

        /// A downstream test handler that reports whether a TrustedIdentity
        /// extension is present, so the test can observe the middleware's
        /// effect without needing a real admin handler.
        async fn echo_trusted(
            trusted: Option<axum::extract::Extension<crate::admin::state::TrustedIdentity>>,
        ) -> String {
            match trusted {
                Some(axum::extract::Extension(t)) => format!("trusted:{}", t.username),
                None => "untrusted".to_string(),
            }
        }

        #[tokio::test]
        async fn sets_extension_on_secret_and_group_match() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"trusted:alice");
        }

        #[tokio::test]
        async fn does_not_set_extension_on_wrong_secret() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "wrong")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"untrusted");
        }

        #[tokio::test]
        async fn does_not_set_extension_on_non_matching_group() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "guests")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"untrusted");
        }

        #[tokio::test]
        async fn disabled_feature_never_sets_extension() {
            let state = state_with_trust(None).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"untrusted");
        }
    }
```

- [ ] **Step 3: Wire the middleware into the admin router**

In `src/admin/routes.rs`, inside `run_admin_server`, change:

```rust
    let app = axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .route(
            "/config",
            axum::routing::get(get_config)
                .put(update_config)
                .patch(patch_config),
        )
        .route(
            "/config/validate",
            axum::routing::post(crate::admin::config_api::validate_config),
        )
        .route(
            "/config/diff",
            axum::routing::post(crate::admin::config_api::diff_config),
        )
        .route(
            "/config/export",
            axum::routing::post(crate::admin::config_api::export_config),
        )
        .route(
            "/config/import",
            axum::routing::post(crate::admin::config_api::import_config),
        )
        .route(
            "/config/reload",
            axum::routing::post(crate::admin::config_api::reload_config),
        )
        .route("/health", axum::routing::get(health_check))
        .route("/audit-log", axum::routing::get(get_audit_log))
        .route("/stats", axum::routing::get(get_stats))
        .route("/stats.json", axum::routing::get(get_stats_json))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::middleware::csrf_middleware,
        ))
        .with_state(state);
```

to (one new `.layer(...)` call inserted before `security_middleware`'s):

```rust
    let app = axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .route(
            "/config",
            axum::routing::get(get_config)
                .put(update_config)
                .patch(patch_config),
        )
        .route(
            "/config/validate",
            axum::routing::post(crate::admin::config_api::validate_config),
        )
        .route(
            "/config/diff",
            axum::routing::post(crate::admin::config_api::diff_config),
        )
        .route(
            "/config/export",
            axum::routing::post(crate::admin::config_api::export_config),
        )
        .route(
            "/config/import",
            axum::routing::post(crate::admin::config_api::import_config),
        )
        .route(
            "/config/reload",
            axum::routing::post(crate::admin::config_api::reload_config),
        )
        .route("/health", axum::routing::get(health_check))
        .route("/audit-log", axum::routing::get(get_audit_log))
        .route("/stats", axum::routing::get(get_stats))
        .route("/stats.json", axum::routing::get(get_stats_json))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::middleware::trusted_header_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::middleware::csrf_middleware,
        ))
        .with_state(state);
```

- [ ] **Step 4: Write router-level integration tests covering both `routes.rs` and `config_api.rs` handlers**

Add to `src/admin/routes.rs`'s existing `#[cfg(test)] mod tests` block (near
the other route-integration tests), building the router the same way
`run_admin_server` does but scoped to the two routes under test:

```rust
    mod trusted_header_integration_tests {
        use super::*;
        use crate::admin::state::TrustedHeaderConfig;

        async fn test_state_with_trust() -> AdminState {
            let server_config = AdminServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                username: "admin".to_string(),
                password_hash: PasswordHash::hash("admin").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_csrf: false,
                enable_rate_limiting: false,
                trusted_header: Some(TrustedHeaderConfig {
                    username_header: axum::http::HeaderName::from_static("x-authentik-username"),
                    groups_header: axum::http::HeaderName::from_static("x-authentik-groups"),
                    secret_header: axum::http::HeaderName::from_static("x-admin-proxy-secret"),
                    secret: "shhh".to_string(),
                    allowed_groups: vec!["admins".to_string()],
                }),
            };
            AdminState {
                config: Arc::new(RwLock::new(Config::default())),
                server_config,
                audit_logger: AuditLogger::new(100).await,
                csrf_tokens: Arc::new(RwLock::new(Vec::new())),
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
                flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            }
        }

        fn trusted_headers_request(method: Method, uri: &str) -> Request<Body> {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap()
        }

        #[tokio::test]
        async fn get_config_succeeds_with_trusted_headers_alone_no_basic_auth() {
            let state = test_state_with_trust().await;
            let mut request = trusted_headers_request(Method::GET, "/config");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn export_config_succeeds_with_trusted_headers_alone_no_basic_auth() {
            let state = test_state_with_trust().await;
            let mut request = trusted_headers_request(Method::POST, "/config/export");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route(
                    "/config/export",
                    axum::routing::post(crate::admin::config_api::export_config),
                )
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn get_config_falls_back_to_basic_auth_when_no_trusted_headers_present() {
            let state = test_state_with_trust().await;
            let mut request = create_request_with_auth(Method::GET, "/config", "admin", "admin", None);
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Basic Auth must still work when no trusted headers are present"
            );
        }

        #[tokio::test]
        async fn get_config_rejects_when_neither_trusted_headers_nor_basic_auth_present() {
            let state = test_state_with_trust().await;
            let mut request = create_request_without_auth(Method::GET, "/config");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn get_config_records_header_derived_username_in_audit_log() {
            let state = test_state_with_trust().await;
            let mut request = trusted_headers_request(Method::GET, "/config");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state.clone());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            let entry = entries
                .iter()
                .find(|e| e.action == "CONFIG_READ")
                .expect("CONFIG_READ entry should exist");
            assert_eq!(entry.username, "alice");
        }
    }
```

(This module reuses `inject_connect_info`, `create_request_with_auth`, and
`create_request_without_auth` already defined earlier in
`routes.rs`'s `#[cfg(test)] mod tests`.)

- [ ] **Step 5: Run tests**

Run: `cargo test --lib admin::`
Expected: all pre-existing tests plus every new test from Tasks 1-5 pass.

- [ ] **Step 6: Commit**

```bash
git add src/admin/middleware.rs src/admin/routes.rs
git commit -m "feat(admin): wire trusted_header_middleware into the admin router"
```

---

## Task 6: End-to-end real-socket test + `docs/admin-security.md`

**Files:**
- Modify: `src/admin/routes.rs` (new e2e test)
- Modify: `docs/admin-security.md`

**Interfaces:**
- Consumes: everything from Tasks 1-5 (this is the final wiring proof — a
  real running server, real HTTP, no shortcuts).

- [ ] **Step 1: Write the end-to-end test**

Add to `src/admin/routes.rs`'s `#[cfg(test)] mod tests` block, near
`e2e_shared_source_stats_reach_stats_json_over_real_socket`:

```rust
    #[tokio::test]
    async fn e2e_trusted_header_auth_over_real_socket() {
        use crate::admin::state::TrustedHeaderConfig;

        let server_config = AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: Some(TrustedHeaderConfig {
                username_header: axum::http::HeaderName::from_static("x-authentik-username"),
                groups_header: axum::http::HeaderName::from_static("x-authentik-groups"),
                secret_header: axum::http::HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string()],
            }),
        };
        let state = AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
        };

        let app = axum::Router::new()
            .route("/config", axum::routing::get(get_config))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::admin::middleware::trusted_header_middleware,
            ))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::new();

        // Trusted headers alone, no Authorization header at all → 200.
        let resp = client
            .get(format!("http://{real_addr}/config"))
            .header("x-admin-proxy-secret", "shhh")
            .header("x-authentik-username", "alice")
            .header("x-authentik-groups", "admins")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "real HTTP request with valid trusted headers and no Basic Auth must succeed"
        );

        // Wrong secret, no Authorization header → 401 (falls through, no fallback available).
        let resp = client
            .get(format!("http://{real_addr}/config"))
            .header("x-admin-proxy-secret", "wrong-secret")
            .header("x-authentik-username", "alice")
            .header("x-authentik-groups", "admins")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "a wrong shared secret must not grant access, even with correct-looking identity headers"
        );
    }
```

- [ ] **Step 2: Run it**

Run: `cargo test --lib admin::routes::tests::e2e_trusted_header_auth_over_real_socket -- --nocapture`
Expected: passes.

- [ ] **Step 3: Document the feature in `docs/admin-security.md`**

Read the existing file first to find its last numbered section (currently
"6. Rate Limiting") and its exact heading/code-block style, then append a new
numbered section (`### 7. Trusted Reverse-Proxy Header Auth (Authentik)`)
matching that style:

```markdown
### 7. Trusted Reverse-Proxy Header Auth (Authentik)

The admin interface can trust identity headers injected by a reverse-proxy
forward-auth setup (e.g. an Authentik outpost), as an alternative to typing
Basic Auth credentials. This is opt-in and additive — Basic Auth keeps
working unchanged as a fallback.

```bash
WEF_ADMIN_TRUST_PROXY_HEADERS=true
WEF_ADMIN_TRUSTED_HEADER=X-authentik-username           # default shown
WEF_ADMIN_TRUSTED_GROUPS_HEADER=X-authentik-groups       # default shown
WEF_ADMIN_TRUSTED_SECRET_HEADER=X-Admin-Proxy-Secret     # default shown
WEF_ADMIN_TRUSTED_HEADER_SECRET=<a long random value only the proxy and this server know>
WEF_ADMIN_TRUSTED_GROUPS=admins,ops                      # comma-separated allowlist
```

**Both `WEF_ADMIN_TRUSTED_HEADER_SECRET` and `WEF_ADMIN_TRUSTED_GROUPS` are
required whenever `WEF_ADMIN_TRUST_PROXY_HEADERS=true`** — the admin server
refuses to start otherwise, regardless of bind address. Presence of the
identity headers alone is never trusted: Authentik does not itself guarantee
that a reverse-proxy config strips client-forged copies of these headers —
that's the proxy's job. **The proxy must overwrite (not merely pass through)
any client-supplied copy of these headers**, and the shared secret must never
be reachable by anything other than the proxy and this server.

**Caveat — verify before relying on this in production**: Authentik's exact
delimiter for `X-authentik-groups` was not confirmed against live Authentik
documentation at the time this was implemented. This implementation accepts
both `,` and `|` as a best-effort default. Confirm the actual format against
your deployed Authentik version before relying on group-based access control.

JWT verification of Authentik's signed `X-authentik-jwt` header is not
implemented — the shared-secret + loopback-bind + group-check combination is
the current trust model.
```

- [ ] **Step 4: Commit**

```bash
git add src/admin/routes.rs docs/admin-security.md
git commit -m "test(admin): e2e trusted-header auth over a real socket + docs"
```

---

## Task 7: Final verification pass

**Files:** none modified — verification only.

- [ ] **Step 1: Re-run the exhaustive grep inventories and diff against the spec**

```bash
grep -rn "AdminServerConfig {" src/admin/
grep -rn "ensure_authorized(" src/admin/
grep -rn "build_admin_config_from_parts(" src/admin/
```

Expected: identical site count and locations to
`docs/superpowers/specs/2026-08-25-authentik-header-auth-design.md`'s
inventories (9 `AdminServerConfig` sites, 15 `ensure_authorized` references
+ definition, 18 `build_admin_config_from_parts` references + definition) —
every one already updated by Tasks 1, 2, and 4. If this turns up a site not
already handled, stop and fix it before proceeding (this is the exact
failure pattern two coherence-review rounds caught during design — don't let
it slip through at implementation time too).

- [ ] **Step 2: Full clean build and test run**

```bash
cargo build --lib
cargo test --lib admin::
cargo clippy --lib -- -D warnings
```

Expected: all green, zero warnings.

- [ ] **Step 3: Automated smoke check of the new fail-closed startup guard**

This is already covered by the unit tests in Task 2 Step 5
(`trusted_header_enabled_without_secret_errs`,
`trusted_header_enabled_with_empty_groups_errs`), which call
`build_admin_config_from_parts` directly and assert `Err`. No separate
manual run is needed — confirm those two tests are in the green set from
Step 2 above.

- [ ] **Step 4: Report completion**

Summarize: which tasks landed, full test counts (existing + new), and the
final branch/commit state (`feat/authentik-header-auth`). Per this
project's CLAUDE.md and the auto-develop skill's guardrails, **do not**
merge to master, push, or open a PR — hand the branch back for the user's
own merge/PR decision.
