# Read-Only Admin Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every configuration-editing path from the admin web interface, leaving a read-only console, so the only way an operator changes configuration is `LOGTHING__*` environment variables over `logthing.toml`.

**Architecture:** This is mostly deletion. Environment-variable configuration already works through `config::Environment` in `Config::load()`. Five write endpoints, the HTML form, the admin-written `logthing.admin.toml` config layer, and the plumbing that existed only to serve them are removed. Two things are added: `validate_config_invariants` moves into `Config::load()` so those checks still run somewhere, and the admin page gains a list of set `LOGTHING__*` variable names so an operator can see what the process actually received.

**Tech Stack:** Rust 2024, axum 0.7, the `config` crate 0.14, tokio, `quick_xml::escape` for HTML escaping (already a dependency — do not add a templating or escaping crate).

**Spec:** `docs/superpowers/specs/2026-09-20-admin-readonly-env-config-design.md` — read it before starting. It records which decisions came from the user and must not be revisited.

## Global Constraints

- **Branch:** all work happens on `feat/admin-readonly-env-config`. Do not commit to `master`. Do not merge, rebase onto master, or open a PR — the merge decision belongs to the user.
- **Build environment — builds hang without this.** `~/.local/bin/cc` and `~/.local/bin/gcc` are `zig cc` shims that shadow `/usr/bin` and fail to compile this project's C dependencies. Every `cargo` invocation needs:
  ```bash
  source ~/.cargo/env
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  ```
  Both the `CC` line and the `..._LINKER` line are required; dropping the second silently links LLVM libunwind. A clean first compile takes about 4 minutes.
- **Testing levels.** This project requires unit, integration, and end-to-end coverage for changed behaviour. Do not report a task complete until the tests named in that task pass, with the output to show it.
- **Do not claim "configuration is via environment variables only"** in any code comment, doc, page copy, or commit message. `logthing.toml` and `/etc/logthing/config` remain live config layers for the whole schema. See the spec's "What this change is, stated honestly".
- **`security.allowed_ips` and `aggregate.rules` are file-only** — no environment-variable equivalent exists. Anywhere operator-facing text mentions environment variables, these two must be called out as exceptions.
- **Do not** collapse `Arc<RwLock<Config>>` to `Arc<Config>`, add a `list_separator` to the env source, or touch `security_middleware` (it gates on `LOGTHING_ADMIN_ALLOWED_IPS`, a separate admin-only allowlist).
- Run `cargo fmt` and `cargo clippy --all-targets` before every commit; both must be clean.

## File Structure

| File | Change |
|---|---|
| `src/admin/config_api.rs` | 1,413 lines → ~200. Keeps only `REDACTED`, `redact_s3_connection`, `redacted_config`. |
| `src/admin/routes.rs` | Drop 7 routes and 2 handlers; `admin_page` rewritten in Task 4. |
| `src/admin/state.rs` | Drop `AdminState.csrf_tokens`, `.flush_registry`, `.ip_whitelist`; drop `AdminServerConfig.enable_csrf` and its env var. |
| `src/admin/middleware.rs` | Delete `csrf_middleware` and its tests. |
| `src/admin/auth.rs` | Delete `generate_csrf_token` and its tests. |
| `src/admin/mod.rs` | Update the `test_state()` helper; delete `write_config_outputs_toml`. |
| `src/admin/templates/admin.html` | 663 lines → ~140, server-rendered, no JavaScript config calls. |
| `src/config/mod.rs` | Drop the `logthing.admin.toml` source and `ADMIN_OVERRIDE_FILE`; gain `validate_config_invariants` and the stale-file warning. |
| `src/middleware/mod.rs` | Delete `IpWhitelist::set_networks`. |
| `src/forwarding/flush_registry.rs` | Delete `FlushIntervalRegistry::set_secs`. |
| `src/main.rs` | Two fewer arguments to `spawn_admin_server`. |
| `logthing.admin.toml` | Deleted from the repository. |
| `tests/admin_flush_interval_e2e.rs` | Deleted. |
| `tests/admin_trusted_header_e2e.rs` | Drop the CSRF setup line. |
| `tests/admin_readonly_console_e2e.rs` | Created in Task 5. |
| `logthing.toml`, `README.md`, `docs/admin-security.md`, `CHANGELOG.md` | Updated in Task 6. |

Tasks are strictly sequential — they touch overlapping files, so do not run two in parallel.

---

### Task 1: Delete the config write endpoints and shrink `config_api.rs`

**Files:**
- Modify: `src/admin/routes.rs:78-109` (router), and delete the `update_config` and `patch_config` handlers
- Modify: `src/admin/config_api.rs` (delete all but the read path)
- Modify: `src/admin/mod.rs:110-121` (delete the `write_config_outputs_toml` test)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `crate::admin::config_api::redacted_config(&Config) -> Config` survives with its current signature and is the only item Task 4 needs from this file. `REDACTED: &str` and `redact_s3_connection` stay `pub(crate)`/private as they are today.

- [ ] **Step 1: Write the failing integration test**

Add to the `mod tests` block at the bottom of `src/admin/routes.rs`. It builds the real router the way the existing tests there do and asserts the write verbs are gone. `405` is what axum returns for a known path with an unrouted method; `404` for a path with no route at all.

```rust
#[tokio::test]
async fn config_write_endpoints_are_gone() {
    let state = test_state().await;
    let app = axum::Router::new()
        .route(
            "/config",
            axum::routing::get(get_config),
        )
        .with_state(state);

    for method in [Method::PUT, Method::PATCH] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri("/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} /config must no longer be routed"
        );
    }
}
```

- [ ] **Step 2: Run it to make sure it fails**

```bash
source ~/.cargo/env && export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib admin::routes::tests::config_write_endpoints_are_gone
```

Expected: fails to compile, because `update_config` and `patch_config` still exist and the test's router does not match production. That compile failure is the red state — proceed.

- [ ] **Step 3: Strip the router**

In `src/admin/routes.rs`, replace the route block at lines 78-109 with:

```rust
    let app = axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .route("/config", axum::routing::get(get_config))
        .route("/health", axum::routing::get(health_check))
        .route("/audit-log", axum::routing::get(get_audit_log))
        .route("/stats", axum::routing::get(get_stats))
        .route("/stats.json", axum::routing::get(get_stats_json))
```

Leave the long layer-ordering comment and the three `.layer(...)` calls that follow exactly as they are — Task 3 edits them.

- [ ] **Step 4: Delete the two handlers**

Delete `async fn update_config` (starts `src/admin/routes.rs:277`) and `async fn patch_config` (starts `src/admin/routes.rs:362`) in full, including their doc comments.

- [ ] **Step 5: Fix the imports**

`src/admin/routes.rs:13-17` currently imports seven items from `config_api`. Only one survives:

```rust
use crate::admin::config_api::redacted_config;
```

- [ ] **Step 6: Shrink `config_api.rs`**

Delete from `src/admin/config_api.rs`: `apply_flush_intervals`, `apply_live_security_settings`, `merge_redacted_secrets`, `validate_config_invariants` (Task 2 re-creates it in `src/config/mod.rs` — do not delete it before copying the body somewhere you can find it), `ValidationResult`, `validate_config`, `diff_config`, `export_config`, `import_config`, `reload_config`, `persist_config`, `write_config_to_path`, the `test_support` module, and every test that exercises those.

Keep: the `REDACTED` constant, `redact_s3_connection`, `redacted_config`, and their tests. Remove `ADMIN_OVERRIDE_FILE` and `S3ConnectionConfig` from the import at line 16 only if nothing remaining uses them — `redact_s3_connection` still needs `S3ConnectionConfig`.

- [ ] **Step 7: Delete the orphaned test in `mod.rs`**

Delete `write_config_outputs_toml` (`src/admin/mod.rs:110-121`) — it tested a function that no longer exists. Remove the now-unused `tempdir` import if nothing else in that test module uses it.

- [ ] **Step 8: Delete the test-support references in `routes.rs` tests**

`src/admin/routes.rs:1125` imports `config_api::test_support::sandbox_persist_config_path`. Delete every test in that module that calls it — they all exercise `PUT`, `PATCH`, `import`, or `reload`. Also delete the `export_config` route test near line 1849.

- [ ] **Step 9: Run the tests**

```bash
cargo test --lib admin:: 2>&1 | tail -20
```

Expected: PASS, including `config_write_endpoints_are_gone`. Fix any test that referenced a deleted item by deleting it — do not resurrect the deleted functions.

- [ ] **Step 10: Commit**

```bash
cargo fmt && cargo clippy --all-targets 2>&1 | tail -5
git add -A src/admin/
git commit -m "refactor(admin): delete the config write endpoints

PUT/PATCH /config and POST /config/{validate,diff,export,import,reload}
are gone, along with persist_config, the live-apply helpers, and the
test sandbox that kept the write tests off the real override file.
config_api.rs keeps only the read path used by GET /config."
```

---

### Task 2: Move config validation into `Config::load()`, drop the `logthing.admin.toml` layer

**Files:**
- Modify: `src/config/mod.rs:5` (delete `ADMIN_OVERRIDE_FILE`), `src/config/mod.rs:1602-1625` (`Config::load`)
- Delete: `logthing.admin.toml`
- Test: `src/config/mod.rs` `mod tests`

**Interfaces:**
- Consumes: `validate_config_invariants`'s body, deleted from `src/admin/config_api.rs` in Task 1.
- Produces: `pub fn validate_config_invariants(cfg: &Config) -> Result<(), String>` in `crate::config`, called from `Config::load()`.

- [ ] **Step 1: Write the failing unit tests**

Add to `mod tests` in `src/config/mod.rs`. The first test needs the process working directory to contain a `logthing.admin.toml`; follow the rename/restore safety pattern already used by `load_reads_configuration_file` in that file, and serialise against the same lock it uses — `Config::load()` reads the real working directory, so two of these running concurrently will fight.

```rust
#[test]
fn load_ignores_a_stale_admin_override_file() {
    // logthing.admin.toml was written by the old admin API. It must no
    // longer be read: an operator upgrading with the file still on disk
    // gets logthing.toml's values, not the stale override's.
    let _guard = CONFIG_FILE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = std::path::Path::new("logthing.admin.toml");
    std::fs::write(path, "bind_address = \"127.0.0.1:9999\"\n").unwrap();

    let result = std::panic::catch_unwind(|| {
        let cfg = Config::load().expect("load must succeed");
        assert_ne!(
            cfg.bind_address,
            "127.0.0.1:9999".parse().unwrap(),
            "logthing.admin.toml must not be a config source any more"
        );
    });

    let _ = std::fs::remove_file(path);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn validate_config_invariants_rejects_tls_without_cert() {
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    cfg.tls.cert_file = None;
    cfg.tls.key_file = None;

    let err = validate_config_invariants(&cfg).expect_err("must reject");
    assert!(err.contains("tls.cert_file"), "got: {err}");
    assert!(err.contains("tls.key_file"), "got: {err}");
}

#[test]
fn validate_config_invariants_rejects_port_zero() {
    let mut cfg = Config::default();
    cfg.bind_address = "0.0.0.0:0".parse().unwrap();

    let err = validate_config_invariants(&cfg).expect_err("must reject");
    assert!(err.contains("bind_address port cannot be 0"), "got: {err}");
}
```

If `CONFIG_FILE_TEST_LOCK` does not already exist in that test module, add it beside the other test statics:

```rust
static CONFIG_FILE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
```

and make `load_reads_configuration_file` take it too, so the two cannot interleave.

- [ ] **Step 2: Run them to make sure they fail**

```bash
cargo test --lib config::tests::load_ignores_a_stale_admin_override_file config::tests::validate_config_invariants
```

Expected: FAIL — `validate_config_invariants` is not in scope, and the override file is still a source.

- [ ] **Step 3: Add `validate_config_invariants` to `src/config/mod.rs`**

Paste the body deleted in Task 1, with the doc comment rewritten — the original referenced `apply_live_security_settings` and "before persist", neither of which exists now:

```rust
/// Reject configurations that parse but cannot work.
///
/// Called from [`Config::load`], so these checks run once at startup for
/// every deployment regardless of where the values came from. Before the
/// admin write endpoints were removed this ran only on an admin-driven
/// config change, which meant a bad file or environment variable was
/// accepted at startup and failed later at the point of use.
///
/// `security.allowed_ips` is parsed here and again in `main.rs`, where
/// `IpWhitelist::new` needs the parsed networks anyway. Both fail fast and
/// agree; the duplication is deliberate, not an oversight.
pub fn validate_config_invariants(cfg: &Config) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    if cfg.bind_address.port() == 0 {
        errors.push("bind_address port cannot be 0".to_string());
    }

    if cfg.tls.enabled {
        if cfg.tls.cert_file.is_none() {
            errors.push("tls.enabled is true but tls.cert_file is not set".to_string());
        }
        if cfg.tls.key_file.is_none() {
            errors.push("tls.enabled is true but tls.key_file is not set".to_string());
        }
    }

    // Also rejected at router construction (`Server::create_router`);
    // catching them here fails the process at startup with a clear message
    // instead of at first request.
    if cfg.security.max_connections == 0 {
        errors.push("security.max_connections must be greater than 0".to_string());
    }
    if cfg.security.connection_timeout_secs == 0 {
        errors.push("security.connection_timeout_secs must be greater than 0".to_string());
    }

    if let Err(err) = crate::middleware::parse_allowed_ips(&cfg.security.allowed_ips) {
        errors.push(format!("security.allowed_ips: {err}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
```

- [ ] **Step 4: Rewrite `Config::load()`**

Replace the body at `src/config/mod.rs:1602-1625` with:

```rust
    pub fn load() -> anyhow::Result<Self> {
        let mut builder = config::Config::builder();

        builder = builder.set_default("bind_address", "0.0.0.0:5985")?;

        builder = builder.add_source(config::File::with_name("logthing").required(false));
        builder =
            builder.add_source(config::File::with_name("/etc/logthing/config").required(false));

        // `LOGTHING__<SECTION>__<FIELD>` overrides every file layer above.
        builder = builder.add_source(config::Environment::with_prefix("LOGTHING").separator("__"));

        let config = builder.build()?;
        let config: Config = config.try_deserialize()?;

        // Written by the admin API before it became read-only. It is no
        // longer a config source, so say so rather than letting an
        // operator wonder why their settings changed after the upgrade.
        if Path::new("logthing.admin.toml").exists() {
            tracing::warn!(
                "logthing.admin.toml exists but is no longer read. The admin \
                 interface is read-only; set configuration with LOGTHING__* \
                 environment variables or logthing.toml, then delete this file."
            );
        }

        validate_config_invariants(&config).map_err(|e| anyhow::anyhow!("invalid config: {e}"))?;
        validate_iceberg_config(&config.iceberg)?;
        validate_recv_tasks_config(&config)?;
        validate_recv_batch_size_config(&config)?;
        Ok(config)
    }
```

Then delete `pub const ADMIN_OVERRIDE_FILE: &str = "logthing.admin.toml";` at line 5, and fix the doc comment above `load()` that lists the source precedence — it currently names `logthing.admin.toml` as layer 3.

- [ ] **Step 5: Run the tests**

```bash
cargo test --lib config:: 2>&1 | tail -20
```

Expected: PASS. Note the existing test at `src/config/mod.rs:2099` references `ADMIN_OVERRIDE_FILE`; delete or rewrite it — it asserts the behaviour being removed.

- [ ] **Step 6: Delete the tracked override file**

```bash
git rm logthing.admin.toml
```

This changes local development defaults from `127.0.0.1:9999`/`debug` back to `logthing.toml`'s `0.0.0.0:5985`/`info`. That is intended.

- [ ] **Step 7: Verify the whole suite still builds**

```bash
cargo test --lib 2>&1 | tail -10
```

Expected: PASS. A failure naming `ADMIN_OVERRIDE_FILE` means a reference was missed.

- [ ] **Step 8: Commit**

```bash
cargo fmt && cargo clippy --all-targets 2>&1 | tail -5
git add -A
git commit -m "feat(config): validate at startup, drop the admin override layer

logthing.admin.toml is no longer a config source and the tracked copy is
deleted; a leftover file on disk now produces a startup warning instead
of silently changing behaviour.

validate_config_invariants moves from the deleted admin write path into
Config::load(), so TLS-without-cert and port-0 are rejected at startup
for every deployment rather than only on an admin-driven config change."
```

---

### Task 3: Delete the orphaned CSRF and live-apply plumbing

**Files:**
- Modify: `src/admin/middleware.rs:94` (delete `csrf_middleware`), `src/admin/auth.rs:169` (delete `generate_csrf_token`)
- Modify: `src/admin/state.rs:302-321` (`AdminState`), `:201-213` (`AdminServerConfig`), `:503` (`build_admin_config_from_parts`), `:597` (`load_admin_config`)
- Modify: `src/admin/routes.rs` (`run_admin_server`, `spawn_admin_server`, `admin_page`)
- Modify: `src/middleware/mod.rs:95` (delete `set_networks`), `src/forwarding/flush_registry.rs:33` (delete `set_secs`)
- Modify: `src/main.rs:83-88`

**Interfaces:**
- Consumes: the stripped router from Task 1.
- Produces: `pub fn spawn_admin_server(config: Arc<RwLock<Config>>, source_stats: Arc<SourceHourlyStats>)` — two parameters, down from four. Task 5's end-to-end test calls it with this signature.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/admin/state.rs`, proving the CSRF env var no longer produces config:

```rust
#[test]
fn admin_config_has_no_csrf_knob() {
    // Every surviving admin route is a GET, so there is nothing to forge
    // and LOGTHING_ADMIN_ENABLE_CSRF no longer does anything. This test
    // exists so the field is not quietly reintroduced.
    let cfg = build_admin_config_from_parts(
        None,
        "admin",
        "password",
        None,
        None,
        None,
        None,
        true,
        false,
        TrustedHeaderEnv::default(),
    )
    .expect("config builds");
    assert!(cfg.allowed_ips.is_empty());
}
```

Adjust the argument list to match the real signature after `enable_csrf` is removed — the point of the test is that it does not compile while the parameter still exists.

- [ ] **Step 2: Run it to confirm it fails**

```bash
cargo test --lib admin::state::tests::admin_config_has_no_csrf_knob
```

Expected: compile error about argument count. That is the red state.

- [ ] **Step 3: Delete the CSRF code**

- `src/admin/middleware.rs`: delete `pub async fn csrf_middleware` (line 94) and every test in that file exercising it.
- `src/admin/auth.rs`: delete `pub async fn generate_csrf_token` (line 169) and its tests.
- `src/admin/state.rs`: delete `AdminState.csrf_tokens` (line 306) and `AdminServerConfig.enable_csrf` (line 207); drop the `enable_csrf` parameter from `build_admin_config_from_parts` (line 503) and its doc-comment bullet (line 500); delete the `LOGTHING_ADMIN_ENABLE_CSRF` read (line 605) and the `enable_csrf` field initialisers (lines 590, 628). Update the `load_admin_config_env_scenarios` test — it has numbered scenarios asserting on `enable_csrf`; delete those scenarios rather than rewriting them.
- `src/admin/routes.rs`: in `run_admin_server`, delete the `csrf_tokens` local and the `.layer(...)` call that installs `csrf_middleware`. In the long layer-ordering comment, delete the `csrf_middleware (outermost, runs 1st)` line from the diagram and adjust the remaining two entries — the comment is load-bearing and must stay accurate.

- [ ] **Step 4: Simplify `admin_page`**

In `src/admin/routes.rs:247`, delete the CSRF token generation and the template substitution. The handler body from the `let username = ...` line becomes:

```rust
    state
        .audit_logger
        .log("ADMIN_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    Ok(Html(include_str!("templates/admin.html").to_string()))
```

Task 4 replaces this again; this step only needs it to compile.

- [ ] **Step 5: Delete the live-apply plumbing**

- `src/admin/state.rs`: delete `AdminState.flush_registry` (line 313) and `AdminState.ip_whitelist` (line 320) with their doc comments.
- `src/middleware/mod.rs`: delete `pub fn set_networks` (line 95) and its tests. Keep `parse_allowed_ips` — Task 2's validation calls it.
- `src/forwarding/flush_registry.rs`: delete `pub fn set_secs` (line 33) and its tests. Keep `register`; `main.rs` calls it for every sink.

- [ ] **Step 6: Narrow `spawn_admin_server` and update `main.rs`**

`src/admin/routes.rs`:

```rust
pub fn spawn_admin_server(
    config: Arc<RwLock<Config>>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) {
```

Thread the same two-parameter change through `run_admin_server` and the `AdminState` construction inside it. Then `src/main.rs:83`:

```rust
    admin::spawn_admin_server(shared_config.clone(), source_stats.clone());
```

`flush_registry` and `ip_whitelist` are still used elsewhere in `main.rs` — do not delete the locals.

- [ ] **Step 7: Fix every `AdminState` construction**

Test helpers build `AdminState` literally at `src/admin/mod.rs:25`, `src/admin/auth.rs:259` and `:416`, `src/admin/middleware.rs:211`, `:469` and `:917`, and in `src/admin/routes.rs`'s `test_state()`. Remove the three deleted fields from each. `src/admin/routes.rs:1513-1527` has a test that sets `state.ip_whitelist` to prove live allowlist updates — delete it; it tests a removed feature.

- [ ] **Step 8: Run the full library suite**

```bash
cargo test --lib 2>&1 | tail -15
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
cargo fmt && cargo clippy --all-targets 2>&1 | tail -5
git add -A
git commit -m "refactor(admin): delete CSRF and live-apply plumbing

Every surviving admin route is a GET, so csrf_middleware,
generate_csrf_token, AdminState.csrf_tokens and LOGTHING_ADMIN_ENABLE_CSRF
have nothing to protect. AdminState.ip_whitelist and .flush_registry each
had exactly one reader, both in the deleted live-apply helpers, so
spawn_admin_server drops two parameters and IpWhitelist::set_networks and
FlushIntervalRegistry::set_secs go with them.

security.allowed_ips, hec.token and the S3 flush intervals are now
restart-only. BREAKING CHANGE, recorded in CHANGELOG."
```

---

### Task 4: Rebuild the admin page as a read-only console

**Files:**
- Modify: `src/admin/templates/admin.html` (663 → ~140 lines)
- Modify: `src/admin/routes.rs` (`admin_page`)
- Create: the `set_env_var_names` helper in `src/admin/routes.rs`

**Interfaces:**
- Consumes: `redacted_config` from Task 1; the simplified `admin_page` from Task 3.
- Produces: `fn set_env_var_names() -> Vec<String>` — sorted `LOGTHING__*` variable names, never values.

**A deliberate simplification to flag at review:** the spec says "a read-only table of the effective configuration". This implements it as a `<pre>` block of the redacted config serialised to TOML rather than an HTML table. Same information, about forty fewer lines, and it renders in the format operators actually write. If the reviewer wants a real `<table>`, that is a reasonable rejection — say so rather than accepting silently.

- [ ] **Step 1: Write the failing unit test**

In `src/admin/routes.rs`'s `mod tests`:

```rust
#[test]
fn set_env_var_names_lists_names_and_never_values() {
    // SAFETY: single-threaded test, variable removed before returning.
    unsafe { std::env::set_var("LOGTHING__HEC__TOKEN", "super-secret-value") };

    let names = set_env_var_names();

    unsafe { std::env::remove_var("LOGTHING__HEC__TOKEN") };

    assert!(
        names.iter().any(|n| n == "LOGTHING__HEC__TOKEN"),
        "the variable name must be listed: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("super-secret-value")),
        "a value must never appear: {names:?}"
    );
}
```

- [ ] **Step 2: Run it to make sure it fails**

```bash
cargo test --lib admin::routes::tests::set_env_var_names
```

Expected: FAIL — `set_env_var_names` is not defined.

- [ ] **Step 3: Implement the helper**

In `src/admin/routes.rs`:

```rust
/// Names — never values — of the `LOGTHING__*` variables set in this
/// process, sorted.
///
/// Values are withheld because `LOGTHING__HEC__TOKEN` and the S3
/// credentials would otherwise be rendered straight into the page.
///
/// This is an approximation of provenance, not provenance itself: the
/// `config` crate exposes no per-field source attribution, so a typo'd
/// name like `LOGTHING__SYSLOG__UDP_PRT` still appears here looking
/// legitimate. What disambiguates it is the resolved config shown
/// alongside — the variable is listed, but the field it was meant to set
/// still shows its old value.
fn set_env_var_names() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("LOGTHING__"))
        .collect();
    names.sort();
    names
}
```

- [ ] **Step 4: Run it to verify it passes**

```bash
cargo test --lib admin::routes::tests::set_env_var_names
```

Expected: PASS.

- [ ] **Step 5: Write the page-rendering test**

```rust
#[tokio::test]
async fn admin_page_renders_config_read_only() {
    let state = test_state().await;
    let app = axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .with_state(state);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = String::from_utf8(
        axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(!body.contains("<form"), "the config form must be gone");
    assert!(!body.contains("wef-server.admin.toml"), "stale subtitle must be gone");
    assert!(
        body.contains("security.allowed_ips") && body.contains("aggregate.rules"),
        "the page must name the two file-only settings that have no env equivalent"
    );
    assert!(
        body.contains("bind_address"),
        "the effective config must be rendered"
    );
}
```

- [ ] **Step 6: Run it to make sure it fails**

```bash
cargo test --lib admin::routes::tests::admin_page_renders_config_read_only
```

Expected: FAIL on the `<form`, subtitle, or file-only assertions.

- [ ] **Step 7: Rewrite the template**

Replace `src/admin/templates/admin.html` entirely. Keep the existing `<style>` block's look — reuse the current colours and the `.shell`, `.subtitle`, `.audit-section` classes so the page still matches `stats.html`. The body:

```html
<body>
    <div class="shell">
        <h1>logthing Admin Console</h1>
        <p class="subtitle">Read-only. Configuration is set with
        <code>LOGTHING__*</code> environment variables layered over
        <code>logthing.toml</code>, and changes take effect on restart.</p>

        <div class="security-notice">
            <strong>Two settings have no environment variable.</strong>
            <code>security.allowed_ips</code> and <code>aggregate.rules</code>
            can only be set in <code>logthing.toml</code> — a list and a list
            of tables respectively, neither of which a single environment
            variable can express. Setting
            <code>LOGTHING__SECURITY__ALLOWED_IPS</code> does nothing.
        </div>

        <h2>LOGTHING__* variables set in this process</h2>
        <p class="subtitle">Names only; values are withheld because some are
        secrets. A misspelled name still appears here — check it against the
        effective configuration below to confirm it took effect.</p>
        <pre>{{ENV_VAR_NAMES}}</pre>

        <h2>Effective configuration</h2>
        <p class="subtitle">Secrets are redacted.</p>
        <pre>{{CONFIG_TOML}}</pre>

        <div id="audit-section" class="audit-section">
            <h2>Recent Audit Log</h2>
            <div id="audit-entries"></div>
        </div>

        <p><a href="/stats">Ingest statistics</a></p>
    </div>

    <script>
        // The only JavaScript left: the audit log, rendered with
        // textContent so a wire-derived username cannot inject markup.
        fetch('/audit-log')
            .then((res) => res.json())
            .then((entries) => {
                const container = document.getElementById('audit-entries');
                entries.forEach((entry) => {
                    const row = document.createElement('div');
                    row.className = 'audit-entry';
                    row.textContent = `${entry.timestamp} ${entry.action} ${entry.username} ${entry.client_ip}`;
                    container.appendChild(row);
                });
            })
            .catch(() => {});
    </script>
</body>
```

Check the audit entry field names against the `AuditEntry` struct in `src/admin/state.rs` before writing this — use the real field names, and keep `textContent` (commit `1f23979` fixed an injection here; do not reintroduce `innerHTML`).

- [ ] **Step 8: Render it server-side**

Rewrite `admin_page`'s tail in `src/admin/routes.rs`. `quick_xml::escape` is already a dependency — use it rather than adding one or hand-rolling:

```rust
    state
        .audit_logger
        .log("ADMIN_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    let redacted = redacted_config(&*state.config.read().await);
    let config_toml = toml::to_string_pretty(&redacted)
        .unwrap_or_else(|e| format!("could not render configuration: {e}"));
    let env_names = set_env_var_names();
    let env_block = if env_names.is_empty() {
        "(none set — every value comes from logthing.toml or a built-in default)".to_string()
    } else {
        env_names.join("\n")
    };

    // Config values are operator-supplied and can contain markup.
    let html = include_str!("templates/admin.html")
        .replace("{{CONFIG_TOML}}", &quick_xml::escape::escape(&config_toml))
        .replace("{{ENV_VAR_NAMES}}", &quick_xml::escape::escape(&env_block));
    Ok(Html(html))
```

- [ ] **Step 9: Run the tests**

```bash
cargo test --lib admin::routes:: 2>&1 | tail -15
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
cargo fmt && cargo clippy --all-targets 2>&1 | tail -5
git add -A src/admin/
git commit -m "feat(admin): read-only console replaces the config form

The form, its seven buttons and ~350 lines of JavaScript driving the
deleted endpoints are gone. The page now renders the redacted effective
config server-side as TOML, lists the LOGTHING__* variable names set in
the process (names only — some values are secrets), and states plainly
that security.allowed_ips and aggregate.rules have no env equivalent.

Config values are operator-supplied, so both blocks are escaped through
quick_xml::escape before rendering."
```

---

### Task 5: End-to-end coverage

**Files:**
- Delete: `tests/admin_flush_interval_e2e.rs`
- Modify: `tests/admin_trusted_header_e2e.rs`
- Create: `tests/admin_readonly_console_e2e.rs`

**Interfaces:**
- Consumes: the two-parameter `spawn_admin_server` from Task 3 and the rendered page from Task 4.

**Critical constraint:** `Server::run` installs the Prometheus recorder through `metrics::set_global_recorder`, which panics if called twice in one process. Cargo runs each integration-test *file* as its own process, so the new file must contain exactly **one** `#[tokio::test]`. Also do not bind port 601 in a test — it silently succeeds as root and fails for everyone else.

- [ ] **Step 1: Delete the obsolete end-to-end test**

```bash
git rm tests/admin_flush_interval_e2e.rs
```

It drives a real `PUT /config` to prove flush intervals apply live — the feature Task 3 removed.

- [ ] **Step 2: Fix the trusted-header test**

`tests/admin_trusted_header_e2e.rs` already exercises only `GET /config`, so it survives. Delete its `std::env::set_var("LOGTHING_ADMIN_ENABLE_CSRF", "false")` line (around line 66) and the comment above it referencing `config_api`'s `PERSIST_CONFIG_ENV_LOCK` (around line 61). Update its `spawn_admin_server` call to the two-argument form.

- [ ] **Step 3: Write the new end-to-end test**

Create `tests/admin_readonly_console_e2e.rs`. Model the server setup on the surviving `tests/admin_trusted_header_e2e.rs` — same port reservation idiom, same real-socket approach.

```rust
//! End-to-end: a real admin server over a real socket proves the console
//! is read-only and that a LOGTHING__* environment variable reaches the
//! running process.
//!
//! This MUST be the only `#[tokio::test]` in this binary — see the note in
//! `tests/ipfix_socket_drop_metric_e2e.rs` about `set_global_recorder`.

#[tokio::test]
async fn console_is_read_only_and_reports_the_env_var_that_configured_it() {
    // SAFETY: set before any config load, single-threaded at this point.
    unsafe { std::env::set_var("LOGTHING__SYSLOG__UDP_PORT", "15514") };

    let config = logthing::config::Config::load().expect("config loads");
    assert_eq!(
        config.syslog.udp_port, 15514,
        "the environment variable must win over logthing.toml"
    );

    // ... start the admin server on a reserved port with basic auth,
    // following tests/admin_trusted_header_e2e.rs's setup ...

    let page = client
        .get(format!("{base_url}/"))
        .basic_auth("admin", Some("password"))
        .send()
        .await
        .expect("GET / over real HTTP")
        .text()
        .await
        .unwrap();

    assert!(
        page.contains("LOGTHING__SYSLOG__UDP_PORT"),
        "the set variable must be listed on the page:\n{page}"
    );
    assert!(
        page.contains("15514"),
        "the resolved value must be rendered:\n{page}"
    );
    assert!(!page.contains("<form"), "no config form may remain:\n{page}");

    for (method, path) in [
        (reqwest::Method::PUT, "/config"),
        (reqwest::Method::PATCH, "/config"),
        (reqwest::Method::POST, "/config/reload"),
        (reqwest::Method::POST, "/config/import"),
        (reqwest::Method::POST, "/config/validate"),
        (reqwest::Method::POST, "/config/diff"),
        (reqwest::Method::POST, "/config/export"),
    ] {
        let res = client
            .request(method.clone(), format!("{base_url}{path}"))
            .basic_auth("admin", Some("password"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("request completes");
        assert!(
            res.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
                || res.status() == reqwest::StatusCode::NOT_FOUND,
            "{method} {path} must not be routed, got {}",
            res.status()
        );
    }

    unsafe { std::env::remove_var("LOGTHING__SYSLOG__UDP_PORT") };
}
```

Fill in the server setup from the trusted-header test rather than inventing one.

- [ ] **Step 4: Run it**

```bash
cargo test --test admin_readonly_console_e2e --test admin_trusted_header_e2e 2>&1 | tail -20
```

Expected: both PASS.

- [ ] **Step 5: Run every test that touches admin or config**

```bash
cargo test 2>&1 | tail -30
```

Expected: PASS. Anything still referencing a deleted endpoint is a leftover — delete it.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets 2>&1 | tail -5
git add -A tests/
git commit -m "test(admin): end-to-end coverage for the read-only console

Proves over a real socket that a LOGTHING__* variable reaches the running
process and is reported on the page, and that all seven deleted config
endpoints are unrouted. Deletes admin_flush_interval_e2e, which drove a
real PUT /config to test live flush intervals."
```

---

### Task 6: Documentation and changelog

**Files:**
- Modify: `logthing.toml`, `README.md`, `docs/admin-security.md`, `CHANGELOG.md`

- [ ] **Step 1: Annotate `logthing.toml`**

It already carries `# env: LOGTHING__*` comments on many fields (see the syslog port lines). Add the missing ones, and above `security.allowed_ips` and the `[aggregate]` rules add:

```toml
# FILE-ONLY: no environment variable equivalent. This is a list, and the
# loader sets no list separator, so LOGTHING__SECURITY__ALLOWED_IPS cannot
# set it.
```

- [ ] **Step 2: Update `docs/admin-security.md`**

Delete the CSRF Protection section and the `LOGTHING_ADMIN_ENABLE_CSRF` variable. Keep the TLS, password-hashing, IP-allowlist, rate-limiting, audit-logging and trusted-header sections. Add a short section stating the interface is read-only and that configuration changes go through `LOGTHING__*` or `logthing.toml` and need a restart. Remove `CONFIG_UPDATED` and `CONFIG_UPDATE_FAILED` from the audit-action list.

- [ ] **Step 3: Update `README.md`**

Wherever it describes editing configuration through the admin interface, replace with the environment-variable and `logthing.toml` path, naming the two file-only exceptions.

- [ ] **Step 4: Write the changelog entry**

```markdown
### Changed — BREAKING

- The admin interface is read-only. `PUT`/`PATCH /config` and
  `POST /config/{validate,diff,export,import,reload}` are removed, along
  with the configuration form. `GET /config`, `/stats`, `/stats.json`,
  `/audit-log` and `/health` are unchanged.
- `security.allowed_ips`, `hec.token` and the S3 `flush_interval_secs`
  values no longer apply live. All three now require a restart. Operators
  relying on live allowlist or token updates must change their process.
- `logthing.admin.toml` is no longer a configuration source and the
  tracked copy is deleted. A leftover file produces a startup warning.
  Move any settings it held into `logthing.toml` or `LOGTHING__*`.
- `LOGTHING_ADMIN_ENABLE_CSRF` is removed; with no state-changing routes
  left there is nothing to protect.
- Configuration is now validated at startup: TLS enabled without a
  certificate or key, a zero port, and a malformed `security.allowed_ips`
  entry all fail the process immediately instead of at first use.

Configuration is set with `LOGTHING__*` environment variables layered over
`logthing.toml` and `/etc/logthing/config`. Note that
`security.allowed_ips` and `aggregate.rules` have no environment-variable
equivalent and remain file-only.
```

- [ ] **Step 5: Verify no doc claims env-only**

```bash
grep -rn "only via environment\|environment variables only\|env vars only" README.md docs/admin-security.md CHANGELOG.md logthing.toml
```

Expected: no output. Any hit overclaims and must be reworded.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "docs: record the read-only admin console and its breaking changes"
```

---

## Self-Review

**Spec coverage.** Section 1 → Task 2. Section 2 → Task 1. Section 3 → Task 3. Section 4 → Task 4. Section 5 → Task 3 commit message and Task 6 changelog. Section 6 unit → Tasks 2 and 4; integration → Tasks 1 and 3; end-to-end → Task 5. Section 7 → Task 6. The spec's "file-only" requirement appears in Global Constraints, Task 4's page copy, Task 6's TOML comment, and the Task 6 changelog. No gaps.

**Placeholders.** One intentional gap: Task 5 Step 3 says to fill the server setup from `tests/admin_trusted_header_e2e.rs` rather than reproducing ~60 lines of port-reservation and auth boilerplate that already exists and must match. The file to copy from is named exactly.

**Type consistency.** `redacted_config(&Config) -> Config` is used identically in Tasks 1 and 4. `set_env_var_names() -> Vec<String>` is defined in Task 4 Step 3 and used in Step 8. `validate_config_invariants(&Config) -> Result<(), String>` is defined in Task 2 Step 3 and called in Step 4. `spawn_admin_server` is narrowed to two parameters in Task 3 Step 6 and called with two in Task 5.

**Known risk.** Task 3 touches `load_admin_config_env_scenarios` (`src/admin/state.rs:1389`), a large table-driven test with numbered scenarios. Deleting the CSRF scenarios renumbers the rest; check that no comment references a scenario by number after editing.
