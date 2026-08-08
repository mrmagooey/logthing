# Remove Generic Forwarding Feature Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the `[forwarding]` config section (`buffer_size`, `retry_attempts`, `destinations`) and the `Forwarder`/`Destination` HTTP/TCP/UDP/syslog-forwarding feature it drives, everywhere: source, admin UI, TOML configs, and living docs.

**Architecture:** This is a pure deletion/refactor plan, not new-feature work, so the usual "write failing test, implement" TDD cycle doesn't apply. Instead each task's steps are: make the deletion → run the build/test commands that prove nothing else depended on it → commit. Task boundaries follow compile-unit coupling, not file boundaries: `admin.html`'s JS would throw at runtime (`Cannot set property of undefined`) if the Rust `Config.forwarding` field were removed without also removing the JS that writes `payload.forwarding.buffer_size`, so those land in one task.

**Tech Stack:** Rust (serde/config crate for TOML deserialization, no `deny_unknown_fields` anywhere — confirmed via `grep -n deny_unknown_fields src/config/mod.rs` returning nothing), vanilla JS in `admin.html`, TOML config files.

## Global Constraints

- Scope is the *entire* generic `Forwarder` feature (HTTP/TCP/UDP/syslog destination forwarding for WEF events), decided explicitly over the alternative of removing only the dead config fields — see conversation history: `Forwarder::new()` discards its `_destinations` argument and always starts with `destinations: Vec::new()`, so the feature has never been reachable via config, only via direct construction in tests.
- Do **not** touch `docs/superpowers/specs/2026-06-21-syslog-ipfix-s3-persistence-options.md`, `docs/superpowers/plans/2026-06-21-ipfix-phase4-ipfix-s3.md`, or any other dated `docs/superpowers/{specs,plans}/*.md` file — these are historical design records, not living documentation, and editing them would falsify the historical record of what was decided at the time.
- Do **not** touch `src/forwarding/{buffered_writer,drop_log,flush_registry,generic_s3,iceberg_descriptor,ipfix_s3,local_sink,parquet_s3,s3_sink,sflow_s3,structured_syslog_s3,suricata_s3,syslog_s3,zeek_s3}.rs` — these are the real, working Parquet/S3 sink modules and are unrelated to the `Forwarder`/`Destination` generic-forwarding code being removed. Only the top-level `Forwarder`/`Destination` types and their impls in `src/forwarding/mod.rs` go; the `pub mod ...;` declarations in that same file stay.
- `README.md`'s pre-existing stale `wef_events_forwarded_total` / `wef_connections_total` / `wef_active_subscriptions` metrics documentation (lines 734-737) is a separate, unrelated inaccuracy (those metrics aren't emitted anywhere in `src/`) — out of scope, do not fix as a drive-by.

---

### Task 1: Remove `Forwarder`/`ForwardingConfig` from Rust source and the admin UI

**Files:**
- Modify: `src/forwarding/mod.rs` (delete `Forwarder`/`Destination` structs, all impls, and the `#[cfg(test)] mod tests` block; keep the 14 `pub mod ...;` lines and drop now-unused top-of-file imports)
- Modify: `src/config/mod.rs` (delete `ForwardingConfig`, `DestinationConfig`, `ForwardProtocol`, their default fns, and the `forwarding` field on `Config`; fix one test assertion)
- Modify: `src/server/mod.rs` (delete `AppState.forwarder` field and every construction/use site)
- Modify: `tests/otlp_e2e.rs` (delete `Forwarder` construction in `build_app_state`)
- Modify: `src/admin/config_api.rs` (delete the forwarding-destinations validation loop)
- Modify: `src/admin/mod.rs` (delete the two tests that exist only to exercise that validation loop)
- Modify: `src/admin/templates/admin.html` (delete the Forwarding fieldset and its JS bindings)

**Interfaces:**
- Consumes: nothing from other tasks (this is Task 1).
- Produces: a `Config` struct with no `forwarding` field, an `AppState` with no `forwarder` field, and a `src/forwarding/mod.rs` that only re-exports the 14 sink submodules. Task 2 (TOML cleanup) and Task 3 (docs) depend on this being done first, since they reference the same field/type names being deleted here.

- [ ] **Step 1: Gut `src/forwarding/mod.rs` down to its module declarations**

Replace the entire file content with:

```rust
pub mod buffered_writer;
pub mod drop_log;
pub mod flush_registry;
pub mod generic_s3;
pub mod iceberg_descriptor;
pub mod ipfix_s3;
pub mod local_sink;
pub mod parquet_s3;
pub mod s3_sink;
pub mod sflow_s3;
pub mod structured_syslog_s3;
pub mod suricata_s3;
pub mod syslog_s3;
pub mod zeek_s3;
```

This removes the `Forwarder`/`Destination` structs, all `impl Forwarder` methods (`new`, `initialize`, `forward`, `forward_event`, `forward_http`, `forward_tcp`, `forward_udp`, `forward_syslog`, `calculate_priority`), and the 18-test `#[cfg(test)] mod tests` block at the bottom of the file — none of it is reachable from config, and Task-1's later steps remove every call site.

- [ ] **Step 2: Remove `ForwardingConfig`/`DestinationConfig`/`ForwardProtocol` from `src/config/mod.rs`**

Remove the `forwarding` field from the `Config` struct:

```rust
    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub forwarding: ForwardingConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
```
becomes
```rust
    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
```

Remove the three type definitions (`ForwardingConfig`, `DestinationConfig`, `ForwardProtocol`):

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub destinations: Vec<DestinationConfig>,

    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DestinationConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub protocol: ForwardProtocol,
    #[serde(default = "default_destination_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}
```
delete entirely (both structs). Also delete the enum a few lines further down:
```rust
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProtocol {
    #[default]
    Http,
    Https,
    Tcp,
    Udp,
    Syslog,
}
```
delete entirely.

Remove the `forwarding: ForwardingConfig::default(),` line from `impl Default for Config`:
```rust
            security: SecurityConfig::default(),
            forwarding: ForwardingConfig::default(),
            logging: LoggingConfig::default(),
```
becomes
```rust
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
```

Remove the `impl Default for ForwardingConfig` block:
```rust
impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            destinations: Vec::new(),
            buffer_size: default_buffer_size(),
            retry_attempts: default_retry_attempts(),
        }
    }
}
```
delete entirely.

Remove the three now-unused default functions:
```rust
fn default_buffer_size() -> usize {
    10000
}

fn default_retry_attempts() -> u32 {
    3
}
```
delete both (they sit right before `fn default_log_level`), and further down:
```rust
fn default_destination_enabled() -> bool {
    true
}
```
delete (it sits right after `fn default_metrics_port`).

Fix the one test that asserts on the field being removed — `load_reads_configuration_file`:
```rust
        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads");
            assert!(!cfg.tls.enabled, "logthing.toml disables TLS");
            assert!(!cfg.forwarding.destinations.is_empty());
        });
```
becomes
```rust
        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads");
            assert!(!cfg.tls.enabled, "logthing.toml disables TLS");
        });
```

- [ ] **Step 3: Remove `forwarder` from `src/server/mod.rs`**

Remove the import:
```rust
use crate::forwarding::Forwarder;
use crate::forwarding::drop_log::{DropKind, DropSite};
```
becomes
```rust
use crate::forwarding::drop_log::{DropKind, DropSite};
```

Remove the field from `AppState`:
```rust
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub throughput: Arc<ThroughputStats>,
    pub forwarder: Forwarder,
    pub parser: WefParser,
```
becomes
```rust
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub throughput: Arc<ThroughputStats>,
    pub parser: WefParser,
```

Update the doc comment above `Server::new` (it currently says "including the forwarder"):
```rust
    /// Initializes all components including the forwarder, parser, and optional
    /// Parquet S3 forwarder.
```
becomes
```rust
    /// Initializes all components including the parser and optional
    /// Parquet S3 forwarder.
```

Remove the construction in `Server::new`:
```rust
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;

        #[cfg(feature = "kerberos-auth")]
```
becomes
```rust
        #[cfg(feature = "kerberos-auth")]
```

Remove the `forwarder,` line from the `AppState { ... }` construction in `Server::new` (around line 258 — find the `let state = Arc::new(AppState {` block and delete the `forwarder,` line inside it).

Remove the call site and its comment in `process_single_event`:
```rust
    let event_type = describe_event_type(&event);
    state.throughput.record_event(event_type).await;

    // Pass Arc to forwarder (cheap clone of Arc, not the event)
    state.forwarder.forward(event.clone()).await;

    // Send to Parquet S3 and/or local-disk via channel (non-blocking, independent
```
becomes
```rust
    let event_type = describe_event_type(&event);
    state.throughput.record_event(event_type).await;

    // Send to Parquet S3 and/or local-disk via channel (non-blocking, independent
```
Also reword the stale comment a few lines above it:
```rust
async fn process_single_event(state: &Arc<AppState>, event: WindowsEvent) {
    // Wrap event in Arc to avoid cloning for each forwarder
    let event = Arc::new(event);
```
becomes
```rust
async fn process_single_event(state: &Arc<AppState>, event: WindowsEvent) {
    let event = Arc::new(event);
```

Remove the construction in the `#[cfg(test)]` helper `build_state_with_config`:
```rust
    async fn build_state_with_config(config: Config) -> Arc<AppState> {
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            forwarder,
            parser: WefParser::new(),
```
becomes
```rust
    async fn build_state_with_config(config: Config) -> Arc<AppState> {
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            parser: WefParser::new(),
```

- [ ] **Step 4: Remove `Forwarder` from `tests/otlp_e2e.rs`**

```rust
    use logthing::forwarding::Forwarder;
```
delete this `use` line.

```rust
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;
        Arc::new(AppState {
```
becomes
```rust
        Arc::new(AppState {
```
and remove the `forwarder,` line inside that `AppState { ... }` literal.

- [ ] **Step 5: Remove forwarding validation from `src/admin/config_api.rs`**

```rust
    // Validate forwarding destinations
    for dest in &config_to_validate.forwarding.destinations {
        if dest.name.is_empty() {
            errors.push("Forwarding destination name cannot be empty".to_string());
        }
        if dest.url.is_empty() {
            errors.push(format!(
                "Forwarding destination '{}' URL cannot be empty",
                dest.name
            ));
        }
    }

    // Validate metrics port
```
becomes
```rust
    // Validate metrics port
```

- [ ] **Step 6: Remove the two now-dead tests in `src/admin/mod.rs`**

Delete both `#[tokio::test]` functions entirely — `validate_config_with_empty_destination_name` and `validate_config_with_empty_destination_url` (in `mod additional_validation_tests`, they only exist to exercise the validation loop removed in Step 5, and reference `crate::config::DestinationConfig` / `crate::config::ForwardProtocol` which no longer exist):

```rust
        #[tokio::test]
        async fn validate_config_with_empty_destination_name() {
            let state = test_state().await;
            let auth = TypedHeader(Authorization::basic("user", "pass"));
            let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

            let mut config = Config::default();
            config
                .forwarding
                .destinations
                .push(crate::config::DestinationConfig {
                    name: "".to_string(),
                    url: "http://test".to_string(),
                    protocol: crate::config::ForwardProtocol::Http,
                    enabled: true,
                    headers: std::collections::HashMap::new(),
                });

            let Json(result) = config_api::validate_config(
                axum::extract::State(state),
                axum::extract::ConnectInfo(addr),
                Some(auth),
                axum::Json(config),
            )
            .await
            .expect("validation runs");

            assert!(!result.valid);
            assert!(
                result
                    .errors
                    .iter()
                    .any(|e: &String| e.contains("name cannot be empty"))
            );
        }

        #[tokio::test]
        async fn validate_config_with_empty_destination_url() {
            let state = test_state().await;
            let auth = TypedHeader(Authorization::basic("user", "pass"));
            let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

            let mut config = Config::default();
            config
                .forwarding
                .destinations
                .push(crate::config::DestinationConfig {
                    name: "test".to_string(),
                    url: "".to_string(),
                    protocol: crate::config::ForwardProtocol::Http,
                    enabled: true,
                    headers: std::collections::HashMap::new(),
                });

            let Json(result) = config_api::validate_config(
                axum::extract::State(state),
                axum::extract::ConnectInfo(addr),
                Some(auth),
                axum::Json(config),
            )
            .await
            .expect("validation runs");

            assert!(!result.valid);
            assert!(
                result
                    .errors
                    .iter()
                    .any(|e: &String| e.contains("URL cannot be empty"))
            );
        }
```

Delete both in full, leaving the surrounding `mod additional_validation_tests { ... }` block with its remaining tests (e.g. `validate_config_with_metrics_port_zero`) intact.

- [ ] **Step 7: Remove the Forwarding fieldset from `src/admin/templates/admin.html`**

```html
            <fieldset>
                <legend>Forwarding</legend>
                <div class="grid-3">
                    <label>Buffer Size
                        <input type="number" name="forwarding_buffer_size" min="0" />
                    </label>
                    <label>Retry Attempts
                        <input type="number" name="forwarding_retry_attempts" min="0" />
                    </label>
                </div>
                <label>Destinations (JSON array)
                    <textarea name="forwarding_destinations" placeholder='[{"name":"siem","url":"https://..."}]'></textarea>
                </label>
            </fieldset>

            <fieldset>
                <legend>Metrics</legend>
```
becomes
```html
            <fieldset>
                <legend>Metrics</legend>
```

Remove the JS that loads those fields:
```javascript
            form.forwarding_buffer_size.value = cfg.forwarding?.buffer_size ?? '';
            form.forwarding_retry_attempts.value = cfg.forwarding?.retry_attempts ?? '';
            form.forwarding_destinations.value = JSON.stringify(cfg.forwarding?.destinations || [], null, 2);

            form.metrics_enabled.checked = cfg.metrics?.enabled ?? false;
```
becomes
```javascript
            form.metrics_enabled.checked = cfg.metrics?.enabled ?? false;
```

Remove the JS that builds those fields into the save payload (this one is load-bearing: leaving it in after `Config` loses its `forwarding` field would throw `Cannot set property 'buffer_size' of undefined` the next time anyone saves config in the admin UI):
```javascript
            payload.forwarding.buffer_size = toInt(form.forwarding_buffer_size.value, payload.forwarding.buffer_size);
            payload.forwarding.retry_attempts = toInt(form.forwarding_retry_attempts.value, payload.forwarding.retry_attempts);
            const parsedDestinations = JSON.parse(form.forwarding_destinations.value || '[]');
            if (!Array.isArray(parsedDestinations)) {
                throw new Error('Destinations must be a JSON array');
            }
            payload.forwarding.destinations = parsedDestinations;

            payload.metrics.enabled = form.metrics_enabled.checked;
```
becomes
```javascript
            payload.metrics.enabled = form.metrics_enabled.checked;
```

- [ ] **Step 8: Build and run the full workspace test suite**

Run:
```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --workspace
cargo test --workspace
```
Expected: clean build, no references to `Forwarder`, `ForwardingConfig`, `DestinationConfig`, or `ForwardProtocol` remain anywhere (confirm with `grep -rn "ForwardingConfig\|DestinationConfig\|ForwardProtocol\|forwarding::Forwarder" src/ tests/` returning nothing), all tests pass. If `cargo test` surfaces any other call site this plan missed, fix it here before moving on — do not proceed to Task 2 with a red build.

- [ ] **Step 9: Commit**

```bash
git add src/forwarding/mod.rs src/config/mod.rs src/server/mod.rs tests/otlp_e2e.rs src/admin/config_api.rs src/admin/mod.rs src/admin/templates/admin.html
git commit -m "refactor: remove unreachable generic HTTP/TCP/UDP/syslog forwarding feature

Forwarder::new() has always discarded its destinations argument and
started empty, so [forwarding] config (buffer_size, retry_attempts,
destinations) has never had any effect at runtime -- only direct
Forwarder construction in tests exercised the forward_http/tcp/udp/
syslog code paths. Removing the whole feature rather than just the
dead config fields, since leaving Forwarder in place with no config
path to reach it is equally dead code."
```

---

### Task 2: Remove `[forwarding]` blocks from TOML config files

**Files:**
- Modify: `logthing.toml`
- Modify: `logthing.admin.toml`
- Modify: `tests/e2e/simulation-environment/config/logthing-kerberos.toml`
- Modify: `tests/e2e/simulation-environment/config/logthing.toml`
- Modify: `tests/e2e/simulation-environment/config/logthing-10k-sustained.toml`
- Modify: `tests/e2e/simulation-environment/config/logthing-tls.toml`
- Modify: `tests/e2e/real-ad-environment/ansible/templates/wef-server.toml.j2`

**Interfaces:**
- Consumes: Task 1's removal of the `ForwardingConfig` Rust type (these fields are now unread — the `config` crate silently ignores unknown TOML keys since no struct in this codebase uses `#[serde(deny_unknown_fields)]`, confirmed empty grep result, so this task is safe to do after Task 1 without a compile dependency, but is sequenced second because leaving stale `[forwarding]` blocks around after the feature is gone is confusing to anyone reading these files).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `logthing.toml`**

Remove lines 16-39 (the `[forwarding]` section, both `[[forwarding.destinations]]` example blocks, and the misleading `# Parquet S3 Forwarder Example` comment above the second one — that comment is inaccurate on top of being for a dead feature: this `destinations` entry never actually persisted to S3, real S3 Parquet persistence is the separate `[wef.s3]`-style config used by the real sink modules):

```toml
[forwarding]
buffer_size = 10000
retry_attempts = 3

[[forwarding.destinations]]
name = "example"
url = "http://localhost:9200/events"
protocol = "http"
enabled = false

# Parquet S3 Forwarder Example (stores events in S3-compatible storage as Parquet files)
[[forwarding.destinations]]
name = "parquet-s3"
url = "s3://wef-events"
protocol = "http"
enabled = false
[forwarding.destinations.headers]
endpoint = "http://localhost:9000"  # S3-compatible endpoint (MinIO, etc.)
region = "us-east-1"
access-key = "minioadmin"
secret-key = "minioadmin"
max-size-mb = "100"          # Flush when buffer reaches 100MB
flush-interval-secs = "900"  # Flush every 15 minutes (900 seconds)
buffer-path = "/tmp/wef-events"  # Local temp directory for Parquet files

[metrics]
```
becomes
```toml
[metrics]
```
(i.e. delete straight through from `[forwarding]` to the blank line right before `[metrics]`).

- [ ] **Step 2: `logthing.admin.toml`**

```toml
[security.kerberos]
enabled = false

[forwarding]
destinations = []
buffer_size = 10000
retry_attempts = 3

[logging]
```
becomes
```toml
[security.kerberos]
enabled = false

[logging]
```

- [ ] **Step 3: `tests/e2e/simulation-environment/config/logthing-kerberos.toml`**

Delete the 3-line `[forwarding]` block (`buffer_size = 10`, `retry_attempts = 1`) at lines 18-20, plus the blank line separating it from its neighbors, following the same pattern as Steps 1-2 (delete the section header, its keys, and the trailing blank line, leaving the sections before and after adjacent with a single blank line between them).

- [ ] **Step 4: `tests/e2e/simulation-environment/config/logthing.toml`**

Delete the 3-line `[forwarding]` block (`buffer_size = 10000`, `retry_attempts = 3`) at lines 65-67, same pattern.

- [ ] **Step 5: `tests/e2e/simulation-environment/config/logthing-10k-sustained.toml`**

Delete the 3-line `[forwarding]` block (`buffer_size = 100000`, `retry_attempts = 3`) at lines 15-17, same pattern.

- [ ] **Step 6: `tests/e2e/simulation-environment/config/logthing-tls.toml`**

Delete the 3-line `[forwarding]` block (`buffer_size = 10`, `retry_attempts = 1`) at lines 23-25, same pattern.

- [ ] **Step 7: `tests/e2e/real-ad-environment/ansible/templates/wef-server.toml.j2`**

Delete the 3-line `[forwarding]` block (`buffer_size = 1000`, `retry_attempts = 3`) at lines 33-35, same pattern.

- [ ] **Step 8: Verify no TOML config still references the removed section**

Run:
```bash
grep -rn --exclude-dir=target --exclude-dir=.git "\[forwarding\]\|buffer_size\s*=\|retry_attempts\s*=" logthing.toml logthing.admin.toml tests/e2e/
```
Expected: no output (all three patterns were unique to the now-deleted `[forwarding]` blocks in these files — confirm nothing else in these specific files happened to use those key names before treating a nonzero result as a real leftover).

- [ ] **Step 9: Commit**

```bash
git add logthing.toml logthing.admin.toml tests/e2e/simulation-environment/config/logthing-kerberos.toml tests/e2e/simulation-environment/config/logthing.toml tests/e2e/simulation-environment/config/logthing-10k-sustained.toml tests/e2e/simulation-environment/config/logthing-tls.toml tests/e2e/real-ad-environment/ansible/templates/wef-server.toml.j2
git commit -m "chore: remove [forwarding] blocks from config files

Follows removal of the ForwardingConfig/Forwarder Rust types -- these
TOML blocks configured a feature that was never actually reachable
(Forwarder::new() discarded the destinations it was given)."
```

---

### Task 3: Update living docs (`README.md`, e2e performance-test README)

**Files:**
- Modify: `README.md`
- Modify: `tests/e2e/simulation-environment/performance-test/README.md`

**Interfaces:**
- Consumes: Tasks 1-2's removal (this task documents that removal — no code/type dependency, pure prose).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `README.md` — feature bullet list**

```markdown
- **Parquet S3 Storage**: Aggregate events into Parquet files and store in S3-compatible storage
- **TLS/SSL Encryption**: Secure connections with certificate support
- **IP Whitelisting**: Control which hosts can connect
- **Multiple Output Formats**: Forward to HTTP, TCP, UDP, Syslog, or S3 destinations
- **High Performance**: Async I/O with Tokio for handling 100+ hosts
```
becomes
```markdown
- **Parquet S3 Storage**: Aggregate events into Parquet files and store in S3-compatible storage
- **TLS/SSL Encryption**: Secure connections with certificate support
- **IP Whitelisting**: Control which hosts can connect
- **High Performance**: Async I/O with Tokio for handling 100+ hosts
```
(the S3-storage capability is already covered by the bullet directly above it and the IPFIX/Zeek bullets earlier in the list; the HTTP/TCP/UDP/Syslog generic-destination claim is what's being removed).

- [ ] **Step 2: `README.md` — example config block**

```toml
[security]
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
max_connections = 10000
connection_timeout_secs = 300

[[forwarding.destinations]]
name = "elasticsearch"
url = "https://elasticsearch:9200/events"
protocol = "https"
enabled = true

[[forwarding.destinations]]
name = "syslog"
url = "syslog://log-server:514"
protocol = "syslog"
enabled = true

[metrics]
```
becomes
```toml
[security]
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
max_connections = 10000
connection_timeout_secs = 300

[metrics]
```

- [ ] **Step 3: `README.md` — architecture diagram**

```
                    ┌─────────────────────────────────────┐
                    │           WEF Server                │
  Windows Hosts →   │  ┌─────────┐  ┌─────────────────┐  │   → Forwarders
      (HTTPS)       │  │  WEF    │  │  Syslog Parser  │  │        ↓
                    │  │Handler  │  │  (RFC 3164/5424)│  │   ┌─────────────┐
                    │  └────┬────┘  └────────┬────────┘  │   │  HTTP/HTTPS │
                    │       │                │           │   │  TCP/UDP    │
                    │       ↓                ↓           │   │  S3         │
                    │  ┌─────────────────────────────┐   │   └─────────────┘
                    │  │   Event Processors          │   │
```
becomes
```
                    ┌─────────────────────────────────────┐
                    │           WEF Server                │
  Windows Hosts →   │  ┌─────────┐  ┌─────────────────┐  │   → S3 (Parquet)
      (HTTPS)       │  │  WEF    │  │  Syslog Parser  │  │
                    │  │Handler  │  │  (RFC 3164/5424)│  │
                    │  └────┬────┘  └────────┬────────┘  │
                    │       │                │           │
                    │       ↓                ↓           │
                    │  ┌─────────────────────────────┐   │
                    │  │   Event Processors          │   │
```
(check the remaining lines of this diagram block below what's shown here — read `README.md` around this region before editing, and drop/adjust any other line that still references the deleted "Forwarders" box so the box borders stay visually aligned; the exact remaining diagram lines below this excerpt are unaffected and don't need changes, only the `→ Forwarders` / `HTTP/HTTPS, TCP/UDP, S3` box being replaced above does).

- [ ] **Step 4: `tests/e2e/simulation-environment/performance-test/README.md`**

```markdown
### Server Configuration (Sustained 10k Test)

The `config/logthing-10k-sustained.toml` configures the server for the sustained test:

```toml
[forwarding]
buffer_size = 10
retry_attempts = 1

[[forwarding.destinations]]
name = "parquet"
url = "s3://wef-events/archive"
protocol = "http"
enabled = true

[forwarding.destinations.headers]
endpoint = "http://minio:9000"
"max-size-mb" = "100"          # 100MB parquet file limit
"flush-interval-secs" = "5"     # Flush every 5 seconds
"buffer-path" = "/tmp/wef-events"
```

## Exit Codes
```
delete the entire `### Server Configuration (Sustained 10k Test)` subsection (heading, intro sentence, and code block) — note this example was already out of sync with the real file even before this plan (the actual `logthing-10k-sustained.toml` has never had a `[[forwarding.destinations]]` block, only `buffer_size`/`retry_attempts`), so nothing of current value is lost. Result:
```markdown
## Exit Codes
```

- [ ] **Step 5: Verify**

Run:
```bash
grep -n "forwarding\|Forwarder" README.md tests/e2e/simulation-environment/performance-test/README.md
```
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add README.md tests/e2e/simulation-environment/performance-test/README.md
git commit -m "docs: remove references to the deleted generic forwarding feature"
```

---

### Task 4: Final full-repo verification sweep

**Files:** none modified — this task only runs verification commands.

**Interfaces:**
- Consumes: the completed state of Tasks 1-3.
- Produces: nothing (terminal task).

- [ ] **Step 1: Confirm no residual references anywhere outside the intentionally-excluded historical docs**

```bash
grep -rn --exclude-dir=target --exclude-dir=.git "ForwardingConfig\|DestinationConfig\|ForwardProtocol\|forwarding::Forwarder\|forwarding_buffer_size\|forwarding_retry_attempts\|forwarding_destinations" . 2>/dev/null
```
Expected: only hits inside `docs/superpowers/specs/2026-06-21-syslog-ipfix-s3-persistence-options.md` and `docs/superpowers/plans/2026-06-21-ipfix-phase4-ipfix-s3.md` (the historical records this plan deliberately excludes per Global Constraints). Any hit outside `docs/superpowers/` is a miss — go fix it before continuing.

- [ ] **Step 2: Full build, full test, clippy**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: all three succeed with no errors or new warnings.

- [ ] **Step 3: Confirm the TOML files this codebase actually loads at startup still parse and start the server cleanly**

```bash
cargo run --release -- --config logthing.toml &
SERVER_PID=$!
sleep 2
curl -sf http://127.0.0.1:9090/metrics > /dev/null && echo "UP"
kill $SERVER_PID
```
(adjust the `--config` flag/port to whatever `Config::load()` actually expects if it differs from a CLI flag — check `src/main.rs` first if unsure; the goal is just confirming the edited `logthing.toml` still boots the server without a deserialization error).
Expected: `UP` printed, no panic/error in server output before that.

No commit for this task — it's verification only, not a change.

## Self-Review

- **Spec coverage:** every file identified during investigation (7 Rust source files, 7 TOML configs, 2 living docs) has a task step. Historical `docs/superpowers/` files are explicitly excluded with a stated reason, not silently dropped.
- **Placeholder scan:** every step shows exact before/after code, not a description of a change.
- **Type/name consistency:** `Forwarder`, `ForwardingConfig`, `DestinationConfig`, `ForwardProtocol`, `AppState.forwarder` are referenced identically across Tasks 1-4, matching the names confirmed present in the codebase during investigation.
