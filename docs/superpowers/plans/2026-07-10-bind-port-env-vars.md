# Bind-Port Env-Var Configurability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the test-coverage and documentation gap on logthing's already-working bind-port environment-variable overrides (verified end-to-end in the approved spec), with zero new runtime/production code paths.

**Architecture:** `Config::load()` (`src/config/mod.rs`) already layers `config::Environment::with_prefix("WEF").separator("__")` over TOML file sources, so every listener's port/bind-address field is already overridable via `WEF__<SECTION>__<FIELD>`. This plan adds: (1) one consolidated unit test locking in that behavior at the config-parsing layer, (2) one integration test proving an override reaches a real OS socket bind (using ipfix, the listener with both `udp_port` and `bind_address` fields), and (3) documentation in `README.md` and `logthing.toml` making the capability discoverable.

**Tech Stack:** Rust 2024 edition, `config` crate (TOML + env source layering), `tokio` (async listeners, `#[tokio::test]`).

## Global Constraints

- No new runtime/production code paths — this is tests + docs only, per the approved spec (`docs/superpowers/specs/2026-07-10-bind-port-env-vars-design.md`).
- Do NOT add a `bind_address` field to `SyslogConfig` — explicitly out of scope per the spec (syslog's bind address stays hardcoded `"0.0.0.0"`; the asymmetry is documented, not fixed).
- Do NOT introduce a second/bespoke env-var naming scheme — use only the existing `WEF__<SECTION>__<FIELD>` convention.
- Working directory for all tasks: `/home/dev/projects/logthing`, branch `feature/bind-port-env-vars` (already checked out).
- Build toolchain requirement (see project memory `build-cc-toolchain`): before running any `cargo` command, export:
  ```bash
  export PATH="$HOME/.cargo/bin:$PATH"
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  ```
  Omitting this makes the build fail with `UnknownOperatingSystem` (a zig-cc shim shadows real gcc on `PATH`). A clean first build takes ~3 minutes; incremental builds are fast.

---

## Task 1: Config-loader unit test for env-var port/bind-address overrides

**Files:**
- Modify: `src/config/mod.rs` (add one test inside the existing `#[cfg(test)] mod tests { ... }` block, near `load_reads_configuration_file`, which starts at line 1516 in the current file)

**Interfaces:**
- Consumes: `Config::load()` (defined in this same file, `impl Config`), `Config` struct fields `bind_address: SocketAddr`, `tls.port: u16`, `metrics.port: u16`, `syslog.udp_port: u16`, `syslog.tcp_port: u16`, `ipfix.udp_port: u16`, `ipfix.bind_address: String`, `zeek.tcp_port: u16`, `zeek.bind_address: String`, `suricata.tcp_port: u16`, `suricata.bind_address: String`, `sflow.udp_port: u16`, `sflow.bind_address: String`.
- Produces: nothing consumed by later tasks — this is a standalone regression test.

- [ ] **Step 1: Write the failing test**

Open `src/config/mod.rs`, find the `load_reads_configuration_file` test (search for `fn load_reads_configuration_file`). Immediately after its closing `}` (before the next test, `fn ipfix_config_defaults`), insert:

```rust
    #[test]
    fn env_vars_override_bind_ports_for_all_log_types() {
        // `WEF__<SECTION>__<FIELD>` env vars are process-global, and cargo
        // runs unit tests in this file's binary on multiple threads by
        // default. No other test in this file (or reachable from this test
        // binary) reads these particular fields, so no cross-test lock is
        // needed — but we still wrap set/load/assert in catch_unwind and
        // guarantee cleanup runs even on a failed assertion, so a panic here
        // can never leak `WEF__*` state into a test added later. This
        // mirrors the `load_reads_configuration_file` test's rename/restore
        // safety pattern above.
        let vars: &[(&str, &str)] = &[
            ("WEF__BIND_ADDRESS", "127.0.0.1:15985"),
            ("WEF__TLS__PORT", "15986"),
            ("WEF__METRICS__PORT", "19090"),
            ("WEF__SYSLOG__UDP_PORT", "15140"),
            ("WEF__SYSLOG__TCP_PORT", "16010"),
            ("WEF__IPFIX__UDP_PORT", "14739"),
            ("WEF__IPFIX__BIND_ADDRESS", "127.0.0.2"),
            ("WEF__ZEEK__TCP_PORT", "14776"),
            ("WEF__ZEEK__BIND_ADDRESS", "127.0.0.3"),
            ("WEF__SURICATA__TCP_PORT", "14777"),
            ("WEF__SURICATA__BIND_ADDRESS", "127.0.0.4"),
            ("WEF__SFLOW__UDP_PORT", "16343"),
            ("WEF__SFLOW__BIND_ADDRESS", "127.0.0.5"),
        ];

        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }

        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads with env overrides");
            assert_eq!(cfg.bind_address, "127.0.0.1:15985".parse().unwrap());
            assert_eq!(cfg.tls.port, 15986);
            assert_eq!(cfg.metrics.port, 19090);
            assert_eq!(cfg.syslog.udp_port, 15140);
            assert_eq!(cfg.syslog.tcp_port, 16010);
            assert_eq!(cfg.ipfix.udp_port, 14739);
            assert_eq!(cfg.ipfix.bind_address, "127.0.0.2");
            assert_eq!(cfg.zeek.tcp_port, 14776);
            assert_eq!(cfg.zeek.bind_address, "127.0.0.3");
            assert_eq!(cfg.suricata.tcp_port, 14777);
            assert_eq!(cfg.suricata.bind_address, "127.0.0.4");
            assert_eq!(cfg.sflow.udp_port, 16343);
            assert_eq!(cfg.sflow.bind_address, "127.0.0.5");
        });

        for (k, _) in vars {
            unsafe { std::env::remove_var(k) };
        }

        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
```

- [ ] **Step 2: Run the test to verify it currently passes (this is regression coverage for existing behavior, not new behavior — it should pass immediately, proving the spec's finding)**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib env_vars_override_bind_ports_for_all_log_types -- --nocapture
```
Expected: `test config::tests::env_vars_override_bind_ports_for_all_log_types ... ok` (1 passed). If it fails, that itself is a real finding — stop and report which field did not override rather than adjusting the test to match, since the spec's claim was empirically verified separately.

- [ ] **Step 3: Run the full existing config test suite to confirm no regressions from the new test's env-var mutation**

```bash
cargo test --lib config:: -- --test-threads=4
```
Expected: all tests in `config::tests` pass (no interference from the new test's `WEF__*` vars leaking into `load_reads_configuration_file` or others).

- [ ] **Step 4: Commit**

```bash
git add src/config/mod.rs
git commit -m "$(cat <<'EOF'
test(config): lock in env-var bind-port overrides for every log type

Config::load() already layers config::Environment::with_prefix("WEF")
over TOML sources, so WEF__<SECTION>__<FIELD> already overrides every
listener's port and bind address end-to-end. Nothing tested this
directly until now — a future config-loader refactor could silently
break it with nothing to catch it.
EOF
)"
```

---

## Task 2: Live-bind integration test proving an env-var override reaches a real socket

**Files:**
- Create: `tests/ipfix_env_var_bind_integration.rs`

**Interfaces:**
- Consumes: `logthing::config::Config::load()`; `logthing::ipfix::listener::{IpfixListener, IpfixListenerConfig, DefaultIpfixHandler}` (all `pub`, defined in `src/ipfix/listener.rs`) — `IpfixListener::new(config: IpfixListenerConfig, handler: Arc<dyn IpfixHandler>) -> Self`, `async fn start_with_shutdown(&self, shutdown_rx: tokio::sync::watch::Receiver<bool>) -> anyhow::Result<()>`, `IpfixListenerConfig { udp_port: u16, bind_address: String }`, `DefaultIpfixHandler` (unit struct implementing `IpfixHandler`).
- Produces: nothing consumed by later tasks — standalone integration test, runs in its own process (no interference with Task 1's test).

- [ ] **Step 1: Write the failing test**

Create `tests/ipfix_env_var_bind_integration.rs`:

```rust
//! Integration test: an env-var override on `ipfix.udp_port` /
//! `ipfix.bind_address` reaches a real OS-level socket bind, not just a
//! parsed `Config` struct. Ipfix is the representative listener because it
//! has both a port and a bind-address field; syslog/zeek/suricata/sflow all
//! use byte-for-byte identical `format!("{bind}:{port}").parse() -> bind()`
//! wiring (verified in the design spec), so this one listener's live-bind
//! check stands in for all five without duplicating the same proof five times.

use logthing::config::Config;
use logthing::ipfix::listener::{DefaultIpfixHandler, IpfixListener, IpfixListenerConfig};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Duration, sleep, timeout};

#[tokio::test]
async fn env_var_override_binds_ipfix_listener_on_overridden_address_and_port() {
    // Obtain a free ephemeral port on 127.0.0.1, then release it immediately
    // so the listener can bind it — same TOCTOU-avoidance idiom already used
    // by this crate's own listener tests (see
    // `src/ipfix/listener.rs::start_with_shutdown_exits_on_signal`).
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    unsafe {
        std::env::set_var("WEF__IPFIX__UDP_PORT", port.to_string());
        std::env::set_var("WEF__IPFIX__BIND_ADDRESS", "127.0.0.1");
    }
    let cfg = Config::load().expect("config loads with env overrides");
    unsafe {
        std::env::remove_var("WEF__IPFIX__UDP_PORT");
        std::env::remove_var("WEF__IPFIX__BIND_ADDRESS");
    }

    assert_eq!(cfg.ipfix.udp_port, port, "env override did not reach Config");
    assert_eq!(
        cfg.ipfix.bind_address, "127.0.0.1",
        "env override did not reach Config"
    );

    let listener_config = IpfixListenerConfig {
        udp_port: cfg.ipfix.udp_port,
        bind_address: cfg.ipfix.bind_address.clone(),
    };
    let listener = IpfixListener::new(listener_config, Arc::new(DefaultIpfixHandler));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });

    // Give the listener time to bind and enter its receive loop.
    sleep(Duration::from_millis(100)).await;

    // While the listener holds the port, a second bind on the exact same
    // 127.0.0.1:<port> must fail with AddrInUse — this is the proof the
    // override reached a real OS socket, not just a Config field.
    let second_bind = UdpSocket::bind(format!("127.0.0.1:{port}")).await;
    assert!(
        second_bind.is_err(),
        "expected AddrInUse binding {port} a second time while the listener holds it; \
         override did not actually reach a live socket bind"
    );

    // Shut the listener down and confirm the port is released afterward.
    shutdown_tx.send(true).unwrap();
    let result = timeout(Duration::from_secs(2), task).await;
    assert!(result.is_ok(), "listener did not exit after shutdown signal");

    let rebind = UdpSocket::bind(format!("127.0.0.1:{port}")).await;
    assert!(
        rebind.is_ok(),
        "port {port} should be free again after listener shutdown"
    );
}
```

- [ ] **Step 2: Run the test to verify it passes**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --test ipfix_env_var_bind_integration -- --nocapture
```
Expected: `test env_var_override_binds_ipfix_listener_on_overridden_address_and_port ... ok` (1 passed).

- [ ] **Step 3: Commit**

```bash
git add tests/ipfix_env_var_bind_integration.rs
git commit -m "$(cat <<'EOF'
test(ipfix): prove env-var port/bind-address overrides reach a live socket

Task 1 proved Config::load() parses WEF__IPFIX__UDP_PORT and
WEF__IPFIX__BIND_ADDRESS correctly; this proves the override actually
reaches UdpSocket::bind. Ipfix stands in for syslog/zeek/suricata/sflow,
which share identical bind wiring, per the design spec.
EOF
)"
```

---

## Task 3: Document per-log-type env-var port overrides in README.md

**Files:**
- Modify: `README.md` (the "Running" bash example block, currently around line 561-569, and the "Configuration Sources" numbered list right after it, currently around line 82-90)

**Interfaces:**
- Consumes: nothing (docs only).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Locate and replace the "Running" example block**

Find this exact block in `README.md` (search for `WEF__BIND_ADDRESS=0.0.0.0:5985`):

```bash
# Run with config file
./logthing

# Or with environment variables (note the double underscore)
WEF__BIND_ADDRESS=0.0.0.0:5985 WEF__TLS__ENABLED=true ./logthing

# For nested configuration values
WEF__SECURITY__MAX_CONNECTIONS=5000 WEF__METRICS__PORT=8080 ./logthing
```

Replace it with:

```bash
# Run with config file
./logthing

# Or with environment variables (note the double underscore)
WEF__BIND_ADDRESS=0.0.0.0:5985 WEF__TLS__ENABLED=true ./logthing

# For nested configuration values
WEF__SECURITY__MAX_CONNECTIONS=5000 WEF__METRICS__PORT=8080 ./logthing

# Every listener's bind port (and, except for syslog, its bind address) can
# be overridden the same way — no code or config-file changes needed:
WEF__SYSLOG__UDP_PORT=5514 WEF__SYSLOG__TCP_PORT=5601 ./logthing
WEF__IPFIX__UDP_PORT=14739 WEF__IPFIX__BIND_ADDRESS=127.0.0.1 ./logthing
WEF__ZEEK__TCP_PORT=47760 WEF__ZEEK__BIND_ADDRESS=127.0.0.1 ./logthing
WEF__SURICATA__TCP_PORT=47761 WEF__SURICATA__BIND_ADDRESS=127.0.0.1 ./logthing
WEF__SFLOW__UDP_PORT=6343 WEF__SFLOW__BIND_ADDRESS=127.0.0.1 ./logthing
```

Note: syslog has no `WEF__SYSLOG__BIND_ADDRESS` — its listener always binds
`0.0.0.0` (not configurable), unlike ipfix/zeek/suricata/sflow above.

- [ ] **Step 2: Add the same asymmetry note to the "Configuration Sources" section**

Find this exact block (search for `Configuration is loaded from multiple sources`):

```markdown
### Configuration Sources

Configuration is loaded from multiple sources (in order of precedence):
1. Default values
2. `logthing.toml` file (optional)
3. **Admin override file** (`logthing.admin.toml`, optional) - takes precedence over main config
4. `/etc/logthing/config.toml` (optional)
5. Environment variables with `WEF__` prefix (double underscore for nesting)

The admin override file is useful for runtime configuration changes without modifying the main config file.
```

Replace it with:

```markdown
### Configuration Sources

Configuration is loaded from multiple sources (in order of precedence):
1. Default values
2. `logthing.toml` file (optional)
3. **Admin override file** (`logthing.admin.toml`, optional) - takes precedence over main config
4. `/etc/logthing/config.toml` (optional)
5. Environment variables with `WEF__` prefix (double underscore for nesting)

The admin override file is useful for runtime configuration changes without modifying the main config file.

Every config field is reachable this way, including each listener's bind
port: `WEF__SYSLOG__UDP_PORT`, `WEF__SYSLOG__TCP_PORT`,
`WEF__IPFIX__UDP_PORT`, `WEF__ZEEK__TCP_PORT`, `WEF__SURICATA__TCP_PORT`,
`WEF__SFLOW__UDP_PORT`. Ipfix, Zeek, Suricata, and sFlow additionally accept
`WEF__<SECTION>__BIND_ADDRESS` to change which interface they listen on;
syslog's bind address is fixed at `0.0.0.0` and has no such override.
```

- [ ] **Step 3: Verify the edits render correctly**

```bash
grep -n "WEF__SYSLOG__UDP_PORT\|WEF__IPFIX__BIND_ADDRESS\|bind address is fixed" README.md
```
Expected: matches in both the "Running" block and the "Configuration Sources" block (at least 3 lines total).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): document per-log-type bind-port env-var overrides

The env-var section only showed BIND_ADDRESS/TLS/SECURITY/METRICS
examples, never the per-log-type listener ports — even though they
already worked. Add examples for every listener and note the syslog
bind-address asymmetry.
EOF
)"
```

---

## Task 4: Inline TOML comments naming each port's override env var

**Files:**
- Modify: `logthing.toml` (all 104 lines currently; edits touch the `[syslog]`, `[zeek]`, `[ipfix]` sections — `[sflow]`/`[suricata]` are not present in this file today, see note in Step 3)

**Interfaces:**
- Consumes: nothing (docs only).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add inline comments to the `[syslog]` section**

Find this exact block (search for `udp_port = 514      # Standard syslog UDP port`):

```toml
[syslog]
enabled = true
udp_port = 514      # Standard syslog UDP port
tcp_port = 601      # Standard syslog TCP port (RFC 6587)
parse_dns = true    # Enable DNS log parsing
```

Replace it with:

```toml
# Bind ports below can be overridden without editing this file, via
# WEF__SYSLOG__UDP_PORT / WEF__SYSLOG__TCP_PORT env vars. Unlike the other
# listeners below, syslog's bind address is fixed at 0.0.0.0 — there is no
# WEF__SYSLOG__BIND_ADDRESS.
[syslog]
enabled = true
udp_port = 514      # Standard syslog UDP port (env: WEF__SYSLOG__UDP_PORT)
tcp_port = 601      # Standard syslog TCP port (RFC 6587) (env: WEF__SYSLOG__TCP_PORT)
parse_dns = true    # Enable DNS log parsing
```

- [ ] **Step 2: Add inline comments to the `[zeek]` section**

Find this exact block (search for `tcp_port     = 47760       # default Zeek NDJSON listener port`):

```toml
[zeek]
enabled      = false
tcp_port     = 47760       # default Zeek NDJSON listener port
bind_address = "0.0.0.0"
```

Replace it with:

```toml
[zeek]
enabled      = false
tcp_port     = 47760       # default Zeek NDJSON listener port (env: WEF__ZEEK__TCP_PORT)
bind_address = "0.0.0.0"   # env: WEF__ZEEK__BIND_ADDRESS
```

- [ ] **Step 3: Add inline comments to the `[ipfix]` section**

Find this exact block (search for `udp_port     = 4739        # IANA-standard IPFIX port`):

```toml
[ipfix]
enabled      = false
udp_port     = 4739        # IANA-standard IPFIX port
bind_address = "0.0.0.0"
```

Replace it with:

```toml
[ipfix]
enabled      = false
udp_port     = 4739        # IANA-standard IPFIX port (env: WEF__IPFIX__UDP_PORT)
bind_address = "0.0.0.0"   # env: WEF__IPFIX__BIND_ADDRESS
```

Note: `[sflow]` and `[suricata]` sections are not present in `logthing.toml`
today (they fall back to `Config`'s built-in defaults, same as `[ipfix]`/
`[zeek]` did before being added to this file at some point). Do not add new
`[sflow]`/`[suricata]` sections in this task — that would be scope creep
beyond documenting the fields that already have example blocks in this
file. Their env-var overrides are already covered by the README changes in
Task 3.

- [ ] **Step 4: Verify the edits**

```bash
grep -n "env: WEF__" logthing.toml
```
Expected: 6 matches (2 in `[syslog]`, 2 in `[zeek]`, 2 in `[ipfix]`).

- [ ] **Step 5: Confirm the file still parses (config tests exercise it indirectly, but TOML comments can't break parsing — this step is a sanity check, not a strict requirement)**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib load_reads_configuration_file -- --nocapture
```
Expected: `test config::tests::load_reads_configuration_file ... ok`.

- [ ] **Step 6: Commit**

```bash
git add logthing.toml
git commit -m "$(cat <<'EOF'
docs(config): name each listener's override env var inline in logthing.toml

Same discoverability gap as the README: the port/bind_address fields
already accept WEF__<SECTION>__<FIELD> overrides but nothing in the
example config said so.
EOF
)"
```

---

## Final Verification

- [ ] **Step 1: Run the full test suite**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test
```
Expected: all tests pass, including the two new ones from Tasks 1 and 2.

- [ ] **Step 2: Confirm no unintended runtime code changed**

```bash
git diff master --stat
```
Expected: only `docs/superpowers/specs/2026-07-10-bind-port-env-vars-design.md`,
`docs/superpowers/plans/2026-07-10-bind-port-env-vars.md`, `src/config/mod.rs`,
`tests/ipfix_env_var_bind_integration.rs`, `README.md`, `logthing.toml` —
no files under `src/` other than `src/config/mod.rs` (test-only addition).
