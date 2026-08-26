//! End-to-end test proving Authentik trusted-header auth works through the
//! *real* admin HTTP path.
//!
//! Spins up the actual admin server (`logthing::admin::spawn_admin_server`)
//! as a real TCP listener with `WEF_ADMIN_TRUST_PROXY_HEADERS=true` and the
//! rest of the `WEF_ADMIN_TRUSTED_*` env vars set, then fires genuine HTTP
//! `GET /config` requests at it via `reqwest` carrying only the trusted
//! identity headers (no `Authorization` header at all). This exercises the
//! full path — real HTTP request → `trusted_header_middleware` → header
//! parsing → shared-secret check → group allowlist check → `ensure_authorized`
//! — over a real network connection through the real production entry point,
//! not a hand-built partial `Router` (see the existing
//! `e2e_trusted_header_auth_over_real_socket` test inside
//! `src/admin/routes.rs`'s own `#[cfg(test)]` module for that narrower
//! variant) and with no Basic Auth involved anywhere.
//!
//! `spawn_admin_server` internally calls `load_admin_config()`, which reads
//! all `WEF_ADMIN_*` env vars including the six trust-mode ones, so no code
//! changes are needed to test trust mode through this entry point — just
//! setting the right env vars first, exactly like the existing
//! `admin_flush_interval_e2e.rs` sets `WEF_ADMIN_BIND`/`WEF_ADMIN_USER`/etc.

use logthing::admin::spawn_admin_server;
use logthing::config::{Config, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::stats::SourceHourlyStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[tokio::test]
async fn get_config_over_real_http_succeeds_with_trusted_headers_alone_no_basic_auth() {
    // ---------------------------------------------------------------------
    // 1. The real admin HTTP server, via the actual production entry point.
    // ---------------------------------------------------------------------

    // Reserve an ephemeral port by binding to it, reading the assigned
    // port, then dropping the listener before `spawn_admin_server` binds
    // its own listener to the same address. `spawn_admin_server` binds
    // internally and does not return the bound address, so this is the
    // only way to discover a free port up front. This has a small,
    // theoretical TOCTOU race (another process could grab the port in the
    // gap between drop and rebind) but is an accepted, standard pattern for
    // tests of this shape (see `admin_flush_interval_e2e.rs`).
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let trusted_secret = "e2e-shared-secret-over-16-chars";

    // Safety: this test file contains exactly one `#[tokio::test]`, so
    // there is no other test in this binary that could race on these
    // process-global env vars. Cargo compiles each `tests/*.rs` file into
    // its own process, so this doesn't race with other integration/e2e
    // files or the lib's own `#[cfg(test)]` suite either.
    //
    // DO NOT add a second `#[tokio::test]` to this file without introducing
    // the same kind of crate-wide env-var mutex that
    // `src/admin/config_api.rs`'s `test_support::PERSIST_CONFIG_ENV_LOCK`
    // uses for `WEF_ADMIN_OVERRIDE_FILE` — that module is `pub(crate)` and
    // not reusable from here, so a from-scratch equivalent would be needed.
    unsafe {
        std::env::set_var("WEF_ADMIN_BIND", format!("127.0.0.1:{port}"));
        std::env::set_var("WEF_ADMIN_ENABLE_CSRF", "false");
        std::env::set_var("WEF_ADMIN_ENABLE_RATE_LIMIT", "false");
        std::env::set_var("WEF_ADMIN_TRUST_PROXY_HEADERS", "true");
        std::env::set_var("WEF_ADMIN_TRUSTED_HEADER_SECRET", trusted_secret);
        std::env::set_var("WEF_ADMIN_TRUSTED_GROUPS", "admins");
        // WEF_ADMIN_TRUSTED_HEADER / WEF_ADMIN_TRUSTED_GROUPS_HEADER /
        // WEF_ADMIN_TRUSTED_SECRET_HEADER are deliberately left unset so
        // this test exercises the real defaults: X-authentik-username,
        // X-authentik-groups, X-Admin-Proxy-Secret (see
        // `build_trusted_header_config` in `src/admin/state.rs`).
    }

    let initial_config = Config {
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let shared_config = Arc::new(RwLock::new(initial_config));

    spawn_admin_server(
        shared_config,
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
    );

    // ---------------------------------------------------------------------
    // 2. Wait for the admin server to actually be listening.
    // ---------------------------------------------------------------------
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(ready, "admin server did not become ready in time");

    // ---------------------------------------------------------------------
    // 3. A real GET /config request carrying only the trusted identity
    //    headers, no Authorization header at all, must succeed.
    // ---------------------------------------------------------------------
    let response = client
        .get(format!("{base_url}/config"))
        .header("X-authentik-username", "alice")
        .header("X-authentik-groups", "admins")
        .header("X-Admin-Proxy-Secret", trusted_secret)
        .send()
        .await
        .expect("GET /config request should succeed over the network");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a real HTTP request with valid trusted headers and no Basic Auth \
         must succeed through the real production spawn_admin_server entry \
         point — this is SSO-only auth, proven end to end over a real socket"
    );

    // ---------------------------------------------------------------------
    // 4. The same request with a wrong shared secret must not grant access,
    //    even with correct-looking identity headers and still no
    //    Authorization header — proving there's no accidental fallback.
    // ---------------------------------------------------------------------
    let response = client
        .get(format!("{base_url}/config"))
        .header("X-authentik-username", "alice")
        .header("X-authentik-groups", "admins")
        .header("X-Admin-Proxy-Secret", "wrong-secret")
        .send()
        .await
        .expect("GET /config request should succeed over the network");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a wrong shared secret must not grant access, even with \
         correct-looking identity headers and no Authorization header"
    );

    // ---------------------------------------------------------------------
    // 5. Real-router proof that `trusted_header_middleware` runs before
    //    `security_middleware` in the ACTUAL assembled production router
    //    (`run_admin_server`'s `.layer(...)` chain), not just in an isolated
    //    test double. A request with a valid secret and a spoofed
    //    `X-Forwarded-For` value must have that XFF IP show up as the
    //    audit log's `client_ip` — the real peer address here is loopback
    //    (this test client connects over 127.0.0.1), so any regression that
    //    flips the layer order back (silently falling through to
    //    `ConnectInfo`) would make this assert on "127.0.0.1" instead and
    //    fail.
    // ---------------------------------------------------------------------
    let spoofed_xff_ip = "203.0.113.77";
    let response = client
        .get(format!("{base_url}/config"))
        .header("X-authentik-username", "xff-tester")
        .header("X-authentik-groups", "admins")
        .header("X-Admin-Proxy-Secret", trusted_secret)
        .header("X-Forwarded-For", spoofed_xff_ip)
        .send()
        .await
        .expect("GET /config request should succeed over the network");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let audit_response = client
        .get(format!("{base_url}/audit-log"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .expect("GET /audit-log request should succeed over the network");
    assert_eq!(audit_response.status(), reqwest::StatusCode::OK);

    let entries: Vec<serde_json::Value> = audit_response
        .json()
        .await
        .expect("audit log response should be valid JSON");
    let entry = entries
        .iter()
        .find(|e| e["action"] == "CONFIG_READ" && e["username"] == "xff-tester")
        .expect("CONFIG_READ entry for the xff-tester request should exist");
    assert_eq!(
        entry["client_ip"], spoofed_xff_ip,
        "the audit entry for a valid-secret request carrying X-Forwarded-For \
         must record the XFF-derived IP — this proves trusted_header_middleware \
         runs before security_middleware in the real production router, not \
         just in an isolated middleware-chain test double; got entry: {entry:?}"
    );
}
