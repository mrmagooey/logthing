//! End-to-end: the real `logthing` binary, admin console with trusted proxy headers and an IP
//! allowlist. The allowlist is judged against the RIGHTMOST `X-Forwarded-For` hop.

mod common;

use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const SECRET: &str = "binary-e2e-shared-secret";

#[tokio::test]
async fn binary_allowlist_uses_rightmost_xff_hop() {
    let admin_port = common::free_port().to_string();
    let bind = format!("127.0.0.1:{admin_port}");
    let toml = "bind_address = \"127.0.0.1:{HTTP}\"\n[tls]\nenabled = false\n\
                [syslog]\nenabled = false\n[metrics]\nenabled = false\n";
    let _proc = common::Proc::spawn_healthy(
        BIN,
        toml,
        &[
            ("LOGTHING_ADMIN_BIND", &bind),
            ("LOGTHING_ADMIN_ENABLE_RATE_LIMIT", "false"),
            ("LOGTHING_ADMIN_TRUST_PROXY_HEADERS", "true"),
            ("LOGTHING_ADMIN_TRUSTED_HEADER_SECRET", SECRET),
            ("LOGTHING_ADMIN_TRUSTED_GROUPS", "admins"),
            ("LOGTHING_ADMIN_ALLOWED_IPS", "127.0.0.1/32"),
        ],
    )
    .await;

    let client = reqwest::Client::new();
    let base = format!("http://{bind}");
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(r) = client.get(format!("{base}/health")).send().await
            && r.status() == reqwest::StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "admin console did not come up");

    for (xff, want) in [
        ("10.9.9.9, 127.0.0.1", reqwest::StatusCode::OK),
        ("127.0.0.1, 10.9.9.9", reqwest::StatusCode::FORBIDDEN),
    ] {
        let res = client
            .get(format!("{base}/config"))
            .header("X-authentik-username", "alice")
            .header("X-authentik-groups", "admins")
            .header("X-Admin-Proxy-Secret", SECRET)
            .header("X-Forwarded-For", xff)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "X-Forwarded-For: {xff}");
    }
}
