//! End-to-end tests of the Windows-shaped WEF flow against the real `logthing` binary over
//! plain HTTP: one keep-alive client plays Enumerate, Heartbeat, Events (SLDC + UTF-16) and
//! SubscriptionEnd, and the events must land in Parquet. Also: the binary must refuse to start
//! an unauthenticated WEF topology without the explicit opt-in.

mod common;

use arrow::array::Array;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const MACHINE: &str = "win10.example.com";

const BASE: &str = r#"
bind_address = "127.0.0.1:{HTTP}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = false
"#;

fn config(wef_toml: &str) -> String {
    format!(
        "{BASE}{wef_toml}\n[wef.local]\ndirectory = \"{{DIR}}/out/wef\"\nflush_interval_secs = 1\n"
    )
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    envelope: &str,
    sldc: bool,
) -> (reqwest::StatusCode, String) {
    let body = if sldc {
        common::sldc_literals(&common::utf16(envelope))
    } else {
        common::utf16(envelope)
    };
    let mut req = client
        .post(url)
        .header("Content-Type", "application/soap+xml;charset=UTF-16");
    if sldc {
        req = req.header("Content-Encoding", "SLDC");
    }
    let resp = req.body(body).send().await.expect("POST");
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap();
    let text = if bytes.is_empty() {
        String::new()
    } else {
        common::decode_utf16(&bytes)
    };
    (status, text)
}

#[tokio::test]
async fn test_e2e_windows_shaped_flow_lands_in_parquet() {
    let toml = config(&common::wef_toml("http://127.0.0.1:{HTTP}"));
    let mut p = common::Proc::spawn(BIN, &toml, &[]);
    p.wait_healthy().await;
    let client = reqwest::Client::builder()
        // Keep-alive reuse is not asserted (reqwest exposes no connection counter); a single
        // pooled HTTP/1.1 client is what makes consecutive requests eligible for reuse.
        .pool_max_idle_per_host(1)
        .http1_only()
        .build()
        .unwrap();

    let (st, body) = post(
        &client,
        &format!("{}/wsman", p.base()),
        &common::enumerate_envelope("e1", MACHINE),
        false,
    )
    .await;
    assert_eq!(st, 200, "{}", p.logs());
    let url = common::notify_to(&body);
    assert_eq!(
        url,
        format!("{}/wsman/subscriptions/{}", p.base(), common::TEST_SUB_UUID)
    );

    let (st, body) = post(
        &client,
        &url,
        &common::heartbeat_envelope("e2", MACHINE),
        true,
    )
    .await;
    assert_eq!(st, 200);
    assert!(common::acks(&body, "e2"), "{body}");

    let fixtures = ["security_4624", "security_4688", "sysmon_3"].map(common::wef_fixture);
    let refs: Vec<&str> = fixtures.iter().map(String::as_str).collect();
    let (st, body) = post(
        &client,
        &url,
        &common::events_envelope("e3", MACHINE, 2061, &refs),
        true,
    )
    .await;
    assert_eq!(st, 200);
    assert!(common::acks(&body, "e3"), "{body}");

    let end = common::heartbeat_envelope("e4", MACHINE).replace(
        "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat",
        "http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd",
    );
    let (st, body) = post(&client, &url, &end, false).await;
    assert_eq!(st, 200);
    assert!(body.is_empty());

    let batches = common::wait_for_rows(&p.dir().join("out/wef"), 3, Duration::from_secs(20)).await;
    let mut ids: Vec<u32> = Vec::new();
    for b in &batches {
        let a = b
            .column_by_name("event_id")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::UInt32Array>()
            .unwrap();
        ids.extend(a.values().iter().copied());
        let sub = common::str_col(b, "subscription_id");
        assert!((0..sub.len()).all(|i| sub.value(i) == "security"));
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![3, 4624, 4688]);
}

#[test]
fn test_e2e_binary_refuses_start_without_auth() {
    let toml = config(&common::wef_toml("http://127.0.0.1:{HTTP}").replace(
        "allow_unauthenticated = true",
        "allow_unauthenticated = false",
    ))
    .replace("{HTTP}", &common::free_port().to_string());
    let (status, stderr) = common::run_to_exit(BIN, &toml, &[]);
    assert!(!status.success(), "must exit non-zero; stderr:\n{stderr}");
    assert!(
        stderr.contains(
            "WEF subscriptions require authentication: enable [security.kerberos] (built with \
             --features kerberos-auth) or TLS with require_client_cert, or set \
             wef.allow_unauthenticated = true"
        ),
        "{stderr}"
    );
}
