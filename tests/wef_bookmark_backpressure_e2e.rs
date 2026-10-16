//! End-to-end test (real `logthing` binary, plain HTTP) that a WEF Events batch the sink could
//! not take is answered `503` and does not advance the stored bookmark.

mod common;

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
[wef.local]
directory = "{DIR}/out/wef"
flush_interval_secs = 1
channel_capacity = 1
"#;

async fn post(
    client: &reqwest::Client,
    url: &str,
    envelope: &str,
) -> (reqwest::StatusCode, String) {
    let (st, _, text) = post_with_headers(client, url, envelope).await;
    (st, text)
}

async fn post_with_headers(
    client: &reqwest::Client,
    url: &str,
    envelope: &str,
) -> (reqwest::StatusCode, reqwest::header::HeaderMap, String) {
    let resp = client
        .post(url)
        .header("Content-Type", "application/soap+xml;charset=UTF-16")
        .body(common::utf16(envelope))
        .send()
        .await
        .expect("POST");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.bytes().await.unwrap();
    let text = if bytes.is_empty() {
        String::new()
    } else {
        common::decode_utf16(&bytes)
    };
    (status, headers, text)
}

#[tokio::test]
async fn test_e2e_sink_drop_returns_503_and_enumerate_keeps_previous_bookmark() {
    let toml = format!("{BASE}{}", common::wef_toml("http://127.0.0.1:{HTTP}"));
    let p = common::Proc::spawn_healthy(BIN, &toml, &[]).await;
    let client = reqwest::Client::builder().http1_only().build().unwrap();
    let enum_url = format!("{}/wsman", p.base());
    let (st, body) = post(
        &client,
        &enum_url,
        &common::enumerate_envelope("e1", MACHINE),
    )
    .await;
    assert_eq!(st, 200, "{}", p.logs());
    let url = common::notify_to(&body);

    // One event fits the (empty) channel: acknowledged, bookmark 100 stored.
    let one = common::wef_fixture("security_4624");
    let (st, body) = post(
        &client,
        &url,
        &common::events_envelope("e2", MACHINE, 100, &[one.as_str()]),
    )
    .await;
    assert_eq!(st, 200, "{}", p.logs());
    assert!(common::acks(&body, "e2"), "{body}");

    // A flood against a capacity-1 channel must drop events: 503, no bookmark movement.
    let flood: Vec<&str> = std::iter::repeat_n(one.as_str(), 1000).collect();
    let (st, headers, body) = post_with_headers(
        &client,
        &url,
        &common::events_envelope("e3", MACHINE, 99_999, &flood),
    )
    .await;
    assert_eq!(st, 503, "{}", p.logs());
    assert_eq!(
        headers.get("retry-after").and_then(|v| v.to_str().ok()),
        Some("1"),
        "WEF 503 must carry Retry-After like OTLP"
    );
    assert!(!common::acks(&body, "e3"), "{body}");

    let (st, body) = post(
        &client,
        &enum_url,
        &common::enumerate_envelope("e4", MACHINE),
    )
    .await;
    assert_eq!(st, 200);
    assert!(body.contains("RecordId=\"100\""), "{body}");
    assert!(!body.contains("RecordId=\"99999\""), "{body}");
}
