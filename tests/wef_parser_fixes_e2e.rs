//! End-to-end: the real `logthing` binary receives a 4689 event with a hex `ProcessId` and an
//! XML-escaped `ProcessName` over WEF. Generic-parser fields are not written to Parquet, so the
//! observable result is the "parsed with generic parser" log line carrying the formatted
//! message (`PID 420`, `AT&T`), plus the event still reaching Parquet.

mod common;

use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const MACHINE: &str = "win10.example.com";

const TOML: &str = r#"
bind_address = "127.0.0.1:{HTTP}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = false
"#;

async fn post(client: &reqwest::Client, url: &str, envelope: &str) -> reqwest::StatusCode {
    client
        .post(url)
        .header("Content-Type", "application/soap+xml;charset=UTF-16")
        .body(common::utf16(envelope))
        .send()
        .await
        .expect("POST")
        .status()
}

#[tokio::test]
async fn test_e2e_hex_pid_and_entities_parsed_by_binary() {
    let dir = tempfile::tempdir().unwrap();
    // The binary loads parsers from ./config/event_parsers relative to its cwd.
    let parsers = dir.path().join("config/event_parsers");
    std::fs::create_dir_all(&parsers).unwrap();
    let src = format!(
        "{}/config/event_parsers/4689_process_terminated.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::copy(&src, parsers.join("4689_process_terminated.yaml")).unwrap();

    let toml = format!(
        "{TOML}{}\n[wef.local]\ndirectory = \"{{DIR}}/out/wef\"\nflush_interval_secs = 1\n",
        common::wef_toml("http://127.0.0.1:{HTTP}")
    );
    let mut p = common::Proc::spawn_in(BIN, &toml, &[], dir, common::free_port());
    p.wait_healthy().await;

    let client = reqwest::Client::new();
    let url = format!("{}/wsman/subscriptions/{}", p.base(), common::TEST_SUB_UUID);
    let ev = common::wef_fixture("security_4689_hex_pid");
    let env = common::events_envelope("e1", MACHINE, 1, &[ev.as_str()]);
    assert_eq!(post(&client, &url, &env).await, 200, "{}", p.logs());

    let batches = common::wait_for_rows(&p.dir().join("out/wef"), 1, Duration::from_secs(20)).await;
    assert!(batches.iter().map(|b| b.num_rows()).sum::<usize>() >= 1);

    let want = "AT&T.exe (PID 420) terminated";
    let seen = common::wait_until(Duration::from_secs(10), || p.logs().contains(want)).await;
    assert!(seen, "no parsed 4689 log line; logs:\n{}", p.logs());
}
