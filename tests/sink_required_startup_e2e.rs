//! The real binary must refuse to start when [hec]/[otlp] is enabled with no sink, with an
//! actionable message on stderr, and must start normally once a sink is configured.

mod common;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

const BASE: &str = r#"
bind_address = "127.0.0.1:{HTTP}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = false
"#;

const HEC_MSG: &str = "[hec] enabled = true but no sink configured: add [hec.s3] or [hec.local] \
                       (see docs/hec.md#migration)";
#[cfg(feature = "otlp")]
const OTLP_MSG: &str = "[otlp] enabled = true but no sink configured: add [otlp.s3] or \
                        [otlp.local] (OTLP no longer writes to [hec] sinks since 0.22.0; \
                        see docs/otlp.md#migration)";

fn bad(extra: &str, envs: &[(&str, &str)]) -> (std::process::ExitStatus, String) {
    let port = common::free_port().to_string();
    let toml = format!("{}{extra}", BASE.replace("{HTTP}", &port));
    common::run_to_exit(BIN, &toml, envs)
}

#[test]
fn hec_enabled_without_sink_fails_startup() {
    let (status, stderr) = bad("[hec]\nenabled = true\n", &[]);
    assert!(!status.success());
    assert!(stderr.contains(HEC_MSG), "stderr was:\n{stderr}");
}

#[cfg(feature = "otlp")]
#[test]
fn otlp_enabled_without_sink_fails_startup_even_when_hec_has_one() {
    // The pre-0.22 working shape: OTLP riding [hec.local]. Must now be a loud startup error.
    let (status, stderr) = bad(
        "[hec]\nenabled = true\n[hec.local]\ndirectory = \"/tmp/logthing-test-hec\"\n\
         [otlp]\nenabled = true\n",
        &[],
    );
    assert!(!status.success());
    assert!(stderr.contains(OTLP_MSG), "stderr was:\n{stderr}");
}

#[test]
fn hec_enabled_via_env_without_sink_fails_startup() {
    let (status, stderr) = bad("", &[("LOGTHING__HEC__ENABLED", "true")]);
    assert!(!status.success());
    assert!(stderr.contains(HEC_MSG), "stderr was:\n{stderr}");
}

#[cfg(feature = "otlp")]
#[test]
fn otlp_enabled_via_env_without_sink_fails_startup() {
    let (status, stderr) = bad("", &[("LOGTHING__OTLP__ENABLED", "true")]);
    assert!(!status.success());
    assert!(stderr.contains(OTLP_MSG), "stderr was:\n{stderr}");
}

#[cfg(feature = "otlp")]
#[test]
fn otlp_zero_service_partitions_fails_startup() {
    let (status, stderr) = bad(
        "[otlp]\nenabled = true\nmax_service_partitions = 0\n\
         [otlp.local]\ndirectory = \"/tmp/logthing-test-otlp\"\n",
        &[],
    );
    assert!(!status.success());
    assert!(
        stderr.contains("[otlp] max_service_partitions must be greater than 0"),
        "stderr was:\n{stderr}"
    );
}

#[tokio::test]
async fn hec_with_local_sink_starts_and_serves() {
    let mut p = common::Proc::spawn(
        BIN,
        &format!("{BASE}[hec]\nenabled = true\n[hec.local]\ndirectory = \"{{DIR}}/hec\"\n"),
        &[],
    );
    p.wait_healthy().await;
    let r = reqwest::Client::new()
        .post(format!("{}/services/collector/event", p.base()))
        .json(&serde_json::json!({"event": "up"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[cfg(feature = "otlp")]
#[tokio::test]
async fn otlp_with_local_sink_starts() {
    let mut p = common::Proc::spawn(
        BIN,
        &format!("{BASE}[otlp]\nenabled = true\n[otlp.local]\ndirectory = \"{{DIR}}/otlp\"\n"),
        &[],
    );
    p.wait_healthy().await;
}
