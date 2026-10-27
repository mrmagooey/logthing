//! End-to-end checks for `scripts/profile-ingest.sh`'s generated configs: each of the nine
//! formats must print a TOML that parses as a real [`Config`], enables exactly one ingest source
//! (with a local sink on a 5 s flush), and boots the real `logthing` binary to a healthy state.
//! The profiling/loadgen half of the script is exercised by the script itself (needs a `pprof`
//! build), not here.

use logthing::config::Config;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const FORMATS: [&str; 9] = [
    "syslog", "zeek", "suricata", "ipfix", "sflow", "hec", "generic", "otlp", "wef",
];

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/profile-ingest.sh")
}

/// Run the script with `args` and a clean `LOGTHING__*` environment.
fn run_script(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(script());
    cmd.args(args);
    for (k, _) in std::env::vars() {
        if k.starts_with("LOGTHING__") {
            cmd.env_remove(k);
        }
    }
    cmd.output().expect("run profile-ingest.sh")
}

/// `--print-config <fmt>` stdout. The script leaves its temp work dir for the caller; the dir is
/// the parent of the printed sink directory, which this returns so the test can remove it.
fn print_config(fmt: &str) -> (String, Config, PathBuf) {
    let out = run_script(&["--print-config", fmt]);
    assert!(
        out.status.success(),
        "--print-config {fmt} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let toml = String::from_utf8(out.stdout).expect("utf8 config");
    let cfg: Config = toml::from_str(&toml).unwrap_or_else(|e| panic!("{fmt}: {e}\n{toml}"));
    let sink_dir = sink_directory(&cfg);
    let work = sink_dir
        .parent()
        .expect("sink dir has a parent")
        .to_path_buf();
    (toml, cfg, work)
}

/// The directory of whichever `.local` sink is configured (asserting at most one is).
fn sink_directory(cfg: &Config) -> PathBuf {
    let dirs: Vec<PathBuf> = [
        cfg.syslog.local.as_ref().map(|l| l.directory.clone()),
        cfg.zeek.local.as_ref().map(|l| l.directory.clone()),
        cfg.suricata.local.as_ref().map(|l| l.directory.clone()),
        cfg.ipfix.local.as_ref().map(|l| l.directory.clone()),
        cfg.sflow.local.as_ref().map(|l| l.directory.clone()),
        cfg.hec.local.as_ref().map(|l| l.directory.clone()),
        cfg.otlp.local.as_ref().map(|l| l.directory.clone()),
        cfg.wef.local.as_ref().map(|l| l.directory.clone()),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(
        dirs.len(),
        1,
        "expected exactly one local sink, got {dirs:?}"
    );
    dirs[0].clone()
}

#[test]
fn test_list_prints_all_nine_formats() {
    let out = run_script(&["--list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines, FORMATS);
}

#[test]
fn test_unknown_format_exits_2() {
    let out = run_script(&["--print-config", "nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .to_lowercase()
            .contains("usage")
    );
}

#[test]
fn test_each_print_config_enables_exactly_one_source() {
    for fmt in FORMATS {
        let (_, c, work) = print_config(fmt);
        let enabled = [
            ("syslog", c.syslog.enabled),
            ("zeek", c.zeek.enabled),
            ("suricata", c.suricata.enabled),
            ("ipfix", c.ipfix.enabled),
            ("sflow", c.sflow.enabled),
            ("hec", c.hec.enabled),
            ("otlp", c.otlp.enabled),
            ("wef", c.wef.allow_unauthenticated),
        ];
        let expected = match fmt {
            "generic" => "hec",
            f => f,
        };
        let on: Vec<&str> = enabled
            .iter()
            .filter(|(_, e)| *e)
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(on, [expected], "{fmt}: enabled sources");

        let flush = match expected {
            "syslog" => c.syslog.local.map(|l| l.flush_interval_secs),
            "zeek" => c.zeek.local.map(|l| l.flush_interval_secs),
            "suricata" => c.suricata.local.map(|l| l.flush_interval_secs),
            "ipfix" => c.ipfix.local.map(|l| l.flush_interval_secs),
            "sflow" => c.sflow.local.map(|l| l.flush_interval_secs),
            "hec" => c.hec.local.map(|l| l.flush_interval_secs),
            "otlp" => c.otlp.local.map(|l| l.flush_interval_secs),
            _ => c.wef.local.map(|l| l.flush_interval_secs),
        };
        assert_eq!(flush, Some(5), "{fmt}: local sink flush interval");
        if expected == "wef" {
            assert_eq!(c.wef.subscriptions.len(), 1);
        } else {
            assert!(c.wef.subscriptions.is_empty(), "{fmt}: no WEF subscription");
        }
        assert_eq!(c.logging.level, "error");
        assert!(c.metrics.enabled);
        assert!(!c.tls.enabled);
        assert!(c.spool.is_none() && !c.aggregate.enabled);
        let _ = std::fs::remove_dir_all(work);
    }
}

/// Spawn the binary on `toml` in `work`, wait for `/health`. `Ok(false)` = lost a port race.
async fn boots(toml: &str, work: &Path, http_port: u16) -> Result<bool, String> {
    std::fs::write(work.join("logthing.toml"), toml).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_logthing"))
        .current_dir(work)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(work.join("stdout.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(work.join("stderr.log")).unwrap(),
        ))
        .spawn()
        .expect("spawn logthing");
    let deadline = Instant::now() + Duration::from_secs(15);
    let result = loop {
        if let Ok(r) = reqwest::get(format!("http://127.0.0.1:{http_port}/health")).await
            && r.status().is_success()
        {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if child.try_wait().unwrap().is_none() {
                break Ok(true);
            }
        }
        if let Some(st) = child.try_wait().unwrap() {
            let logs = std::fs::read_to_string(work.join("stderr.log")).unwrap_or_default()
                + &std::fs::read_to_string(work.join("stdout.log")).unwrap_or_default();
            if logs.to_lowercase().contains("address already in use") {
                break Ok(false);
            }
            break Err(format!("exited early ({st}):\n{logs}"));
        }
        if Instant::now() > deadline {
            break Err("never became healthy within 15s".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[tokio::test]
async fn test_each_print_config_starts_the_real_binary() {
    for fmt in FORMATS {
        let mut last = String::new();
        let mut ok = false;
        for _ in 0..3 {
            let (toml, cfg, work) = print_config(fmt);
            let port = cfg.bind_address.port();
            match boots(&toml, &work, port).await {
                Ok(true) => ok = true,
                Ok(false) => last = "port clash".into(),
                Err(e) => last = e,
            }
            let _ = std::fs::remove_dir_all(&work);
            if ok || !last.contains("port clash") {
                break;
            }
        }
        assert!(ok, "{fmt}: {last}");
    }
}

#[test]
fn test_probe_usage_nonexistent_pid_is_empty_and_succeeds() {
    let out = run_script(&["--probe-usage", "99999999"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "rss= ticks=");
}

#[test]
fn test_probe_usage_live_pid_reports_numbers() {
    let mut child = Command::new("sleep").arg("5").spawn().unwrap();
    let out = run_script(&["--probe-usage", &child.id().to_string()]);
    let _ = child.kill();
    let _ = child.wait();
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (rss, ticks) = line.split_once(" ticks=").expect(&line);
    assert!(
        rss.strip_prefix("rss=").unwrap().parse::<u64>().unwrap() > 0,
        "{line}"
    );
    assert!(ticks.parse::<u64>().is_ok(), "{line}");
}
