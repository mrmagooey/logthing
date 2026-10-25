//! End-to-end: the compiled `loadgen wef-http` against the real `logthing` binary.
//!
//! The `logthing` binary is not built by `cargo test -p loadgen`; build it first with
//! `cargo build --bin logthing` (or point `LOGTHING_BIN` at one). A missing binary fails
//! the test loudly rather than skipping.

use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SUB_UUID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

fn logthing_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("LOGTHING_BIN") {
        return PathBuf::from(p);
    }
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let bin = target.join("debug/logthing");
    assert!(
        bin.exists(),
        "logthing binary not found at {}; build it first with `cargo build --bin logthing` \
         (or set LOGTHING_BIN)",
        bin.display()
    );
    bin
}

fn parquet_rows(dir: &Path) -> i64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "parquet") {
                let b = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(p).unwrap())
                    .unwrap();
                total += b.metadata().file_metadata().num_rows();
            }
        }
    }
    total
}

/// Kills the child on drop so a failed assertion never leaks a server.
struct Guard(std::process::Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wef_http_against_real_logthing_lands_parquet() {
    let bin = logthing_bin();
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let out_dir = dir.path().join("out/wef");
    std::fs::write(
        dir.path().join("logthing.toml"),
        format!(
            "bind_address = \"127.0.0.1:{port}\"\n[tls]\nenabled = false\n\
             [syslog]\nenabled = false\n[metrics]\nenabled = false\n\
             [wef]\ncollector_url = \"http://127.0.0.1:{port}\"\nallow_unauthenticated = true\n\n\
             [[wef.subscriptions]]\nname = \"security\"\nuuid = \"{SUB_UUID}\"\n\
             channels = [\"Security\"]\n\n\
             [wef.local]\ndirectory = \"{}\"\nflush_interval_secs = 1\n",
            out_dir.display()
        ),
    )
    .unwrap();
    let mut server = Guard(
        Command::new(&bin)
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn logthing"),
    );

    let client = reqwest::Client::new();
    let health = format!("http://127.0.0.1:{port}/health");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if client
            .get(&health)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        assert!(Instant::now() < deadline, "logthing never became healthy");
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "logthing exited early"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let port_s = port.to_string();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_loadgen"))
            .args([
                "wef-http",
                "--port",
                &port_s,
                "--target-rate",
                "500",
                "--duration-secs",
                "3",
                "--events-per-request",
                "25",
            ])
            .output()
            .expect("run loadgen")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "loadgen failed:\n{stdout}\n{stderr}"
    );
    assert!(!stdout.contains("requests rejected"), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("backpressure: 0 503 responses, 0 requests abandoned"),
        "{stdout}\n{stderr}"
    );
    assert!(stdout.contains("loadgen wef-http: sent "), "{stdout}");

    let pid = server.0.id();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while server.0.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "logthing did not exit after SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let rows = parquet_rows(&out_dir);
    assert!(rows > 0, "no parquet rows under {}", out_dir.display());
}
