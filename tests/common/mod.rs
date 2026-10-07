//! Shared helpers for tests that read the Parquet a local sink wrote.
#![allow(dead_code)]

pub mod fake_s3;

use arrow::array::StringArray;
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Every `*.parquet` file under `dir`, sorted.
pub fn parquet_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "parquet") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// All record batches of all Parquet files under `dir`.
pub fn read_all(dir: &Path) -> Vec<RecordBatch> {
    let mut batches = Vec::new();
    for p in parquet_files(dir) {
        let bytes = Bytes::from(std::fs::read(&p).expect("read parquet"));
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .expect("parquet footer")
            .build()
            .expect("parquet reader");
        batches.extend(reader.map(|b| b.expect("batch")));
    }
    batches
}

/// Poll until at least `min_rows` rows are readable under `dir`, or panic after `timeout`.
pub async fn wait_for_rows(dir: &Path, min_rows: usize, timeout: Duration) -> Vec<RecordBatch> {
    let deadline = Instant::now() + timeout;
    loop {
        // A file may be mid-write; a failed read just means "try again".
        let batches = std::panic::catch_unwind(|| read_all(dir)).unwrap_or_default();
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        if rows >= min_rows {
            return batches;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {min_rows} rows under {} (have {rows})",
            dir.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Poll `f` every 20 ms until it returns true or `deadline` elapses; returns the last result.
pub async fn wait_until(deadline: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + deadline;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Downcast a column to `StringArray`.
pub fn str_col<'a>(batch: &'a RecordBatch, name: &str) -> &'a StringArray {
    batch
        .column_by_name(name)
        .unwrap_or_else(|| panic!("missing column {name}"))
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap_or_else(|| panic!("column {name} is not Utf8"))
}

/// Ask the OS for a free localhost TCP port (released immediately; small race is accepted,
/// same trade-off the other e2e tests make).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_cfg(dir: &Path, toml: &str) {
    std::fs::write(dir.join("logthing.toml"), toml).expect("write logthing.toml");
}

/// Run the binary with `toml` as `./logthing.toml` in a fresh temp dir and wait for it to exit
/// (use for configs that must be rejected at startup). Returns (status, stderr).
pub fn run_to_exit(
    bin: &str,
    toml: &str,
    envs: &[(&str, &str)],
) -> (std::process::ExitStatus, String) {
    let dir = tempfile::tempdir().unwrap();
    write_cfg(dir.path(), toml);
    let mut cmd = Command::new(bin);
    cmd.current_dir(dir.path()).stdin(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let stdout = dir.path().join("stdout.log");
    let stderr = dir.path().join("stderr.log");
    cmd.stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()));
    let mut child = cmd.spawn().expect("spawn logthing");
    // Never hang the test run: a config that should be rejected but starts serving would
    // otherwise block forever.
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "process did not exit (validation regression?); stderr so far:\n{}",
                std::fs::read_to_string(&stderr).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (status, std::fs::read_to_string(&stderr).unwrap_or_default())
}

/// A running logthing process; killed and reaped on drop.
pub struct Proc {
    child: Child,
    pub http_port: u16,
    dir: Option<tempfile::TempDir>,
}

impl Proc {
    /// Spawn the binary. `toml` may contain the placeholders `{HTTP}` and `{DIR}`, replaced by
    /// the chosen HTTP port and the process temp dir (sinks should live under `{DIR}`).
    pub fn spawn(bin: &str, toml: &str, envs: &[(&str, &str)]) -> Proc {
        Self::spawn_in(bin, toml, envs, tempfile::tempdir().unwrap(), free_port())
    }

    /// [`Proc::spawn`] in an existing directory (e.g. one handed over by [`Proc::into_dir`]),
    /// so a restarted process sees the first process's files, spool included.
    pub fn spawn_in(
        bin: &str,
        toml: &str,
        envs: &[(&str, &str)],
        dir: tempfile::TempDir,
        http_port: u16,
    ) -> Proc {
        let toml = toml
            .replace("{HTTP}", &http_port.to_string())
            .replace("{DIR}", &dir.path().display().to_string());
        write_cfg(dir.path(), &toml);
        let mut cmd = Command::new(bin);
        cmd.current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                std::fs::File::create(dir.path().join("stdout.log")).unwrap(),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(dir.path().join("stderr.log")).unwrap(),
            ));
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn logthing");
        Proc {
            child,
            http_port,
            dir: Some(dir),
        }
    }

    /// The process temp dir.
    pub fn dir(&self) -> &Path {
        self.dir.as_ref().expect("dir taken").path()
    }

    /// Hand the temp dir to the caller (for a restart). Kills and reaps the child first
    /// unless it has already exited.
    pub fn into_dir(mut self) -> tempfile::TempDir {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.dir.take().expect("dir taken")
    }

    /// Send SIGTERM (`kill -TERM <pid>`, as `sigterm_graceful_shutdown_e2e` does) and wait up
    /// to `timeout` for a graceful exit; panics with the logs on timeout.
    pub fn terminate(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let pid = self.child.id();
        let st = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("run kill(1)");
        assert!(st.success(), "kill -TERM {pid} failed");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(st) = self.child.try_wait().expect("try_wait") {
                return st;
            }
            assert!(
                Instant::now() < deadline,
                "logthing {pid} did not exit within {timeout:?} of SIGTERM:\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Base URL of the HTTP listener.
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    /// Poll `/health` until it answers 200 (panics with the child's logs on timeout or exit).
    pub async fn wait_healthy(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(r) = reqwest::get(format!("{}/health", self.base())).await
                && r.status().is_success()
            {
                return;
            }
            if let Some(st) = self.child.try_wait().unwrap() {
                panic!("logthing exited early ({st}); stderr:\n{}", self.logs());
            }
            assert!(
                Instant::now() < deadline,
                "logthing never became healthy:\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// stdout+stderr captured so far.
    pub fn logs(&self) -> String {
        let read = |n: &str| std::fs::read_to_string(self.dir().join(n)).unwrap_or_default();
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            read("stdout.log"),
            read("stderr.log")
        )
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
