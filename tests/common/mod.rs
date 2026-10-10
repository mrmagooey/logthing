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

/// Ask the OS for a free localhost TCP port. The probe listener is dropped immediately, so
/// another test can grab the port before the caller binds it. Callers that start a server must
/// tolerate that: see [`spawn_server`] / [`await_ready`] (in-process) and
/// [`Proc::spawn_healthy`] (binary), which retry on a fresh port.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// How many times a harness retries startup on a fresh port after losing a bind race.
pub const START_ATTEMPTS: usize = 5;

/// True when `e` (or anything in its cause chain) is an `AddrInUse` I/O error.
pub fn is_addr_in_use(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
    })
}

/// A server running on a tokio task, remembering whether it died on a bind clash.
pub struct ServerTask {
    pub handle: tokio::task::JoinHandle<()>,
    addr_in_use: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Spawn `fut` (a `Server::run`/`run_tls` call). `AddrInUse` is recorded for [`await_ready`]
/// (the task then ends quietly); any other error panics the task as before.
pub fn spawn_server<F>(fut: F) -> ServerTask
where
    F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    let addr_in_use = std::sync::Arc::new(AtomicBool::new(false));
    let flag = addr_in_use.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = fut.await {
            if is_addr_in_use(&e) {
                flag.store(true, Ordering::SeqCst);
            } else {
                panic!("server run: {e:#}");
            }
        }
    });
    ServerTask {
        handle,
        addr_in_use,
    }
}

/// Poll `health_url` until it answers 2xx. Returns `true` when ready, `false` when the server
/// task ended on `AddrInUse` (the caller should retry on a fresh port). Panics on any other
/// early exit or on timeout.
pub async fn await_ready(client: &reqwest::Client, health_url: &str, task: &ServerTask) -> bool {
    // True when the task already ended; asserts that it ended on a bind clash.
    let lost_bind = || {
        if !task.handle.is_finished() {
            return false;
        }
        assert!(
            task.addr_in_use.load(std::sync::atomic::Ordering::SeqCst),
            "server task exited before becoming ready"
        );
        true
    };
    for _ in 0..100 {
        if lost_bind() {
            return false;
        }
        if let Ok(r) = client.get(health_url).send().await
            && r.status().is_success()
        {
            // The 200 may come from another test's server that owns the port while our task
            // (not yet polled on a current-thread runtime) loses its bind. Let it settle.
            tokio::time::sleep(Duration::from_millis(50)).await;
            return !lost_bind();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become ready");
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
        assert!(
            self.wait_healthy_or_port_clash().await,
            "logthing exited early on a port clash; stderr:\n{}",
            self.logs()
        );
    }

    /// Like [`Proc::wait_healthy`], but returns `false` (instead of panicking) when the child
    /// exited with "Address already in use", so the caller can respawn on a fresh port.
    pub async fn wait_healthy_or_port_clash(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(r) = reqwest::get(format!("{}/health", self.base())).await
                && r.status().is_success()
            {
                // The 200 may come from another test's server on our port while the child is
                // still starting; it only counts if the child survives a settle period.
                tokio::time::sleep(Duration::from_millis(300)).await;
                if self.child.try_wait().unwrap().is_none() {
                    return true;
                }
            }
            if let Some(st) = self.child.try_wait().unwrap() {
                let logs = self.logs();
                if logs.to_lowercase().contains("address already in use") {
                    return false;
                }
                panic!("logthing exited early ({st}); stderr:\n{logs}");
            }
            assert!(
                Instant::now() < deadline,
                "logthing never became healthy:\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// [`Proc::spawn`] + wait for health, respawning on a fresh port (up to
    /// [`START_ATTEMPTS`]) when the port was taken between `free_port()` and the bind.
    pub async fn spawn_healthy(bin: &str, toml: &str, envs: &[(&str, &str)]) -> Proc {
        for _ in 1..START_ATTEMPTS {
            let mut p = Proc::spawn(bin, toml, envs);
            if p.wait_healthy_or_port_clash().await {
                return p;
            }
        }
        let mut p = Proc::spawn(bin, toml, envs);
        p.wait_healthy().await;
        p
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

/// UUID of the single subscription `wef_toml` configures.
pub const TEST_SUB_UUID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

/// A `[wef]` config block: `collector_url`, `allow_unauthenticated = true` and one
/// subscription named "security" (uuid `TEST_SUB_UUID`, channel "Security").
pub fn wef_toml(collector_url: &str) -> String {
    format!(
        "[wef]\ncollector_url = \"{collector_url}\"\nallow_unauthenticated = true\n\n\
         [[wef.subscriptions]]\nname = \"security\"\nuuid = \"{TEST_SUB_UUID}\"\n\
         channels = [\"Security\"]\n"
    )
}

/// UTF-16LE with a leading BOM, the encoding Windows clients send.
pub fn utf16(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

const ENV_OPEN: &str = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
    xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
    xmlns:n=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\" \
    xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" \
    xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\" \
    xmlns:b=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\">";

fn msg_id(message_id: &str) -> String {
    if message_id.starts_with("uuid:") {
        message_id.to_string()
    } else {
        format!("uuid:{message_id}")
    }
}

fn delivery_header(action: &str, message_id: &str, machine_id: &str, extra: &str) -> String {
    format!(
        "<s:Header><a:To>http://logthing.example.com:5985/wsman/subscriptions/{TEST_SUB_UUID}/1\
         </a:To><m:MachineID xmlns:m=\"http://schemas.microsoft.com/wbem/wsman/1/machineid\" \
         s:mustUnderstand=\"false\">{machine_id}</m:MachineID><a:ReplyTo><a:Address \
         s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous\
         </a:Address></a:ReplyTo><a:Action s:mustUnderstand=\"true\">\
         http://schemas.dmtf.org/wbem/wsman/1/wsman/{action}</a:Action>\
         <a:MessageID>{mid}</a:MessageID><p:OperationID s:mustUnderstand=\"false\">\
         uuid:3E4F5061-7283-4940-A5B6-C7D8E9F0A1B2</p:OperationID>\
         <p:SequenceId s:mustUnderstand=\"false\">1</p:SequenceId>\
         <w:OperationTimeout>PT60.000S</w:OperationTimeout>\
         <e:Identifier xmlns:e=\"http://schemas.xmlsoap.org/ws/2004/08/eventing\" \
         s:mustUnderstand=\"true\">{TEST_SUB_UUID}</e:Identifier>{extra}<w:AckRequested/>\
         </s:Header>",
        mid = msg_id(message_id)
    )
}

/// A subscription-manager `Enumerate` request in the shape Windows sends.
pub fn enumerate_envelope(message_id: &str, machine_id: &str) -> String {
    format!(
        "{ENV_OPEN}<s:Header><a:To>http://logthing.example.com:5985/wsman/SubscriptionManager/WEC\
         </a:To><w:ResourceURI s:mustUnderstand=\"true\">\
         http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription\
         </w:ResourceURI><m:MachineID xmlns:m=\"http://schemas.microsoft.com/wbem/wsman/1/machineid\" \
         s:mustUnderstand=\"false\">{machine_id}</m:MachineID><a:ReplyTo><a:Address \
         s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous\
         </a:Address></a:ReplyTo><a:Action s:mustUnderstand=\"true\">\
         http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>\
         <w:MaxEnvelopeSize s:mustUnderstand=\"true\">512000</w:MaxEnvelopeSize>\
         <a:MessageID>{mid}</a:MessageID><w:OperationTimeout>PT60.000S</w:OperationTimeout>\
         </s:Header><s:Body><n:Enumerate><w:OptimizeEnumeration/><w:MaxElements>32000\
         </w:MaxElements></n:Enumerate></s:Body></s:Envelope>",
        mid = msg_id(message_id)
    )
}

/// A delivery `Events` request: each entry of `events_xml` becomes one CDATA `w:Event`, and
/// a bookmark for channel Security at `bookmark_record_id` rides in the header.
pub fn events_envelope(
    message_id: &str,
    machine_id: &str,
    bookmark_record_id: u64,
    events_xml: &[&str],
) -> String {
    let bookmark = format!(
        "<w:Bookmark><BookmarkList><Bookmark Channel=\"Security\" \
         RecordId=\"{bookmark_record_id}\" IsCurrent=\"true\"/></BookmarkList></w:Bookmark>"
    );
    let events: String = events_xml
        .iter()
        .map(|e| {
            format!(
                "<w:Event Action=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/Event\">\
                 <![CDATA[{e}]]></w:Event>"
            )
        })
        .collect();
    format!(
        "{ENV_OPEN}{}<s:Body><w:Events>{events}</w:Events></s:Body></s:Envelope>",
        delivery_header("Events", message_id, machine_id, &bookmark)
    )
}

/// An empty keep-alive `Heartbeat` delivery request.
pub fn heartbeat_envelope(message_id: &str, machine_id: &str) -> String {
    format!(
        "{ENV_OPEN}{}<s:Body><w:Events></w:Events></s:Body></s:Envelope>",
        delivery_header("Heartbeat", message_id, machine_id, "")
    )
}

/// Literal-only SLDC encoder (ECMA-321 scheme 1): a Reset-1 control, every byte as a 9-bit
/// literal (`0` + 8 data bits), then End-of-Record zero-padded to a 32-bit boundary. Valid
/// SLDC, so it drives the server's decoder without needing a match-finding compressor.
pub fn sldc_literals(data: &[u8]) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    let mut push = |value: u32, n: usize| {
        for i in (0..n).rev() {
            bits.push((value >> i) & 1 == 1);
        }
    };
    push(0x1FF0 | 0x5, 13);
    for &b in data {
        push(u32::from(b), 9);
    }
    push(0x1FF0 | 0x4, 13);
    while !bits.len().is_multiple_of(32) {
        bits.push(false);
    }
    bits.chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b)))
        .collect()
}

/// Decode a UTF-16LE (BOM optional) response body to a `String`.
pub fn decode_utf16(bytes: &[u8]) -> String {
    let body = bytes.strip_prefix(&[0xFF, 0xFE][..]).unwrap_or(bytes);
    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).expect("response is valid UTF-16")
}

/// The first `NotifyTo` `a:Address` in an `EnumerateResponse` (the delivery URL a client uses).
pub fn notify_to(enumerate_response: &str) -> String {
    let after = enumerate_response
        .split("<e:NotifyTo>")
        .nth(1)
        .expect("NotifyTo in EnumerateResponse");
    after
        .split("<a:Address>")
        .nth(1)
        .and_then(|s| s.split("</a:Address>").next())
        .expect("NotifyTo a:Address")
        .to_string()
}

/// The `m:Version` GUID of the first subscription item in an `EnumerateResponse`.
pub fn subscription_version(enumerate_response: &str) -> String {
    enumerate_response
        .split("<m:Version>")
        .nth(1)
        .and_then(|s| s.split("</m:Version>").next())
        .expect("m:Version in EnumerateResponse")
        .to_string()
}

/// Whether `response` is an Ack whose `a:RelatesTo` is exactly `message_id` (with `uuid:`).
pub fn acks(response: &str, message_id: &str) -> bool {
    response.contains("wsman/Ack")
        && response.contains(&format!("<a:RelatesTo>uuid:{message_id}</a:RelatesTo>"))
}

/// Contents of the fixture `tests/fixtures/wef/events/<name>.xml`.
pub fn wef_fixture(name: &str) -> String {
    let p = format!(
        "{}/tests/fixtures/wef/events/{name}.xml",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}
