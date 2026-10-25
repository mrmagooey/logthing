//! Integration: `spawn_admin_server` startup paths driven by `LOGTHING_ADMIN_*`
//! environment variables: a rejected configuration, a failed bind, and TLS.
//!
//! This MUST stay the only `#[tokio::test]` in this binary: it mutates process
//! environment variables and installs a global tracing subscriber to read the
//! server's error logs.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use logthing::admin::spawn_admin_server;
use logthing::config::Config;
use logthing::stats::SourceHourlyStats;

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    /// Poll until the log contains `needle` or panic after a generous deadline.
    async fn wait_for(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let text = self.text();
            if text.contains(needle) {
                return text;
            }
            assert!(
                Instant::now() < deadline,
                "never logged {needle:?}; log:\n{text}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn spawn() {
    spawn_admin_server(
        Arc::new(RwLock::new(Config::default())),
        Arc::new(SourceHourlyStats::new()),
    );
}

/// Removes every `LOGTHING_ADMIN_*` variable this test set, even on panic.
struct EnvGuard;

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let keys: Vec<String> = std::env::vars()
            .map(|(k, _)| k)
            .filter(|k| k.starts_with("LOGTHING_ADMIN_"))
            .collect();
        for key in keys {
            // SAFETY: see `set`.
            unsafe { std::env::remove_var(key) };
        }
    }
}

fn set(key: &str, val: &str) {
    // SAFETY: the only test in this binary; nothing else reads or writes env
    // concurrently, and the admin task only reads it inside `spawn_admin_server`.
    unsafe { std::env::set_var(key, val) };
}

#[tokio::test]
async fn test_spawn_admin_server_startup_failures_and_tls() {
    let _env = EnvGuard;
    let logs = LogBuf::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let dir = tempfile::tempdir().unwrap();
    set(
        "LOGTHING_ADMIN_AUDIT_LOG",
        dir.path().join("audit.log").to_str().unwrap(),
    );
    set("LOGTHING_ADMIN_ENABLE_RATE_LIMIT", "false");

    // 1. A configuration the loader rejects: logged, and no server comes up.
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held = holder.local_addr().unwrap();
    set("LOGTHING_ADMIN_BIND", &held.to_string());
    set("LOGTHING_ADMIN_ALLOWED_IPS", "bogus-entry");
    spawn();
    let text = logs.wait_for("Failed to load admin configuration").await;
    assert!(text.contains("LOGTHING_ADMIN_ALLOWED_IPS"), "{text}");
    unsafe { std::env::remove_var("LOGTHING_ADMIN_ALLOWED_IPS") };

    // 2. A valid configuration whose bind address is already taken: the bind
    //    error is reported by the spawned task rather than panicking it.
    spawn();
    let text = logs.wait_for("Admin server error").await;
    assert!(
        text.contains("in use"),
        "bind failure should name the cause:\n{text}"
    );
    drop(holder);

    // 3. TLS: the same entry point serves HTTPS with the configured cert.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    set("LOGTHING_ADMIN_BIND", &addr.to_string());
    set("LOGTHING_ADMIN_TLS_CERT", cert_path.to_str().unwrap());
    set("LOGTHING_ADMIN_TLS_KEY", key_path.to_str().unwrap());
    let before = logs.text().matches("Admin server error").count();
    spawn();

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap())
        .resolve("localhost", addr)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let body = loop {
        let attempt = client
            .get(format!("https://localhost:{}/health", addr.port()))
            .send()
            .await;
        match attempt {
            Ok(resp) => {
                assert_eq!(resp.status(), 200);
                break resp.text().await.unwrap();
            }
            Err(err) => {
                let text = logs.text();
                assert_eq!(
                    text.matches("Admin server error").count(),
                    before,
                    "TLS server failed to start (port race or bad cert): {err}\n{text}"
                );
                assert!(Instant::now() < deadline, "no HTTPS answer: {err}\n{text}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert_eq!(body, "OK");
    assert!(logs.text().contains("(TLS enabled)"), "{}", logs.text());
}
