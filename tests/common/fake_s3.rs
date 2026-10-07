//! Minimal in-process S3 stand-in: accepts PUT object, records (key, body), and can be
//! switched to answer 503 so tests can model outages without MinIO/Docker.
//!
//! Bodies are recorded verbatim. The real SDK client is exercised against it by
//! `tests/spool_integration.rs`, whose assertions (`PAR1` magic, byte-identical re-uploads)
//! would fail if the SDK ever started sending `aws-chunked` bodies for these requests.
#![allow(dead_code)]

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::put,
};
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Recorded `(key, body)` pairs.
type Puts = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
/// Recorded `(key, request headers)` of every PUT that reached the handler, failed or not.
type Headers = Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>;

#[derive(Clone)]
struct Shared {
    puts: Puts,
    headers: Headers,
    failing: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
}

/// A running fake S3 endpoint; the server task is aborted on drop.
pub struct FakeS3 {
    pub addr: SocketAddr,
    shared: Shared,
    task: tokio::task::JoinHandle<()>,
}

async fn put_object(
    State(s): State<Shared>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    s.requests.fetch_add(1, Ordering::SeqCst);
    let key = path
        .split_once('/')
        .map_or(path.as_str(), |(_, k)| k)
        .to_string();
    let hs = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    s.headers.lock().unwrap().push((key.clone(), hs));
    if s.failing.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, "down").into_response();
    }
    s.puts.lock().unwrap().push((key, body.to_vec()));
    (StatusCode::OK, [("ETag", "\"fake\"")]).into_response()
}

impl FakeS3 {
    pub async fn start() -> FakeS3 {
        let shared = Shared {
            puts: Arc::default(),
            headers: Arc::default(),
            failing: Arc::new(AtomicBool::new(false)),
            requests: Arc::default(),
        };
        let app = Router::new()
            .route("/*path", put(put_object))
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeS3 { addr, shared, task }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_failing(&self, failing: bool) {
        self.shared.failing.store(failing, Ordering::SeqCst);
    }

    /// Keys of every SUCCESSFUL put, in arrival order.
    pub fn put_keys(&self) -> Vec<String> {
        let puts = self.shared.puts.lock().unwrap();
        puts.iter().map(|(k, _)| k.clone()).collect()
    }

    /// Body of the most recent successful put of `key`.
    pub fn body(&self, key: &str) -> Option<Vec<u8>> {
        let puts = self.shared.puts.lock().unwrap();
        puts.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, b)| b.clone())
    }

    /// Every successful put as `(key, body)`.
    pub fn puts(&self) -> Vec<(String, Vec<u8>)> {
        self.shared.puts.lock().unwrap().clone()
    }

    /// Request headers (lowercased names) of the most recent PUT of `key`, successful or not.
    pub fn put_headers(&self, key: &str) -> Vec<(String, String)> {
        let hs = self.shared.headers.lock().unwrap();
        hs.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, h)| h.clone())
            .unwrap_or_default()
    }

    /// Number of successful puts.
    pub fn put_count(&self) -> usize {
        self.shared.puts.lock().unwrap().len()
    }

    /// Number of PUT requests received, successful or not.
    pub fn request_count(&self) -> usize {
        self.shared.requests.load(Ordering::SeqCst)
    }
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        self.task.abort();
    }
}
