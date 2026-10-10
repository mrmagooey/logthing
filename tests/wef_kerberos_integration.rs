#![cfg(feature = "kerberos-auth")]
//! Real-Kerberos integration tests: an in-process `Server` using the production libgssapi
//! adapter (`LibGssFactory`), driven over persistent HTTP/1.1 connections by a libgssapi
//! *client* that speaks the Windows wire format (`Authorization: Kerberos <AP-REQ>` on the
//! first request of a TCP connection, then MS-WSMV multipart-encrypted bodies).
//!
//! Needs a live MIT KDC: `eval "$(scripts/kdc-test-env.sh up)"` exports the
//! `LOGTHING_TEST_KRB5_*` variables. Without them the tests skip locally and fail when
//! `CI=true`.
//!
//! Client credentials come from the client keytab (`KRB5_CLIENT_KTNAME`), for `alice` too:
//! the host has no `kinit`, and keytab initiation exercises the same ticket path. The
//! credential cache is a private `DIR:` collection (one cache per principal, since a single
//! cache holds one principal) so no test touches the developer's real ticket cache.
//! The process environment is set once before any GSS call; tests share one process and
//! need no `--test-threads=1` because every server and connection owns its own state.

mod common;

use arrow::record_batch::RecordBatch;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{
    GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE, GSS_NT_KRB5_PRINCIPAL, Oid, OidSet,
};
use libgssapi::util::{GssIov, GssIovType};
use logthing::config::{
    Config, KerberosSecurityConfig, MetricsConfig, SecurityConfig, TlsConfig, WefConfig,
    WefLocalConfig,
};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::wef::multipart::{self, EncProtocol};
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

const HOST: &str = "logthing.example.com";
const MACHINE: &str = "win10.example.com";
const SYSLOG_MSG: &str = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: \
                          query: example.com IN A + (93.184.216.34)";

/// The `LOGTHING_TEST_KRB5_*` settings exported by `scripts/kdc-test-env.sh up`.
struct Env {
    spn: String,
}

static INIT: Once = Once::new();
/// Backing directory of the `DIR:` ccache collection; statics are never dropped, so it
/// outlives every test (a few KiB in the temp dir).
static CCACHE_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();

/// `Some(env)` when the KDC variables are set (and the process environment is primed);
/// otherwise panics in CI and returns `None` (skip) locally.
fn krb_env() -> Option<Env> {
    let get = |k: &str| std::env::var(format!("LOGTHING_TEST_KRB5_{k}")).ok();
    let (Some(config), Some(server_kt), Some(client_kt), Some(spn)) = (
        get("CONFIG"),
        get("SERVER_KEYTAB"),
        get("CLIENT_KEYTAB"),
        get("SPN"),
    ) else {
        if std::env::var("CI").as_deref() == Ok("true") {
            panic!("LOGTHING_TEST_KRB5_* unset in CI");
        }
        eprintln!("skipping: LOGTHING_TEST_KRB5_* unset (run scripts/kdc-test-env.sh up)");
        return None;
    };
    INIT.call_once(|| {
        // SAFETY: runs once, before any test in this binary touches GSSAPI or spawns a
        // server, and every test passes through `krb_env` first (Once blocks the rest).
        unsafe {
            std::env::set_var("KRB5_CONFIG", config);
            std::env::set_var("KRB5_KTNAME", server_kt);
            std::env::set_var("KRB5_CLIENT_KTNAME", client_kt);
            let dir = CCACHE_DIR.get_or_init(|| tempfile::tempdir().unwrap());
            std::env::set_var("KRB5CCNAME", format!("DIR:{}", dir.path().display()));
        }
    });
    Some(Env { spn })
}

// ---------------------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------------------

struct Harness {
    port: u16,
    dir: tempfile::TempDir,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl Harness {
    async fn start(env: &Env) -> Harness {
        let port = common::free_port();
        let dir = tempfile::tempdir().unwrap();
        let toml = common::wef_toml(&format!("http://{HOST}:{port}")).replace(
            "allow_unauthenticated = true",
            "allow_unauthenticated = false",
        );
        let wef: WefConfig = toml::from_str::<Config>(&toml).unwrap().wef;
        let config = Config {
            bind_address: format!("127.0.0.1:{port}").parse().unwrap(),
            tls: TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            },
            metrics: MetricsConfig {
                enabled: false,
                ..MetricsConfig::default()
            },
            security: SecurityConfig {
                // keytab stays None: the harness exported KRB5_KTNAME once, and the server
                // would otherwise setenv concurrently with other tests' GSS calls.
                kerberos: KerberosSecurityConfig {
                    enabled: true,
                    spn: Some(env.spn.clone()),
                    keytab: None,
                },
                ..SecurityConfig::default()
            },
            wef: WefConfig {
                local: Some(WefLocalConfig {
                    directory: dir.path().to_path_buf(),
                    prefix: "".to_string(),
                    flush_threshold_bytes: usize::MAX,
                    flush_interval_secs: 3600,
                    channel_capacity: 256,
                    max_buffer_rows: 100_000,
                }),
                ..wef
            },
            ..Config::default()
        };
        let shared = Arc::new(RwLock::new(config.clone()));
        let mut server = Server::new(
            config,
            shared,
            Arc::new(ThroughputStats::new()),
            Arc::new(SourceHourlyStats::new()),
            FlushIntervalRegistry::new(),
            IpWhitelist::empty(),
            Vec::new(),
        )
        .await
        .expect("Server::new with real Kerberos");
        let workers = server.take_wef_worker_handles();
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            server.run(rx).await.expect("server run");
        });
        let client = reqwest::Client::new();
        for _ in 0..100 {
            if let Ok(r) = client
                .get(format!("http://127.0.0.1:{port}/health"))
                .send()
                .await
                && r.status().is_success()
            {
                return Harness {
                    port,
                    dir,
                    shutdown,
                    task,
                    workers,
                };
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become ready");
    }

    async fn conn(&self) -> Conn {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        let (sender, driver) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = driver.await;
        });
        Conn { sender }
    }

    fn sub_url(&self) -> String {
        format!("/wsman/subscriptions/{}", common::TEST_SUB_UUID)
    }

    async fn finish(self) -> Vec<RecordBatch> {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("server joins")
            .expect("server task");
        for h in self.workers {
            tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("worker joins")
                .expect("worker task");
        }
        common::read_all(self.dir.path())
    }
}

/// One persistent HTTP/1.1 connection: connection identity is exactly this TCP stream.
struct Conn {
    sender: SendRequest<Full<Bytes>>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Conn {
    async fn post(
        &mut self,
        path: &str,
        content_type: Option<&str>,
        authorization: Option<String>,
        body: Vec<u8>,
    ) -> Reply {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header("Host", HOST);
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        if let Some(a) = authorization {
            req = req.header("Authorization", a);
        }
        let resp = self
            .sender
            .send_request(req.body(Full::new(Bytes::from(body))).unwrap())
            .await
            .expect("request on persistent connection");
        let (parts, body) = resp.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// GSS client
// ---------------------------------------------------------------------------------------

/// Initiator context for `principal` towards `HTTP@<target_host>` plus its first token.
/// Windows' flags: mutual, replay, sequence, confidentiality, integrity.
fn initiate(principal: &str, target_host: &str, mech: &'static Oid) -> (ClientCtx, Vec<u8>) {
    let name = Name::new(principal.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL)).unwrap();
    let mut mechs = OidSet::new().unwrap();
    mechs.add(mech).unwrap();
    let cred = Cred::acquire(Some(&name), None, CredUsage::Initiate, Some(&mechs))
        .unwrap_or_else(|e| panic!("client credential for {principal} from keytab: {e}"));
    let target = Name::new(
        format!("HTTP@{target_host}").as_bytes(),
        Some(&GSS_NT_HOSTBASED_SERVICE),
    )
    .unwrap();
    let flags = CtxFlags::GSS_C_MUTUAL_FLAG
        | CtxFlags::GSS_C_REPLAY_FLAG
        | CtxFlags::GSS_C_SEQUENCE_FLAG
        | CtxFlags::GSS_C_CONF_FLAG
        | CtxFlags::GSS_C_INTEG_FLAG;
    let mut ctx = ClientCtx::new(Some(cred), target, flags, Some(mech));
    let token = ctx
        .step(None, None)
        .unwrap_or_else(|e| panic!("init_sec_context for {principal} -> {target_host}: {e}"))
        .expect("first token");
    (ctx, token.to_vec())
}

fn auth_header(scheme: &str, token: &[u8]) -> String {
    format!("{scheme} {}", B64.encode(token))
}

/// Windows handshake on a fresh connection: empty POST with the AP-REQ, then feed the
/// AP-REP from `WWW-Authenticate` to the client so mutual authentication completes.
async fn authenticate(conn: &mut Conn, principal: &str, target_host: &str) -> ClientCtx {
    let (mut ctx, token) = initiate(principal, target_host, &GSS_MECH_KRB5);
    let r = conn
        .post(
            "/wsman",
            None,
            Some(auth_header("Kerberos", &token)),
            Vec::new(),
        )
        .await;
    assert_eq!(r.status, 200, "AP-REQ for {principal} must be accepted");
    assert!(r.body.is_empty(), "handshake reply carries no body");
    let challenge = r
        .headers
        .get("www-authenticate")
        .expect("AP-REP in WWW-Authenticate")
        .to_str()
        .unwrap();
    let ap_rep = challenge
        .strip_prefix("Kerberos ")
        .unwrap_or_else(|| panic!("scheme must be mirrored, got {challenge:?}"));
    let out = ctx
        .step(Some(&B64.decode(ap_rep).unwrap()), None)
        .expect("AP-REP accepted by client");
    assert!(out.is_none(), "mutual auth completes with no further token");
    assert!(ctx.is_complete());
    ctx
}

/// MS-WSMV client encryption of a UTF-16 SOAP body: header and padding allocated by
/// GSSAPI, data encrypted in place.
fn encrypt(ctx: &mut ClientCtx, plain: &[u8]) -> Vec<u8> {
    let mut data = plain.to_vec();
    let mut iov = [
        GssIov::new_alloc(GssIovType::Header),
        GssIov::new(GssIovType::Data, &mut data),
        GssIov::new_alloc(GssIovType::Padding),
    ];
    ctx.wrap_iov(true, &mut iov).expect("client wrap_iov");
    let header = iov[0].to_vec();
    let padding = iov[2].to_vec();
    drop(iov);
    data.extend_from_slice(&padding);
    multipart::build(EncProtocol::Kerberos, plain.len(), &header, &data)
}

/// Inverse of [`encrypt`] for a server response; returns the decoded SOAP text.
fn decrypt(ctx: &mut ClientCtx, reply: &Reply) -> String {
    let ct = reply
        .headers
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string());
    assert_eq!(
        multipart::detect(ct.as_deref()),
        Some(EncProtocol::Kerberos),
        "response must be encrypted, got {ct:?}"
    );
    let payload = multipart::parse(&reply.body).expect("server multipart");
    let mut header = payload.header;
    let mut data = payload.data;
    let mut iov = [
        GssIov::new(GssIovType::Header, &mut header),
        GssIov::new(GssIovType::Data, &mut data),
    ];
    ctx.unwrap_iov(&mut iov)
        .expect("client unwrap_iov of server response");
    drop(iov);
    data.truncate(payload.original_length);
    assert_eq!(
        &data[..2],
        &[0xFF, 0xFE],
        "decrypted body starts with a UTF-16LE BOM"
    );
    common::decode_utf16(&data)
}

const ENC_CT: &str = "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";\
                      boundary=\"Encrypted Boundary\"";

/// Send `envelope` encrypted with `ctx` and return the (status, decrypted text if 200+body).
async fn exchange(
    conn: &mut Conn,
    ctx: &mut ClientCtx,
    path: &str,
    envelope: &str,
) -> (StatusCode, Option<String>) {
    let body = encrypt(ctx, &common::utf16(envelope));
    let r = conn.post(path, Some(ENC_CT), None, body).await;
    let text = (r.status == 200 && !r.body.is_empty()).then(|| decrypt(ctx, &r));
    (r.status, text)
}

fn plain_enumerate() -> Vec<u8> {
    common::utf16(&common::enumerate_envelope(
        "22222222-0000-4000-8000-000000000001",
        MACHINE,
    ))
}

async fn assert_unauthorized(conn: &mut Conn, what: &str) {
    let r = conn
        .post(
            "/wsman",
            Some("application/soap+xml;charset=UTF-16"),
            None,
            plain_enumerate(),
        )
        .await;
    assert_eq!(r.status, 401, "{what}");
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_empty_auth_post_then_encrypted_enumerate() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut conn = h.conn().await;
    let mut ctx = authenticate(&mut conn, "WIN10$@EXAMPLE.COM", HOST).await;

    let mid = "11111111-0000-4000-8000-000000000001";
    let (st, text) = exchange(
        &mut conn,
        &mut ctx,
        "/wsman",
        &common::enumerate_envelope(mid, MACHINE),
    )
    .await;
    assert_eq!(st, 200);
    let text = text.expect("encrypted EnumerateResponse");
    assert!(text.contains("EnumerateResponse"), "{text}");
    assert!(
        text.contains(&format!("<a:RelatesTo>uuid:{mid}</a:RelatesTo>")),
        "{text}"
    );
    assert!(text.contains(&h.sub_url()), "{text}");
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_encrypted_events_ingested() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut conn = h.conn().await;
    let mut ctx = authenticate(&mut conn, "WIN10$@EXAMPLE.COM", HOST).await;

    let fixtures = ["security_4624", "security_4625", "sysmon_1"].map(common::wef_fixture);
    let refs: Vec<&str> = fixtures.iter().map(String::as_str).collect();
    let mid = "11111111-0000-4000-8000-000000000003";
    let (st, text) = exchange(
        &mut conn,
        &mut ctx,
        &h.sub_url(),
        &common::events_envelope(mid, MACHINE, 1742, &refs),
    )
    .await;
    assert_eq!(st, 200);
    let text = text.expect("encrypted Ack");
    assert!(common::acks(&text, mid), "{text}");

    let rows: usize = h.finish().await.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        rows, 3,
        "events decrypted by the server must land in the sink"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_new_principal_on_same_connection_authenticates_as_new() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut conn = h.conn().await;

    let mut first = authenticate(&mut conn, "WIN10$@EXAMPLE.COM", HOST).await;
    let (st, _) = exchange(
        &mut conn,
        &mut first,
        "/wsman",
        &common::enumerate_envelope("a1", MACHINE),
    )
    .await;
    assert_eq!(st, 200);

    // A new Authorization header on the same connection builds a fresh context: the server
    // can then only decrypt traffic wrapped by the *second* client context.
    let mut second = authenticate(&mut conn, "WIN11$@EXAMPLE.COM", HOST).await;
    let (st, text) = exchange(
        &mut conn,
        &mut second,
        "/wsman",
        &common::enumerate_envelope("a2", "win11.example.com"),
    )
    .await;
    assert_eq!(st, 200);
    assert!(text.expect("encrypted reply").contains("EnumerateResponse"));

    let garbage = auth_header("Kerberos", b"\x60\x03not-a-real-ap-req");
    let r = conn.post("/wsman", None, Some(garbage), Vec::new()).await;
    assert_eq!(r.status, 401, "garbage token after two successes");
    assert_unauthorized(
        &mut conn,
        "failed re-auth must drop the connection's authentication",
    )
    .await;
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_garbage_token_after_success_401() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut conn = h.conn().await;
    let mut ctx = authenticate(&mut conn, "WIN10$@EXAMPLE.COM", HOST).await;
    let (st, _) = exchange(
        &mut conn,
        &mut ctx,
        "/wsman",
        &common::enumerate_envelope("b1", MACHINE),
    )
    .await;
    assert_eq!(st, 200);

    let r = conn
        .post(
            "/wsman",
            None,
            Some(auth_header("Kerberos", &[0x42; 64])),
            Vec::new(),
        )
        .await;
    assert_eq!(r.status, 401);
    let challenges: Vec<_> = r.headers.get_all("www-authenticate").iter().collect();
    assert!(
        challenges.len() >= 2,
        "401 offers Kerberos and Negotiate: {challenges:?}"
    );
    // The earlier success must not leave the connection authenticated.
    let (st, _) = exchange(
        &mut conn,
        &mut ctx,
        "/wsman",
        &common::enumerate_envelope("b2", MACHINE),
    )
    .await;
    assert_eq!(st, 401);
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_wrong_spn_ticket_401() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut conn = h.conn().await;

    // A genuine KDC-issued ticket, but for HTTP/other.example.com: the server keytab holds
    // no key for it.
    let (_ctx, token) = initiate("WIN10$@EXAMPLE.COM", "other.example.com", &GSS_MECH_KRB5);
    let r = conn
        .post(
            "/wsman",
            None,
            Some(auth_header("Kerberos", &token)),
            Vec::new(),
        )
        .await;
    assert_eq!(r.status, 401);
    assert_unauthorized(&mut conn, "connection stays unauthenticated").await;
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_negotiate_syslog_per_request() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut conn = h.conn().await;

    // SPNEGO-wrapped token, as curl/browsers send it, on a non-WSMan route: authenticated
    // per request, no connection state.
    let (_ctx, token) = initiate("alice@EXAMPLE.COM", HOST, &GSS_MECH_SPNEGO);
    let r = conn
        .post(
            "/syslog",
            Some("text/plain"),
            Some(auth_header("Negotiate", &token)),
            SYSLOG_MSG.as_bytes().to_vec(),
        )
        .await;
    assert!(r.status.is_success(), "alice via SPNEGO: {}", r.status);

    let r = conn
        .post(
            "/syslog",
            Some("text/plain"),
            None,
            SYSLOG_MSG.as_bytes().to_vec(),
        )
        .await;
    assert_eq!(r.status, 401, "no per-request credentials, no access");
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_real_kerberos_second_connection_needs_own_auth() {
    let Some(env) = krb_env() else { return };
    let h = Harness::start(&env).await;
    let mut a = h.conn().await;
    let mut b = h.conn().await;

    let mut ctx = authenticate(&mut a, "WIN10$@EXAMPLE.COM", HOST).await;
    assert_unauthorized(&mut b, "connection B never authenticated").await;

    // Connection A is unaffected by B's rejection.
    let (st, _) = exchange(
        &mut a,
        &mut ctx,
        "/wsman",
        &common::enumerate_envelope("c1", MACHINE),
    )
    .await;
    assert_eq!(st, 200);
    h.finish().await;
}
