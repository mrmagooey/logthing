//! Integration tests of the HTTPS client-certificate WEF topology: an in-process `Server`
//! serving TLS with `require_client_cert`, a throwaway CA generated per test run, and a
//! `reqwest` client presenting (or not) a client certificate.

mod common;

use logthing::config::{Config, MetricsConfig, TlsConfig, WefConfig, WefLocalConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use sha1::{Digest, Sha1};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

const MACHINE: &str = "win10.example.com";

/// A CA with its key, able to sign leaf certificates.
struct Ca {
    cert: Certificate,
    key: KeyPair,
}

/// A leaf certificate and key, PEM encoded.
struct Leaf {
    cert_pem: String,
    key_pem: String,
}

impl Ca {
    fn new(cn: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert, key }
    }

    fn pem(&self) -> String {
        self.cert.pem()
    }

    fn der_sha1_upper(&self) -> String {
        Sha1::digest(self.cert.der().as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    fn issue(&self, cn: &str, server: bool) -> Leaf {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        if server {
            params
                .subject_alt_names
                .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        } else {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}

struct Harness {
    base: String,
    dir: tempfile::TempDir,
    _tls_dir: tempfile::TempDir,
    ca: Ca,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

/// Build a config for the TLS listener on `port`, with the CA, server key and cert written
/// under `tls_dir`.
fn tls_config(
    wef_toml: &str,
    port: u16,
    dir: &Path,
    tls_dir: &Path,
    ca: &Ca,
    require_client_cert: bool,
) -> Config {
    let server = ca.issue("localhost", true);
    let (ca_file, cert_file, key_file) = (
        tls_dir.join("ca.pem"),
        tls_dir.join("server.pem"),
        tls_dir.join("server.key"),
    );
    std::fs::write(&ca_file, ca.pem()).unwrap();
    std::fs::write(&cert_file, &server.cert_pem).unwrap();
    std::fs::write(&key_file, &server.key_pem).unwrap();
    let wef: WefConfig = toml::from_str::<Config>(wef_toml).unwrap().wef;
    Config {
        bind_address: format!("127.0.0.1:{}", common::free_port())
            .parse()
            .unwrap(),
        tls: TlsConfig {
            enabled: true,
            port,
            cert_file: Some(cert_file),
            key_file: Some(key_file),
            ca_file: Some(ca_file),
            require_client_cert,
        },
        metrics: MetricsConfig {
            enabled: false,
            ..MetricsConfig::default()
        },
        wef: WefConfig {
            local: Some(WefLocalConfig {
                directory: dir.to_path_buf(),
                prefix: "".to_string(),
                flush_threshold_bytes: usize::MAX,
                flush_interval_secs: 3600,
                channel_capacity: 256,
                max_buffer_rows: 100_000,
            }),
            ..wef
        },
        ..Config::default()
    }
}

async fn new_server(config: Config) -> anyhow::Result<Server> {
    let shared = Arc::new(RwLock::new(config.clone()));
    Server::new(
        config,
        shared,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
        Vec::new(),
    )
    .await
}

/// A client trusting `ca`, presenting `identity` (cert + key PEM) when given.
fn client(ca: &Ca, identity: Option<&Leaf>) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap());
    if let Some(l) = identity {
        let pem = format!("{}\n{}", l.cert_pem, l.key_pem);
        b = b.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
    }
    b.build().unwrap()
}

impl Harness {
    async fn start() -> Harness {
        Self::start_with(|c| c, |t| t).await
    }

    async fn start_with(
        tweak_config: impl FnOnce(Config) -> Config,
        tweak_toml: impl Fn(String) -> String,
    ) -> Harness {
        logthing::server::install_crypto_provider();
        let port = common::free_port();
        let base = format!("https://127.0.0.1:{port}");
        let dir = tempfile::tempdir().unwrap();
        let tls_dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("logthing mtls test CA");
        let toml =
            tweak_toml(common::wef_toml(&base).replace("allow_unauthenticated = true\n", ""));
        let config = tweak_config(tls_config(
            &toml,
            port,
            dir.path(),
            tls_dir.path(),
            &ca,
            true,
        ));
        let mut server = new_server(config).await.expect("Server::new");
        let workers = server.take_wef_worker_handles();
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            server.run_tls(rx).await.expect("server run_tls");
        });
        let h = Harness {
            base,
            dir,
            _tls_dir: tls_dir,
            ca,
            shutdown,
            task,
            workers,
        };
        let c = h.good_client();
        for _ in 0..100 {
            if let Ok(r) = c.get(format!("{}/health", h.base)).send().await
                && r.status().is_success()
            {
                return h;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("TLS server did not become ready");
    }

    fn good_client(&self) -> reqwest::Client {
        client(&self.ca, Some(&self.ca.issue("win10.example.com", false)))
    }

    async fn post(&self, c: &reqwest::Client, url: &str, envelope: &str) -> (u16, String) {
        let resp = c
            .post(url)
            .header("Content-Type", "application/soap+xml;charset=UTF-16")
            .body(common::utf16(envelope))
            .send()
            .await
            .expect("POST");
        let status = resp.status().as_u16();
        let ct = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = resp.bytes().await.unwrap();
        if bytes.is_empty() {
            return (status, String::new());
        }
        assert_eq!(&bytes[..2], &[0xFF, 0xFE], "UTF-16LE BOM expected");
        assert_eq!(ct.as_deref(), Some("application/soap+xml;charset=UTF-16"));
        (status, common::decode_utf16(&bytes))
    }

    async fn finish(self) -> Vec<arrow::record_batch::RecordBatch> {
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

#[tokio::test]
async fn test_mtls_enumerate_returns_https_mutual_policy_with_ca_thumbprint() {
    let h = Harness::start().await;
    let c = h.good_client();
    let (st, body) = h
        .post(
            &c,
            &format!("{}/wsman", h.base),
            &common::enumerate_envelope("c1", MACHINE),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("Thumbprint"), "{body}");
    assert!(
        body.contains(&format!(
            "<auth:Thumbprint Role=\"issuer\">{}</auth:Thumbprint>",
            h.ca.der_sha1_upper()
        )),
        "{body}"
    );
    assert!(common::notify_to(&body).starts_with("https://"), "{body}");
    h.finish().await;
}

#[tokio::test]
async fn test_mtls_events_flow_lands_rows() {
    let h = Harness::start().await;
    let c = h.good_client();
    let (_, body) = h
        .post(
            &c,
            &format!("{}/wsman", h.base),
            &common::enumerate_envelope("d1", MACHINE),
        )
        .await;
    let url = common::notify_to(&body);
    let fixtures = ["security_4624", "security_4625"].map(common::wef_fixture);
    let refs: Vec<&str> = fixtures.iter().map(String::as_str).collect();
    let mid = "33333333-0000-4000-8000-000000000001";
    let (st, body) = h
        .post(&c, &url, &common::events_envelope(mid, MACHINE, 77, &refs))
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(common::acks(&body, mid), "{body}");
    let batches = h.finish().await;
    assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
}

#[tokio::test]
async fn test_mtls_no_client_cert_handshake_rejected() {
    let h = Harness::start().await;
    let anonymous = client(&h.ca, None);
    let res = anonymous.get(format!("{}/health", h.base)).send().await;
    assert!(
        res.is_err(),
        "no client cert must not get a response: {res:?}"
    );
    h.finish().await;
}

#[tokio::test]
async fn test_mtls_cert_from_other_ca_rejected() {
    let h = Harness::start().await;
    let other = Ca::new("unrelated CA");
    let rogue = other.issue("win10.example.com", false);
    let c = client(&h.ca, Some(&rogue));
    let res = c.get(format!("{}/health", h.base)).send().await;
    assert!(res.is_err(), "foreign-CA cert must be rejected: {res:?}");
    h.finish().await;
}

#[tokio::test]
async fn test_oversize_wsman_body_is_413_over_mtls() {
    let h = Harness::start().await;
    let c = h.good_client();
    let big = vec![b'a'; 5 * 1024 * 1024];
    let resp = c
        .post(format!("{}/wsman", h.base))
        .header("Content-Type", "application/soap+xml;charset=UTF-16")
        .body(big)
        .send()
        .await
        .expect("POST");
    assert_eq!(resp.status().as_u16(), 413);
    h.finish().await;
}

#[tokio::test]
async fn test_tls_without_require_client_cert_and_subscriptions_fails_startup() {
    let port = common::free_port();
    let dir = tempfile::tempdir().unwrap();
    let tls_dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("startup CA");
    let toml = common::wef_toml(&format!("https://127.0.0.1:{port}"))
        .replace("allow_unauthenticated = true\n", "");
    let config = tls_config(&toml, port, dir.path(), tls_dir.path(), &ca, false);
    let err = new_server(config)
        .await
        .err()
        .expect("Server::new must refuse TLS without client certs for WEF subscriptions");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("WEF subscriptions over TLS require tls.require_client_cert = true"),
        "{msg}"
    );
}

/// Write a keytab (file format 0x502) holding one fabricated aes256 key for `principal`
/// (`service/host@REALM`), enough for GSSAPI to acquire an acceptor credential offline.
#[cfg(feature = "kerberos-auth")]
fn write_dummy_keytab(path: &Path, principal: &str) {
    let (name, realm) = principal.split_once('@').unwrap();
    let comps: Vec<&str> = name.split('/').collect();
    let mut e = Vec::new();
    e.extend((comps.len() as u16).to_be_bytes());
    e.extend((realm.len() as u16).to_be_bytes());
    e.extend(realm.as_bytes());
    for c in &comps {
        e.extend((c.len() as u16).to_be_bytes());
        e.extend(c.as_bytes());
    }
    e.extend(1u32.to_be_bytes()); // KRB5_NT_PRINCIPAL
    e.extend(0u32.to_be_bytes()); // timestamp
    e.push(1); // kvno
    e.extend(18u16.to_be_bytes()); // aes256-cts-hmac-sha1-96
    e.extend(32u16.to_be_bytes());
    e.extend([7u8; 32]);
    let mut out = vec![0x05, 0x02];
    out.extend((e.len() as i32).to_be_bytes());
    out.extend(e);
    std::fs::write(path, out).unwrap();
}

#[cfg(feature = "kerberos-auth")]
#[tokio::test]
async fn test_mtls_syslog_still_requires_kerberos_when_enabled() {
    let keytab_dir = tempfile::tempdir().unwrap();
    let keytab = keytab_dir.path().join("test.keytab");
    let spn = "HTTP/wec.example.com@EXAMPLE.COM";
    write_dummy_keytab(&keytab, spn);
    let kt = keytab.clone();
    let h = Harness::start_with(
        move |mut c| {
            c.security.kerberos.enabled = true;
            c.security.kerberos.spn = Some(spn.to_string());
            c.security.kerberos.keytab = Some(kt);
            c
        },
        |t| t,
    )
    .await;
    let c = h.good_client();
    // /syslog keeps the Negotiate challenge even over a valid mTLS connection ...
    let resp = c
        .post(format!("{}/syslog", h.base))
        .body("<34>Oct 11 22:14:15 host su: test")
        .send()
        .await
        .expect("POST /syslog");
    assert_eq!(resp.status().as_u16(), 401);
    // ... while /wsman is authenticated by the client certificate alone.
    let (st, _) = h
        .post(
            &c,
            &format!("{}/wsman", h.base),
            &common::enumerate_envelope("e1", MACHINE),
        )
        .await;
    assert_eq!(st, 200);
    h.finish().await;
}
