//! WEF subscription runtime: deployment-topology validation, version GUIDs, and rendering
//! of the `<m:Subscription>` item returned inside an EnumerateResponse.

use std::path::Path;

use anyhow::{Context, anyhow, bail};
use quick_xml::Reader;
use quick_xml::events::Event;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::config::{Config, ContentFormat, WefSubscriptionConfig};
use crate::wef::soap::{ACTION_SUBSCRIBE, ADDRESS_ANONYMOUS, xml_escape};

/// Fixed namespace for deriving subscription version GUIDs (UUIDv5). Never change it:
/// doing so would make every client see every subscription as modified.
const VERSION_NAMESPACE: Uuid = Uuid::from_u128(0x6f0c5b9e_3a1d_4c7e_9b52_7d4e8a1f2c60);

const MAX_CHANNELS: usize = 256;
const MIN_ENVELOPE_SIZE: u32 = 8192;

/// How clients authenticate to this collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WefTopology {
    /// Plain HTTP with Kerberos (SPNEGO) message-level encryption.
    PlainKerberos,
    /// Plain HTTP, no client authentication (explicitly opted in).
    PlainUnauthenticated,
    /// HTTPS with mutual TLS client certificates.
    HttpsMutual,
}

impl WefTopology {
    fn as_str(self) -> &'static str {
        match self {
            Self::PlainKerberos => "plain-kerberos",
            Self::PlainUnauthenticated => "plain-unauthenticated",
            Self::HttpsMutual => "https-mutual",
        }
    }
}

/// Validated WEF settings shared by the subscription manager and delivery endpoints.
#[derive(Debug, Clone)]
pub struct WefRuntime {
    /// Deployment topology.
    pub topology: WefTopology,
    /// Collector base URL without trailing slash.
    pub collector_url: String,
    /// Enabled subscriptions.
    pub subscriptions: Vec<Subscription>,
    /// Uppercase SHA-1 thumbprints of the client CA certificates (HTTPS only).
    pub issuer_thumbprints: Vec<String>,
}

/// A validated, enabled subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Original configuration.
    pub cfg: WefSubscriptionConfig,
    /// Version GUID; changes whenever any client-visible parameter changes.
    pub version: Uuid,
    /// The `<QueryList>` XML sent to clients.
    pub query_xml: String,
}

/// True for a pre-subscription WEF config: WEF settings are present (a sink, a collector URL
/// or `allow_unauthenticated`) but no `[[wef.subscriptions]]`, so `/wsman` now answers 404.
pub fn wef_legacy_config_without_subscriptions(wef: &crate::config::WefConfig) -> bool {
    wef.subscriptions.is_empty()
        && (wef.s3.is_some()
            || wef.local.is_some()
            || wef.collector_url.is_some()
            || wef.allow_unauthenticated)
}

/// True when Kerberos is configured but TLS makes `/wsman` use the client-certificate
/// topology, which does not apply Kerberos.
pub fn kerberos_ignored_under_tls(tls_enabled: bool, kerberos_available: bool) -> bool {
    tls_enabled && kerberos_available
}

/// Checks the deployment-topology matrix in one place.
///
/// `kerberos_available` = `security.kerberos.enabled && cfg!(feature = "kerberos-auth")`.
/// Returns `Ok(None)` when no subscriptions are configured (subscription manager disabled).
pub fn validate_wef_topology(
    cfg: &Config,
    kerberos_available: bool,
) -> anyhow::Result<Option<WefRuntime>> {
    let wef = &cfg.wef;
    if wef.subscriptions.is_empty() {
        return Ok(None);
    }
    let mut queries = Vec::with_capacity(wef.subscriptions.len());
    for (i, s) in wef.subscriptions.iter().enumerate() {
        if wef.subscriptions[..i].iter().any(|p| p.name == s.name) {
            bail!("duplicate wef.subscriptions name '{}'", s.name);
        }
        if wef.subscriptions[..i].iter().any(|p| p.uuid == s.uuid) {
            bail!("duplicate wef.subscriptions uuid {} ('{}')", s.uuid, s.name);
        }
        queries.push(validate_subscription(s)?);
    }

    let url = match wef.collector_url.as_deref().map(str::trim) {
        Some(u) if !u.is_empty() => u.trim_end_matches('/').to_string(),
        _ => bail!("wef.collector_url is required when [[wef.subscriptions]] are configured"),
    };
    let tls = &cfg.tls;
    let (topology, issuer_thumbprints) = if tls.enabled {
        if !tls.require_client_cert {
            bail!(
                "WEF subscriptions over TLS require tls.require_client_cert = true (Windows \
                 HTTPS delivery uses client certificates); for Kerberos, disable TLS and use \
                 the plain HTTP listener"
            );
        }
        let ca = tls.ca_file.as_deref().ok_or_else(|| {
            anyhow!("WEF subscriptions over TLS require tls.ca_file (client CA certificates)")
        })?;
        if !url.starts_with("https://") {
            bail!("wef.collector_url must use https:// when TLS is enabled");
        }
        if kerberos_ignored_under_tls(tls.enabled, kerberos_available) {
            tracing::warn!(
                "Kerberos is enabled but TLS is also enabled: Kerberos is not applied to \
                 /wsman when TLS is enabled (clients authenticate with client certificates)"
            );
        }
        (WefTopology::HttpsMutual, ca_thumbprints(ca)?)
    } else {
        if !url.starts_with("http://") {
            bail!("wef.collector_url must use http:// when TLS is disabled");
        }
        if kerberos_available {
            (WefTopology::PlainKerberos, Vec::new())
        } else if wef.allow_unauthenticated {
            tracing::warn!(
                "WEF subscription manager and delivery endpoints accept ANY client; \
                 security.allowed_ips is the only remaining control"
            );
            (WefTopology::PlainUnauthenticated, Vec::new())
        } else {
            bail!(
                "WEF subscriptions require authentication: enable [security.kerberos] (built \
                 with --features kerberos-auth) or TLS with require_client_cert, or set \
                 wef.allow_unauthenticated = true"
            );
        }
    };

    let subscriptions = wef
        .subscriptions
        .iter()
        .zip(queries)
        .filter(|(s, _)| s.enabled)
        .map(|(s, query_xml)| Subscription {
            version: version_uuid(s, &query_xml, &url, topology, &issuer_thumbprints),
            cfg: s.clone(),
            query_xml,
        })
        .collect();
    Ok(Some(WefRuntime {
        topology,
        collector_url: url,
        subscriptions,
        issuer_thumbprints,
    }))
}

fn validate_subscription(s: &WefSubscriptionConfig) -> anyhow::Result<String> {
    let name_ok = !s.name.is_empty()
        && s.name.len() <= 128
        && s.name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !name_ok {
        bail!(
            "wef.subscriptions name '{}' must be 1..=128 chars of [A-Za-z0-9_.-]",
            s.name
        );
    }
    if s.max_envelope_size < MIN_ENVELOPE_SIZE {
        bail!(
            "wef.subscriptions '{}': max_envelope_size must be >= {MIN_ENVELOPE_SIZE}",
            s.name
        );
    }
    match (&s.query, s.channels.is_empty()) {
        (Some(_), false) => {
            bail!(
                "wef.subscriptions '{}': set either channels or query, not both",
                s.name
            )
        }
        (None, true) => bail!(
            "wef.subscriptions '{}': set either channels or query",
            s.name
        ),
        (Some(q), true) => {
            validate_query_list(q).with_context(|| format!("wef.subscriptions '{}'", s.name))?;
            Ok(q.clone())
        }
        (None, false) => {
            if s.channels.len() > MAX_CHANNELS {
                bail!(
                    "wef.subscriptions '{}': at most {MAX_CHANNELS} channels",
                    s.name
                );
            }
            if s.channels.iter().any(|c| c.trim().is_empty()) {
                bail!("wef.subscriptions '{}': empty channel name", s.name);
            }
            Ok(render_query_list(&s.channels))
        }
    }
}

/// Requires well-formed XML with a single `QueryList` root and no declaration/DTD/PI, since
/// the text is embedded verbatim inside the Subscribe filter.
fn validate_query_list(q: &str) -> anyhow::Result<()> {
    validate_xml_fragment(q, "QueryList")
}

/// Checks that `xml` is a complete, well-formed fragment with exactly one root element whose
/// local name is `root`: all elements closed, no declaration/DOCTYPE/PI, no comments, CDATA or
/// text outside the root, and no undeclared entities. Callers embed the text verbatim in an
/// outgoing envelope, so anything that could unbalance or extend it is rejected.
pub(crate) fn validate_xml_fragment(xml: &str, root: &str) -> anyhow::Result<()> {
    let bad_root = || anyhow!("XML must have a single <{root}> root element");
    let mut r = Reader::from_str(xml);
    let (mut depth, mut roots) = (0usize, 0usize);
    loop {
        let ev = r
            .read_event()
            .map_err(|e| anyhow!("XML is not well-formed: {e}"))?;
        match &ev {
            Event::Start(e) | Event::Empty(e) => {
                if depth == 0 {
                    roots += 1;
                    if roots > 1 || e.local_name().as_ref() != root.as_bytes() {
                        return Err(bad_root());
                    }
                }
                for a in e.attributes() {
                    let a = a.map_err(|e| anyhow!("XML is not well-formed: {e}"))?;
                    a.unescape_value()
                        .map_err(|e| anyhow!("XML has a bad entity: {e}"))?;
                }
                if matches!(ev, Event::Start(_)) {
                    depth += 1;
                }
            }
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Decl(_) | Event::DocType(_) | Event::PI(_) => {
                bail!("XML must not contain an XML declaration, DOCTYPE or processing instruction")
            }
            Event::Comment(_) | Event::CData(_) if depth == 0 => {
                bail!("XML has a comment or CDATA outside <{root}>")
            }
            Event::Text(t) => {
                if depth == 0 && !t.iter().all(u8::is_ascii_whitespace) {
                    bail!("XML has text outside <{root}>");
                }
                t.unescape()
                    .map_err(|e| anyhow!("XML has a bad entity: {e}"))?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        bail!("XML has unclosed elements");
    }
    if roots != 1 {
        return Err(bad_root());
    }
    Ok(())
}

/// Version GUID: UUIDv5 under [`VERSION_NAMESPACE`] over a canonical, length-prefixed
/// serialization of ONLY the client-visible parameters, in this order: name, uuid,
/// query_xml, content_format, heartbeat_interval_secs, max_latency_secs, max_envelope_size,
/// read_existing_events, collector_url, topology, issuer thumbprints. `enabled` is excluded.
fn version_uuid(
    s: &WefSubscriptionConfig,
    query_xml: &str,
    collector_url: &str,
    topology: WefTopology,
    thumbprints: &[String],
) -> Uuid {
    let fields = [
        s.name.clone(),
        s.uuid.as_hyphenated().to_string(),
        query_xml.to_string(),
        match s.content_format {
            ContentFormat::Raw => "Raw",
            ContentFormat::RenderedText => "RenderedText",
        }
        .to_string(),
        s.heartbeat_interval_secs.to_string(),
        s.max_latency_secs.to_string(),
        s.max_envelope_size.to_string(),
        s.read_existing_events.to_string(),
        collector_url.to_string(),
        topology.as_str().to_string(),
        thumbprints.join(","),
    ];
    let mut canon = String::new();
    for f in &fields {
        canon.push_str(&format!("{}:{};", f.len(), f));
    }
    Uuid::new_v5(&VERSION_NAMESPACE, canon.as_bytes())
}

fn upper(u: Uuid) -> String {
    u.as_hyphenated().to_string().to_uppercase()
}

/// Renders `<QueryList>` selecting every event of each channel.
pub fn render_query_list(channels: &[String]) -> String {
    let mut out = String::from("<QueryList><Query Id=\"0\">");
    for c in channels {
        out.push_str(&format!("<Select Path=\"{}\">*</Select>", xml_escape(c)));
    }
    out.push_str("</Query></QueryList>");
    out
}

/// Renders the `<m:Subscription>` item (Version + embedded Subscribe envelope).
///
/// `bookmark` is XML replayed verbatim; without one, `read_existing_events` selects the
/// "earliest" bookmark URI. Everything else interpolated is XML-escaped.
pub fn render_subscription_item(
    rt: &WefRuntime,
    sub: &Subscription,
    bookmark: Option<&str>,
) -> String {
    let c = &sub.cfg;
    let version = upper(sub.version);
    let msg_id = upper(Uuid::new_v5(&sub.version, b"message-id"));
    let op_id = upper(Uuid::new_v5(&sub.version, b"operation-id"));
    let addr = xml_escape(&format!(
        "{}/wsman/subscriptions/{}",
        rt.collector_url,
        upper(c.uuid)
    ))
    .into_owned();
    let anon = xml_escape(ADDRESS_ANONYMOUS);
    let format = match c.content_format {
        ContentFormat::Raw => "Raw",
        ContentFormat::RenderedText => "RenderedText",
    };
    let read_existing = if c.read_existing_events {
        "<w:Option Name=\"ReadExistingEvents\">true</w:Option>"
    } else {
        ""
    };
    let policy = match rt.topology {
        WefTopology::HttpsMutual => {
            let mut p = String::from(
                "<auth:Authentication Profile=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/\
                 secprofile/https/mutual\"><auth:ClientCertificate>",
            );
            for t in &rt.issuer_thumbprints {
                p.push_str(&format!(
                    "<auth:Thumbprint Role=\"issuer\">{}</auth:Thumbprint>",
                    xml_escape(t)
                ));
            }
            p.push_str("</auth:ClientCertificate></auth:Authentication>");
            p
        }
        _ => "<auth:Authentication Profile=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/\
              secprofile/http/spnego-kerberos\"></auth:Authentication>"
            .to_string(),
    };
    let bookmark_xml = match bookmark {
        Some(b) => format!("<w:Bookmark>{b}</w:Bookmark>"),
        None if c.read_existing_events => "<w:Bookmark>http://schemas.dmtf.org/wbem/wsman/1/\
             wsman/bookmark/earliest</w:Bookmark>"
            .to_string(),
        None => String::new(),
    };
    let ref_props = format!(
        "<a:Address>{addr}</a:Address><a:ReferenceProperties><e:Identifier>{version}\
         </e:Identifier></a:ReferenceProperties>"
    );
    format!(
        "<m:Subscription xmlns:m=\"http://schemas.microsoft.com/wbem/wsman/1/subscription\">\
<m:Version>uuid:{version}</m:Version>\
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:e=\"http://schemas.xmlsoap.org/ws/2004/08/eventing\" \
xmlns:n=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\" \
xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" \
xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">\
<s:Header>\
<a:To>{anon}</a:To>\
<w:ResourceURI s:mustUnderstand=\"true\">\
http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</w:ResourceURI>\
<a:ReplyTo><a:Address s:mustUnderstand=\"true\">{anon}</a:Address></a:ReplyTo>\
<a:Action s:mustUnderstand=\"true\">{action}</a:Action>\
<w:MaxEnvelopeSize s:mustUnderstand=\"true\">{env}</w:MaxEnvelopeSize>\
<a:MessageID>uuid:{msg_id}</a:MessageID>\
<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>\
<p:DataLocale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>\
<p:OperationID s:mustUnderstand=\"false\">uuid:{op_id}</p:OperationID>\
<p:SequenceId s:mustUnderstand=\"false\">1</p:SequenceId>\
<w:OptionSet xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\
<w:Option Name=\"SubscriptionName\">{name}</w:Option>\
<w:Option Name=\"Compression\">SLDC</w:Option>\
<w:Option Name=\"CDATA\" xsi:nil=\"true\"/>\
<w:Option Name=\"ContentFormat\">{format}</w:Option>\
<w:Option Name=\"IgnoreChannelError\" xsi:nil=\"true\"/>\
{read_existing}\
</w:OptionSet>\
</s:Header>\
<s:Body><e:Subscribe>\
<e:EndTo>{ref_props}</e:EndTo>\
<e:Delivery Mode=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/Events\">\
<w:Heartbeats>PT{hb}.000S</w:Heartbeats>\
<e:NotifyTo>{ref_props}\
<c:Policy xmlns:c=\"http://schemas.xmlsoap.org/ws/2002/12/policy\" \
xmlns:auth=\"http://schemas.microsoft.com/wbem/wsman/1/authentication\">\
<c:ExactlyOne><c:All>{policy}</c:All></c:ExactlyOne></c:Policy>\
</e:NotifyTo>\
<w:ConnectionRetry Total=\"5\">PT60.0S</w:ConnectionRetry>\
<w:MaxTime>PT{lat}.000S</w:MaxTime>\
<w:MaxEnvelopeSize Policy=\"Notify\">{env}</w:MaxEnvelopeSize>\
<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>\
<p:DataLocale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>\
<w:ContentEncoding>UTF-16</w:ContentEncoding>\
</e:Delivery>\
<w:Filter Dialect=\"http://schemas.microsoft.com/win/2004/08/events/eventquery\">{query}\
</w:Filter>\
{bookmark_xml}\
<w:SendBookmarks/>\
</e:Subscribe></s:Body>\
</s:Envelope>\
</m:Subscription>",
        action = ACTION_SUBSCRIBE,
        env = c.max_envelope_size,
        name = xml_escape(&c.name),
        hb = c.heartbeat_interval_secs,
        lat = c.max_latency_secs,
        query = sub.query_xml,
    )
}

/// SHA-1 over each DER cert in the PEM CA file, uppercase hex, no separators.
pub fn ca_thumbprints(pem_path: &Path) -> anyhow::Result<Vec<String>> {
    let file = std::fs::File::open(pem_path)
        .with_context(|| format!("opening CA file {}", pem_path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.with_context(|| format!("parsing CA file {}", pem_path.display()))?;
        out.push(
            Sha1::digest(cert.as_ref())
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect(),
        );
    }
    if out.is_empty() {
        bail!("CA file {} contains no certificates", pem_path.display());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wef_legacy_config_detected_without_subscriptions() {
        use crate::config::WefConfig;
        assert!(!wef_legacy_config_without_subscriptions(
            &WefConfig::default()
        ));
        let c = WefConfig {
            collector_url: Some("http://x".into()),
            ..Default::default()
        };
        assert!(wef_legacy_config_without_subscriptions(&c));
        let c = WefConfig {
            allow_unauthenticated: true,
            ..Default::default()
        };
        assert!(wef_legacy_config_without_subscriptions(&c));
        let local: WefConfig = toml::from_str("[local]\ndirectory = \"/tmp/x\"").unwrap();
        assert!(wef_legacy_config_without_subscriptions(&local));
    }

    #[test]
    fn test_kerberos_ignored_under_tls_only_when_both_enabled() {
        assert!(kerberos_ignored_under_tls(true, true));
        assert!(!kerberos_ignored_under_tls(true, false));
        assert!(!kerberos_ignored_under_tls(false, true));
    }
    use crate::config::TlsConfig;
    use quick_xml::NsReader;
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;

    const CA_PEM: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wef/tls/test-ca.pem"
    );
    const CA_SHA1: &str = "2A3546C602AA06D8CAE612248EBD879960667C86";

    fn sub_cfg(name: &str, uuid: u128) -> WefSubscriptionConfig {
        toml::from_str(&format!(
            "name = \"{name}\"\nuuid = \"{}\"\nchannels = [\"Security\", \"System\"]\n",
            Uuid::from_u128(uuid)
        ))
        .unwrap()
    }

    fn base_cfg() -> Config {
        let mut c = Config::default();
        c.tls = TlsConfig {
            enabled: false,
            ..c.tls
        };
        c.wef.collector_url = Some("http://logthing.example.com:5985".into());
        c.wef.subscriptions = vec![sub_cfg("security", 1)];
        c
    }

    fn tls_cfg() -> Config {
        let mut c = base_cfg();
        c.tls.enabled = true;
        c.tls.require_client_cert = true;
        c.tls.ca_file = Some(CA_PEM.into());
        c.wef.collector_url = Some("https://logthing.example.com:5986".into());
        c
    }

    fn err(c: &Config, k: bool) -> String {
        format!("{:#}", validate_wef_topology(c, k).unwrap_err())
    }

    fn rt(c: &Config, k: bool) -> WefRuntime {
        validate_wef_topology(c, k).unwrap().unwrap()
    }

    #[test]
    fn test_validate_empty_subscriptions_is_disabled() {
        let mut c = base_cfg();
        c.wef.subscriptions.clear();
        c.wef.collector_url = None;
        assert!(validate_wef_topology(&c, false).unwrap().is_none());
    }

    #[test]
    fn test_validate_plain_kerberos() {
        assert_eq!(rt(&base_cfg(), true).topology, WefTopology::PlainKerberos);
    }

    #[test]
    fn test_validate_plain_unauthenticated_when_allowed() {
        let mut c = base_cfg();
        c.wef.allow_unauthenticated = true;
        assert_eq!(rt(&c, false).topology, WefTopology::PlainUnauthenticated);
    }

    #[test]
    fn test_validate_plain_without_auth_rejected() {
        assert!(err(&base_cfg(), false).starts_with("WEF subscriptions require authentication:"));
    }

    #[test]
    fn test_validate_https_mutual() {
        let mut c = tls_cfg();
        c.wef.allow_unauthenticated = true;
        let r = rt(&c, false);
        assert_eq!(r.topology, WefTopology::HttpsMutual);
        assert_eq!(r.issuer_thumbprints, vec![CA_SHA1.to_string()]);
    }

    #[test]
    fn test_validate_tls_without_client_cert_rejected() {
        let mut c = tls_cfg();
        c.tls.require_client_cert = false;
        assert!(err(&c, true).contains("require tls.require_client_cert = true"));
    }

    #[test]
    fn test_validate_collector_url_missing_rejected() {
        let mut c = base_cfg();
        c.wef.collector_url = None;
        assert_eq!(
            err(&c, true),
            "wef.collector_url is required when [[wef.subscriptions]] are configured"
        );
    }

    #[test]
    fn test_validate_https_url_without_tls_rejected() {
        let mut c = base_cfg();
        c.wef.collector_url = Some("https://x:1".into());
        assert_eq!(
            err(&c, true),
            "wef.collector_url must use http:// when TLS is disabled"
        );
    }

    #[test]
    fn test_validate_http_url_with_tls_rejected() {
        let mut c = tls_cfg();
        c.wef.collector_url = Some("http://x:1".into());
        assert_eq!(
            err(&c, true),
            "wef.collector_url must use https:// when TLS is enabled"
        );
    }

    #[test]
    fn test_validate_duplicate_name_and_uuid_rejected() {
        let mut c = base_cfg();
        c.wef.subscriptions.push(sub_cfg("security", 2));
        assert!(err(&c, true).contains("duplicate wef.subscriptions name 'security'"));
        c.wef.subscriptions[1] = sub_cfg("other", 1);
        assert!(err(&c, true).contains("duplicate wef.subscriptions uuid"));
    }

    #[test]
    fn test_validate_channels_query_and_limits_rejected() {
        let q =
            "<QueryList><Query Id=\"0\"><Select Path=\"Security\">*</Select></Query></QueryList>";
        let mut c = base_cfg();
        c.wef.subscriptions[0].query = Some(q.into());
        assert!(err(&c, true).contains("not both"));
        c.wef.subscriptions[0].channels.clear();
        assert_eq!(rt(&c, true).subscriptions[0].query_xml, q);
        c.wef.subscriptions[0].query = None;
        assert!(err(&c, true).contains("either channels or query"));
        c.wef.subscriptions[0].channels = (0..257).map(|i| format!("C{i}")).collect();
        assert!(err(&c, true).contains("at most 256"));
        c.wef.subscriptions[0].channels = vec!["A".into()];
        c.wef.subscriptions[0].max_envelope_size = 8191;
        assert!(err(&c, true).contains("max_envelope_size"));
    }

    #[test]
    fn test_validate_bad_query_and_name_rejected() {
        let mut c = base_cfg();
        c.wef.subscriptions[0].channels.clear();
        for bad in [
            "<Other/>",
            "<QueryList><a></QueryList>",
            "<QueryList/><QueryList/>",
            "x",
        ] {
            c.wef.subscriptions[0].query = Some(bad.into());
            assert!(validate_wef_topology(&c, true).is_err(), "{bad}");
        }
        let mut c = base_cfg();
        c.wef.subscriptions[0].name = "bad name".into();
        assert!(err(&c, true).contains("[A-Za-z0-9_.-]"));
    }

    #[test]
    fn test_validate_https_mutual_without_ca_file_rejected() {
        let mut c = tls_cfg();
        c.tls.ca_file = None;
        assert!(err(&c, true).contains("tls.ca_file"));
    }

    #[test]
    fn test_validate_warning_only_for_plain_unauthenticated() {
        crate::test_support::install_and_clear();
        let mut c = base_cfg();
        c.wef.allow_unauthenticated = true;
        rt(&c, false);
        let warned = crate::test_support::captured_events_at(tracing::Level::WARN)
            .iter()
            .any(|m| m.contains("accept ANY client"));
        assert!(warned);
        crate::test_support::install_and_clear();
        let mut c = tls_cfg();
        c.wef.allow_unauthenticated = true;
        rt(&c, false);
        assert!(crate::test_support::captured_events_at(tracing::Level::WARN).is_empty());
    }

    #[test]
    fn test_validate_disabled_subscription_not_served() {
        let mut c = base_cfg();
        c.wef.subscriptions[0].enabled = false;
        assert!(rt(&c, true).subscriptions.is_empty());
    }

    fn version_of(c: &Config) -> Uuid {
        rt(c, true).subscriptions[0].version
    }

    #[test]
    fn test_version_uuid_stable_for_same_params() {
        assert_eq!(version_of(&base_cfg()), version_of(&base_cfg()));
    }

    #[test]
    fn test_version_uuid_changes_when_query_changes() {
        let a = version_of(&base_cfg());
        let mut c = base_cfg();
        c.wef.subscriptions[0].channels.push("Application".into());
        assert_ne!(a, version_of(&c));
    }

    #[test]
    fn test_version_uuid_changes_when_client_visible_param_changes() {
        let a = version_of(&base_cfg());
        let muts: [fn(&mut Config); 5] = [
            |c| c.wef.subscriptions[0].heartbeat_interval_secs = 60,
            |c| c.wef.subscriptions[0].content_format = ContentFormat::RenderedText,
            |c| c.wef.collector_url = Some("http://other:5985".into()),
            |c| c.wef.subscriptions[0].read_existing_events = true,
            |c| c.wef.subscriptions[0].max_latency_secs = 5,
        ];
        for m in muts {
            let mut c = base_cfg();
            m(&mut c);
            assert_ne!(a, version_of(&c));
        }
        let mut c = base_cfg();
        c.wef.allow_unauthenticated = true;
        let unauth = rt(&c, false).subscriptions[0].version;
        assert_ne!(a, unauth, "topology is hashed");
    }

    #[test]
    fn test_version_uuid_ignores_enabled_flag_order_noise() {
        let mut c = base_cfg();
        c.wef.subscriptions.push(sub_cfg("second", 2));
        let a = rt(&c, true).subscriptions[0].version;
        c.wef.subscriptions[1].enabled = false;
        c.wef.collector_url = Some("http://logthing.example.com:5985/".into());
        assert_eq!(a, rt(&c, true).subscriptions[0].version);
        let mut d = base_cfg();
        d.wef.subscriptions[0].enabled = false;
        d.wef.subscriptions[0].enabled = true;
        assert_eq!(version_of(&d), version_of(&base_cfg()));
    }

    fn item(c: &Config, k: bool, bookmark: Option<&str>) -> String {
        let r = rt(c, k);
        render_subscription_item(&r, &r.subscriptions[0], bookmark)
    }

    /// Returns (ns, local, text) for every element carrying text.
    fn texts(xml: &str) -> Vec<(String, String, String)> {
        let mut r = NsReader::from_str(xml);
        let mut stack: Vec<(String, String)> = Vec::new();
        let mut out = Vec::new();
        loop {
            let (ns, ev) = r.read_resolved_event().expect("well-formed");
            match ev {
                Event::Start(e) => {
                    let ns = match ns {
                        ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).into(),
                        _ => String::new(),
                    };
                    stack.push((ns, String::from_utf8_lossy(e.local_name().as_ref()).into()));
                }
                Event::End(_) => {
                    stack.pop();
                }
                Event::Text(t) => {
                    if let Some((n, l)) = stack.last() {
                        out.push((n.clone(), l.clone(), t.unescape().unwrap().into_owned()));
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        out
    }

    #[test]
    fn test_render_subscription_embedded_action_parses() {
        let x = item(&base_cfg(), true, None);
        let t = texts(&x);
        assert!(t.iter().any(
            |(n, l, v)| n == "http://schemas.xmlsoap.org/ws/2004/08/addressing"
                && l == "Action"
                && v == ACTION_SUBSCRIBE
        ));
        assert!(
            t.iter()
                .any(|(_, l, v)| l == "Version" && v.starts_with("uuid:"))
        );
    }

    #[test]
    fn test_render_subscription_kerberos_policy() {
        let x = item(&base_cfg(), true, None);
        assert!(x.contains("secprofile/http/spnego-kerberos\"></auth:Authentication>"));
        assert!(!x.contains("Thumbprint"));
    }

    #[test]
    fn test_render_subscription_https_mutual_policy_has_issuer_thumbprints() {
        let x = item(&tls_cfg(), false, None);
        assert!(x.contains("secprofile/https/mutual"));
        assert!(x.contains(&format!(
            "<auth:Thumbprint Role=\"issuer\">{CA_SHA1}</auth:Thumbprint>"
        )));
        texts(&x);
    }

    #[test]
    fn test_render_subscription_notify_to_and_end_to_address() {
        let mut c = base_cfg();
        c.wef.collector_url = Some("http://logthing.example.com:5985/".into());
        let r = rt(&c, true);
        let s = &r.subscriptions[0];
        let x = render_subscription_item(&r, s, None);
        let addr = format!(
            "http://logthing.example.com:5985/wsman/subscriptions/{}",
            upper(s.cfg.uuid)
        );
        assert_eq!(
            x.matches(&format!("<a:Address>{addr}</a:Address>")).count(),
            2
        );
        assert_eq!(
            x.matches(&format!(
                "<e:Identifier>{}</e:Identifier>",
                upper(s.version)
            ))
            .count(),
            2
        );
    }

    #[test]
    fn test_render_subscription_options() {
        let mut c = base_cfg();
        c.wef.subscriptions[0].content_format = ContentFormat::RenderedText;
        let x = item(&c, true, None);
        for o in [
            "<w:Option Name=\"SubscriptionName\">security</w:Option>",
            "<w:Option Name=\"Compression\">SLDC</w:Option>",
            "<w:Option Name=\"CDATA\" xsi:nil=\"true\"/>",
            "<w:Option Name=\"ContentFormat\">RenderedText</w:Option>",
            "<w:Option Name=\"IgnoreChannelError\" xsi:nil=\"true\"/>",
        ] {
            assert!(x.contains(o), "{o}");
        }
        assert!(!x.contains("ReadExistingEvents"));
        assert!(!x.contains("<w:Bookmark>"));
        assert!(x.contains("<w:SendBookmarks/>"));
    }

    #[test]
    fn test_render_subscription_bookmark_replayed_verbatim() {
        let bm = "<BookmarkList><Bookmark Channel=\"Security\" RecordId=\"5\"/></BookmarkList>";
        let x = item(&base_cfg(), true, Some(bm));
        assert!(x.contains(&format!("<w:Bookmark>{bm}</w:Bookmark>")));
        texts(&x);
    }

    #[test]
    fn test_render_subscription_earliest_uri_when_read_existing_and_no_bookmark() {
        let mut c = base_cfg();
        c.wef.subscriptions[0].read_existing_events = true;
        let x = item(&c, true, None);
        assert!(x.contains("<w:Option Name=\"ReadExistingEvents\">true</w:Option>"));
        assert!(x.contains(
            "<w:Bookmark>http://schemas.dmtf.org/wbem/wsman/1/wsman/bookmark/earliest</w:Bookmark>"
        ));
        let y = item(&c, true, Some("<B/>"));
        assert!(y.contains("<w:Bookmark><B/></w:Bookmark>") && !y.contains("earliest"));
    }

    #[test]
    fn test_render_subscription_durations_format() {
        let x = item(&base_cfg(), true, None);
        assert!(x.contains("<w:Heartbeats>PT3600.000S</w:Heartbeats>"));
        assert!(x.contains("<w:MaxTime>PT30.000S</w:MaxTime>"));
        assert!(x.contains("<w:ConnectionRetry Total=\"5\">PT60.0S</w:ConnectionRetry>"));
        assert!(x.contains("<w:MaxEnvelopeSize Policy=\"Notify\">512000</w:MaxEnvelopeSize>"));
    }

    #[test]
    fn test_render_subscription_ids_are_deterministic() {
        assert_eq!(item(&base_cfg(), true, None), item(&base_cfg(), true, None));
    }

    #[test]
    fn test_render_query_list_escapes_channel_names() {
        let q = render_query_list(&["A&B".into(), "x\"y<".into()]);
        assert_eq!(
            q,
            "<QueryList><Query Id=\"0\"><Select Path=\"A&amp;B\">*</Select>\
             <Select Path=\"x&quot;y&lt;\">*</Select></Query></QueryList>"
        );
    }

    #[test]
    fn test_ca_thumbprints_matches_openssl() {
        assert_eq!(
            ca_thumbprints(Path::new(CA_PEM)).unwrap(),
            vec![CA_SHA1.to_string()]
        );
    }

    #[test]
    fn test_ca_thumbprints_rejects_missing_and_empty() {
        assert!(ca_thumbprints(Path::new("/nonexistent/ca.pem")).is_err());
        let f = tempfile::NamedTempFile::new().unwrap();
        assert!(ca_thumbprints(f.path()).is_err());
    }
}
