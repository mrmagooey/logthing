//! MS-WSMV "session-encrypted" multipart framing.
//!
//! Windows clients on Kerberos/SPNEGO connections wrap each SOAP body in a two-part
//! `multipart/encrypted` message: a text part announcing the plaintext length, then an
//! octet-stream part holding `<LE32 header_len><GSS header><encrypted data>`. This module
//! only frames and unframes; the GSS wrap/unwrap happens elsewhere.

use anyhow::{Context, Result, bail};

const BOUNDARY: &[u8] = b"--Encrypted Boundary";
const CLOSING: &[u8] = b"--Encrypted Boundary--";
const KERBEROS: &str = "application/HTTP-Kerberos-session-encrypted";
const SPNEGO: &str = "application/HTTP-SPNEGO-session-encrypted";

/// Which GSS mechanism the encrypted session uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncProtocol {
    /// `HTTP-Kerberos-session-encrypted`.
    Kerberos,
    /// `HTTP-SPNEGO-session-encrypted`.
    Spnego,
}

impl EncProtocol {
    /// The `protocol=` / part `Content-Type` token for this mechanism.
    pub fn protocol_str(self) -> &'static str {
        match self {
            EncProtocol::Kerberos => KERBEROS,
            EncProtocol::Spnego => SPNEGO,
        }
    }

    /// The full HTTP `Content-Type` header value for an encrypted message.
    pub fn content_type(self) -> String {
        format!(
            "multipart/encrypted;protocol=\"{}\";boundary=\"Encrypted Boundary\"",
            self.protocol_str()
        )
    }

    fn from_text(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase();
        if s.contains(&KERBEROS.to_ascii_lowercase()) {
            Some(EncProtocol::Kerberos)
        } else if s.contains(&SPNEGO.to_ascii_lowercase()) {
            Some(EncProtocol::Spnego)
        } else {
            None
        }
    }
}

/// A parsed encrypted message, still wrapped.
#[derive(Debug)]
pub struct EncryptedPayload {
    /// Mechanism announced by the client.
    pub protocol: EncProtocol,
    /// Plaintext length announced in `OriginalContent`.
    pub original_length: usize,
    /// GSS header bytes (the `header_len`-prefixed block).
    pub header: Vec<u8>,
    /// Encrypted data following the header, including any padding.
    pub data: Vec<u8>,
}

/// `Some(protocol)` when the HTTP Content-Type is multipart/encrypted with a known protocol.
pub fn detect(content_type: Option<&str>) -> Option<EncProtocol> {
    let ct = content_type?;
    if !ct.to_ascii_lowercase().contains("multipart/encrypted") {
        return None;
    }
    EncProtocol::from_text(ct)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Skips a CRLF (or bare LF) at the start of `b`; returns the remainder.
fn skip_eol(b: &[u8]) -> Result<&[u8]> {
    if let Some(r) = b.strip_prefix(b"\r\n") {
        Ok(r)
    } else if let Some(r) = b.strip_prefix(b"\n") {
        Ok(r)
    } else {
        bail!("expected line break after boundary")
    }
}

/// Parses an `OriginalContent` value's `Length=<N>` parameter.
fn parse_length(value: &str) -> Option<usize> {
    let lower = value.to_ascii_lowercase();
    let at = lower.find("length=")? + "length=".len();
    let digits: String = lower[at..]
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Parses an encrypted multipart body into its protocol, announced length, GSS header and data.
///
/// The closing boundary is located from the end so binary data may contain CRLF or boundary
/// look-alikes.
pub fn parse(body: &[u8]) -> Result<EncryptedPayload> {
    let start = find(body, BOUNDARY).context("missing opening boundary")?;
    let after_first = skip_eol(&body[start + BOUNDARY.len()..])?;

    // Part 1 is plain text, so the next boundary is the first one that follows.
    let p1_end = find(after_first, BOUNDARY).context("missing second boundary")?;
    let part1 = std::str::from_utf8(&after_first[..p1_end]).context("non-UTF-8 part headers")?;
    let mut protocol = None;
    let mut original_length = None;
    for line in part1.lines() {
        let line = line.trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-type" => protocol = EncProtocol::from_text(value),
            "originalcontent" => original_length = parse_length(value),
            _ => {}
        }
    }
    let protocol = protocol.context("unknown or missing encrypted protocol")?;
    let original_length = original_length.context("missing OriginalContent Length")?;

    let rest = skip_eol(&after_first[p1_end + BOUNDARY.len()..])?;
    // Part 2 header line(s): only Content-Type is expected; the binary starts after it.
    let mut rest = {
        let eol = find(rest, b"\n").context("truncated octet-stream header")?;
        let line = std::str::from_utf8(&rest[..eol]).context("non-UTF-8 octet-stream header")?;
        if !line
            .to_ascii_lowercase()
            .contains("application/octet-stream")
        {
            bail!("second part is not application/octet-stream");
        }
        &rest[eol + 1..]
    };
    if let Some(r) = rest.strip_prefix(b"\r\n") {
        rest = r; // some clients emit a blank line before the binary
    }

    let end = rfind(rest, CLOSING).context("missing closing boundary")?;
    let bin = &rest[..end];
    if bin.len() < 4 {
        bail!("octet-stream part too short for header length");
    }
    let header_len = i32::from_le_bytes([bin[0], bin[1], bin[2], bin[3]]);
    let header_len = usize::try_from(header_len).context("negative GSS header length")?;
    let bin = &bin[4..];
    if header_len > bin.len() {
        bail!("GSS header length {header_len} exceeds body");
    }
    Ok(EncryptedPayload {
        protocol,
        original_length,
        header: bin[..header_len].to_vec(),
        data: bin[header_len..].to_vec(),
    })
}

/// Builds the encrypted multipart body for `header` + `data`; `original_length` is the
/// plaintext SOAP length in bytes.
pub fn build(protocol: EncProtocol, original_length: usize, header: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + header.len() + data.len());
    out.extend_from_slice(
        format!(
            "--Encrypted Boundary\r\nContent-Type: {}\r\nOriginalContent: \
             type=application/soap+xml;charset=UTF-16;Length={original_length}\r\n\
             --Encrypted Boundary\r\nContent-Type: application/octet-stream\r\n",
            protocol.protocol_str()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&(header.len() as i32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(data);
    out.extend_from_slice(b"--Encrypted Boundary--\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &[u8] = include_bytes!("../../tests/fixtures/wef/golden/multipart_layout.txt");

    #[test]
    fn test_build_then_parse_roundtrip() {
        for p in [EncProtocol::Kerberos, EncProtocol::Spnego] {
            let body = build(p, 1234, b"hdr", b"data\x00\xff");
            let got = parse(&body).unwrap();
            assert_eq!(got.protocol, p);
            assert_eq!(got.original_length, 1234);
            assert_eq!(got.header, b"hdr");
            assert_eq!(got.data, b"data\x00\xff");
        }
    }

    #[test]
    fn test_parse_tolerates_tab_indented_headers() {
        let mut body = b"--Encrypted Boundary\r\n\tContent-Type: application/HTTP-Kerberos-session-encrypted\r\n\
\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=77\r\n\
--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n"
            .to_vec();
        body.extend_from_slice(&2i32.to_le_bytes());
        body.extend_from_slice(b"hdxyz--Encrypted Boundary--\r\n");
        let got = parse(&body).unwrap();
        assert_eq!(got.original_length, 77);
        assert_eq!(got.header, b"hd");
        assert_eq!(got.data, b"xyz");
    }

    #[test]
    fn test_parse_tolerates_blank_line_before_binary() {
        let built = build(EncProtocol::Kerberos, 5, b"h", b"d");
        let marker = b"application/octet-stream\r\n";
        let at = find(&built, marker).unwrap() + marker.len();
        let mut body = built[..at].to_vec();
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&built[at..]);
        let got = parse(&body).unwrap();
        assert_eq!((got.header, got.data), (b"h".to_vec(), b"d".to_vec()));
    }

    #[test]
    fn test_parse_binary_containing_crlf_and_boundary_prefix() {
        let data = b"a\r\n--Encrypted Bound\r\nb\r\n--Encrypted Boundary\r\nc";
        let body = build(EncProtocol::Spnego, 9, b"\r\nHH", data);
        let got = parse(&body).unwrap();
        assert_eq!(got.header, b"\r\nHH");
        assert_eq!(got.data, data);
    }

    #[test]
    fn test_parse_rejects_header_len_exceeding_body() {
        let mut body = build(EncProtocol::Kerberos, 1, b"", b"");
        let at = find(&body, b"octet-stream\r\n").unwrap() + 14;
        body.splice(at..at, 100i32.to_le_bytes());
        assert!(parse(&body).is_err());
    }

    #[test]
    fn test_parse_rejects_negative_header_len() {
        let mut body = build(EncProtocol::Kerberos, 1, b"", b"");
        let at = find(&body, b"octet-stream\r\n").unwrap() + 14;
        body.splice(at..at + 4, (-1i32).to_le_bytes());
        assert!(parse(&body).is_err());
    }

    #[test]
    fn test_parse_rejects_missing_original_length() {
        let body = b"--Encrypted Boundary\r\nContent-Type: application/HTTP-Kerberos-session-encrypted\r\n\
--Encrypted Boundary\r\nContent-Type: application/octet-stream\r\n\0\0\0\0--Encrypted Boundary--\r\n";
        assert!(parse(body).is_err());
    }

    #[test]
    fn test_detect_kerberos_and_spnego_content_types() {
        for p in [EncProtocol::Kerberos, EncProtocol::Spnego] {
            assert_eq!(detect(Some(&p.content_type())), Some(p));
        }
    }

    #[test]
    fn test_detect_plain_soap_is_none() {
        assert_eq!(detect(None), None);
        assert_eq!(detect(Some("application/soap+xml;charset=UTF-16")), None);
        assert_eq!(detect(Some("multipart/encrypted;protocol=\"x/y\"")), None);
    }

    #[test]
    fn test_build_layout_matches_golden() {
        let golden = std::str::from_utf8(GOLDEN).unwrap();
        let (pre, post) = golden.split_once("<BINARY>").unwrap();
        let mut expected = pre.replace("{N}", "42").into_bytes();
        expected.extend_from_slice(&3i32.to_le_bytes());
        expected.extend_from_slice(b"HDRDD");
        expected.extend_from_slice(post.as_bytes());
        assert_eq!(build(EncProtocol::Kerberos, 42, b"HDR", b"DD"), expected);
    }
}
