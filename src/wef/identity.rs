//! Authenticated identity of a WEF client, used to key its bookmarks.
//!
//! The auth layers attach a [`ClientIdentity`] to each authenticated request as an extension:
//! the Kerberos middleware from the connection's GSS principal, the TLS acceptor from the
//! client certificate. The client-asserted `MachineID` is never trusted for storage under an
//! authenticated topology.

use sha2::{Digest, Sha256};

/// Verified identity of the client that sent a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    /// Kerberos principal display name from GSS, e.g. `WIN10$@EXAMPLE.COM`.
    Kerberos(String),
    /// SHA-256 of the leaf client certificate (DER).
    Certificate([u8; 32]),
}

impl ClientIdentity {
    /// Bookmark-store key: `krb:<principal>` or `x509:sha256:<lowercase hex>`.
    pub fn bookmark_key(&self) -> String {
        match self {
            ClientIdentity::Kerberos(p) => format!("krb:{p}"),
            ClientIdentity::Certificate(fp) => format!("x509:sha256:{}", hex::encode(fp)),
        }
    }

    /// Short label for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            ClientIdentity::Kerberos(_) => "kerberos",
            ClientIdentity::Certificate(_) => "certificate",
        }
    }
}

/// SHA-256 fingerprint of a DER-encoded certificate.
pub fn cert_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Bookmark-store key for a client-asserted MachineID (unauthenticated topology only).
pub fn machine_key(machine_id: &str) -> String {
    format!("machine:{machine_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_bookmark_key_kerberos_is_prefixed_exact_principal() {
        let id = ClientIdentity::Kerberos("WIN10$@EXAMPLE.COM".into());
        assert_eq!(id.bookmark_key(), "krb:WIN10$@EXAMPLE.COM");
        assert_eq!(id.kind(), "kerberos");
    }

    #[test]
    fn test_bookmark_key_certificate_is_lowercase_hex_sha256() {
        let id = ClientIdentity::Certificate([0xAB; 32]);
        let k = id.bookmark_key();
        assert_eq!(k, format!("x509:sha256:{}", "ab".repeat(32)));
        assert_eq!(k.len(), "x509:sha256:".len() + 64);
        assert_eq!(id.kind(), "certificate");
    }

    #[test]
    fn test_cert_fingerprint_matches_sha256_of_der() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["win10.example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().as_ref();
        let expected: [u8; 32] = Sha256::digest(der).into();
        assert_eq!(cert_fingerprint(der), expected);
    }

    #[test]
    fn test_machine_key_namespace_disjoint_from_identity_keys() {
        // A client-asserted MachineID that imitates an identity key still lands in `machine:`.
        let spoof = machine_key("krb:WIN10$@EXAMPLE.COM");
        assert_eq!(spoof, "machine:krb:WIN10$@EXAMPLE.COM");
        assert_ne!(
            spoof,
            ClientIdentity::Kerberos("WIN10$@EXAMPLE.COM".into()).bookmark_key()
        );
        assert!(!machine_key("x").starts_with("krb:"));
        assert!(!machine_key("x").starts_with("x509:"));
    }
}
