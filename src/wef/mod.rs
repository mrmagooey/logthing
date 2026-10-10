//! Windows Event Forwarding (WEF) wire handling.
//!
//! A request body from a Windows client travels through these stages in order:
//! decrypt (Kerberos multipart envelope, when present) -> SLDC decode-or-raw (compressed
//! payloads are expanded, others pass through) -> charset decode (UTF-16LE or UTF-8, see
//! [`encoding`]) -> SOAP parse.

pub mod encoding;
pub mod event;
pub mod multipart;
pub mod sldc;
pub mod soap;
