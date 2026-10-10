//! Body charset codec: Windows clients send UTF-16LE, responses must be UTF-16LE with a BOM.

use anyhow::{Context, Result, bail};

/// Decode a request body: BOM `FF FE` means UTF-16LE; BOM `EF BB BF` or no BOM means UTF-8.
///
/// Errors on invalid UTF-16 (odd length, unpaired surrogate) or invalid UTF-8.
pub fn decode_body(bytes: &[u8]) -> Result<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        if rest.len() % 2 != 0 {
            bail!("UTF-16LE body has odd length");
        }
        let (pairs, _) = rest.as_chunks::<2>();
        let units = pairs.iter().map(|c| u16::from_le_bytes(*c));
        char::decode_utf16(units)
            .collect::<std::result::Result<String, _>>()
            .context("invalid UTF-16LE body")
    } else {
        let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        String::from_utf8(rest.to_vec()).context("invalid UTF-8 body")
    }
}

/// Encode as UTF-16LE prefixed with the BOM `FF FE`.
pub fn encode_utf16le_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_body_utf16le_with_bom() {
        assert_eq!(decode_body(&[0xFF, 0xFE, b'<', 0, b'a', 0]).unwrap(), "<a");
    }

    #[test]
    fn test_decode_body_utf8_with_bom() {
        assert_eq!(decode_body(&[0xEF, 0xBB, 0xBF, 0x3C, 0x61]).unwrap(), "<a");
    }

    #[test]
    fn test_decode_body_utf8_without_bom() {
        assert_eq!(decode_body(b"<a/>").unwrap(), "<a/>");
    }

    #[test]
    fn test_decode_body_utf16_odd_length_errors() {
        assert!(decode_body(&[0xFF, 0xFE, b'<']).is_err());
    }

    #[test]
    fn test_decode_body_utf16_unpaired_surrogate_errors() {
        assert!(decode_body(&[0xFF, 0xFE, 0x00, 0xD8]).is_err());
    }

    #[test]
    fn test_decode_body_utf8_invalid_errors() {
        assert!(decode_body(&[0xC3, 0x28]).is_err());
    }

    #[test]
    fn test_encode_utf16le_bom_roundtrip() {
        let s = "héllo €";
        let bytes = encode_utf16le_bom(s);
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert_eq!(decode_body(&bytes).unwrap(), s);
    }
}
