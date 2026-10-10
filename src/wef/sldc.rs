//! ECMA-321 SLDC decompressor.
//!
//! Windows clients set `Content-Encoding: SLDC` on WEF request bodies. The stream is MSB-first
//! bits made of scheme-1 symbols (9-bit literal, or copy pointer = `1` + match-count field +
//! 10-bit history-buffer location), scheme-2 symbols (raw bytes, `FF` followed by a `0` bit) and
//! 13-bit control symbols (nine `1` bits + a 4-bit code). The history buffer is a 1024-byte ring;
//! a copy pointer carries the ring *location* of the first byte, not a relative distance.

use std::borrow::Cow;

use anyhow::{Result, bail};

const HISTORY: usize = 1024;
#[cfg(test)]
const LONGEST_MATCH: usize = 271;

const CTL_FLUSH: u8 = 0x0;
const CTL_SCHEME1: u8 = 0x1;
const CTL_SCHEME2: u8 = 0x2;
const CTL_EOR: u8 = 0x4;
const CTL_RESET1: u8 = 0x5;
const CTL_RESET2: u8 = 0x6;
const CTL_END_MARKER: u8 = 0xF;

/// MSB-first bit reader over a byte slice.
#[derive(Debug)]
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    /// Read `n` (<= 16) bits as an integer.
    fn read(&mut self, n: usize) -> Result<u32> {
        if self.remaining() < n {
            bail!("SLDC stream truncated");
        }
        let mut v = 0u32;
        for _ in 0..n {
            let byte = self.data[self.pos / 8];
            v = (v << 1) | u32::from((byte >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Ok(v)
    }

    /// Consume pad bits up to the next 32-bit boundary; returns the pad value (bits as read).
    fn align32(&mut self) -> (u32, usize) {
        let n = ((32 - self.pos % 32) % 32).min(self.remaining());
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.read(1).unwrap_or(0);
        }
        (v, n)
    }
}

/// The 1024-byte ring history shared by both schemes.
#[derive(Debug)]
struct History {
    buf: [u8; HISTORY],
    /// Bytes recorded since the last reset, saturating at `HISTORY`.
    filled: usize,
    next: usize,
}

impl History {
    fn new() -> Self {
        Self {
            buf: [0; HISTORY],
            filled: 0,
            next: 0,
        }
    }

    fn push(&mut self, b: u8) {
        self.buf[self.next] = b;
        self.next = (self.next + 1) % HISTORY;
        self.filled = (self.filled + 1).min(HISTORY);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Scheme {
    One,
    Two,
}

fn emit(out: &mut Vec<u8>, hist: &mut History, b: u8, max_out: usize) -> Result<()> {
    if out.len() >= max_out {
        bail!("SLDC output exceeds limit of {max_out} bytes");
    }
    out.push(b);
    hist.push(b);
    Ok(())
}

/// Read the match-count field of a copy pointer. `Ok(None)` means the field was actually the
/// tail of a control symbol, whose 4-bit code is returned via `ctl`.
fn read_match_count(r: &mut BitReader, ctl: &mut u8) -> Result<Option<usize>> {
    if r.read(1)? == 0 {
        return Ok(Some(2 + r.read(1)? as usize));
    }
    if r.read(1)? == 0 {
        return Ok(Some(4 + r.read(2)? as usize));
    }
    if r.read(1)? == 0 {
        return Ok(Some(8 + r.read(3)? as usize));
    }
    if r.read(1)? == 0 {
        return Ok(Some(16 + r.read(4)? as usize));
    }
    let v = r.read(8)?;
    if v >= 0xF0 {
        *ctl = (v & 0xF) as u8;
        return Ok(None);
    }
    Ok(Some(32 + v as usize))
}

/// Decompress one SLDC record. `max_out` bounds output (decompression-bomb guard): exceeding it
/// is an error. Decoding stops at the first End-of-Record or End Marker; a stream that ends
/// before either, or an End Marker not followed by all-ONE pad to a 32-bit boundary, is an error.
pub fn decompress(input: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut r = BitReader::new(input);
    let mut hist = History::new();
    let mut scheme = Scheme::One;
    let mut out = Vec::new();
    loop {
        let mut ctl = 0u8;
        match scheme {
            Scheme::One => {
                if r.read(1)? == 0 {
                    let b = r.read(8)? as u8;
                    emit(&mut out, &mut hist, b, max_out)?;
                    continue;
                }
                let Some(len) = read_match_count(&mut r, &mut ctl)? else {
                    if handle_control(&mut r, ctl, &mut scheme, &mut hist)? {
                        return Ok(out);
                    }
                    continue;
                };
                let mut loc = r.read(10)? as usize;
                for _ in 0..len {
                    // A location not yet written since the last reset has no data to copy.
                    if hist.filled < HISTORY && loc >= hist.filled {
                        bail!("SLDC copy pointer references unwritten history");
                    }
                    let b = hist.buf[loc];
                    emit(&mut out, &mut hist, b, max_out)?;
                    loc = (loc + 1) % HISTORY;
                }
            }
            Scheme::Two => {
                let b = r.read(8)? as u8;
                if b != 0xFF {
                    emit(&mut out, &mut hist, b, max_out)?;
                } else if r.read(1)? == 0 {
                    emit(&mut out, &mut hist, 0xFF, max_out)?;
                } else {
                    ctl = r.read(4)? as u8;
                    if handle_control(&mut r, ctl, &mut scheme, &mut hist)? {
                        return Ok(out);
                    }
                }
            }
        }
    }
}

/// Apply a control symbol; `Ok(true)` means the record is complete.
fn handle_control(
    r: &mut BitReader,
    code: u8,
    scheme: &mut Scheme,
    hist: &mut History,
) -> Result<bool> {
    match code {
        CTL_FLUSH => {
            r.align32();
        }
        CTL_SCHEME1 => *scheme = Scheme::One,
        CTL_SCHEME2 => *scheme = Scheme::Two,
        CTL_RESET1 | CTL_RESET2 => {
            *hist = History::new();
            *scheme = if code == CTL_RESET1 {
                Scheme::One
            } else {
                Scheme::Two
            };
        }
        CTL_EOR => {
            r.align32();
            return Ok(true);
        }
        CTL_END_MARKER => {
            let (pad, n) = r.align32();
            if pad != (1u32 << n) - 1 {
                bail!("SLDC End Marker pad is not all ONEs");
            }
            return Ok(true);
        }
        other => bail!("unsupported SLDC control symbol {other:#x}"),
    }
    Ok(false)
}

/// WEF rule: Windows sets `Content-Encoding: SLDC` even on uncompressed/empty bodies.
/// Try to decompress; on any error return the input unchanged.
pub fn decode_or_raw(input: &[u8], max_out: usize) -> Cow<'_, [u8]> {
    match decompress(input, max_out) {
        Ok(v) => Cow::Owned(v),
        Err(_) => Cow::Borrowed(input),
    }
}

/// Test-only encoder: Reset 1, greedy longest match (>= 2) within the 1023 preceding bytes,
/// End-of-Record (which carries its own zero pad to a 32-bit boundary).
#[cfg(test)]
pub(crate) fn compress_literals_and_copies(data: &[u8]) -> Vec<u8> {
    let mut w = tests::BitWriter::default();
    w.push(0x1FF0 | u32::from(CTL_RESET1), 13);
    let mut pos = 0;
    while pos < data.len() {
        let (mut best_len, mut best_d) = (0, 0);
        for d in 1..=pos.min(HISTORY - 1) {
            let mut l = 0;
            while l < LONGEST_MATCH && pos + l < data.len() && data[pos + l] == data[pos + l - d] {
                l += 1;
            }
            if l > best_len {
                (best_len, best_d) = (l, d);
            }
        }
        if best_len >= 2 {
            w.push(1, 1);
            match best_len {
                2..=3 => w.push(best_len as u32 - 2, 2),
                4..=7 => w.push(0b10_00 | (best_len as u32 - 4), 4),
                8..=15 => w.push(0b110_000 | (best_len as u32 - 8), 6),
                16..=31 => w.push(0b1110_0000 | (best_len as u32 - 16), 8),
                _ => w.push(0xF00 | (best_len as u32 - 32), 12),
            }
            w.push(((pos - best_d) % HISTORY) as u32, 10);
            pos += best_len;
        } else {
            w.push(u32::from(data[pos]), 9);
            pos += 1;
        }
    }
    w.push(0x1FF0 | u32::from(CTL_EOR), 13);
    w.pad32();
    w.finish()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::wef::encoding::encode_utf16le_bom;

    /// MSB-first bit assembler for building test streams.
    #[derive(Debug, Default)]
    pub(crate) struct BitWriter {
        bits: Vec<bool>,
    }

    impl BitWriter {
        pub(crate) fn push(&mut self, value: u32, n: usize) {
            for i in (0..n).rev() {
                self.bits.push((value >> i) & 1 == 1);
            }
        }

        pub(crate) fn pad32(&mut self) {
            while !self.bits.len().is_multiple_of(32) {
                self.bits.push(false);
            }
        }

        pub(crate) fn finish(self) -> Vec<u8> {
            self.bits
                .chunks(8)
                .map(|c| {
                    c.iter()
                        .enumerate()
                        .fold(0u8, |a, (i, b)| a | (u8::from(*b) << (7 - i)))
                })
                .collect()
        }
    }

    const MAX: usize = 1 << 20;

    fn ctl(w: &mut BitWriter, code: u8) {
        w.push(0x1FF0 | u32::from(code), 13);
    }

    #[test]
    fn test_decompress_literal_only_record() {
        let mut w = BitWriter::default();
        ctl(&mut w, CTL_RESET1);
        w.push(u32::from(b'A'), 9);
        w.push(u32::from(b'B'), 9);
        ctl(&mut w, CTL_EOR);
        w.pad32();
        assert_eq!(decompress(&w.finish(), MAX).unwrap(), b"AB");
    }

    #[test]
    fn test_decompress_literals_without_leading_reset_default_to_scheme1() {
        let mut w = BitWriter::default();
        w.push(u32::from(b'A'), 9);
        ctl(&mut w, CTL_EOR);
        w.pad32();
        assert_eq!(decompress(&w.finish(), MAX).unwrap(), b"A");
    }

    #[test]
    fn test_decompress_hand_assembled_literal_copy_eor_vector() {
        // Bits worked out by hand from the standard's tables (not via the test encoder):
        // Reset 1 = 1 1111 1111 0101; 'A' = 0 01000001; 'B' = 0 01000010;
        // copy len 2 (match count 00) from location 0 = 1 00 0000000000; EOR = ...0100; pad.
        let bytes = [0xff, 0xa9, 0x04, 0x85, 0x00, 0x0f, 0xfa, 0x00];
        assert_eq!(decompress(&bytes, MAX).unwrap(), b"ABAB");
    }

    #[test]
    fn test_decompress_hand_assembled_scheme2_vector() {
        // Reset 2 = 1 1111 1111 0110; 'A'; FF + ZERO; 'B'; EOR; pad.
        let bytes = [0xff, 0xb2, 0x0f, 0xf9, 0x0b, 0xfe, 0x80, 0x00];
        assert_eq!(decompress(&bytes, MAX).unwrap(), b"A\xffB");
    }

    #[test]
    fn test_decompress_end_marker_only_is_empty() {
        assert_eq!(decompress(&[0xff; 4], MAX).unwrap(), b"");
        // pad must be all ONEs
        assert!(decompress(&[0xff, 0xf8, 0x00, 0x00], MAX).is_err());
    }

    #[test]
    fn test_decompress_copy_pointer_repeats_history() {
        let data = b"abcabcabc";
        let enc = compress_literals_and_copies(data);
        assert!(
            enc.len() < data.len() * 9 / 8 + 8,
            "encoder should emit a copy"
        );
        assert_eq!(decompress(&enc, MAX).unwrap(), data);
    }

    #[test]
    fn test_decompress_roundtrip_every_match_length_tier() {
        for run in [2usize, 3, 4, 7, 8, 15, 16, 31, 32, 33, 270, 271, 272, 600] {
            let data: Vec<u8> = b"xy".iter().cycle().take(run + 2).copied().collect();
            let enc = compress_literals_and_copies(&data);
            assert_eq!(decompress(&enc, MAX).unwrap(), data, "run {run}");
        }
    }

    #[test]
    fn test_decompress_roundtrip_utf16_soap() {
        let mut xml =
            String::from("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">");
        for i in 0..60 {
            xml.push_str(&format!(
                "<e:Event id=\"{}\">logon of user admin{}</e:Event>",
                i % 7,
                i % 3
            ));
        }
        xml.push_str("</s:Envelope>");
        let body = encode_utf16le_bom(&xml);
        assert!(body.len() > 4096);
        let enc = compress_literals_and_copies(&body);
        assert!(enc.len() < body.len());
        assert_eq!(decompress(&enc, MAX).unwrap(), body);
    }

    #[test]
    fn test_decompress_roundtrip_pseudorandom_bytes_wraps_history() {
        let mut x = 0x1234_5678u32;
        let data: Vec<u8> = (0..5000)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8 & 0x0F
            })
            .collect();
        let enc = compress_literals_and_copies(&data);
        assert_eq!(decompress(&enc, MAX).unwrap(), data);
    }

    #[test]
    fn test_decompress_rejects_output_over_max() {
        let enc = compress_literals_and_copies(&[b'z'; 100]);
        assert!(decompress(&enc, 10).is_err());
        assert_eq!(decompress(&enc, 100).unwrap().len(), 100);
    }

    #[test]
    fn test_decompress_rejects_copy_before_history_start() {
        let mut w = BitWriter::default();
        ctl(&mut w, CTL_RESET1);
        w.push(u32::from(b'A'), 9);
        w.push(1, 1);
        w.push(0, 2);
        w.push(5, 10); // location 5 was never written
        ctl(&mut w, CTL_EOR);
        w.pad32();
        assert!(decompress(&w.finish(), MAX).is_err());
    }

    #[test]
    fn test_decompress_truncated_input_errors() {
        let enc = compress_literals_and_copies(b"hello hello hello hello");
        for cut in 0..enc.len() - 1 {
            // must never panic; every strict prefix lacks the EOR
            let _ = decompress(&enc[..cut], MAX);
        }
        assert!(decompress(&enc[..enc.len() - 4], MAX).is_err());
        assert!(decompress(&[], MAX).is_err());
    }

    #[test]
    fn test_decompress_unknown_control_symbol_errors() {
        let mut w = BitWriter::default();
        ctl(&mut w, 0x7);
        w.pad32();
        assert!(decompress(&w.finish(), MAX).is_err());
    }

    #[test]
    fn test_decode_or_raw_returns_input_when_not_sldc() {
        let input = b"\xFF\xFE<\0";
        let got = decode_or_raw(input, MAX);
        assert!(matches!(got, Cow::Borrowed(_)));
        assert_eq!(&*got, input);
    }

    #[test]
    fn test_decode_or_raw_decodes_valid_stream() {
        let enc = compress_literals_and_copies(b"hello");
        assert_eq!(&*decode_or_raw(&enc, MAX), b"hello");
    }

    #[test]
    fn test_decode_or_raw_empty_input() {
        assert!(decode_or_raw(&[], MAX).is_empty());
    }
}
