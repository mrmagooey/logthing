import struct
from pathlib import Path

import pytest

from wefemu import multipart

GOLDEN = Path(__file__).resolve().parents[4] / "fixtures" / "wef" / "golden"
PROTO = "application/HTTP-Kerberos-session-encrypted"


def _layout() -> bytes:
    return (GOLDEN / "multipart_layout.txt").read_bytes()


def test_build_matches_golden_layout():
    header, data = b"H" * 60, b"\x01\x02\r\n\x03"
    body = multipart.build(PROTO, 3240, header, data)
    binary = struct.pack("<i", 60) + header + data
    expected = _layout().replace(b"{N}", b"3240").replace(b"<BINARY>", binary)
    assert body == expected


def test_build_has_no_tabs_and_crlf_everywhere():
    body = multipart.build(PROTO, 1, b"h" * 4, b"d")
    prefix = body[: body.index(b"application/octet-stream")]
    assert b"\t" not in prefix
    assert b"\n" not in prefix.replace(b"\r\n", b"")


def test_parse_roundtrip_with_binary_containing_crlf_and_boundary_text():
    header = b"\r\n--Encrypted Boundary--\r\n" + b"x" * 10
    data = b"--Encrypted Boundary\r\n\x00\xff"
    body = multipart.build(PROTO, 99, header, data)
    # the parser takes the header length from the LE32, so it can split the binary section
    assert multipart.parse(body) == (PROTO, 99, header, data)


def test_parse_golden_template_substituted():
    binary = struct.pack("<i", 2) + b"HH" + b"DATA"
    body = _layout().replace(b"{N}", b"4").replace(b"<BINARY>", binary)
    assert multipart.parse(body) == (PROTO, 4, b"HH", b"DATA")


def test_content_type_header_value_exact():
    assert multipart.CONTENT_TYPE == (
        'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";'
        'boundary="Encrypted Boundary"'
    )


@pytest.mark.parametrize(
    "mutate,msg",
    [
        (lambda b: b.replace(b"Content-Type: application/HTTP", b"\tContent-Type: application/HTTP"), "tab"),
        (lambda b: b.replace(b"charset=UTF-16", b"charset=UTF-8"), "charset"),
        (lambda b: b.replace(b"charset=UTF-16;", b"charset=UTF-16 ;"), "charset"),
        (lambda b: b.replace(b";Length=", b";length="), "Length"),
        (lambda b: b.replace(b"\r\nOriginalContent", b"\nOriginalContent"), "CRLF"),
        (lambda b: b.replace(b"octet-stream\r\n", b"octet-stream\r\n\r\n"), "blank"),
        (lambda b: b[:-2], "terminator"),
        (lambda b: b[: -len(b"--Encrypted Boundary--\r\n")] + b"--Encrypted Boundary-\r\n", "terminator"),
        (lambda b: b.replace(b"--Encrypted Boundary\r\n", b"--Other Boundary\r\n", 1), "boundary"),
        (lambda b: b.replace(b"type=application/soap+xml", b"type=text/xml"), "type"),
    ],
)
def test_parse_rejects_malformed(mutate, msg):
    body = multipart.build(PROTO, 4, b"HH", b"DATA")
    with pytest.raises(multipart.MultipartError):
        multipart.parse(mutate(body))


def test_parse_rejects_bad_header_length():
    body = _layout().replace(b"{N}", b"1").replace(b"<BINARY>", struct.pack("<i", 500) + b"ab")
    with pytest.raises(multipart.MultipartError):
        multipart.parse(body)
    body = _layout().replace(b"{N}", b"1").replace(b"<BINARY>", struct.pack("<i", -1) + b"ab")
    with pytest.raises(multipart.MultipartError):
        multipart.parse(body)


def test_check_length_equals_decrypted():
    multipart.check_length(10, b"x" * 10)
    with pytest.raises(multipart.MultipartError):
        multipart.check_length(10, b"x" * 9)
