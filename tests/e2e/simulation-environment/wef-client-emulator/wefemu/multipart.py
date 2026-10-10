"""WEF Kerberos-encrypted multipart body (MS-WSMV "multipart/encrypted").

Exact layout (golden/multipart_layout.txt), CRLF line endings, no tabs, no blank line before the
binary part, and the closing boundary directly after the binary bytes:

    --Encrypted Boundary
    Content-Type: application/HTTP-Kerberos-session-encrypted
    OriginalContent: type=application/soap+xml;charset=UTF-16;Length=<N>
    --Encrypted Boundary
    Content-Type: application/octet-stream
    <LE int32 L><L bytes GSS header token><encrypted data>--Encrypted Boundary--
"""
import struct

BOUNDARY = b"--Encrypted Boundary"
PROTOCOL = "application/HTTP-Kerberos-session-encrypted"
CONTENT_TYPE = f'multipart/encrypted;protocol="{PROTOCOL}";boundary="Encrypted Boundary"'

_CRLF = b"\r\n"
_TAIL = BOUNDARY + b"--\r\n"


class MultipartError(ValueError):
    pass


def build(protocol: str, plaintext_len: int, header: bytes, data: bytes) -> bytes:
    return (
        BOUNDARY + _CRLF
        + b"Content-Type: " + protocol.encode("ascii") + _CRLF
        + b"OriginalContent: type=application/soap+xml;charset=UTF-16;Length="
        + str(plaintext_len).encode("ascii") + _CRLF
        + BOUNDARY + _CRLF
        + b"Content-Type: application/octet-stream" + _CRLF
        + struct.pack("<i", len(header)) + header + data
        + _TAIL
    )


def _take_line(body: bytes, pos: int, what: str) -> tuple[bytes, int]:
    end = body.find(_CRLF, pos)
    if end < 0:
        raise MultipartError(f"missing CRLF after {what}")
    line = body[pos:end]
    if b"\n" in line or b"\r" in line:
        raise MultipartError(f"bare CR/LF in {what}")
    return line, end + 2


def parse(body: bytes) -> tuple[str, int, bytes, bytes]:
    """Strictly parse a body into (protocol, original_length, header, data)."""
    pos = 0
    line, pos = _take_line(body, pos, "first boundary")
    if line != BOUNDARY:
        raise MultipartError(f"bad first boundary {line[:40]!r}")
    line, pos = _take_line(body, pos, "protocol line")
    if b"\t" in line or not line.startswith(b"Content-Type: "):
        raise MultipartError(f"bad protocol line (tab or wrong name): {line[:80]!r}")
    protocol = line[len(b"Content-Type: "):].decode("ascii", "replace")
    line, pos = _take_line(body, pos, "OriginalContent line")
    prefix = b"OriginalContent: type=application/soap+xml;charset=UTF-16;Length="
    if b"\t" in line or not line.startswith(prefix):
        raise MultipartError(
            f"bad OriginalContent line (tab, type or charset!=UTF-16 or Length missing): {line[:100]!r}")
    digits = line[len(prefix):]
    if not digits.isdigit():
        raise MultipartError(f"Length is not a decimal number: {digits[:20]!r}")
    length = int(digits)
    line, pos = _take_line(body, pos, "second boundary")
    if line != BOUNDARY:
        raise MultipartError(f"bad second boundary {line[:40]!r}")
    line, pos = _take_line(body, pos, "octet-stream line")
    if line != b"Content-Type: application/octet-stream":
        raise MultipartError(f"bad octet-stream part header: {line[:80]!r}")
    if not body.endswith(_TAIL):
        raise MultipartError("body does not end with '--Encrypted Boundary--' CRLF")
    binary = body[pos:len(body) - len(_TAIL)]
    if len(binary) < 4:
        raise MultipartError("binary part shorter than the 4-byte header length")
    (hlen,) = struct.unpack("<i", binary[:4])
    if hlen < 0 or 4 + hlen > len(binary):
        raise MultipartError(f"header length {hlen} out of range (binary part is {len(binary)})")
    return protocol, length, binary[4:4 + hlen], binary[4 + hlen:]


def check_length(original_length: int, decrypted: bytes) -> None:
    if len(decrypted) != original_length:
        raise MultipartError(
            f"OriginalContent Length={original_length} but decrypted payload is {len(decrypted)} bytes")
