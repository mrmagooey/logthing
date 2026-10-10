"""SLDC - Streaming Lossless Data Compression, written from ECMA-321 (1st ed., June 2001).

Clauses used: 7.1/7.2 (schemes), 7.3 + 8.2 (1024-byte History Buffer, Displacement Field is an
absolute location 0..1023 in the circular buffer), 8.3 (MSB-first bit packing), 8.4.1-8.4.3
(Literal 1, Copy Pointer + Table 1 Match Count Field, Literal 2), 8.5 (Control Symbol values
and Pad rules), 8.6 (Pad).

Encoder: scheme 1 only, greedy longest match, one Record terminated by an EOR Symbol followed by
a Flush Symbol and zero Pad up to a 32-bit boundary (what a WEF client appends to a message).
The encoder emits no leading Reset 1: the History Buffer is empty at the start of a stream.
Decoder: full control-symbol support (Flush, Scheme 1/2, File Mark, EOR, Reset 1/2, End Marker).
"""

HISTORY = 1024
MAX_MATCH = 271  # Table 1: Match Count Field 1111 11101111
MIN_MATCH = 2

CS_FLUSH, CS_SCHEME1, CS_SCHEME2, CS_FILEMARK, CS_EOR, CS_RESET1, CS_RESET2 = range(7)
CS_END = 0b1111


class SldcError(ValueError):
    pass


class _BitWriter:
    def __init__(self):
        self.acc = 0
        self.n = 0

    def put(self, value: int, width: int):
        self.acc = (self.acc << width) | (value & ((1 << width) - 1))
        self.n += width

    def pad(self, bit: int):
        pad = -self.n % 32
        self.put(((1 << pad) - 1) if bit else 0, pad)

    def to_bytes(self) -> bytes:
        assert self.n % 8 == 0
        return self.acc.to_bytes(self.n // 8, "big")


def _put_control(w: _BitWriter, code: int):
    w.put(0b1_1111_1111, 9)  # nine leading ONEs (clause 8.4.3 note)
    w.put(code, 4)


def _put_count(w: _BitWriter, n: int):
    """Match Count Field, Table 1."""
    if n == 2:
        w.put(0b00, 2)
    elif n == 3:
        w.put(0b01, 2)
    elif n <= 7:
        w.put(0b10, 2)
        w.put(n - 4, 2)
    elif n <= 15:
        w.put(0b110, 3)
        w.put(n - 8, 3)
    elif n <= 31:
        w.put(0b1110, 4)
        w.put(n - 16, 4)
    else:
        w.put(0b1111, 4)
        w.put(n - 32, 8)


def compress(data: bytes) -> bytes:
    """Encode `data` as a single scheme-1 Record: ... EOR, Flush, Pad(zeros) to 32 bits."""
    w = _BitWriter()
    if not data:
        _put_control(w, CS_END)  # empty user data = End Marker first (clause 8.5)
        w.pad(1)
        return w.to_bytes()
    n = len(data)
    index: dict[bytes, list[int]] = {}
    i = 0
    while i < n:
        best_len, best_pos = 0, -1
        if i + 1 < n:
            for p in reversed(index.get(data[i:i + 2], ())):
                if i - p >= HISTORY:  # distance 1024 would be location == write pointer
                    break
                limit = min(MAX_MATCH, n - i)
                length = 2
                while length < limit and data[p + length] == data[i + length]:
                    length += 1
                if length > best_len:
                    best_len, best_pos = length, p
                    if length == limit:
                        break
        step = 1
        if best_len >= MIN_MATCH:
            w.put(1, 1)
            _put_count(w, best_len)
            w.put(best_pos % HISTORY, 10)  # absolute History Buffer location
            step = best_len
        else:
            w.put(data[i], 9)  # leading ZERO + byte
        for j in range(i, min(i + step, n - 1)):
            index.setdefault(data[j:j + 2], []).append(j)
        i += step
    _put_control(w, CS_EOR)
    _put_control(w, CS_FLUSH)
    w.pad(0)
    return w.to_bytes()


class _BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.total = len(data) * 8

    def left(self) -> int:
        return self.total - self.pos

    def peek(self, width: int) -> int:
        """Next `width` bits (zero-extended if fewer remain)."""
        v = 0
        for k in range(width):
            p = self.pos + k
            bit = (self.data[p >> 3] >> (7 - (p & 7))) & 1 if p < self.total else 0
            v = (v << 1) | bit
        return v

    def get(self, width: int) -> int:
        if width > self.left():
            raise SldcError("truncated SLDC stream")
        v = self.peek(width)
        self.pos += width
        return v

    def to_boundary(self) -> int:
        return min(self.left(), -self.pos % 32)

    def align32(self):
        self.pos += self.to_boundary()


def _read_count(r: _BitReader):
    """Read a Match Count Field (Table 1) after the leading ONE.

    Returns ("len", n) or ("ctl", code) for the 1111 1111xxxx range."""
    if r.get(1) == 0:
        return "len", 2 + r.get(1)
    if r.get(1) == 0:
        return "len", 4 + r.get(2)
    if r.get(1) == 0:
        return "len", 8 + r.get(3)
    if r.get(1) == 0:
        return "len", 16 + r.get(4)
    ext = r.get(8)
    if ext >= 0xF0:
        return "ctl", ext & 0xF
    return "len", 32 + ext


def decompress(data: bytes) -> bytes:
    """Decode an SLDC stream. Raises SldcError on malformed or unterminated input.

    The stream must end with EOR (optionally followed by Flush + Pad) or an End Marker. One
    that merely runs out of bits is reported as truncated: that is how callers tell an
    uncompressed payload from a compressed one.
    """
    r = _BitReader(data)
    out = bytearray()
    hist = bytearray(HISTORY)
    wp = 0  # next History Buffer location to write
    filled = 0  # bytes recorded since the last Reset (history valid for locations < filled)
    scheme = 1
    terminated = False

    def emit(b: int):
        nonlocal wp, filled
        out.append(b)
        hist[wp] = b
        wp = (wp + 1) % HISTORY
        filled = min(HISTORY, filled + 1)

    while True:
        if terminated and r.left() <= 32 and r.peek(r.left()) == 0:
            return bytes(out)  # only zero Pad is left
        code = None
        if scheme == 1:
            if r.left() < 9:
                break
            if r.get(1) == 0:
                emit(r.get(8))
                terminated = False
                continue
            kind, val = _read_count(r)
            if kind == "len":
                disp = r.get(10)
                if disp >= filled or disp == wp:
                    raise SldcError(f"copy pointer to undefined history location {disp}")
                for k in range(val):
                    loc = (disp + k) % HISTORY
                    if loc == wp or (filled < HISTORY and loc >= filled):
                        raise SldcError("copy pointer reads undefined history")
                    emit(hist[loc])
                terminated = False
                continue
            code = val
        else:
            if r.left() < 8:
                break
            if r.peek(9) == 0x1FF:
                # nine ONEs: Control Symbol (a Literal 2 0xFF has a ZERO after its eight ONEs)
                r.get(9)
                code = r.get(4)
            else:
                b = r.get(8)
                if b == 0xFF:
                    r.get(1)  # the trailing ZERO
                emit(b)
                terminated = False
                continue
        if code == CS_FLUSH or code == CS_FILEMARK:
            r.align32()
            terminated = True
        elif code == CS_EOR:
            terminated = True
            gap = r.to_boundary()
            if gap and r.peek(gap) == 0 and (r.left() - gap) >= 9 and (
                    _peek_at(r, gap, 9) == 0x1FF):
                r.pos += gap  # EOR followed by Pad, then a Control Symbol on the boundary
        elif code == CS_SCHEME1:
            scheme = 1
        elif code == CS_SCHEME2:
            scheme = 2
        elif code == CS_RESET1:
            scheme, wp, filled = 1, 0, 0
        elif code == CS_RESET2:
            scheme, wp, filled = 2, 0, 0
        elif code == CS_END:
            return bytes(out)
        else:
            raise SldcError(f"reserved control symbol {code:#x}")
    if terminated and r.peek(r.left()) == 0:
        return bytes(out)
    raise SldcError("SLDC stream not terminated by EOR/Flush/End Marker")


def _peek_at(r: _BitReader, offset: int, width: int) -> int:
    save = r.pos
    r.pos += offset
    v = r.peek(width)
    r.pos = save
    return v
