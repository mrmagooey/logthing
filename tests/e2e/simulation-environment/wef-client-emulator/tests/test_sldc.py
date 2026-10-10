"""SLDC (ECMA-321) tests. The hand-assembled vectors are built from the bit tables in the
standard (clause 8.4 / Table 1 match-count fields, clause 8.5 / Table 1 control symbols) and
do not use the encoder."""
import random

import pytest

from wefemu import sldc


def bits(*parts: str) -> bytes:
    """Pack a string of '0'/'1' (spaces ignored) MSB-first, zero-padded to a 32-bit boundary."""
    s = "".join(parts).replace(" ", "")
    s += "0" * (-len(s) % 32)
    return int(s, 2).to_bytes(len(s) // 8, "big")


LIT_A = "0 01000001"
LIT_B = "0 01000010"
EOR = "1 1111 1111 0100"
FLUSH = "1 1111 1111 0000"
END_MARKER = "1 1111 1111 1111"


def test_decode_hand_assembled_literals_and_copy_pointer():
    # A, B as Literal 1; Copy Pointer: ONE + count 4 ("10 00") + displacement 0 -> ABAB;
    # then EOR and Flush (pad zeros to 32 bits).
    vec = bits(LIT_A, LIT_B, "1 1000 0000000000", EOR, FLUSH)
    assert sldc.decompress(vec) == b"ABABAB"


def test_decode_hand_assembled_literal_only_vector():
    vec = bits("0 01001000", "0 01101001", EOR, FLUSH)  # "Hi"
    assert sldc.decompress(vec) == b"Hi"


def test_encoder_matches_hand_assembled_vector():
    vec = bits(LIT_A, LIT_B, "1 1000 0000000000", EOR, FLUSH)
    assert sldc.compress(b"ABABAB") == vec


def test_encoder_literal_only_matches_hand_vector():
    assert sldc.compress(b"Hi") == bits("0 01001000", "0 01101001", EOR, FLUSH)


@pytest.mark.parametrize(
    "count_field,length",
    [("00", 2), ("01", 3), ("1000", 4), ("1011", 7), ("110000", 8), ("110111", 15),
     ("11100000", 16), ("11101111", 31), ("111100000000", 32), ("111111101111", 271)],
)
def test_decode_match_count_field_table(count_field, length):
    # 'x' literal at location 0, then copy from location 0 (overlapping run, distance 1).
    vec = bits("0 01111000", "1 " + count_field + " 0000000000", EOR, FLUSH)
    assert sldc.decompress(vec) == b"x" * (1 + length)


def test_decode_scheme2_with_ff_trailing_zero():
    # Reset 2, then 0x41, 0xFF followed by ZERO, 0x42; EOR; Flush.
    vec = bits("1 1111 1111 0110", "01000001", "11111111 0", "01000010", EOR, FLUSH)
    assert sldc.decompress(vec) == b"A\xffB"


def test_decode_scheme_switch_and_reset1():
    vec = bits("1 1111 1111 0101", LIT_A, "1 1111 1111 0010", "01000010", EOR, FLUSH)
    assert sldc.decompress(vec) == b"AB"


def test_decode_end_marker_only_is_empty():
    # End Marker = 1 1111 1111 1111 then Pad of ONEs up to the 32-bit boundary (Table 1).
    assert sldc.decompress(b"\xff\xff\xff\xff") == b""
    assert sldc.compress(b"") == b"\xff\xff\xff\xff"


def test_displacement_is_absolute_history_location_after_wrap():
    # 1030 literals fill locations 0..1023 and then 0..5 again. A Copy Pointer at location
    # 1022 with Match Count 8 wraps around the end of the History Buffer (clause 7.3,
    # "Offset 1 022, Length 10" example) and so yields the last 8 literals.
    rng = random.Random(7)
    head = bytes(rng.randrange(256) for _ in range(1030))
    parts = ["1 1111 1111 0101"]  # Reset 1
    parts += ["0" + format(b, "08b") for b in head]
    parts += ["1 110000 " + format(1022, "010b"), EOR, FLUSH]  # count 8 = "110 000"
    assert sldc.decompress(bits(*parts)) == head + head[1022:1030]


@pytest.mark.parametrize("seed", range(5))
def test_roundtrip_random_bytes(seed):
    rng = random.Random(seed)
    data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 3000)))
    assert sldc.decompress(sldc.compress(data)) == data


def test_roundtrip_utf16_text_compresses():
    text = ("<Event><Data Name='x'>hello world </Data></Event>" * 40).encode("utf-16-le")
    c = sldc.compress(text)
    assert len(c) < len(text) // 2
    assert sldc.decompress(c) == text


@pytest.mark.parametrize("n", [1, 2, 3, 271, 272, 273, 1023, 1024, 1025, 5000])
def test_roundtrip_all_same_byte(n):
    data = b"\x00" * n
    assert sldc.decompress(sldc.compress(data)) == data
    data = b"\xff" * n
    assert sldc.decompress(sldc.compress(data)) == data


@pytest.mark.parametrize("dist", [1022, 1023, 1024, 1025, 1026])
def test_roundtrip_window_boundary(dist):
    rng = random.Random(dist)
    block = bytes(rng.randrange(256) for _ in range(dist))
    data = block + block + block[:100]
    assert sldc.decompress(sldc.compress(data)) == data


def test_window_boundary_1023_is_matched_1024_is_not():
    rng = random.Random(1)
    block = bytes(rng.randrange(256) for _ in range(1023))
    assert len(sldc.compress(block + block)) < len(sldc.compress(block)) * 1.2
    block = bytes(rng.randrange(256) for _ in range(1024))
    assert len(sldc.compress(block + block)) > len(sldc.compress(block)) * 1.9


def test_output_is_32_bit_aligned():
    for n in range(0, 40):
        assert len(sldc.compress(bytes(range(n)))) % 4 == 0


def test_decoder_rejects_truncated_copy_pointer():
    with pytest.raises(sldc.SldcError):
        sldc.decompress(b"\xe0")  # ONE + 7 bits: count field "1110 xxxx" is cut short


def test_decoder_rejects_copy_before_any_history():
    with pytest.raises(sldc.SldcError):
        sldc.decompress(bits("1 00 0000000101", EOR, FLUSH))


def test_decoder_rejects_reserved_control_symbol():
    with pytest.raises(sldc.SldcError):
        sldc.decompress(bits("1 1111 1111 1000", EOR, FLUSH))


def test_decompress_garbage_raises():
    with pytest.raises(sldc.SldcError):
        sldc.decompress("<s:Envelope xmlns:s=x/>".encode("utf-16-le"))
