#!/usr/bin/env python3
"""Regenerate fuzz/seeds/{ipfix,sflow}/*.bin from the bench fixtures.

Usage: scripts/gen_binary_fuzz_seeds.py   (run from the repo root)
IPFIX seeds use the fuzz harness framing: each datagram is prefixed with
its length as a big-endian u16.
"""
import pathlib, re, struct

def arr(path, name):
    src = pathlib.Path(path).read_text()
    body = re.search(rf"const {name}: &\[u8\] = &\[(.*?)\];", src, re.S).group(1)
    body = re.sub(r"//[^\n]*", "", body)
    return bytes(int(t, 16) for t in re.findall(r"0x([0-9A-Fa-f]{2})\b", body))

def framed(*dgrams):
    return b"".join(struct.pack(">H", len(d)) + d for d in dgrams)

IPFIX_BENCH = "benches/ipfix_decode_recv_path.rs"
SFLOW_BENCH = "benches/sflow_decode_recv_path.rs"

v10_tpl_data = arr(IPFIX_BENCH, "TEMPLATE_THEN_DATA")
v10_data = arr(IPFIX_BENCH, "DATA_ONLY")

v5 = struct.pack(">HHIIIIBBH", 5, 1, 1000, 1_700_000_000, 0, 1, 0, 0, 0) + struct.pack(
    ">4s4s4sHHIIIIHHBBBBHHBBH",
    bytes([192, 168, 1, 1]), bytes([10, 0, 0, 1]), bytes(4),
    1, 2, 10, 1500, 900, 1000, 12345, 443, 0, 0x18, 6, 0, 0, 0, 24, 24, 0,
)
v9_tpl = struct.pack(">HHHH", 0, 16, 256, 2) + struct.pack(">HHHH", 8, 4, 12, 4)
v9_data = struct.pack(">HH", 256, 12) + bytes([192, 168, 1, 1, 10, 0, 0, 1])
v9 = struct.pack(">HHIIII", 9, 2, 1000, 1_700_000_000, 1, 0) + v9_tpl + v9_data

out = pathlib.Path("fuzz/seeds/ipfix"); out.mkdir(parents=True, exist_ok=True)
(out / "v10_template_then_data.bin").write_bytes(framed(v10_tpl_data))
(out / "v10_template_then_data_only.bin").write_bytes(framed(v10_tpl_data, v10_data))
(out / "v5_single_flow.bin").write_bytes(framed(v5))
(out / "v9_template_then_data.bin").write_bytes(framed(v9))

out = pathlib.Path("fuzz/seeds/sflow"); out.mkdir(parents=True, exist_ok=True)
for name in ["FIXTURE_SFLOW_FLOW_RAW_HEADER", "FIXTURE_SFLOW_SAMPLED_IPV4", "FIXTURE_SFLOW_COUNTER"]:
    (out / f"{name.removeprefix('FIXTURE_SFLOW_').lower()}.bin").write_bytes(arr(SFLOW_BENCH, name))
