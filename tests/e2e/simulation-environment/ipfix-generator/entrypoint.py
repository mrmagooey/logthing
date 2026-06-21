#!/usr/bin/env python3
"""
IPFIX v10 datagram generator for E2E testing.

Sends a real IPFIX v10 message: one template set (template 256 with 7 fields)
followed by one data set (template 256, 5 flow records with concrete values).
Uses Python's built-in socket module only — no external dependencies.
"""

import os
import socket
import struct
import time

IPFIX_HOST = os.environ.get("IPFIX_HOST", "127.0.0.1")
IPFIX_PORT = int(os.environ.get("IPFIX_PORT", "4739"))

# ---------------------------------------------------------------------------
# IPFIX v10 field definitions (Information Element IDs)
# ---------------------------------------------------------------------------
# IE 8: sourceIPv4Address (4 bytes)
# IE 12: destinationIPv4Address (4 bytes)
# IE 7: sourceTransportPort (2 bytes)
# IE 11: destinationTransportPort (2 bytes)
# IE 4: protocolIdentifier (1 byte)
# IE 1: octetDeltaCount (8 bytes)
# IE 2: packetDeltaCount (8 bytes)

FIELDS = [
    (8, 4),   # sourceIPv4Address
    (12, 4),  # destinationIPv4Address
    (7, 2),   # sourceTransportPort
    (11, 2),  # destinationTransportPort
    (4, 1),   # protocolIdentifier
    (1, 8),   # octetDeltaCount
    (2, 8),   # packetDeltaCount
]
TEMPLATE_ID = 256
FIELD_COUNT = len(FIELDS)
# Data record length: 4+4+2+2+1+8+8 = 29 bytes
DATA_RECORD_LEN = sum(length for _, length in FIELDS)


def build_ipfix_header(version, length, export_time, seq_num, observation_domain_id):
    """Pack an IPFIX message header (16 bytes)."""
    return struct.pack(
        "!HHIII",
        version,             # Version: 0x000A = 10
        length,              # Total message length
        export_time,         # Export time (Unix seconds)
        seq_num,             # Sequence number
        observation_domain_id,
    )


def build_template_set():
    """Build IPFIX Template Set (set id = 2)."""
    # Template record: template_id + field_count + fields
    # Each field: (IE id (2) + field length (2))
    template_record = struct.pack("!HH", TEMPLATE_ID, FIELD_COUNT)
    for ie_id, ie_len in FIELDS:
        template_record += struct.pack("!HH", ie_id, ie_len)

    # Set header: set_id=2 (template set), set_length
    set_header_len = 4  # set_id (2) + set_length (2)
    set_length = set_header_len + len(template_record)
    # Pad to 4-byte boundary
    pad = (4 - (set_length % 4)) % 4
    set_length_padded = set_length + pad

    return struct.pack("!HH", 2, set_length_padded) + template_record + b"\x00" * pad


def encode_ipv4(addr_str):
    """Encode dotted-decimal IPv4 to 4 bytes."""
    parts = [int(p) for p in addr_str.split(".")]
    return struct.pack("!BBBB", *parts)


def build_data_record(src_ip, dst_ip, src_port, dst_port, proto, octets, packets):
    """Build a single 29-byte data record matching template 256."""
    return (
        encode_ipv4(src_ip)
        + encode_ipv4(dst_ip)
        + struct.pack("!H", src_port)
        + struct.pack("!H", dst_port)
        + struct.pack("!B", proto)
        + struct.pack("!Q", octets)
        + struct.pack("!Q", packets)
    )


def build_data_set(records):
    """Build IPFIX Data Set (set id = TEMPLATE_ID)."""
    payload = b"".join(records)
    set_header_len = 4
    set_length = set_header_len + len(payload)
    pad = (4 - (set_length % 4)) % 4
    set_length_padded = set_length + pad
    return struct.pack("!HH", TEMPLATE_ID, set_length_padded) + payload + b"\x00" * pad


def build_ipfix_message(template_set, data_set):
    """Combine sets into a complete IPFIX message."""
    body = template_set + data_set
    total_len = 16 + len(body)  # 16-byte header
    now_unix = int(time.time())
    header = build_ipfix_header(
        version=10,
        length=total_len,
        export_time=now_unix,
        seq_num=1,
        observation_domain_id=1,
    )
    return header + body


def main():
    # 5 concrete flow records
    flow_records = [
        build_data_record("10.0.0.1", "10.0.0.2", 12345, 80, 6, 1000, 10),
        build_data_record("10.0.0.3", "10.0.0.4", 54321, 443, 6, 2000, 20),
        build_data_record("192.168.1.1", "8.8.8.8", 9999, 53, 17, 500, 5),
        build_data_record("172.16.0.1", "10.10.0.1", 8080, 22, 6, 3000, 30),
        build_data_record("10.1.2.3", "10.4.5.6", 11111, 8080, 6, 4000, 40),
    ]

    template_set = build_template_set()
    data_set = build_data_set(flow_records)
    message = build_ipfix_message(template_set, data_set)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Send template + data in one datagram
        sock.sendto(message, (IPFIX_HOST, IPFIX_PORT))
        print(
            f"Sent IPFIX message ({len(message)} bytes) with {len(flow_records)} "
            f"flow records to {IPFIX_HOST}:{IPFIX_PORT}"
        )
    finally:
        sock.close()

    # Sleep briefly to allow logthing to flush (flush_threshold_bytes=1 triggers immediately)
    time.sleep(2)
    print("IPFIX generator done.")


if __name__ == "__main__":
    main()
