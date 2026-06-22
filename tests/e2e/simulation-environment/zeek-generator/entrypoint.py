#!/usr/bin/env python3
"""
Zeek NDJSON TCP generator for E2E testing.

Connects to logthing's Zeek TCP listener and streams sample NDJSON records:
- 5 conn records
- 3 dns records
- 2 records from an unmodelled stream ("weird") -> routed to unknown/
- 1 malformed JSON line (must not crash the server)
"""

import json
import os
import socket
import time

ZEEK_HOST = os.environ.get("ZEEK_HOST", "logthing")
ZEEK_PORT = int(os.environ.get("ZEEK_PORT", "47760"))
CONNECT_TIMEOUT_SECS = int(os.environ.get("CONNECT_TIMEOUT_SECS", "30"))


def wait_for_server(host, port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            print(f"Connected to {host}:{port}")
            return
        except OSError:
            time.sleep(1)
    raise SystemExit(f"Could not connect to {host}:{port} within {timeout}s")


def send_records(host, port):
    conn_records = [
        {"_path": "conn", "ts": 1700000000.0 + i, "uid": f"CConn{i:03d}",
         "id.orig_h": f"10.0.{i}.1", "id.orig_p": 40000 + i,
         "id.resp_h": "93.184.216.34", "id.resp_p": 80,
         "proto": "tcp", "service": "http", "duration": 0.1 + i * 0.01,
         "orig_bytes": 512 + i * 100, "resp_bytes": 4096 + i * 200,
         "conn_state": "SF", "history": "ShADadFf",
         "orig_pkts": 10 + i, "resp_pkts": 15 + i}
        for i in range(5)
    ]
    dns_records = [
        {"_path": "dns", "ts": 1700001000.0 + i, "uid": f"CDns{i:03d}",
         "id.orig_h": "192.168.1.100", "id.orig_p": 12345 + i,
         "id.resp_h": "8.8.8.8", "id.resp_p": 53,
         "proto": "udp", "trans_id": 1000 + i,
         "query": f"host{i}.example.com", "qtype_name": "A",
         "qclass_name": "C_INTERNET", "rcode_name": "NOERROR",
         "answers": [f"1.2.3.{i}"]}
        for i in range(3)
    ]
    weird_records = [
        {"_path": "weird", "ts": 1700002000.0 + i, "uid": f"CWeird{i:03d}",
         "name": "data_before_established", "addl": f"extra_data_{i}"}
        for i in range(2)
    ]
    all_records = conn_records + dns_records + weird_records

    with socket.create_connection((host, port)) as sock:
        f = sock.makefile("wb")
        for rec in all_records:
            line = json.dumps(rec) + "\n"
            f.write(line.encode())
            f.flush()
        # Send one malformed line — server must continue, not crash
        f.write(b"NOT VALID JSON\n")
        f.flush()
        f.close()

    print(f"Sent {len(all_records)} valid records + 1 malformed line to {host}:{port}")
    # Give logthing time to process and flush (flush_threshold_bytes=1 triggers immediately)
    time.sleep(3)
    print("Zeek generator done.")


if __name__ == "__main__":
    wait_for_server(ZEEK_HOST, ZEEK_PORT, CONNECT_TIMEOUT_SECS)
    send_records(ZEEK_HOST, ZEEK_PORT)
