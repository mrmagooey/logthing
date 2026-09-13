//! Criterion micro-benchmark for per-record `ZeekSink::to_record_batch` cost
//! across all seven Zeek `_path` cases: the six modelled schemas (`conn`,
//! `dns`, `http`, `ssl`, `files`, `notice`) plus the generic envelope
//! fallback every unmodelled stream takes.
//!
//! This asks a different question from `zeek_conn_batch_amortization.rs`,
//! which measures whether the amortized `ConnAccumulator` path beats the
//! per-record path for `conn`. That amortized path exists only for `conn`
//! and is not exercised here -- every case in this file goes through the
//! plain per-record `to_record_batch`, which is the *only* path the other
//! six schemas have. `conn` is included in both files so its per-record
//! figure here can be cross-referenced against the "before" figure there.
//!
//! All nine `ParquetSink` schemas (including all seven Zeek schemas here)
//! gained a non-null `partition_time` column in v0.16.0 (2026-09-06), so
//! figures measured here are NOT comparable to anything recorded before
//! that date.
//!
//! Run with: `cargo bench --bench zeek_schema_encode`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::zeek::ZeekRecord;
use logthing::zeek::schema::{
    conn_schema, dns_schema, envelope_schema, files_schema, http_schema, notice_schema,
    ssl_schema,
};
use std::hint::black_box;

fn record(log_path: &str, fields: serde_json::Value) -> ZeekRecord {
    ZeekRecord {
        log_path: log_path.to_string(),
        fields,
        received_at: Utc::now(),
    }
}

fn bench_zeek_schema_encode(c: &mut Criterion) {
    let sink = ZeekSink;
    let mut group = c.benchmark_group("zeek_schema_encode");
    group.throughput(Throughput::Elements(1));

    // conn -- cross-reference point with zeek_conn_batch_amortization.rs's
    // "per_record_fresh_builders" case: same record shape, same function.
    {
        let schema = conn_schema();
        let rec = record(
            "conn",
            serde_json::json!({
                "ts": 1700000000.123456,
                "uid": "CHhAvVGS1DHFjwGM9",
                "id.orig_h": "192.168.1.23",
                "id.orig_p": 54321,
                "id.resp_h": "93.184.216.34",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 2.345,
                "orig_bytes": 4820,
                "resp_bytes": 193840,
                "conn_state": "SF",
                "history": "ShADadFf",
                "orig_pkts": 12,
                "resp_pkts": 145,
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("conn fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("conn", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    // dns
    {
        let schema = dns_schema();
        let rec = record(
            "dns",
            serde_json::json!({
                "ts": 1700000000.654321,
                "uid": "CDNS1a2b3c4d5e6f7g",
                "id.orig_h": "192.168.1.45",
                "id.orig_p": 51823,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": 48291,
                "query": "www.example.com",
                "qtype_name": "A",
                "qclass_name": "C_INTERNET",
                "rcode_name": "NOERROR",
                "answers": ["93.184.216.34"],
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("dns fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("dns", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    // http
    {
        let schema = http_schema();
        let rec = record(
            "http",
            serde_json::json!({
                "ts": 1700000001.111,
                "uid": "CHTTP2h3i4j5k6l7m",
                "id.orig_h": "192.168.1.77",
                "id.orig_p": 43210,
                "id.resp_h": "203.0.113.10",
                "id.resp_p": 80,
                "method": "GET",
                "host": "www.example.com",
                "uri": "/index.html",
                "status_code": 200,
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "request_body_len": 0,
                "response_body_len": 15234,
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("http fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("http", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    // ssl
    {
        let schema = ssl_schema();
        let rec = record(
            "ssl",
            serde_json::json!({
                "ts": 1700000002.222,
                "uid": "CSSL8n9o0p1q2r3s",
                "id.orig_h": "192.168.1.88",
                "id.orig_p": 55123,
                "id.resp_h": "93.184.216.34",
                "id.resp_p": 443,
                "version": "TLSv12",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "curve": "secp256r1",
                "server_name": "www.example.com",
                "validation_status": "ok",
                "established": true,
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("ssl fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("ssl", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    // files
    {
        let schema = files_schema();
        let rec = record(
            "files",
            serde_json::json!({
                "ts": 1700000003.333,
                "fuid": "Fabc0123456789xyz",
                "tx_hosts": ["203.0.113.10"],
                "rx_hosts": ["192.168.1.77"],
                "conn_uids": ["CHTTP2h3i4j5k6l7m"],
                "source": "HTTP",
                "mime_type": "application/pdf",
                "filename": "report.pdf",
                "total_bytes": 524288,
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("files fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("files", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    // notice
    {
        let schema = notice_schema();
        let rec = record(
            "notice",
            serde_json::json!({
                "ts": 1700000004.444,
                "uid": "CNOTICE4t5u6v7w8x",
                "id.orig_h": "192.168.1.99",
                "id.orig_p": 33445,
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 22,
                "note": "SSH::Password_Guessing",
                "msg": "192.168.1.99 appears to be guessing SSH passwords",
                "sub": "Sampled 20 rejected connections",
                "src": "192.168.1.99",
                "dst": "198.51.100.20",
                "severity": "high",
                "actions": ["Notice::ACTION_LOG"],
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("notice fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("notice", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    // envelope_unmodelled -- "weird" has no registry entry, so
    // get_schema_entry falls through to envelope_schema and the whole JSON
    // object is carried as a string. This is the fallback every unmodelled
    // stream takes, and it has never been measured before this bench.
    {
        let schema = envelope_schema();
        let rec = record(
            "weird",
            serde_json::json!({
                "ts": 1700000005.555,
                "uid": "CWEIRD9y0z1a2b3c",
                "id.orig_h": "192.168.1.100",
                "id.orig_p": 60000,
                "id.resp_h": "198.51.100.30",
                "id.resp_p": 8080,
                "name": "above_hole_data_without_any_acks",
                "addl": "",
                "notice": false,
            }),
        );
        assert!(
            sink.to_record_batch(&rec, &schema)
                .expect("envelope_unmodelled fixture must encode")
                .num_rows()
                >= 1
        );
        group.bench_function("envelope_unmodelled", |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&rec), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_zeek_schema_encode);
criterion_main!(benches);
