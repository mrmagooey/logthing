//! Byte-parity oracle: the production accumulators (`crate::zeek::schema`) versus the frozen
//! pre-fix copy (`crate::zeek::schema::reference`). Every column and the `_extra` / `payload`
//! strings must match for every promoted key drawn from 16 JSON value variants.

use arrow::array::{Array, StringArray};
use arrow::record_batch::RecordBatch;
use chrono::TimeZone;
use serde_json::{Value, json};

use crate::zeek::schema as new;
use crate::zeek::schema::reference as old;

fn rx() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.with_ymd_and_hms(2024, 3, 15, 12, 0, 0).unwrap()
}

type Runner = fn(&[Value]) -> RecordBatch;

macro_rules! conn_runner {
    ($m:ident) => {{
        fn run(vs: &[Value]) -> RecordBatch {
            let mut acc = $m::ConnAccumulator::new();
            for v in vs {
                acc.append_conn_value(v, rx());
            }
            acc.finish_batch().unwrap()
        }
        run as Runner
    }};
}

macro_rules! row_runner {
    ($m:ident, $acc:ident, $append:ident) => {{
        fn run(vs: &[Value]) -> RecordBatch {
            let mut acc = $m::$acc::new();
            for v in vs {
                $m::$append(&mut acc, v, rx());
            }
            acc.finish_batch().unwrap()
        }
        run as Runner
    }};
}

macro_rules! envelope_runner {
    ($m:ident) => {{
        fn run(vs: &[Value]) -> RecordBatch {
            let mut acc = $m::EnvelopeAccumulator::new();
            for v in vs {
                $m::append_envelope_row(&mut acc, v, "weird", rx());
            }
            acc.finish_batch().unwrap()
        }
        run as Runner
    }};
}

struct PathCase {
    name: &'static str,
    base: Value,
    /// Columns whose value is not a function of the input (envelope `ingest_time` = now()).
    skip_cols: &'static [&'static str],
    run_new: Runner,
    run_old: Runner,
}

fn cases() -> Vec<PathCase> {
    let id = |p: u16| {
        json!({"id.orig_h": "10.0.0.1", "id.orig_p": 12345, "id.resp_h": "10.0.0.2",
               "id.resp_p": p})
    };
    let merge = |a: Value, b: Value| {
        let mut a = a;
        a.as_object_mut()
            .unwrap()
            .extend(b.as_object().unwrap().clone());
        a
    };
    let ts_uid = json!({"ts": 1700000000.5, "uid": "C1"});
    vec![
        PathCase {
            name: "conn",
            base: merge(
                merge(ts_uid.clone(), id(443)),
                json!({"proto": "tcp", "service": "http", "duration": 1.5, "orig_bytes": 100,
                       "resp_bytes": 200, "conn_state": "SF", "history": "ShADad",
                       "orig_pkts": 3, "resp_pkts": 4}),
            ),
            skip_cols: &[],
            run_new: conn_runner!(new),
            run_old: conn_runner!(old),
        },
        PathCase {
            name: "dns",
            base: merge(
                merge(ts_uid.clone(), id(53)),
                json!({"proto": "udp", "trans_id": 42, "query": "a.example.com",
                       "qtype_name": "A", "qclass_name": "C_INTERNET", "rcode_name": "NOERROR",
                       "answers": ["1.2.3.4"]}),
            ),
            skip_cols: &[],
            run_new: row_runner!(new, DnsAccumulator, append_dns_row),
            run_old: row_runner!(old, DnsAccumulator, append_dns_row),
        },
        PathCase {
            name: "http",
            base: merge(
                merge(ts_uid.clone(), id(80)),
                json!({"method": "GET", "host": "example.com", "uri": "/p", "status_code": 200,
                       "user_agent": "curl/8", "request_body_len": 10,
                       "response_body_len": 20}),
            ),
            skip_cols: &[],
            run_new: row_runner!(new, HttpAccumulator, append_http_row),
            run_old: row_runner!(old, HttpAccumulator, append_http_row),
        },
        PathCase {
            name: "ssl",
            base: merge(
                merge(ts_uid.clone(), id(443)),
                json!({"version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                       "curve": "x25519", "server_name": "example.com",
                       "validation_status": "ok"}),
            ),
            skip_cols: &[],
            run_new: row_runner!(new, SslAccumulator, append_ssl_row),
            run_old: row_runner!(old, SslAccumulator, append_ssl_row),
        },
        PathCase {
            name: "files",
            base: json!({"ts": 1700000000.5, "fuid": "F1", "tx_hosts": ["a"], "rx_hosts": ["b"],
                         "source": "HTTP", "mime_type": "text/plain", "filename": "f.txt",
                         "total_bytes": 100}),
            skip_cols: &[],
            run_new: row_runner!(new, FilesAccumulator, append_files_row),
            run_old: row_runner!(old, FilesAccumulator, append_files_row),
        },
        PathCase {
            name: "notice",
            base: merge(
                merge(ts_uid.clone(), id(22)),
                json!({"note": "N::X", "msg": "m", "sub": "s",
                       "actions": ["Notice::ACTION_LOG"]}),
            ),
            skip_cols: &[],
            run_new: row_runner!(new, NoticeAccumulator, append_notice_row),
            run_old: row_runner!(old, NoticeAccumulator, append_notice_row),
        },
        PathCase {
            name: "envelope",
            base: merge(ts_uid, id(80)),
            skip_cols: &["ingest_time"],
            run_new: envelope_runner!(new),
            run_old: envelope_runner!(old),
        },
    ]
}

/// The 16 variants of one promoted key; `None` = key absent.
fn variants() -> Vec<Option<Value>> {
    vec![
        None,
        Some(json!(null)),
        Some(json!(true)),
        Some(json!("s")),
        Some(json!("")),
        Some(json!(-1)),
        Some(json!(0)),
        Some(json!(65535)),
        Some(json!(65536)),
        Some(json!(4_294_967_296_u64)),
        Some(json!(u64::MAX)),
        Some(json!(1.5)),
        Some(json!(1e300)),
        Some(json!(-1e300)),
        Some(json!([1, "a\"b\u{e9}"])),
        Some(json!({"k": {"n": [1, "q\"\\\n\u{1F600}"]}})),
    ]
}

fn set(base: &Value, key: &str, variant: &Option<Value>) -> Value {
    let mut v = base.clone();
    let obj = v.as_object_mut().unwrap();
    match variant {
        Some(x) => {
            obj.insert(key.to_string(), x.clone());
        }
        None => {
            obj.remove(key);
        }
    }
    v
}

/// Non-promoted keys in awkward shapes, sorted before, between and after the promoted ones.
fn with_extras(mut v: Value) -> Value {
    let o = v.as_object_mut().unwrap();
    o.insert("_path".into(), json!("x"));
    o.insert("aa_null".into(), json!(null));
    o.insert("empty_obj".into(), json!({}));
    o.insert("mid_arr".into(), json!([1, 2, "x", [], {}]));
    o.insert(
        "zz_nested".into(),
        json!({"a": [1, {"b": null}], "e": "q\"\\\n\t\u{e9}\u{1F600}", "f": 1.0e-7,
               "g": 18_446_744_073_709_551_615_u64}),
    );
    v
}

fn string_col(b: &RecordBatch, name: &str) -> Vec<Option<String>> {
    let a = b
        .column_by_name(name)
        .unwrap_or_else(|| panic!("no column {name}"))
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    (0..a.len())
        .map(|i| a.is_valid(i).then(|| a.value(i).to_string()))
        .collect()
}

fn assert_same(case: &PathCase, new_b: &RecordBatch, old_b: &RecordBatch, ctx: &str) {
    assert_eq!(
        new_b.schema(),
        old_b.schema(),
        "{} schema ({ctx})",
        case.name
    );
    assert_eq!(
        new_b.num_rows(),
        old_b.num_rows(),
        "{} rows ({ctx})",
        case.name
    );
    for name in ["_extra", "payload"] {
        if old_b.column_by_name(name).is_some() {
            assert_eq!(
                string_col(new_b, name),
                string_col(old_b, name),
                "{} {name} bytes differ ({ctx})",
                case.name
            );
        }
    }
    for (i, f) in old_b.schema().fields().iter().enumerate() {
        if case.skip_cols.contains(&f.name().as_str()) {
            continue;
        }
        assert_eq!(
            new_b.column(i).to_data(),
            old_b.column(i).to_data(),
            "{} column {} differs ({ctx})",
            case.name,
            f.name()
        );
    }
}

/// Compare record-by-record (single-row accumulators) AND as one multi-row accumulator, which
/// catches state leaking between records through a reused buffer.
fn compare_all(case: &PathCase, records: &[Value], label: &str) {
    assert!(
        !records.is_empty(),
        "{label}: empty record list would pass vacuously"
    );
    for (i, r) in records.iter().enumerate() {
        let ctx = format!("{label} #{i}: {r}");
        assert_same(
            case,
            &(case.run_new)(std::slice::from_ref(r)),
            &(case.run_old)(std::slice::from_ref(r)),
            &ctx,
        );
    }
    let (new_b, old_b) = ((case.run_new)(records), (case.run_old)(records));
    assert!(new_b.num_rows() > 0, "{label}: no rows produced");
    assert_eq!(
        new_b.num_rows(),
        records.len(),
        "{label}: row count != record count"
    );
    assert_eq!(
        old_b.num_rows(),
        records.len(),
        "{label}: reference row count"
    );
    assert_same(
        case,
        &new_b,
        &old_b,
        &format!("{label} as one batch of {}", records.len()),
    );
}

#[test]
fn single_key_type_matrix_matches_reference() {
    for case in cases() {
        let keys: Vec<String> = case.base.as_object().unwrap().keys().cloned().collect();
        let mut records = Vec::new();
        for key in &keys {
            for variant in variants() {
                records.push(with_extras(set(&case.base, key, &variant)));
            }
        }
        // 16 variants x every promoted key, plus the untouched base.
        records.push(with_extras(case.base.clone()));
        assert!(records.len() >= 16 * keys.len(), "{}", case.name);
        compare_all(&case, &records, &format!("{} single-key", case.name));
    }
}

#[test]
fn multi_key_combinations_match_reference() {
    let vars = variants();
    for case in cases() {
        let keys: Vec<String> = case.base.as_object().unwrap().keys().cloned().collect();
        let mut state: u64 = 0x5eed_f1c4_u64 ^ (case.name.len() as u64);
        let mut records = Vec::new();
        for _ in 0..1500 {
            let mut v = case.base.clone();
            for key in &keys {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // ~1/4 of the keys keep their valid value so valid and invalid mix.
                if (state >> 62) != 0 {
                    v = set(&v, key, &vars[((state >> 33) % 16) as usize]);
                }
            }
            records.push(with_extras(v));
        }
        compare_all(&case, &records, &format!("{} multi-key", case.name));
    }
}

#[test]
fn non_object_and_empty_values_match_reference() {
    for case in cases() {
        let records = vec![
            json!(null),
            json!(5),
            json!("s"),
            json!([1, {"a": 2}]),
            json!({}),
            with_extras(json!({})),
            case.base.clone(),
        ];
        compare_all(&case, &records, &format!("{} non-object", case.name));
    }
}

/// `ts` rounding and range-clamp boundaries (`json_ts_micros` accepts |secs * 1e6| < ~9.22e18,
/// i.e. roughly +-9.223372036854775e12 seconds).
#[test]
fn ts_boundary_values_match_reference() {
    let tss = [
        json!(1.0000005),
        json!(1.9999995),
        json!(1700000000.123456789),
        json!(1700000000.1234565),
        json!(-1.5),
        json!(-0.0000005),
        json!(0.0),
        json!(0),
        json!(1),
        json!(9.2e12),
        json!(9.223372036854e12),
        json!(9.223372036855e12),
        json!(9.3e12),
        json!(-9.2e12),
        json!(-9.223372036854e12),
        json!(-9.3e12),
        json!(1e300),
        json!(-1e300),
        json!(u64::MAX),
        json!("1.5"),
        json!(null),
    ];
    for case in cases() {
        let records: Vec<Value> = tss
            .iter()
            .map(|t| with_extras(set(&case.base, "ts", &Some(t.clone()))))
            .collect();
        compare_all(&case, &records, &format!("{} ts-boundary", case.name));
    }
}
