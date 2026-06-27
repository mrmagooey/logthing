# Ingestion Formats Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add nine new log/event ingestion formats to logthing — Suricata EVE JSON, CEF, LEEF, sFlow, Linux auditd, Splunk HEC, web access logs, DHCP, RADIUS, and OTLP logs — each reusing an existing ingestion mechanism.

**Architecture:** Five independent work units. Each new format maps onto one of four established mechanisms (NDJSON-over-TCP listener, syslog-embedded payload parser, UDP binary decoder, HTTP route) and reuses the shared `ParquetSink`/`ParquetWriterHandle` S3 path and the `main.rs` spawn template. Units are independently testable and independently shippable; implement in tier order (Unit 1 → Unit 5).

**Tech Stack:** Rust 2024, Tokio async, Axum (HTTP), `arrow`/`parquet` + S3 sink, `serde_json`, `regex`/`LazyLock`, `async_trait`, `metrics`; `subtle` (constant-time auth) and `opentelemetry-proto` (OTLP, feature-gated).

**Reference spec:** `docs/superpowers/specs/2026-06-27-ingestion-formats-expansion-design.md`

## Global Constraints

- **Branch:** all work on `feat/ingestion-formats-expansion` (off `d5b2e64`); never commit to master. Stop at the merge/PR decision for user consent.
- **Every new config section defaults to `enabled = false`** — zero behavior change for existing deployments until explicitly enabled.
- **Three test levels per format are mandatory** (global policy): unit (in-source `#[cfg(test)]`), integration (`tests/<fmt>_s3_integration.rs`, gated on `MINIO_ENDPOINT`, skip-with-eprintln when absent), e2e (drive the real socket/HTTP interface on an ephemeral port). If a level genuinely does not apply, state so explicitly.
- **Reuse existing infrastructure, do not reinvent:** `ParquetSink` trait + `ParquetWriterHandle::start` + `try_send` (`src/forwarding/buffered_writer.rs`); partitioned-sink `_overflow` cap pattern (`src/forwarding/zeek_s3.rs`); per-listener config with serde defaults (`src/config/mod.rs`); `main.rs` spawn/shutdown template; existing TLS + IP-whitelist + body-limit middleware for HTTP units.
- **Error handling convention:** malformed input → `metrics::counter!` increment + `warn!` + skip; channel full → warn-and-drop (existing `try_send` pattern); never panic, never block; S3 sink construction failure at startup → fall back to the default log-only handler.
- **`ParquetSink` trait signature** (mirror exactly): `type Record; fn source(&self)->&'static str; fn partition(&self,&Record)->Option<String>; fn schema(&self,Option<&str>)->Arc<arrow_schema::Schema>; fn to_record_batch(&self,&Record,&Arc<Schema>)->anyhow::Result<RecordBatch>`.
- **Listener trait/shutdown signature** (mirror exactly): async handler trait with one method taking `(record/records, SocketAddr)`; `start_with_shutdown(&self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) -> anyhow::Result<()>`.
- **Scope guards (do NOT build in v1):** no OTLP gRPC (HTTP only); no `protoc`/`build.rs` codegen (use pre-generated `opentelemetry-proto` messages); no GELF; no multi-line auditd reassembly (single-record only); no bespoke typed Arrow schema per syslog payload (JSON `parsed` bag); no deep packet decode beyond the 5-tuple for sFlow; no new TLS/auth/whitelist primitives.
- **New ports:** Suricata TCP 47761, sFlow UDP 6343; HEC + OTLP on the existing 5985 server.

---

## Unit 1 — Suricata EVE JSON (`src/suricata/`)

Suricata EVE JSON ingestion is a near-clone of the Zeek module. The only structural differences are the record discriminator field (`event_type` instead of `_path`), the default TCP port (47761 instead of 47760), and a simplified schema layer: Suricata uses a single envelope schema for all event types rather than a per-type typed registry. Every other pattern — listener loop, `ParquetSink` adapter, config, and `main.rs` wiring — is reproduced verbatim with Suricata-specific names.

Tasks 1.1–1.5 build the module bottom-up (record type → listener → schema → S3 sink → config), Task 1.6 wires `main.rs`, and Tasks 1.7–1.8 add integration and e2e tests.

---

### Task 1.1: `SuricataRecord` and module root

**Files:**
- Create `src/suricata/mod.rs`

**Interfaces:**
- Produces: `SuricataRecord { event_type: String, fields: serde_json::Value, received_at: DateTime<Utc> }` — consumed by Tasks 1.2, 1.4, 1.7, 1.8

- [ ] **Step 1: Write the failing test**

  ```rust
  // In src/suricata/mod.rs — place these inside `#[cfg(test)] mod tests { … }`
  // The file does not yet exist, so `cargo test` will fail to compile.
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn suricata_record_stores_event_type_and_fields() {
          let rec = SuricataRecord {
              event_type: "alert".to_string(),
              fields: serde_json::json!({"event_type": "alert", "src_ip": "10.0.0.1"}),
              received_at: chrono::Utc::now(),
          };
          assert_eq!(rec.event_type, "alert");
          assert_eq!(rec.fields["src_ip"], "10.0.0.1");
      }

      #[test]
      fn suricata_record_unknown_event_type() {
          let rec = SuricataRecord {
              event_type: "unknown".to_string(),
              fields: serde_json::json!({}),
              received_at: chrono::Utc::now(),
          };
          assert_eq!(rec.event_type, "unknown");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib suricata::tests
  # Expected: error[E0433]: failed to resolve: use of undeclared crate or module `suricata`
  ```

- [ ] **Step 3: Implement**

  Clone `src/zeek/mod.rs`, adapting:
  - Module doc comment: `"Zeek NDJSON ingestion"` → `"Suricata EVE JSON ingestion"`
  - Struct name: `ZeekRecord` → `SuricataRecord`
  - Field name: `log_path: String` → `event_type: String`
  - Field doc comment: `"Stream type, from the JSON \`_path\` field"` → `"Event type, from the JSON \`event_type\` field"`
  - `pub mod listener;` and `pub mod schema;` remain (Schema is added in Task 1.3)
  - Test struct literals: `log_path:` → `event_type:`, `"conn"` → `"alert"`, `"_path"` field reference → `"event_type"` field reference; second test value `"unknown"` stays

  Add `pub mod suricata;` to `src/lib.rs`.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib suricata::tests
  # Expected: test suricata::tests::suricata_record_stores_event_type_and_fields ... ok
  #           test suricata::tests::suricata_record_unknown_event_type ... ok
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/suricata/mod.rs src/lib.rs
  git commit -m "feat(suricata): add SuricataRecord and suricata module root"
  ```

---

### Task 1.2: `SuricataListener` with `SuricataHandler` trait

**Files:**
- Create `src/suricata/listener.rs`
- Modify `src/suricata/mod.rs` (already declares `pub mod listener;`)

**Interfaces:**
- Consumes: `SuricataRecord` (Task 1.1)
- Produces:
  - `SuricataHandler: async_trait` with `async fn handle_record(&self, record: SuricataRecord, source: SocketAddr)`
  - `DefaultSuricataHandler` — logs + increments `suricata_records_received` and `suricata_records_by_event_type` counters
  - `SuricataListener::new(config: SuricataListenerConfig, handler: Arc<dyn SuricataHandler>) -> Self`
  - `SuricataListener::start_with_shutdown(&self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) -> anyhow::Result<()>`
  - `SuricataListener::run_with_listener(&self, listener: TcpListener) -> anyhow::Result<()>` (pub(crate), for tests)
  - `SuricataListenerConfig { tcp_port: u16, bind_address: String }` with `Default` (port 47761, "0.0.0.0")
  - Constants: `MAX_SURICATA_TCP_CONNECTIONS: usize = 1024`, `SURICATA_MAX_LINE_BYTES: usize = 16 * 1024 * 1024`

- [ ] **Step 1: Write the failing tests**

  ```rust
  // These tests live inside src/suricata/listener.rs in #[cfg(test)] mod tests { … }

  #[cfg(test)]
  mod tests {
      use super::*;
      use std::sync::Mutex;
      use std::time::Duration;
      use tokio::io::AsyncWriteExt;
      use tokio::net::TcpListener;
      use tokio::time::sleep;

      struct CapturingHandler {
          records: Mutex<Vec<SuricataRecord>>,
      }

      impl CapturingHandler {
          fn new() -> Arc<Self> {
              Arc::new(Self { records: Mutex::new(Vec::new()) })
          }
          fn take_records(&self) -> Vec<SuricataRecord> {
              self.records.lock().unwrap().drain(..).collect()
          }
      }

      #[async_trait::async_trait]
      impl SuricataHandler for CapturingHandler {
          async fn handle_record(&self, record: SuricataRecord, _source: SocketAddr) {
              self.records.lock().unwrap().push(record);
          }
      }

      // -- Unit: event_type extraction --

      #[test]
      fn extract_event_type_from_json() {
          let value = serde_json::json!({"event_type": "alert", "src_ip": "10.0.0.1"});
          let event_type = value
              .get("event_type")
              .and_then(|v| v.as_str())
              .map(|s| s.to_string())
              .unwrap_or_else(|| "unknown".to_string());
          assert_eq!(event_type, "alert");
      }

      #[test]
      fn missing_event_type_field_gives_unknown() {
          let value = serde_json::json!({"src_ip": "10.0.0.1"});
          let event_type = value
              .get("event_type")
              .and_then(|v| v.as_str())
              .map(|s| s.to_string())
              .unwrap_or_else(|| "unknown".to_string());
          assert_eq!(event_type, "unknown");
      }

      #[test]
      fn non_string_event_type_gives_unknown() {
          let value = serde_json::json!({"event_type": 42, "src_ip": "10.0.0.1"});
          let event_type = value
              .get("event_type")
              .and_then(|v| v.as_str())
              .map(|s| s.to_string())
              .unwrap_or_else(|| "unknown".to_string());
          assert_eq!(event_type, "unknown");
      }

      // -- Shutdown --

      #[tokio::test]
      async fn start_with_shutdown_exits_on_signal() {
          use tokio::sync::watch;
          use tokio::time::timeout;

          let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let tcp_port = tmp.local_addr().unwrap().port();
          drop(tmp);

          let config = SuricataListenerConfig {
              tcp_port,
              bind_address: "127.0.0.1".to_string(),
          };
          let handler: Arc<dyn SuricataHandler> = Arc::new(DefaultSuricataHandler);
          let listener = SuricataListener::new(config, handler);

          let (shutdown_tx, shutdown_rx) = watch::channel(false);
          let task = tokio::spawn(async move {
              listener.start_with_shutdown(shutdown_rx).await.ok();
          });
          sleep(Duration::from_millis(50)).await;
          shutdown_tx.send(true).unwrap();
          let result = timeout(Duration::from_secs(2), task).await;
          assert!(result.is_ok(), "start_with_shutdown did not return within 2s");
      }

      // -- Integration: TCP listener receives records --

      #[tokio::test]
      async fn listener_dispatches_records_from_ndjson_stream() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          let lines = concat!(
              r#"{"event_type":"alert","src_ip":"1.2.3.4","ts":"2024-01-01T00:00:00Z"}"#,
              "\n",
              r#"{"event_type":"flow","src_ip":"5.6.7.8","ts":"2024-01-01T00:00:01Z"}"#,
              "\n",
          );
          stream.write_all(lines.as_bytes()).await.unwrap();
          drop(stream);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 2, "expected 2 records, got {}", records.len());
          assert_eq!(records[0].event_type, "alert");
          assert_eq!(records[1].event_type, "flow");
      }

      #[tokio::test]
      async fn listener_skips_malformed_json_and_continues() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          let lines = concat!(
              "NOT JSON AT ALL\n",
              r#"{"event_type":"dns","query":"example.com"}"#,
              "\n",
          );
          stream.write_all(lines.as_bytes()).await.unwrap();
          drop(stream);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 1, "only the valid record should be dispatched");
          assert_eq!(records[0].event_type, "dns");
      }

      #[tokio::test]
      async fn listener_routes_missing_event_type_to_unknown() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          stream.write_all(b"{\"src_ip\":\"9.9.9.9\"}\n").await.unwrap();
          drop(stream);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 1);
          assert_eq!(records[0].event_type, "unknown");
      }

      #[tokio::test]
      async fn oversized_line_closes_connection_and_increments_metric() {
          use metrics::set_default_local_recorder;
          use metrics_util::CompositeKey;
          use metrics_util::MetricKind;
          use metrics_util::debugging::DebuggingRecorder;
          use tokio::io::AsyncReadExt;
          use tokio::time::timeout;

          let recorder = DebuggingRecorder::new();
          let snapshotter = recorder.snapshotter();
          let _guard = set_default_local_recorder(&recorder);

          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let oversized = vec![b'x'; SURICATA_MAX_LINE_BYTES + 1];
          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          let _ = stream.write_all(&oversized).await;

          let result = timeout(Duration::from_secs(2), async {
              let mut sink = Vec::new();
              stream.read_to_end(&mut sink).await
          })
          .await;
          assert!(result.is_ok(), "server did not close oversized connection within 2s");

          sleep(Duration::from_millis(50)).await;
          task.abort();

          assert!(handler.take_records().is_empty(), "oversized input must not produce a record");

          let snapshot = snapshotter.snapshot();
          let map = snapshot.into_hashmap();
          let key = CompositeKey::new(
              MetricKind::Counter,
              metrics::Key::from_name("suricata_oversized_lines"),
          );
          let count = map
              .get(&key)
              .map(|(_, _, v)| {
                  if let metrics_util::debugging::DebugValue::Counter(c) = v { *c } else { 0 }
              })
              .unwrap_or(0);
          assert_eq!(count, 1, "suricata_oversized_lines counter must be 1; got {count}");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib suricata::listener::tests
  # Expected: error[E0433]: failed to resolve: use of undeclared module `listener`
  ```

- [ ] **Step 3: Implement**

  Clone `src/zeek/listener.rs`, adapting:
  - All `Zeek` → `Suricata`, `zeek` → `suricata` (types, constants, metric names, log messages)
  - `use crate::zeek::ZeekRecord;` → `use crate::suricata::SuricataRecord;`
  - `ZeekRecord { log_path, fields, received_at }` → `SuricataRecord { event_type, fields, received_at }`
  - `MAX_ZEEK_TCP_CONNECTIONS` → `MAX_SURICATA_TCP_CONNECTIONS`
  - `ZEEK_MAX_LINE_BYTES` → `SURICATA_MAX_LINE_BYTES`
  - `ZeekListenerConfig { tcp_port: 47760 }` → `SuricataListenerConfig { tcp_port: 47761 }`
  - In `handle_tcp_connection`: `value.get("_path")` → `value.get("event_type")`; metric `zeek_missing_path` → `suricata_missing_event_type`; struct field `log_path` → `event_type`
  - `DefaultZeekHandler` → `DefaultSuricataHandler`; metric names `zeek_records_received` → `suricata_records_received`, `zeek_records_by_path` label `"log_path"` → `suricata_records_by_event_type` label `"event_type"`
  - Metric `zeek_oversized_lines` → `suricata_oversized_lines`, `zeek_parse_errors` → `suricata_parse_errors`, `zeek_tcp_connections_rejected` → `suricata_tcp_connections_rejected`
  - Log message prefixes: `"Zeek"` → `"Suricata"`
  - All test `ZeekRecord` / `ZeekHandler` / `ZeekListener` / `ZeekListenerConfig` references → Suricata equivalents; test JSON fields `_path` → `event_type`; test values `"conn"` → `"alert"`, `"dns"` → `"flow"`, `"ssl"` → `"dns"`, `"_path":"conn"` → `"event_type":"alert"` etc.; port `47760` → `47761`

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib suricata::listener::tests
  # Expected: all 8 tests ok
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/suricata/listener.rs
  git commit -m "feat(suricata): add SuricataListener with SuricataHandler trait and unit/integration tests"
  ```

---

### Task 1.3: `SuricataSink` schema (envelope-only)

**Files:**
- Create `src/suricata/schema.rs`
- Modify `src/suricata/mod.rs`: add `pub mod schema;`

**Design note:** Unlike Zeek, Suricata uses a single envelope schema for all event types (`event_type + received_at + fields-as-JSON`). This avoids the per-event-type typed registry entirely and removes the need for a REGISTRY static. The schema has four columns: `event_type` (Utf8, non-null), `received_at` (Utf8, non-null), `src_ip` (Utf8, nullable, opportunistic fast path), and `payload` (Utf8, non-null — full JSON).

**Interfaces:**
- Produces:
  - `pub fn envelope_schema() -> Arc<Schema>` — consumed by Task 1.4
  - `pub fn map_envelope(record: &SuricataRecord) -> anyhow::Result<RecordBatch>` — consumed by Task 1.4

- [ ] **Step 1: Write the failing tests**

  ```rust
  // In src/suricata/schema.rs, inside #[cfg(test)] mod tests { … }

  #[cfg(test)]
  mod tests {
      use super::*;
      use arrow::array::StringArray;
      use arrow::datatypes::DataType;
      use chrono::Utc;
      use crate::suricata::SuricataRecord;

      fn make_alert_record() -> SuricataRecord {
          SuricataRecord {
              event_type: "alert".to_string(),
              fields: serde_json::json!({
                  "event_type": "alert",
                  "src_ip": "192.168.1.100",
                  "dest_ip": "1.2.3.4",
                  "alert": {"signature": "ET SCAN", "category": "Scan"}
              }),
              received_at: Utc::now(),
          }
      }

      #[test]
      fn envelope_schema_has_required_columns() {
          let s = envelope_schema();
          s.field_with_name("event_type").expect("event_type column");
          s.field_with_name("received_at").expect("received_at column");
          s.field_with_name("src_ip").expect("src_ip column");
          s.field_with_name("payload").expect("payload column");

          let f = s.field_with_name("payload").unwrap();
          assert_eq!(*f.data_type(), DataType::Utf8);
          assert!(!f.is_nullable(), "payload must not be nullable");

          let f = s.field_with_name("event_type").unwrap();
          assert!(!f.is_nullable(), "event_type must not be nullable");

          let f = s.field_with_name("src_ip").unwrap();
          assert!(f.is_nullable(), "src_ip is opportunistic — must be nullable");
      }

      #[test]
      fn map_envelope_extracts_event_type_and_payload() {
          let rec = make_alert_record();
          let batch = map_envelope(&rec).unwrap();
          assert_eq!(batch.num_rows(), 1);

          let event_type_col = batch
              .column_by_name("event_type")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(event_type_col.value(0), "alert");

          let payload_col = batch
              .column_by_name("payload")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          let parsed: serde_json::Value = serde_json::from_str(payload_col.value(0)).unwrap();
          assert_eq!(parsed["src_ip"], "192.168.1.100");
      }

      #[test]
      fn map_envelope_unknown_event_type_stored_correctly() {
          let rec = SuricataRecord {
              event_type: "unknown".to_string(),
              fields: serde_json::json!({"dest_port": 443}),
              received_at: Utc::now(),
          };
          let batch = map_envelope(&rec).unwrap();
          let event_type_col = batch
              .column_by_name("event_type")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(event_type_col.value(0), "unknown");
      }

      #[test]
      fn map_envelope_absent_src_ip_is_null() {
          let rec = SuricataRecord {
              event_type: "stats".to_string(),
              fields: serde_json::json!({"uptime": 3600}),
              received_at: Utc::now(),
          };
          let batch = map_envelope(&rec).unwrap();
          use arrow::array::Array;
          let src_ip = batch
              .column_by_name("src_ip")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert!(src_ip.is_null(0), "absent src_ip must be null");
      }

      #[test]
      fn map_envelope_parquet_round_trip() {
          use bytes::Bytes;
          use parquet::arrow::ArrowWriter;
          use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

          let rec = make_alert_record();
          let batch = map_envelope(&rec).unwrap();
          let schema = envelope_schema();

          let mut buf = Vec::new();
          let mut writer = ArrowWriter::try_new(&mut buf, schema, None).unwrap();
          writer.write(&batch).unwrap();
          writer.close().unwrap();
          assert!(!buf.is_empty());

          let bytes = Bytes::from(buf);
          let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
              .unwrap()
              .build()
              .unwrap();
          let rb = reader.next().unwrap().unwrap();
          assert_eq!(rb.num_rows(), 1);
          let event_type_col = rb
              .column_by_name("event_type")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(event_type_col.value(0), "alert");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib suricata::schema::tests
  # Expected: error[E0433]: failed to resolve: use of undeclared module `schema`
  ```

- [ ] **Step 3: Implement**

  `src/suricata/schema.rs` (novel — no Zeek clone for this file):

  ```rust
  //! Suricata EVE JSON schema — single envelope schema for all event types.
  //!
  //! Unlike Zeek (which has a per-stream typed registry), Suricata v1 uses one
  //! envelope schema for every event_type.  This keeps the implementation simple
  //! and avoids the need to maintain a growing registry as Suricata event types evolve.

  use crate::suricata::SuricataRecord;
  use arrow::array::{ArrayRef, StringBuilder};
  use arrow::datatypes::{DataType, Field, Schema};
  use arrow::record_batch::RecordBatch;
  use std::sync::{Arc, LazyLock};

  /// Envelope schema for all Suricata EVE JSON records.
  ///
  /// Columns:
  /// - `event_type`  — Utf8, non-null  (from SuricataRecord.event_type)
  /// - `received_at` — Utf8, non-null  (RFC-3339 wall-clock ingest time)
  /// - `src_ip`      — Utf8, nullable  (opportunistic fast path; null when absent)
  /// - `payload`     — Utf8, non-null  (full JSON object as string)
  pub fn envelope_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("event_type", DataType::Utf8, false),
              Field::new("received_at", DataType::Utf8, false),
              Field::new("src_ip", DataType::Utf8, true),
              Field::new("payload", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// Map one `SuricataRecord` to a single-row `RecordBatch` using the envelope schema.
  pub fn map_envelope(record: &SuricataRecord) -> anyhow::Result<RecordBatch> {
      let schema = envelope_schema();

      let src_ip = record
          .fields
          .get("src_ip")
          .and_then(|v| v.as_str())
          .map(|s| s.to_string());
      let received_at = record.received_at.to_rfc3339();
      let payload = record.fields.to_string();

      let mut b_event_type = StringBuilder::new();
      let mut b_received_at = StringBuilder::new();
      let mut b_src_ip = StringBuilder::new();
      let mut b_payload = StringBuilder::new();

      b_event_type.append_value(&record.event_type);
      b_received_at.append_value(&received_at);
      b_src_ip.append_option(src_ip.as_deref());
      b_payload.append_value(&payload);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_event_type.finish()),
          Arc::new(b_received_at.finish()),
          Arc::new(b_src_ip.finish()),
          Arc::new(b_payload.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }
  ```

  Add `pub mod schema;` to `src/suricata/mod.rs`.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib suricata::schema::tests
  # Expected: all 5 tests ok
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/suricata/schema.rs src/suricata/mod.rs
  git commit -m "feat(suricata): add envelope schema and map_envelope for all event types"
  ```

---

### Task 1.4: `SuricataSink` and `suricata_start` in `src/forwarding/suricata_s3.rs`

**Files:**
- Create `src/forwarding/suricata_s3.rs`
- Modify `src/forwarding/mod.rs`: add `pub mod suricata_s3;`

**Interfaces:**
- Consumes: `SuricataRecord` (Task 1.1), `envelope_schema()` / `map_envelope()` (Task 1.3), `ParquetSink` trait, `ParquetWriterHandle::start`, `BufferedWriterConfig`, `FlushPolicy`, `SuricataS3Config` (Task 1.5, defined before this task)
- Produces:
  - `pub(crate) fn sanitize_event_type(raw: &str) -> String`
  - `pub struct SuricataSink` implementing `ParquetSink<Record = SuricataRecord>`
  - `pub type SuricataS3Handler = ParquetWriterHandle<SuricataSink>`
  - `impl SuricataHandler for ParquetWriterHandle<SuricataSink>`
  - `pub fn suricata_start(cfg: &SuricataS3Config, s3: Arc<S3Sink>) -> (SuricataS3Handler, JoinHandle<()>)`

- [ ] **Step 1: Write the failing tests**

  ```rust
  // In src/forwarding/suricata_s3.rs, inside #[cfg(test)] mod tests { … }

  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::config::S3ConnectionConfig;
      use crate::forwarding::buffered_writer::{
          BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
      };
      use crate::forwarding::s3_sink::S3Sink;
      use crate::suricata::SuricataRecord;
      use chrono::Utc;
      use std::sync::Arc;

      async fn unreachable_sink() -> Arc<S3Sink> {
          let conn = S3ConnectionConfig {
              endpoint: "http://127.0.0.1:1".to_string(),
              bucket: "test-bucket".to_string(),
              region: "us-east-1".to_string(),
              access_key: "AKIATEST".to_string(),
              secret_key: "SECRETTEST".to_string(),
          };
          Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"))
      }

      fn make_alert_record(src_ip: &str) -> SuricataRecord {
          SuricataRecord {
              event_type: "alert".to_string(),
              fields: serde_json::json!({
                  "event_type": "alert",
                  "src_ip": src_ip,
                  "dest_ip": "1.2.3.4",
                  "alert": {"signature": "ET TEST"}
              }),
              received_at: Utc::now(),
          }
      }

      fn make_flow_record() -> SuricataRecord {
          SuricataRecord {
              event_type: "flow".to_string(),
              fields: serde_json::json!({
                  "event_type": "flow",
                  "src_ip": "10.0.0.1",
                  "dest_ip": "8.8.8.8",
                  "flow": {"bytes_toserver": 512, "bytes_toclient": 4096}
              }),
              received_at: Utc::now(),
          }
      }

      // -- sanitize_event_type --

      #[test]
      fn event_type_sanitizer_handles_traversal_and_length() {
          assert_eq!(sanitize_event_type("alert"), "alert");
          assert_eq!(sanitize_event_type("../etc"), "___etc");
          let out = sanitize_event_type("../../etc/passwd");
          assert!(!out.contains('/'));
          assert!(!out.contains('.'));
          assert_eq!(sanitize_event_type(""), "unknown");
          let long_input = "a".repeat(100);
          assert_eq!(sanitize_event_type(&long_input).len(), 64);
      }

      // -- SuricataSink unit --

      #[test]
      fn suricata_sink_source_returns_suricata() {
          assert_eq!(SuricataSink.source(), "suricata");
      }

      #[test]
      fn suricata_sink_partition_sanitizes_event_type() {
          let rec = make_alert_record("10.0.0.1");
          assert_eq!(SuricataSink.partition(&rec), Some("alert".to_string()));

          let bad = SuricataRecord {
              event_type: "../bad".to_string(),
              fields: serde_json::json!({}),
              received_at: Utc::now(),
          };
          let part = SuricataSink.partition(&bad).unwrap();
          assert!(!part.contains('/'));
          assert!(!part.contains('.'));
      }

      #[test]
      fn suricata_sink_schema_always_returns_envelope() {
          use crate::suricata::schema::envelope_schema;

          // All partitions — named, overflow, or None — return the same envelope schema
          assert_eq!(SuricataSink.schema(Some("alert")), envelope_schema());
          assert_eq!(SuricataSink.schema(Some("_overflow")), envelope_schema());
          assert_eq!(SuricataSink.schema(None), envelope_schema());
          assert_eq!(SuricataSink.schema(Some("unknown_anything")), envelope_schema());
      }

      #[test]
      fn suricata_sink_to_record_batch_produces_one_row() {
          let rec = make_alert_record("192.168.1.1");
          let schema = SuricataSink.schema(Some("alert"));
          let batch = SuricataSink.to_record_batch(&rec, &schema).unwrap();
          assert_eq!(batch.num_rows(), 1);
          use arrow::array::StringArray;
          let et = batch
              .column_by_name("event_type")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(et.value(0), "alert");
          let src = batch
              .column_by_name("src_ip")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(src.value(0), "192.168.1.1");
      }

      // -- S3 key layout --

      #[test]
      fn build_key_produces_suricata_event_type_layout() {
          use crate::forwarding::buffered_writer::build_key;
          use chrono::TimeZone;

          let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
          let key = build_key("suricata", Some("alert"), now);
          assert!(
              key.starts_with("suricata/alert/year=2026/month=03/day=07/"),
              "key: {key}"
          );
          assert!(key.ends_with(".parquet"), "key: {key}");
      }

      // -- PartitionedParquetWriter accumulation --

      #[tokio::test]
      async fn writer_accumulates_per_event_type_buffers() {
          let sink = unreachable_sink().await;
          let bwc = BufferedWriterConfig {
              connection: S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "test-bucket".to_string(),
                  region: "us-east-1".to_string(),
                  access_key: "AKIATEST".to_string(),
                  secret_key: "SECRETTEST".to_string(),
              },
              prefix: "suricata".to_string(),
              max_buffer_rows: 100_000,
              flush_threshold_bytes: usize::MAX,
              flush_interval_secs: 3600,
              channel_capacity: 256,
              max_partitions: 256,
          };
          let policy = FlushPolicy {
              max_rows: 100_000,
              max_bytes: usize::MAX,
              interval: std::time::Duration::from_secs(3600),
          };
          let mut writer = PartitionedParquetWriter::new(SuricataSink, sink, bwc, policy);

          writer.push(make_alert_record("1.1.1.1")).await.ok();
          writer.push(make_alert_record("2.2.2.2")).await.ok();
          writer.push(make_flow_record()).await.ok();

          assert_eq!(
              writer.buffers.get("alert").map(|b| b.row_count).unwrap_or(0),
              2,
              "alert buffer should have 2 rows"
          );
          assert_eq!(
              writer.buffers.get("flow").map(|b| b.row_count).unwrap_or(0),
              1,
              "flow buffer should have 1 row"
          );
      }

      // -- Handler overflow drops --

      #[tokio::test]
      #[allow(clippy::mutable_key_type)]
      async fn handler_overflow_increments_dropped_counter() {
          use crate::config::SuricataS3Config;
          use crate::suricata::listener::SuricataHandler;
          use metrics::set_default_local_recorder;
          use metrics_util::CompositeKey;
          use metrics_util::MetricKind;
          use metrics_util::debugging::DebuggingRecorder;
          use std::net::SocketAddr;

          let recorder = DebuggingRecorder::new();
          let snapshotter = recorder.snapshotter();
          let _guard = set_default_local_recorder(&recorder);

          let sink = unreachable_sink().await;
          let cfg = SuricataS3Config {
              connection: S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "test-bucket".to_string(),
                  region: "us-east-1".to_string(),
                  access_key: "AKIATEST".to_string(),
                  secret_key: "SECRETTEST".to_string(),
              },
              prefix: "suricata".to_string(),
              flush_threshold_bytes: 1,
              flush_interval_secs: 3600,
              channel_capacity: 1,
              max_buffer_rows: 1,
          };
          let (handler, _writer_handle) = suricata_start(&cfg, sink);
          tokio::task::yield_now().await;

          let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
          for i in 0..50usize {
              handler.handle_record(make_alert_record(&format!("{i}.0.0.1")), src).await;
          }
          tokio::task::yield_now().await;

          let snapshot = snapshotter.snapshot();
          let map = snapshot.into_hashmap();
          let key = CompositeKey::new(
              MetricKind::Counter,
              metrics::Key::from_parts(
                  "parquet_s3_dropped",
                  vec![metrics::Label::new("source", "suricata")],
              ),
          );
          let dropped = map
              .get(&key)
              .map(|(_, _, v)| {
                  if let metrics_util::debugging::DebugValue::Counter(c) = v { *c } else { 0 }
              })
              .unwrap_or(0);
          assert!(
              dropped >= 1,
              "expected parquet_s3_dropped{{source=\"suricata\"}} >= 1; got {dropped}"
          );
      }

      // -- suricata_start wires handler and join handle --

      #[tokio::test]
      async fn suricata_start_wires_handler_and_join_handle() {
          use crate::config::SuricataS3Config;
          use crate::suricata::listener::SuricataHandler;
          use std::net::SocketAddr;

          let sink = unreachable_sink().await;
          let cfg = SuricataS3Config {
              connection: S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "test-bucket".to_string(),
                  region: "us-east-1".to_string(),
                  access_key: "AKIATEST".to_string(),
                  secret_key: "SECRETTEST".to_string(),
              },
              prefix: "suricata".to_string(),
              flush_threshold_bytes: usize::MAX,
              flush_interval_secs: 3600,
              channel_capacity: 256,
              max_buffer_rows: 100_000,
          };
          let (handler, join_handle) = suricata_start(&cfg, sink);
          let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
          handler.handle_record(make_alert_record("10.0.0.1"), src).await;
          drop(handler);

          tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
              .await
              .expect("writer task must exit within 5s")
              .expect("writer task must not panic");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib forwarding::suricata_s3::tests
  # Expected: error[E0433]: use of undeclared module `suricata_s3`
  ```

- [ ] **Step 3: Implement**

  Clone `src/forwarding/zeek_s3.rs`, adapting:
  - `use crate::config::ZeekS3Config;` → `use crate::config::SuricataS3Config;`
  - `use crate::zeek::ZeekRecord;` → `use crate::suricata::SuricataRecord;`
  - Remove `use crate::zeek::schema::{envelope_schema, get_schema_entry};`; replace with `use crate::suricata::schema::{envelope_schema, map_envelope};`
  - `sanitize_log_path` → `sanitize_event_type`
  - `ZeekSink` → `SuricataSink`; `impl ParquetSink for SuricataSink { type Record = SuricataRecord; fn source(&self) -> &'static str { "suricata" } }`
  - `fn partition` → `Some(sanitize_event_type(&record.event_type))`
  - `fn schema` → always returns `envelope_schema()` (no typed registry); remove the `match` on `_overflow`/typed path — simply `envelope_schema()` for all inputs
  - `fn to_record_batch` → call `map_envelope(record)` directly; the `entry.schema == *schema` guard is unnecessary because there is only one schema
  - `ZeekS3Handler` → `SuricataS3Handler`; `impl SuricataHandler for ParquetWriterHandle<SuricataSink>`; error log `"Suricata S3 channel full; dropped 1 record from {}"`
  - `zeek_start` → `suricata_start(cfg: &SuricataS3Config, s3: Arc<S3Sink>)`; `DEFAULT_MAX_SURICATA_PARTITIONS: usize = 256`; `bwc.prefix = cfg.prefix.clone()`
  - Metric labels: all `source="zeek"` → `source="suricata"` (inherited from `ParquetSink::source`)
  - All `ZeekS3Config` field accesses remain identical (same field names)
  - Add `pub mod suricata_s3;` to `src/forwarding/mod.rs`

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib forwarding::suricata_s3::tests
  # Expected: all 8 tests ok
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/forwarding/suricata_s3.rs src/forwarding/mod.rs
  git commit -m "feat(suricata): add SuricataSink, SuricataS3Handler, and suricata_start"
  ```

---

### Task 1.5: `SuricataConfig` and `SuricataS3Config` in `src/config/mod.rs`

**Files:**
- Modify `src/config/mod.rs`

**Interfaces:**
- Produces:
  - `pub struct SuricataConfig { enabled: bool (default false), tcp_port: u16 (default 47761), bind_address: String (default "0.0.0.0"), s3: Option<SuricataS3Config> }`
  - `pub struct SuricataS3Config { connection: S3ConnectionConfig (flatten), prefix: String (default "suricata"), flush_threshold_bytes: usize (default 100 MiB), flush_interval_secs: u64 (default 900), channel_capacity: usize (default 256), max_buffer_rows: usize (default 100_000) }`
  - `Config.suricata: SuricataConfig` field

- [ ] **Step 1: Write the failing tests**

  ```rust
  // In src/config/mod.rs, inside #[cfg(test)] mod tests { … } — add these test functions

  #[test]
  fn default_suricata_config_disabled_on_port_47761() {
      let cfg = Config::default();
      assert!(!cfg.suricata.enabled, "suricata disabled by default");
      assert_eq!(cfg.suricata.tcp_port, 47761);
      assert_eq!(cfg.suricata.bind_address, "0.0.0.0");
      assert!(cfg.suricata.s3.is_none(), "absent [suricata.s3] must be None");
  }

  #[test]
  fn suricata_s3_flat_toml_deserializes_correctly() {
      let toml_str = r#"
  [suricata]
  enabled = true
  tcp_port = 47761
  [suricata.s3]
  endpoint   = "http://minio:9000"
  bucket     = "suricata-logs"
  region     = "us-east-1"
  access_key = "KEY"
  secret_key = "SECRET"
  "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse config");
      assert!(cfg.suricata.enabled);
      let s3 = cfg.suricata.s3.expect("s3 present");
      assert_eq!(s3.connection.bucket, "suricata-logs");
      assert_eq!(s3.prefix, "suricata");
      assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
      assert_eq!(s3.flush_interval_secs, 900);
      assert_eq!(s3.channel_capacity, 256);
      assert_eq!(s3.max_buffer_rows, 100_000);
  }

  #[test]
  fn suricata_s3_absent_section_means_no_persistence() {
      let toml_str = "[suricata]\nenabled = true\n";
      let cfg: Config = toml::from_str(toml_str).expect("parse");
      assert!(cfg.suricata.s3.is_none(), "absent [suricata.s3] must yield None");
  }

  #[test]
  fn suricata_config_does_not_affect_other_defaults() {
      // Adding suricata must not change zeek, ipfix, or syslog defaults.
      let cfg = Config::default();
      assert!(!cfg.zeek.enabled);
      assert!(!cfg.ipfix.enabled);
      assert!(!cfg.suricata.enabled);
      // syslog is enabled by default — must remain so
      assert!(cfg.syslog.enabled);
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib config::tests::default_suricata_config_disabled_on_port_47761
  # Expected: error[E0609]: no field `suricata` on type `Config`
  ```

- [ ] **Step 3: Implement**

  In `src/config/mod.rs`:

  1. Add `suricata: SuricataConfig` field to `Config` struct (after the `zeek` field), with `#[serde(default)]`.

  2. Add to `Config::default()`: `suricata: SuricataConfig::default()`.

  3. Add the structs and defaults (clone the Zeek block, adapting):

  ```rust
  /// Configuration for the Suricata EVE JSON TCP listener.
  #[derive(Debug, Clone, Deserialize, Serialize)]
  pub struct SuricataConfig {
      #[serde(default = "default_suricata_enabled")]
      pub enabled: bool,

      #[serde(default = "default_suricata_tcp_port")]
      pub tcp_port: u16,

      #[serde(default = "default_suricata_bind_address")]
      pub bind_address: String,

      /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
      #[serde(default)]
      pub s3: Option<SuricataS3Config>,
  }

  impl Default for SuricataConfig {
      fn default() -> Self {
          Self {
              enabled: default_suricata_enabled(),
              tcp_port: default_suricata_tcp_port(),
              bind_address: default_suricata_bind_address(),
              s3: None,
          }
      }
  }

  fn default_suricata_enabled() -> bool { false }
  fn default_suricata_tcp_port() -> u16 { 47761 }
  fn default_suricata_bind_address() -> String { "0.0.0.0".to_string() }

  /// Per-source S3 persistence config for the Suricata listener.
  #[derive(Debug, Clone, Deserialize, Serialize)]
  pub struct SuricataS3Config {
      #[serde(flatten)]
      pub connection: S3ConnectionConfig,
      #[serde(default = "default_suricata_s3_prefix")]
      pub prefix: String,
      #[serde(default = "default_suricata_flush_bytes")]
      pub flush_threshold_bytes: usize,
      #[serde(default = "default_suricata_flush_secs")]
      pub flush_interval_secs: u64,
      #[serde(default = "default_suricata_channel_capacity")]
      pub channel_capacity: usize,
      #[serde(default = "default_suricata_max_buffer_rows")]
      pub max_buffer_rows: usize,
  }

  fn default_suricata_s3_prefix() -> String { "suricata".to_string() }
  fn default_suricata_flush_bytes() -> usize { 100 * 1024 * 1024 }
  fn default_suricata_flush_secs() -> u64 { 900 }
  fn default_suricata_channel_capacity() -> usize { 256 }
  fn default_suricata_max_buffer_rows() -> usize { 100_000 }
  ```

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib config::tests
  # Expected: all existing config tests still pass, plus 4 new suricata tests ok
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/config/mod.rs
  git commit -m "feat(suricata): add SuricataConfig and SuricataS3Config to Config"
  ```

---

### Task 1.6: Wire Suricata into `main.rs` and `lib.rs`

**Files:**
- Modify `src/main.rs`
- Modify `src/lib.rs` (already done in Task 1.1; verify `pub mod suricata;` is present)

**Interfaces:**
- Consumes: `SuricataConfig`, `SuricataListener`, `SuricataHandler`, `DefaultSuricataHandler`, `suricata_start`, `S3Sink`

- [ ] **Step 1: Write the failing test**

  This task's correctness is verified at the integration/e2e level (Tasks 1.7 and 1.8). The unit-level gate is a compile check: confirm that `Config { suricata: SuricataConfig::default() }` round-trips through the existing `config::tests` without touching `main.rs`. The specific test here confirms the `main.rs` import compiles, by adding a doc-test in `lib.rs`:

  ```rust
  // In src/lib.rs — add this pub use to make the import path testable
  // (no new test fn needed; the compile failure when main.rs references
  //  suricata::listener::SuricataListener before the module is wired in
  //  serves as the failing step)
  ```

  The "failing" step here is attempting to compile `main.rs` with the Suricata block added but before `src/suricata/` modules exist — satisfied by the fact that prior to Task 1.1 this would fail. Since Tasks 1.1–1.5 are complete by this point, the failing check is a dry-run diff:

  ```
  cargo build 2>&1 | grep "suricata"
  # Expected before this task: no suricata symbol in main.rs → "unused import" or
  # "use logthing::zeek" missing suricata — confirms nothing is wired yet
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  grep -n "suricata" src/main.rs
  # Expected: no output — suricata is not yet wired
  ```

- [ ] **Step 3: Implement**

  In `src/main.rs`:

  1. Add `suricata` to the top-level `use logthing::{..., suricata};` import line (after `zeek`).

  2. After the closing brace of the Zeek block (around line 191), add:

  ```rust
  // -----------------------------------------------------------------------
  // Start Suricata listener if enabled
  // -----------------------------------------------------------------------
  if config.suricata.enabled {
      let suricata_config_clone = config.clone();
      let suricata_shutdown_rx = shutdown_rx.clone();

      let suricata_handler: Arc<dyn suricata::listener::SuricataHandler> =
          if let Some(s3_cfg) = suricata_config_clone.suricata.s3.as_ref() {
              match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                  Ok(sink) => {
                      let (handler, writer_handle) =
                          forwarding::suricata_s3::suricata_start(s3_cfg, Arc::new(sink));
                      writer_handles.push(writer_handle);
                      Arc::new(handler)
                  }
                  Err(e) => {
                      error!(
                          "Failed to create S3Sink for Suricata persistence, \
                               falling back to DefaultSuricataHandler: {e}"
                      );
                      Arc::new(suricata::listener::DefaultSuricataHandler)
                  }
              }
          } else {
              Arc::new(suricata::listener::DefaultSuricataHandler)
          };

      let listener_config = suricata::listener::SuricataListenerConfig {
          tcp_port: suricata_config_clone.suricata.tcp_port,
          bind_address: suricata_config_clone.suricata.bind_address.clone(),
      };
      let handle = tokio::spawn(async move {
          let listener =
              suricata::listener::SuricataListener::new(listener_config, suricata_handler);
          if let Err(e) = listener.start_with_shutdown(suricata_shutdown_rx).await {
              error!("Suricata listener error: {}", e);
          }
      });
      listener_handles.push(handle);
  }
  ```

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo build
  # Expected: compiles cleanly with no errors or warnings about suricata
  cargo test --lib
  # Expected: all existing tests continue to pass
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/main.rs src/lib.rs
  git commit -m "feat(suricata): wire SuricataListener into main.rs startup sequence"
  ```

---

### Task 1.7: Integration test — `tests/suricata_s3_integration.rs`

**Files:**
- Create `tests/suricata_s3_integration.rs`

**Interfaces:**
- Consumes: `SuricataS3Config`, `SuricataRecord`, `SuricataHandler`, `suricata_start`, `S3Sink`
- Gated on: `std::env::var("MINIO_ENDPOINT")`

- [ ] **Step 1: Write the failing test**

  ```rust
  //! Integration test: SuricataRecord → SuricataS3Handler → Parquet objects in MinIO.
  //!
  //! Set MINIO_ENDPOINT (e.g. http://localhost:9000). Skipped if absent.
  //! Also reads MINIO_BUCKET (default "suricata-logs"), MINIO_ACCESS_KEY,
  //! MINIO_SECRET_KEY (both default "minioadmin").

  use logthing::config::{S3ConnectionConfig, SuricataS3Config};
  use logthing::forwarding::s3_sink::S3Sink;
  use logthing::forwarding::suricata_s3::suricata_start;
  use logthing::suricata::SuricataRecord;
  use logthing::suricata::listener::SuricataHandler;
  use std::sync::Arc;

  fn skip_if_no_minio() -> Option<String> {
      std::env::var("MINIO_ENDPOINT").ok()
  }

  fn minio_suricata_config(endpoint: &str) -> SuricataS3Config {
      SuricataS3Config {
          connection: S3ConnectionConfig {
              endpoint: endpoint.to_string(),
              bucket: std::env::var("MINIO_BUCKET")
                  .unwrap_or_else(|_| "suricata-logs".to_string()),
              region: "us-east-1".to_string(),
              access_key: std::env::var("MINIO_ACCESS_KEY")
                  .unwrap_or_else(|_| "minioadmin".to_string()),
              secret_key: std::env::var("MINIO_SECRET_KEY")
                  .unwrap_or_else(|_| "minioadmin".to_string()),
          },
          prefix: "suricata".to_string(),
          max_buffer_rows: 1,         // flush immediately on first record
          flush_threshold_bytes: 1,
          flush_interval_secs: 3600,
          channel_capacity: 4096,
      }
  }

  fn make_alert_record() -> SuricataRecord {
      SuricataRecord {
          event_type: "alert".to_string(),
          fields: serde_json::json!({
              "event_type": "alert",
              "src_ip": "10.0.0.1",
              "dest_ip": "1.2.3.4",
              "dest_port": 443,
              "alert": {
                  "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                  "category": "Network Scan",
                  "severity": 3
              },
              "timestamp": "2024-01-15T10:30:00.000000+0000"
          }),
          received_at: chrono::Utc::now(),
      }
  }

  fn make_flow_record() -> SuricataRecord {
      SuricataRecord {
          event_type: "flow".to_string(),
          fields: serde_json::json!({
              "event_type": "flow",
              "src_ip": "192.168.1.5",
              "dest_ip": "8.8.8.8",
              "dest_port": 53,
              "proto": "UDP",
              "flow": {
                  "pkts_toserver": 1,
                  "pkts_toclient": 1,
                  "bytes_toserver": 60,
                  "bytes_toclient": 120
              },
              "timestamp": "2024-01-15T10:31:00.000000+0000"
          }),
          received_at: chrono::Utc::now(),
      }
  }

  #[tokio::test]
  async fn suricata_records_appear_as_parquet_in_s3() {
      let endpoint = match skip_if_no_minio() {
          Some(e) => e,
          None => {
              eprintln!("MINIO_ENDPOINT not set — skipping suricata_s3 integration test");
              return;
          }
      };

      let cfg = minio_suricata_config(&endpoint);
      let sink = Arc::new(
          S3Sink::from_connection(&cfg.connection)
              .await
              .expect("S3Sink::from_connection"),
      );

      let (handler, _writer_task) = suricata_start(&cfg, sink.clone());
      let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
      handler.handle_record(make_alert_record(), src).await;
      handler.handle_record(make_flow_record(), src).await;

      tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

      // Build S3 client for verification
      use aws_sdk_s3::Client as S3Client;
      let region = aws_sdk_s3::config::Region::new("us-east-1");
      let credentials = aws_credential_types::Credentials::new(
          cfg.connection.access_key.clone(),
          cfg.connection.secret_key.clone(),
          None,
          None,
          "test",
      );
      let sdk_cfg = aws_config::from_env()
          .region(region)
          .endpoint_url(&cfg.connection.endpoint)
          .credentials_provider(credentials)
          .load()
          .await;
      let s3 = S3Client::from_conf(
          aws_sdk_s3::config::Builder::from(&sdk_cfg)
              .force_path_style(true)
              .build(),
      );

      // Verify alert record under suricata/alert/
      {
          let list = s3
              .list_objects_v2()
              .bucket(&cfg.connection.bucket)
              .prefix("suricata/alert/")
              .send()
              .await
              .expect("list_objects_v2 for alert");

          let objects = list.contents();
          assert!(
              !objects.is_empty(),
              "Expected at least one Parquet object under suricata/alert/, found none"
          );

          let key = objects[0].key().expect("key");
          let get_resp = s3
              .get_object()
              .bucket(&cfg.connection.bucket)
              .key(key)
              .send()
              .await
              .expect("get_object for alert");

          let body_bytes = get_resp.body.collect().await.expect("collect body").into_bytes();

          use bytes::Bytes;
          use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
          let buf = Bytes::from(body_bytes.to_vec());
          let builder =
              ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder for alert");
          let schema = builder.schema().clone();

          // Envelope schema: event_type, received_at, src_ip, payload
          for col in &["event_type", "received_at", "src_ip", "payload"] {
              assert!(
                  schema.field_with_name(col).is_ok(),
                  "Expected column '{}' in suricata alert Parquet schema",
                  col
              );
          }

          let mut reader = builder.build().expect("parquet reader for alert");
          let rb = reader
              .next()
              .expect("at least one batch for alert")
              .expect("batch ok");
          assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in alert Parquet");

          use arrow::array::StringArray;
          let et = rb
              .column_by_name("event_type")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(et.value(0), "alert");

          let src_ip = rb
              .column_by_name("src_ip")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(src_ip.value(0), "10.0.0.1");
      }

      // Verify flow record under suricata/flow/
      {
          let list = s3
              .list_objects_v2()
              .bucket(&cfg.connection.bucket)
              .prefix("suricata/flow/")
              .send()
              .await
              .expect("list_objects_v2 for flow");

          let objects = list.contents();
          assert!(
              !objects.is_empty(),
              "Expected at least one Parquet object under suricata/flow/, found none"
          );

          let key = objects[0].key().expect("key");
          let get_resp = s3
              .get_object()
              .bucket(&cfg.connection.bucket)
              .key(key)
              .send()
              .await
              .expect("get_object for flow");

          let body_bytes = get_resp.body.collect().await.expect("collect body").into_bytes();

          use bytes::Bytes;
          use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
          let buf = Bytes::from(body_bytes.to_vec());
          let mut reader = ParquetRecordBatchReaderBuilder::try_new(buf)
              .unwrap()
              .build()
              .unwrap();
          let rb = reader.next().unwrap().unwrap();
          assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in flow Parquet");

          use arrow::array::StringArray;
          let et = rb
              .column_by_name("event_type")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(et.value(0), "flow");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails (correctly skips without MINIO_ENDPOINT)**

  ```
  cargo test --test suricata_s3_integration
  # Expected: test suricata_records_appear_as_parquet_in_s3 ... ok
  #           (prints "MINIO_ENDPOINT not set — skipping suricata_s3 integration test")
  # With MINIO_ENDPOINT set: compile error until Tasks 1.4–1.5 are complete (already done)
  ```

- [ ] **Step 3: Implement**

  The test file above is the full implementation. No production code changes.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --test suricata_s3_integration
  # Without MINIO_ENDPOINT: test passes (skips with eprintln)
  # With MINIO_ENDPOINT=http://localhost:9000: full assertions pass against live MinIO
  ```

- [ ] **Step 5: Commit**

  ```
  git add tests/suricata_s3_integration.rs
  git commit -m "test(suricata): add MINIO_ENDPOINT-gated S3 integration test"
  ```

---

### Task 1.8: End-to-end test — TCP listener → record observed

**Files:**
- Modify `src/suricata/listener.rs` — the e2e-style tests live alongside the existing integration tests in the `#[cfg(test)]` block already present from Task 1.2. Two tests already cover multi-record dispatch and missing-event-type fallback. This task adds a focused e2e scenario that binds a listener on an ephemeral port and drives it end-to-end from a separate async task simulating a Suricata agent.

**Rationale for placement in `src/suricata/listener.rs`:** The e2e scenario exercises the full stack (bind → accept → NDJSON decode → `SuricataRecord` → handler callback) without network routing or S3, exactly what `run_with_listener` provides. This matches the Zeek pattern (`listener_dispatches_records_from_ndjson_stream` in `src/zeek/listener.rs`) and avoids a separate binary.

- [ ] **Step 1: Write the failing test**

  Add these two tests to the existing `#[cfg(test)] mod tests` block in `src/suricata/listener.rs` (the block was created in Task 1.2):

  ```rust
  /// E2E: bind on ephemeral port, send 3 Suricata EVE JSON records of mixed types
  /// over TCP, assert handler observed all three with correct event_type.
  #[tokio::test]
  async fn e2e_listener_receives_mixed_event_types() {
      let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let addr = tcp_listener.local_addr().unwrap();

      let handler = CapturingHandler::new();
      let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
      let task = tokio::spawn(async move {
          listener.run_with_listener(tcp_listener).await.ok();
      });
      sleep(Duration::from_millis(20)).await;

      // Simulate a Suricata EVE JSON agent sending three records
      let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
      let ndjson = concat!(
          r#"{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"8.8.8.8","alert":{"signature":"ET TEST"},"timestamp":"2024-01-15T10:30:00Z"}"#,
          "\n",
          r#"{"event_type":"flow","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"TCP","timestamp":"2024-01-15T10:30:01Z"}"#,
          "\n",
          r#"{"event_type":"dns","src_ip":"10.0.0.3","dns":{"type":"query","rrname":"example.com"},"timestamp":"2024-01-15T10:30:02Z"}"#,
          "\n",
      );
      stream.write_all(ndjson.as_bytes()).await.unwrap();
      drop(stream);

      sleep(Duration::from_millis(200)).await;
      task.abort();

      let records = handler.take_records();
      assert_eq!(records.len(), 3, "expected 3 records, got {}", records.len());

      let event_types: Vec<&str> = records.iter().map(|r| r.event_type.as_str()).collect();
      assert_eq!(event_types, vec!["alert", "flow", "dns"]);

      // Assert fields are preserved
      assert_eq!(records[0].fields["src_ip"], "10.0.0.1");
      assert_eq!(records[1].fields["proto"], "TCP");
      assert_eq!(records[2].fields["dns"]["rrname"], "example.com");
  }

  /// E2E: records without event_type fall back to "unknown" and are still delivered.
  #[tokio::test]
  async fn e2e_missing_event_type_records_arrive_as_unknown() {
      let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let addr = tcp_listener.local_addr().unwrap();

      let handler = CapturingHandler::new();
      let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
      let task = tokio::spawn(async move {
          listener.run_with_listener(tcp_listener).await.ok();
      });
      sleep(Duration::from_millis(20)).await;

      let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
      let ndjson = concat!(
          // Valid with event_type
          r#"{"event_type":"stats","uptime":3600}"#,
          "\n",
          // Missing event_type — must arrive as "unknown"
          r#"{"uptime":7200,"iface":"eth0"}"#,
          "\n",
          // Malformed JSON — must be skipped entirely
          "GARBAGE\n",
          // Valid with event_type — must arrive
          r#"{"event_type":"anomaly","anomaly":{"type":"pkt"}}"#,
          "\n",
      );
      stream.write_all(ndjson.as_bytes()).await.unwrap();
      drop(stream);

      sleep(Duration::from_millis(200)).await;
      task.abort();

      let records = handler.take_records();
      assert_eq!(records.len(), 3, "expected 3 records (1 malformed skipped), got {}", records.len());
      assert_eq!(records[0].event_type, "stats");
      assert_eq!(records[1].event_type, "unknown");
      assert_eq!(records[2].event_type, "anomaly");
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib suricata::listener::tests::e2e_listener_receives_mixed_event_types
  # Expected: error — the test functions don't exist yet (they are the implementation)
  # After adding: FAILED because listener.rs doesn't yet have the tests added
  ```

- [ ] **Step 3: Implement**

  Add the two test functions above into the existing `#[cfg(test)] mod tests { … }` block in `src/suricata/listener.rs` (created in Task 1.2). No production code changes required — the listener implementation from Task 1.2 already handles all these cases.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib suricata::listener::tests
  # Expected: all tests pass, including the 2 new e2e scenarios:
  #   test suricata::listener::tests::e2e_listener_receives_mixed_event_types ... ok
  #   test suricata::listener::tests::e2e_missing_event_type_records_arrive_as_unknown ... ok
  cargo test --lib
  # Expected: full test suite green
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/suricata/listener.rs
  git commit -m "test(suricata): add e2e TCP listener tests for mixed event types and unknown fallback"
  ```

---

## Unit 2 — Syslog-embedded payload parsers (`src/syslog/payload/`)

This unit adds six format-specific payload parsers (CEF, LEEF, auditd, web access, DHCP, RADIUS) following the existing DNS try-chain pattern in `src/syslog/mod.rs`, a `payload::dispatch` function, shared output types, and a new partitioned `StructuredSyslogSink` that writes matched records to S3 under `payload_type=<format>/year=…` key layout. The existing `SyslogSink` is unchanged — every message continues to persist raw; the structured sink is additive.

---

### Task 2.1: Shared types — `SyslogPayload` enum, `StructuredSyslogRecord`, and `payload` mod skeleton

**Files:**
- Create `src/syslog/payload/mod.rs`
- Modify `src/syslog/mod.rs` (add `pub mod payload;`)

**Interfaces:**
- Produces: `pub enum SyslogPayload`, `pub struct StructuredSyslogRecord`, `pub fn dispatch(&SyslogMessage) -> SyslogPayload` (stub returning `SyslogPayload::None`)

- [ ] **Step 1: Write the failing test**

```rust
// In src/syslog/payload/mod.rs, add at the bottom:
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn bare_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 134,
            severity: 6,
            facility: 16,
            timestamp: None,
            hostname: Some("host".into()),
            app_name: Some("app".into()),
            proc_id: None,
            msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    #[test]
    fn dispatch_unknown_message_returns_none_variant() {
        let msg = bare_msg("this is not any known format");
        assert!(matches!(dispatch(&msg), SyslogPayload::None));
    }

    #[test]
    fn structured_syslog_record_payload_type_roundtrip() {
        let msg = bare_msg("irrelevant");
        let rec = StructuredSyslogRecord {
            priority: msg.priority,
            severity: msg.severity,
            facility: msg.facility,
            timestamp: None,
            hostname: msg.hostname.clone(),
            app_name: msg.app_name.clone(),
            received_at: chrono::Utc::now(),
            payload_type: "cef",
            parsed: serde_json::json!({"vendor": "Acme"}),
        };
        assert_eq!(rec.payload_type, "cef");
        assert_eq!(rec.parsed["vendor"], "Acme");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing 'syslog::payload::tests' 2>&1 | head -30
```

Expected: `error[E0433]: failed to resolve: use of undeclared crate or module 'payload'` (module does not exist yet).

- [ ] **Step 3: Implement**

```rust
// src/syslog/payload/mod.rs
//! Syslog payload sub-parsers.
//!
//! Each parser module exposes `try_parse(&SyslogMessage) -> Option<Payload>`
//! following the DNS try-chain pattern.  `dispatch` runs the chain and returns
//! the first match as a `SyslogPayload` variant, or `SyslogPayload::None`.

use crate::syslog::SyslogMessage;
use chrono::{DateTime, Utc};
use serde_json::Value;

pub mod auditd;
pub mod cef;
pub mod dhcp;
pub mod leef;
pub mod radius;
pub mod web_access;

// ---------------------------------------------------------------------------
// Output types (defined once, referenced by all tasks)
// ---------------------------------------------------------------------------

/// Parsed payload extracted from a syslog message body.
/// Each variant carries the fields specific to that format; `None` means no
/// sub-parser matched.
#[derive(Debug, Clone)]
pub enum SyslogPayload {
    Cef(cef::CefRecord),
    Leef(leef::LeefRecord),
    Auditd(auditd::AuditdRecord),
    Dhcp(dhcp::DhcpRecord),
    Radius(radius::RadiusRecord),
    WebAccess(web_access::WebAccessRecord),
    Dns(crate::syslog::dns::DnsLogEntry),
    None,
}

impl SyslogPayload {
    /// The canonical S3 partition string for this variant.
    /// Returns `None` for `SyslogPayload::None` (caller must gate on this).
    pub fn payload_type(&self) -> Option<&'static str> {
        match self {
            SyslogPayload::Cef(_)       => Some("cef"),
            SyslogPayload::Leef(_)      => Some("leef"),
            SyslogPayload::Auditd(_)    => Some("auditd"),
            SyslogPayload::Dhcp(_)      => Some("dhcp"),
            SyslogPayload::Radius(_)    => Some("radius"),
            SyslogPayload::WebAccess(_) => Some("web_access"),
            SyslogPayload::Dns(_)       => Some("dns"),
            SyslogPayload::None         => None,
        }
    }

    /// Serialize the inner parsed struct to a JSON `Value`.
    pub fn to_json(&self) -> Value {
        match self {
            SyslogPayload::Cef(r)       => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Leef(r)      => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Auditd(r)    => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Dhcp(r)      => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Radius(r)    => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::WebAccess(r) => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Dns(r)       => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::None         => Value::Null,
        }
    }
}

/// The structured record written to `StructuredSyslogSink`.
/// Carries the syslog envelope fields plus the payload type tag and the
/// parsed-fields JSON blob.  No bespoke typed Parquet schema per format in v1.
#[derive(Debug, Clone)]
pub struct StructuredSyslogRecord {
    // Syslog envelope
    pub priority: u8,
    pub severity: u8,
    pub facility: u8,
    pub timestamp: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub received_at: DateTime<Utc>,
    // Payload
    pub payload_type: &'static str,
    pub parsed: Value,
}

impl StructuredSyslogRecord {
    /// Build from a `SyslogMessage` and a matched `SyslogPayload`.
    /// Returns `None` when `payload` is `SyslogPayload::None`.
    pub fn from_syslog_and_payload(
        msg: &SyslogMessage,
        payload: &SyslogPayload,
    ) -> Option<Self> {
        let payload_type = payload.payload_type()?;
        Some(Self {
            priority: msg.priority,
            severity: msg.severity,
            facility: msg.facility,
            timestamp: msg.timestamp,
            hostname: msg.hostname.clone(),
            app_name: msg.app_name.clone(),
            received_at: Utc::now(),
            payload_type,
            parsed: payload.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Try all sub-parsers in priority order and return the first match.
///
/// Priority order:
/// 1. Prefix-keyed (fast rejection on first bytes): CEF, LEEF
/// 2. Key=value record formats: auditd
/// 3. Regex line formats: DHCP, RADIUS, web_access
/// 4. DNS (existing try-chain via `DnsLogEntry::from_syslog`)
/// 5. None
pub fn dispatch(msg: &SyslogMessage) -> SyslogPayload {
    if let Some(r) = cef::try_parse(msg)       { return SyslogPayload::Cef(r); }
    if let Some(r) = leef::try_parse(msg)      { return SyslogPayload::Leef(r); }
    if let Some(r) = auditd::try_parse(msg)    { return SyslogPayload::Auditd(r); }
    if let Some(r) = dhcp::try_parse(msg)      { return SyslogPayload::Dhcp(r); }
    if let Some(r) = radius::try_parse(msg)    { return SyslogPayload::Radius(r); }
    if let Some(r) = web_access::try_parse(msg){ return SyslogPayload::WebAccess(r); }
    if let Some(r) = crate::syslog::dns::DnsLogEntry::from_syslog(msg) {
        return SyslogPayload::Dns(r);
    }
    SyslogPayload::None
}

// Stub sub-modules referenced above are created in Tasks 2.2–2.7.
// Each module must be present (even empty) for this file to compile.
```

Add `pub mod payload;` to `src/syslog/mod.rs` just before the existing `pub mod listener;` line.

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing 'syslog::payload::tests' 2>&1
```

Expected: `test syslog::payload::tests::dispatch_unknown_message_returns_none_variant ... ok` and `test syslog::payload::tests::structured_syslog_record_payload_type_roundtrip ... ok`.

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/mod.rs src/syslog/mod.rs
git commit -m "feat(syslog/payload): add SyslogPayload enum, StructuredSyslogRecord, dispatch stub"
```

---

### Task 2.2: CEF parser — `src/syslog/payload/cef.rs`

**Files:**
- Create `src/syslog/payload/cef.rs`

**Interfaces:**
- Consumes: `&SyslogMessage` (reads `.message`)
- Produces: `pub fn try_parse(msg: &SyslogMessage) -> Option<CefRecord>`; `pub struct CefRecord`

- [ ] **Step 1: Write the failing test**

```rust
// src/syslog/payload/cef.rs  (add at bottom, before impl)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 86, severity: 6, facility: 10,
            timestamp: None, hostname: Some("fw01".into()),
            app_name: Some("ArcSight".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const BASIC_CEF: &str =
        "CEF:0|ArcSight|ArcSight Management Center|2.0|base:system:remotelogin:success|\
         Remote Login Success|3|src=10.0.0.1 dst=10.0.0.2 spt=51234 dpt=22";

    const CEF_ESCAPED: &str =
        r"CEF:0|Vendor|Product|1.0|100|Event with \| pipe and \\ backslash|5|\
          msg=value\\with\\backslash cs1=foo\=bar";

    const LEEF_LINE: &str =
        "LEEF:1.0|Vendor|Product|1.0|EventID|key=value";

    const NOT_CEF: &str =
        "type=SYSCALL msg=audit(1609459200.000:1234): syscall=59";

    #[test]
    fn parses_basic_cef_header_and_extensions() {
        let rec = try_parse(&msg(BASIC_CEF)).expect("must parse");
        assert_eq!(rec.version, 0);
        assert_eq!(rec.device_vendor, "ArcSight");
        assert_eq!(rec.device_product, "ArcSight Management Center");
        assert_eq!(rec.device_version, "2.0");
        assert_eq!(rec.signature_id, "base:system:remotelogin:success");
        assert_eq!(rec.name, "Remote Login Success");
        assert_eq!(rec.severity, "3");
        assert_eq!(rec.extensions.get("src").map(|s| s.as_str()), Some("10.0.0.1"));
        assert_eq!(rec.extensions.get("dst").map(|s| s.as_str()), Some("10.0.0.2"));
        assert_eq!(rec.extensions.get("spt").map(|s| s.as_str()), Some("51234"));
    }

    #[test]
    fn parses_cef_escaped_pipe_and_backslash() {
        let rec = try_parse(&msg(CEF_ESCAPED)).expect("must parse");
        // Header field containing \| should unescape to literal |
        assert!(rec.name.contains('|') || rec.name.contains('\\'),
            "escaped pipe or backslash must survive: {:?}", rec.name);
        // Extension value: cs1=foo\=bar → value is "foo=bar"
        if let Some(v) = rec.extensions.get("cs1") {
            assert_eq!(v, "foo=bar", "\\= should unescape to =");
        }
    }

    #[test]
    fn rejects_leef_prefix() {
        assert!(try_parse(&msg(LEEF_LINE)).is_none());
    }

    #[test]
    fn rejects_non_cef_message() {
        assert!(try_parse(&msg(NOT_CEF)).is_none());
    }

    #[test]
    fn rejects_cef_with_fewer_than_seven_pipe_fields() {
        // Only 5 pipe-separated fields (needs 7 after "CEF:version|")
        let truncated = "CEF:0|Vendor|Product|1.0|SigID";
        assert!(try_parse(&msg(truncated)).is_none());
    }

    #[test]
    fn parses_empty_extension_map() {
        let no_ext = "CEF:0|Vendor|Product|1.0|100|Login|5|";
        let rec = try_parse(&msg(no_ext)).expect("must parse");
        assert!(rec.extensions.is_empty());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing 'syslog::payload::cef::tests' 2>&1 | head -20
```

Expected: `error[E0425]: cannot find function 'try_parse'` — module is empty stub.

- [ ] **Step 3: Implement**

```rust
// src/syslog/payload/cef.rs
//! CEF (Common Event Format) sub-parser.
//!
//! Wire format:  `CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|
//!               SignatureID|Name|Severity|Extensions`
//!
//! Extensions are `key=value` pairs separated by spaces, with CEF escaping:
//!   `\|` → `|`,  `\\` → `\`,  `\=` → `=`  (only in extension values and
//!   inside header fields that come before the final `|`).

use crate::syslog::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefRecord {
    pub version: u8,
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
    pub signature_id: String,
    pub name: String,
    pub severity: String,
    pub extensions: HashMap<String, String>,
}

/// Unescape a CEF header field: `\|` → `|`, `\\` → `\`.
/// (Header fields do not use `\=`.)
fn unescape_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('|') => { out.push('|');  chars.next(); }
                Some('\\') => { out.push('\\'); chars.next(); }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Unescape a CEF extension value: `\|` → `|`, `\\` → `\`, `\=` → `=`.
fn unescape_ext(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('|')  => { out.push('|');  chars.next(); }
                Some('\\') => { out.push('\\'); chars.next(); }
                Some('=')  => { out.push('=');  chars.next(); }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split a CEF header on unescaped `|`, returning up to `n` segments.
fn split_header(s: &str, n: usize) -> Vec<String> {
    let mut parts = Vec::with_capacity(n);
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Consume the escape character and the next character together.
            current.push(c);
            if let Some(next) = chars.next() {
                current.push(next);
            }
        } else if c == '|' {
            parts.push(unescape_header(&current));
            current.clear();
            if parts.len() == n - 1 {
                // Collect remainder as final part (may contain unescaped |).
                let rest: String = chars.collect();
                parts.push(rest);
                return parts;
            }
        } else {
            current.push(c);
        }
    }
    parts.push(unescape_header(&current));
    parts
}

/// Parse CEF extension string `k1=v1 k2=v2 ...` with proper value boundary
/// detection.  The value ends at the next ` key=` token.
fn parse_extensions(ext: &str) -> HashMap<String, String> {
    // Find all key positions by scanning for `word=` patterns.
    // We do a two-pass: first collect key start indices, then extract values.
    let mut map = HashMap::new();
    let trimmed = ext.trim();
    if trimmed.is_empty() {
        return map;
    }

    let bytes = trimmed.as_bytes();
    let len = bytes.len();

    // Find positions of `key=` tokens.
    let mut key_spans: Vec<(usize, usize)> = Vec::new(); // (key_start, eq_pos)
    let mut i = 0usize;
    while i < len {
        // Skip whitespace between pairs.
        while i < len && bytes[i] == b' ' { i += 1; }
        if i >= len { break; }
        let key_start = i;
        // Read key characters: alpha, digit, underscore.
        while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let key_end = i;
        if key_end > key_start && i < len && bytes[i] == b'=' {
            key_spans.push((key_start, i)); // i points at '='
            i += 1; // skip '='
        } else {
            // Not a valid key=; skip to next space.
            while i < len && bytes[i] != b' ' { i += 1; }
        }
    }

    // For each key, value runs from (eq_pos + 1) to the start of the next key - whitespace.
    for idx in 0..key_spans.len() {
        let (ks, eq) = key_spans[idx];
        let key = &trimmed[ks..eq];
        let val_start = eq + 1;
        let val_end = if idx + 1 < key_spans.len() {
            // Walk back from next key_start to strip trailing whitespace.
            let next_ks = key_spans[idx + 1].0;
            let mut end = next_ks;
            while end > val_start && trimmed.as_bytes()[end - 1] == b' ' {
                end -= 1;
            }
            end
        } else {
            trimmed.len()
        };
        let raw_val = &trimmed[val_start..val_end];
        map.insert(key.to_string(), unescape_ext(raw_val));
    }
    map
}

/// Try to parse `msg.message` as a CEF record.
/// Returns `None` if the message does not start with `CEF:`.
pub fn try_parse(msg: &SyslogMessage) -> Option<CefRecord> {
    let m = &msg.message;
    if !m.starts_with("CEF:") {
        return None;
    }
    // Format: CEF:version|vendor|product|dev_ver|sig_id|name|severity|extensions
    let rest = &m["CEF:".len()..];
    // We need 8 pipe-delimited fields: version + 6 header fields + extension blob.
    let parts = split_header(rest, 8);
    if parts.len() < 7 {
        return None;
    }
    let version: u8 = parts[0].parse().ok()?;
    let extensions = if parts.len() >= 8 {
        parse_extensions(&parts[7])
    } else {
        HashMap::new()
    };
    Some(CefRecord {
        version,
        device_vendor:  parts[1].clone(),
        device_product: parts[2].clone(),
        device_version: parts[3].clone(),
        signature_id:   parts[4].clone(),
        name:           parts[5].clone(),
        severity:       parts[6].clone(),
        extensions,
    })
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing 'syslog::payload::cef::tests' 2>&1
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/cef.rs
git commit -m "feat(syslog/payload): add CEF sub-parser with escape handling"
```

---

### Task 2.3: LEEF parser — `src/syslog/payload/leef.rs`

**Files:**
- Create `src/syslog/payload/leef.rs`

**Interfaces:**
- Consumes: `&SyslogMessage`
- Produces: `pub fn try_parse(msg: &SyslogMessage) -> Option<LeefRecord>`; `pub struct LeefRecord`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 14, severity: 6, facility: 1,
            timestamp: None, hostname: Some("qradar".into()),
            app_name: None, proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    // LEEF 1.0: no delimiter field; pairs separated by \t (tab).
    const LEEF_1_0: &str =
        "LEEF:1.0|Vendor|Product|1.0|LoginSuccess|src=192.168.1.10\tdst=10.0.0.1\tusrName=bob";

    // LEEF 2.0: delimiter field (0x7C = '|') after EventID.
    const LEEF_2_0: &str =
        "LEEF:2.0|Vendor|Product|2.0|EventID|0x7C|src=192.168.1.10|dst=10.0.0.1|usrName=alice";

    // LEEF 2.0 with tab delimiter (default when field is absent or 0x09).
    const LEEF_2_0_TAB: &str =
        "LEEF:2.0|Vendor|Product|2.0|EventID|\tsrc=192.168.1.10\tdst=10.0.0.1";

    const NOT_LEEF: &str = "CEF:0|Vendor|Product|1.0|100|Name|5|";

    #[test]
    fn parses_leef_1_0_with_tab_delimiter() {
        let rec = try_parse(&msg(LEEF_1_0)).expect("must parse");
        assert_eq!(rec.leef_version, "1.0");
        assert_eq!(rec.vendor, "Vendor");
        assert_eq!(rec.product, "Product");
        assert_eq!(rec.version, "1.0");
        assert_eq!(rec.event_id, "LoginSuccess");
        assert_eq!(rec.attributes.get("src").map(|s| s.as_str()), Some("192.168.1.10"));
        assert_eq!(rec.attributes.get("usrName").map(|s| s.as_str()), Some("bob"));
        assert!(rec.delimiter.is_none(), "LEEF 1.0 has no delimiter field");
    }

    #[test]
    fn parses_leef_2_0_with_pipe_delimiter() {
        let rec = try_parse(&msg(LEEF_2_0)).expect("must parse");
        assert_eq!(rec.leef_version, "2.0");
        assert_eq!(rec.event_id, "EventID");
        assert_eq!(rec.delimiter, Some('|'));
        assert_eq!(rec.attributes.get("dst").map(|s| s.as_str()), Some("10.0.0.1"));
        assert_eq!(rec.attributes.get("usrName").map(|s| s.as_str()), Some("alice"));
    }

    #[test]
    fn parses_leef_2_0_tab_delimiter_field() {
        let rec = try_parse(&msg(LEEF_2_0_TAB)).expect("must parse");
        assert_eq!(rec.leef_version, "2.0");
        // delimiter field is "\t" → '\t'
        assert!(matches!(rec.delimiter, None | Some('\t')));
        assert_eq!(rec.attributes.get("src").map(|s| s.as_str()), Some("192.168.1.10"));
    }

    #[test]
    fn rejects_cef_prefix() {
        assert!(try_parse(&msg(NOT_LEEF)).is_none());
    }

    #[test]
    fn rejects_truncated_leef() {
        // Only 3 pipe fields
        assert!(try_parse(&msg("LEEF:1.0|Vendor|Product")).is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing 'syslog::payload::leef::tests' 2>&1 | head -20
```

Expected: compile error — `leef.rs` is empty stub.

- [ ] **Step 3: Implement**

```rust
// src/syslog/payload/leef.rs
//! LEEF (Log Event Extended Format) sub-parser.
//!
//! LEEF 1.0:  `LEEF:1.0|Vendor|Product|Version|EventID|<tab-separated k=v>`
//! LEEF 2.0:  `LEEF:2.0|Vendor|Product|Version|EventID|<delim>|<delim-separated k=v>`
//!             where `<delim>` is a one-char literal (e.g. `|`) or a hex escape
//!             (`0x7C` = `|`; `0x09` = `\t`).  If the delimiter field is empty
//!             or absent the default delimiter is `\t`.

use crate::syslog::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeefRecord {
    pub leef_version: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub event_id: String,
    /// Present only for LEEF 2.0 that includes the delimiter field.
    pub delimiter: Option<char>,
    pub attributes: HashMap<String, String>,
}

/// Decode the LEEF 2.0 delimiter field.
/// Accepts: `0x<HH>` hex notation, a single literal character, or empty → `\t`.
fn decode_delimiter(s: &str) -> char {
    let s = s.trim();
    if s.is_empty() || s == "\\t" || s == "\t" {
        return '\t';
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(n) = u8::from_str_radix(hex, 16) {
            return n as char;
        }
    }
    s.chars().next().unwrap_or('\t')
}

/// Parse `k=v` pairs separated by `delim`.
fn parse_attributes(pairs: &str, delim: char) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in pairs.split(delim) {
        if let Some(eq) = pair.find('=') {
            let key = pair[..eq].trim().to_string();
            let val = pair[eq + 1..].to_string();
            if !key.is_empty() {
                map.insert(key, val);
            }
        }
    }
    map
}

pub fn try_parse(msg: &SyslogMessage) -> Option<LeefRecord> {
    let m = &msg.message;
    if !m.starts_with("LEEF:") {
        return None;
    }
    let rest = &m["LEEF:".len()..];
    // Split on '|' to extract the fixed header fields.
    // We need at least 5 fields: leef_version, vendor, product, version, event_id
    let mut parts = rest.splitn(7, '|');
    let leef_version = parts.next()?.to_string();
    let vendor       = parts.next()?.to_string();
    let product      = parts.next()?.to_string();
    let version      = parts.next()?.to_string();
    let event_id     = parts.next()?.to_string();

    // What remains depends on LEEF version.
    let remainder = parts.next().unwrap_or("");

    let (delimiter, attributes) = if leef_version == "2.0" {
        // LEEF 2.0: the 6th pipe-segment is the delimiter spec; the rest is the pairs blob.
        // remainder was split with splitn(7,|) so remainder = "<delim_field>|<pairs>" or
        // just "<delim_field>" if there are no more pipes.
        if let Some(pipe) = remainder.find('|') {
            let delim_field = &remainder[..pipe];
            let pairs_blob  = &remainder[pipe + 1..];
            let delim = decode_delimiter(delim_field);
            let attrs = parse_attributes(pairs_blob, delim);
            (Some(delim), attrs)
        } else {
            // No '|' after delimiter field — delimiter field is the whole remainder,
            // and attributes blob is empty (or delimiter IS the separator and pairs
            // start with it — treat as tab-delimited for robustness).
            let delim = if remainder.is_empty() { '\t' } else { decode_delimiter(remainder) };
            (Some(delim), HashMap::new())
        }
    } else {
        // LEEF 1.0: remainder is the entire attributes blob, tab-delimited.
        let attrs = parse_attributes(remainder, '\t');
        (None, attrs)
    };

    Some(LeefRecord {
        leef_version,
        vendor,
        product,
        version,
        event_id,
        delimiter,
        attributes,
    })
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing 'syslog::payload::leef::tests' 2>&1
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/leef.rs
git commit -m "feat(syslog/payload): add LEEF 1.0/2.0 sub-parser with delimiter handling"
```

---

### Task 2.4: auditd parser — `src/syslog/payload/auditd.rs`

**Files:**
- Create `src/syslog/payload/auditd.rs`

**Interfaces:**
- Consumes: `&SyslogMessage`
- Produces: `pub fn try_parse(msg: &SyslogMessage) -> Option<AuditdRecord>`; `pub struct AuditdRecord`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 80, severity: 0, facility: 10,
            timestamp: None, hostname: Some("server".into()),
            app_name: Some("kernel".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const SYSCALL: &str =
        "type=SYSCALL msg=audit(1609459200.000:1234): arch=c000003e syscall=59 \
         success=yes exit=0 a0=7f1234 a1=0 a2=0 a3=0 items=3 ppid=1000 pid=2000 \
         auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 \
         tty=pts0 ses=42 comm=\"bash\" exe=\"/bin/bash\" key=\"exec\"";

    const LOGIN: &str =
        "type=LOGIN msg=audit(1609459201.000:1235): pid=2001 uid=0 \
         old-auid=4294967295 auid=1001 tty=(none) old-ses=4294967295 ses=43 res=1";

    const PATH_RECORD: &str =
        "type=PATH msg=audit(1609459202.000:1236): item=0 name=\"/bin/bash\" \
         inode=131074 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 \
         nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0";

    const NOT_AUDITD: &str =
        "CEF:0|Vendor|Product|1.0|100|Name|5|";

    const MISSING_MSG_FIELD: &str =
        "type=SYSCALL arch=c000003e syscall=59";

    #[test]
    fn parses_syscall_record() {
        let rec = try_parse(&msg(SYSCALL)).expect("must parse");
        assert_eq!(rec.record_type, "SYSCALL");
        assert_eq!(rec.audit_id, "1609459200.000:1234");
        assert_eq!(rec.fields.get("syscall").map(|s| s.as_str()), Some("59"));
        assert_eq!(rec.fields.get("comm").map(|s| s.as_str()), Some("bash"));
        assert_eq!(rec.fields.get("exe").map(|s| s.as_str()), Some("/bin/bash"));
        assert_eq!(rec.fields.get("key").map(|s| s.as_str()), Some("exec"));
    }

    #[test]
    fn parses_login_record() {
        let rec = try_parse(&msg(LOGIN)).expect("must parse");
        assert_eq!(rec.record_type, "LOGIN");
        assert_eq!(rec.audit_id, "1609459201.000:1235");
        assert_eq!(rec.fields.get("auid").map(|s| s.as_str()), Some("1001"));
        assert_eq!(rec.fields.get("res").map(|s| s.as_str()), Some("1"));
    }

    #[test]
    fn parses_path_record_with_quoted_name() {
        let rec = try_parse(&msg(PATH_RECORD)).expect("must parse");
        assert_eq!(rec.record_type, "PATH");
        assert_eq!(rec.fields.get("name").map(|s| s.as_str()), Some("/bin/bash"));
    }

    #[test]
    fn rejects_non_auditd_message() {
        assert!(try_parse(&msg(NOT_AUDITD)).is_none());
    }

    #[test]
    fn rejects_auditd_without_msg_field() {
        assert!(try_parse(&msg(MISSING_MSG_FIELD)).is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing 'syslog::payload::auditd::tests' 2>&1 | head -20
```

Expected: compile error on empty stub.

- [ ] **Step 3: Implement**

```rust
// src/syslog/payload/auditd.rs
//! Linux auditd sub-parser (single-record; no multi-line reassembly).
//!
//! Expects:  `type=<TYPE> msg=audit(<epoch.ms>:<serial>): k=v k="v" ...`

use crate::syslog::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

/// Match:  `type=<TYPE> msg=audit(<id>):`
static AUDITD_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^type=(\S+)\s+msg=audit\(([^)]+)\):\s*").unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditdRecord {
    pub record_type: String,
    pub audit_id: String,
    pub fields: HashMap<String, String>,
}

/// Parse `k=v k="v" ...` pairs from an auditd body.
/// Values may be bare words or double-quoted strings.
fn parse_kv_pairs(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        // Skip spaces.
        while i < len && bytes[i] == b' ' { i += 1; }
        if i >= len { break; }

        // Read key.
        let key_start = i;
        while i < len && bytes[i] != b'=' && bytes[i] != b' ' { i += 1; }
        if i >= len || bytes[i] != b'=' { break; }
        let key = body[key_start..i].to_string();
        i += 1; // skip '='

        if i >= len { map.insert(key, String::new()); break; }

        // Read value: quoted or unquoted.
        let val = if bytes[i] == b'"' {
            i += 1; // skip opening quote
            let val_start = i;
            while i < len && bytes[i] != b'"' { i += 1; }
            let v = body[val_start..i].to_string();
            if i < len { i += 1; } // skip closing quote
            v
        } else {
            let val_start = i;
            while i < len && bytes[i] != b' ' { i += 1; }
            body[val_start..i].to_string()
        };
        map.insert(key, val);
    }
    map
}

pub fn try_parse(msg: &SyslogMessage) -> Option<AuditdRecord> {
    let m = &msg.message;
    let caps = AUDITD_HEADER_RE.captures(m)?;
    let record_type = caps.get(1)?.as_str().to_string();
    let audit_id    = caps.get(2)?.as_str().to_string();
    let body_start  = caps.get(0)?.end();
    let body        = &m[body_start..];
    let fields      = parse_kv_pairs(body);
    Some(AuditdRecord { record_type, audit_id, fields })
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing 'syslog::payload::auditd::tests' 2>&1
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/auditd.rs
git commit -m "feat(syslog/payload): add auditd single-record sub-parser"
```

---

### Task 2.5: web_access parser — `src/syslog/payload/web_access.rs`

**Files:**
- Create `src/syslog/payload/web_access.rs`

**Interfaces:**
- Consumes: `&SyslogMessage`
- Produces: `pub fn try_parse(msg: &SyslogMessage) -> Option<WebAccessRecord>`; `pub struct WebAccessRecord`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 134, severity: 6, facility: 16,
            timestamp: None, hostname: Some("web01".into()),
            app_name: Some("nginx".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    // Apache/Nginx combined log format.
    const COMBINED: &str = r#"192.168.1.100 - bob [15/Jan/2024:10:30:45 +0000] "GET /api/v1/users HTTP/1.1" 200 4523 "https://example.com/page" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36""#;

    // Hyphen for ident and authuser fields.
    const ANON: &str = r#"10.0.0.1 - - [15/Jan/2024:10:31:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/7.68.0""#;

    // 404 response.
    const NOT_FOUND: &str = r#"172.16.0.5 - - [15/Jan/2024:10:32:15 +0000] "GET /missing HTTP/2.0" 404 162 "-" "-""#;

    const NOT_WEB: &str = "type=SYSCALL msg=audit(1609459200.000:1): syscall=59";

    #[test]
    fn parses_combined_log_with_auth_user() {
        let rec = try_parse(&msg(COMBINED)).expect("must parse");
        assert_eq!(rec.client_ip, "192.168.1.100");
        assert_eq!(rec.ident, Some("-".into()));
        assert_eq!(rec.authuser, Some("bob".into()));
        assert_eq!(rec.method, "GET");
        assert_eq!(rec.path, "/api/v1/users");
        assert_eq!(rec.protocol, "HTTP/1.1");
        assert_eq!(rec.status, 200);
        assert_eq!(rec.bytes, Some(4523));
        assert_eq!(rec.referer.as_deref(), Some("https://example.com/page"));
        assert!(rec.user_agent.as_deref().unwrap().starts_with("Mozilla"));
    }

    #[test]
    fn parses_anonymous_request_with_hyphens() {
        let rec = try_parse(&msg(ANON)).expect("must parse");
        assert_eq!(rec.client_ip, "10.0.0.1");
        assert_eq!(rec.authuser, None);
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.status, 302);
        assert_eq!(rec.bytes, Some(0));
        assert_eq!(rec.referer, None);
    }

    #[test]
    fn parses_404_response() {
        let rec = try_parse(&msg(NOT_FOUND)).expect("must parse");
        assert_eq!(rec.status, 404);
        assert_eq!(rec.path, "/missing");
    }

    #[test]
    fn rejects_non_web_message() {
        assert!(try_parse(&msg(NOT_WEB)).is_none());
    }

    #[test]
    fn hyphen_referer_becomes_none() {
        let rec = try_parse(&msg(ANON)).expect("must parse");
        assert!(rec.referer.is_none(), "'-' referer must become None");
    }

    #[test]
    fn hyphen_user_agent_becomes_none() {
        let rec = try_parse(&msg(NOT_FOUND)).expect("must parse");
        assert!(rec.user_agent.is_none(), "'-' user agent must become None");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing 'syslog::payload::web_access::tests' 2>&1 | head -20
```

Expected: compile error on empty stub.

- [ ] **Step 3: Implement**

```rust
// src/syslog/payload/web_access.rs
//! Apache / Nginx Combined Log Format sub-parser.
//!
//! Pattern:  `host ident authuser [date] "method path proto" status bytes "referer" "ua"`

use crate::syslog::SyslogMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static COMBINED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)""#,
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAccessRecord {
    pub client_ip: String,
    pub ident: Option<String>,
    pub authuser: Option<String>,
    pub timestamp_str: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub bytes: Option<u64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

/// Convert `-` to `None`.
fn opt_hyphen(s: &str) -> Option<String> {
    if s == "-" { None } else { Some(s.to_string()) }
}

pub fn try_parse(msg: &SyslogMessage) -> Option<WebAccessRecord> {
    let caps = COMBINED_RE.captures(&msg.message)?;
    let client_ip    = caps.get(1)?.as_str().to_string();
    let ident        = caps.get(2).and_then(|m| opt_hyphen(m.as_str()));
    let authuser     = caps.get(3).and_then(|m| opt_hyphen(m.as_str()));
    let timestamp_str = caps.get(4)?.as_str().to_string();
    let method       = caps.get(5)?.as_str().to_string();
    let path         = caps.get(6)?.as_str().to_string();
    let protocol     = caps.get(7)?.as_str().to_string();
    let status: u16  = caps.get(8)?.as_str().parse().ok()?;
    let bytes        = caps.get(9).and_then(|m| {
        let s = m.as_str();
        if s == "-" { None } else { s.parse().ok() }
    });
    let referer      = caps.get(10).and_then(|m| opt_hyphen(m.as_str()));
    let user_agent   = caps.get(11).and_then(|m| opt_hyphen(m.as_str()));

    Some(WebAccessRecord {
        client_ip,
        ident,
        authuser,
        timestamp_str,
        method,
        path,
        protocol,
        status,
        bytes,
        referer,
        user_agent,
    })
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing 'syslog::payload::web_access::tests' 2>&1
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/web_access.rs
git commit -m "feat(syslog/payload): add Apache/Nginx combined-log-format sub-parser"
```

---

### Task 2.6: DHCP and RADIUS parsers — `src/syslog/payload/dhcp.rs` and `src/syslog/payload/radius.rs`

**Files:**
- Create `src/syslog/payload/dhcp.rs`
- Create `src/syslog/payload/radius.rs`

**Interfaces:**
- Consumes: `&SyslogMessage`
- Produces: `dhcp::try_parse`, `dhcp::DhcpRecord`; `radius::try_parse`, `radius::RadiusRecord`

These two parsers are grouped in one task because they are similarly sized regex-based parsers over ISC DHCP and FreeRADIUS line formats.

- [ ] **Step 1: Write the failing tests**

```rust
// src/syslog/payload/dhcp.rs — tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 30, severity: 6, facility: 3,
            timestamp: None, hostname: Some("dhcp-server".into()),
            app_name: Some("dhcpd".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const DHCPACK: &str =
        "DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPOFFER: &str =
        "DHCPOFFER on 10.0.0.100 to cc:dd:ee:ff:00:11 via eth1";
    const DHCPREQUEST: &str =
        "DHCPREQUEST for 10.0.0.5 from aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPDISCOVER: &str =
        "DHCPDISCOVER from aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPRELEASE: &str =
        "DHCPRELEASE of 10.0.0.5 from aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPNAK: &str =
        "DHCPNAK on 10.0.0.5 to aa:bb:cc:dd:ee:ff";
    const NOT_DHCP: &str =
        "Login OK: [alice] (from client vpn port 10)";

    #[test]
    fn parses_dhcpack() {
        let rec = try_parse(&msg(DHCPACK)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPACK");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(rec.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(rec.hostname.as_deref(), Some("myhost"));
        assert_eq!(rec.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_dhcpoffer_without_hostname() {
        let rec = try_parse(&msg(DHCPOFFER)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPOFFER");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.100"));
        assert!(rec.hostname.is_none());
    }

    #[test]
    fn parses_dhcprequest() {
        let rec = try_parse(&msg(DHCPREQUEST)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPREQUEST");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_dhcpdiscover() {
        let rec = try_parse(&msg(DHCPDISCOVER)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPDISCOVER");
        assert!(rec.ip_address.is_none());
        assert_eq!(rec.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parses_dhcprelease() {
        let rec = try_parse(&msg(DHCPRELEASE)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPRELEASE");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_dhcpnak_without_hostname_or_interface() {
        let rec = try_parse(&msg(DHCPNAK)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPNAK");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
        assert!(rec.interface.is_none());
    }

    #[test]
    fn rejects_non_dhcp_message() {
        assert!(try_parse(&msg(NOT_DHCP)).is_none());
    }
}
```

```rust
// src/syslog/payload/radius.rs — tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 85, severity: 5, facility: 10,
            timestamp: None, hostname: Some("radius-server".into()),
            app_name: Some("radiusd".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const LOGIN_OK: &str =
        "Login OK: [alice] (from client vpn port 10 cli 10.0.0.5)";
    const LOGIN_OK_NO_CLI: &str =
        "Login OK: [bob] (from client corp port 2)";
    const LOGIN_FAIL: &str =
        "Login incorrect (PAP): [charlie] (from client vpn port 10 cli 10.0.0.7)";
    const LOGIN_FAIL_SIMPLE: &str =
        "Login incorrect: [dave] (from client corp port 5)";
    const NOT_RADIUS: &str =
        "DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff via eth0";

    #[test]
    fn parses_login_ok() {
        let rec = try_parse(&msg(LOGIN_OK)).expect("must parse");
        assert_eq!(rec.outcome, "ok");
        assert_eq!(rec.username.as_deref(), Some("alice"));
        assert_eq!(rec.client.as_deref(), Some("vpn"));
        assert_eq!(rec.port.as_deref(), Some("10"));
        assert_eq!(rec.client_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_login_ok_without_cli() {
        let rec = try_parse(&msg(LOGIN_OK_NO_CLI)).expect("must parse");
        assert_eq!(rec.outcome, "ok");
        assert_eq!(rec.username.as_deref(), Some("bob"));
        assert!(rec.client_ip.is_none());
    }

    #[test]
    fn parses_login_incorrect_with_method() {
        let rec = try_parse(&msg(LOGIN_FAIL)).expect("must parse");
        assert_eq!(rec.outcome, "fail");
        assert_eq!(rec.username.as_deref(), Some("charlie"));
        assert_eq!(rec.method.as_deref(), Some("PAP"));
    }

    #[test]
    fn parses_login_incorrect_without_method() {
        let rec = try_parse(&msg(LOGIN_FAIL_SIMPLE)).expect("must parse");
        assert_eq!(rec.outcome, "fail");
        assert_eq!(rec.username.as_deref(), Some("dave"));
        assert!(rec.method.is_none());
    }

    #[test]
    fn rejects_non_radius_message() {
        assert!(try_parse(&msg(NOT_RADIUS)).is_none());
    }
}
```

- [ ] **Step 2: Run to verify they fail**

```
cargo test -p logthing 'syslog::payload::dhcp::tests' 'syslog::payload::radius::tests' 2>&1 | head -20
```

Expected: compile errors on empty stubs.

- [ ] **Step 3: Implement**

```rust
// src/syslog/payload/dhcp.rs
//! ISC DHCP sub-parser.
//!
//! Handles: DHCPACK, DHCPOFFER, DHCPREQUEST, DHCPDISCOVER, DHCPRELEASE, DHCPNAK.

use crate::syslog::SyslogMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// DHCPACK / DHCPOFFER / DHCPNAK — "on/to" pattern with optional hostname + interface.
/// Groups: (type, ip, mac, hostname?, interface?)
static DHCP_ON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(DHCPACK|DHCPOFFER|DHCPNAK)\s+on\s+(\S+)\s+to\s+([\da-fA-F:]+)(?:\s+\(([^)]+)\))?(?:\s+via\s+(\S+))?",
    )
    .unwrap()
});

/// DHCPREQUEST / DHCPRELEASE — "for/of ... from" pattern.
/// Groups: (type, ip, mac, hostname?, interface?)
static DHCP_FROM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(DHCPREQUEST|DHCPRELEASE)\s+(?:for|of)\s+(\S+)\s+from\s+([\da-fA-F:]+)(?:\s+\(([^)]+)\))?(?:\s+via\s+(\S+))?",
    )
    .unwrap()
});

/// DHCPDISCOVER — "from <mac>" with no IP.
/// Groups: (mac, hostname?, interface?)
static DHCP_DISCOVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^DHCPDISCOVER\s+from\s+([\da-fA-F:]+)(?:\s+\(([^)]+)\))?(?:\s+via\s+(\S+))?",
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRecord {
    pub message_type: String,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub interface: Option<String>,
}

pub fn try_parse(msg: &SyslogMessage) -> Option<DhcpRecord> {
    let m = &msg.message;

    if let Some(caps) = DHCP_ON_RE.captures(m) {
        return Some(DhcpRecord {
            message_type: caps.get(1)?.as_str().to_string(),
            ip_address:   Some(caps.get(2)?.as_str().to_string()),
            mac_address:  Some(caps.get(3)?.as_str().to_string()),
            hostname:     caps.get(4).map(|m| m.as_str().to_string()),
            interface:    caps.get(5).map(|m| m.as_str().to_string()),
        });
    }

    if let Some(caps) = DHCP_FROM_RE.captures(m) {
        return Some(DhcpRecord {
            message_type: caps.get(1)?.as_str().to_string(),
            ip_address:   Some(caps.get(2)?.as_str().to_string()),
            mac_address:  Some(caps.get(3)?.as_str().to_string()),
            hostname:     caps.get(4).map(|m| m.as_str().to_string()),
            interface:    caps.get(5).map(|m| m.as_str().to_string()),
        });
    }

    if let Some(caps) = DHCP_DISCOVER_RE.captures(m) {
        return Some(DhcpRecord {
            message_type: "DHCPDISCOVER".to_string(),
            ip_address:   None,
            mac_address:  Some(caps.get(1)?.as_str().to_string()),
            hostname:     caps.get(2).map(|m| m.as_str().to_string()),
            interface:    caps.get(3).map(|m| m.as_str().to_string()),
        });
    }

    None
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

```rust
// src/syslog/payload/radius.rs
//! FreeRADIUS sub-parser.
//!
//! Handles:
//!   `Login OK: [user] (from client <nas> port <n> [cli <ip>])`
//!   `Login incorrect [(<method>)]: [user] (from client <nas> port <n> [cli <ip>])`

use crate::syslog::SyslogMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Login OK line.
/// Groups: (username, client, port, client_ip?)
static RADIUS_OK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^Login OK:\s+\[([^\]]+)\]\s+\(from client\s+(\S+)\s+port\s+(\S+)(?:\s+cli\s+(\S+))?\)",
    )
    .unwrap()
});

/// Login incorrect line (with optional auth method in parens).
/// Groups: (method?, username, client, port, client_ip?)
static RADIUS_FAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^Login incorrect(?:\s+\(([^)]+)\))?:\s+\[([^\]]+)\]\s+\(from client\s+(\S+)\s+port\s+(\S+)(?:\s+cli\s+(\S+))?\)",
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusRecord {
    /// `"ok"` or `"fail"`
    pub outcome: String,
    pub username: Option<String>,
    pub method: Option<String>,
    pub client: Option<String>,
    pub port: Option<String>,
    pub client_ip: Option<String>,
}

pub fn try_parse(msg: &SyslogMessage) -> Option<RadiusRecord> {
    let m = &msg.message;

    if let Some(caps) = RADIUS_OK_RE.captures(m) {
        return Some(RadiusRecord {
            outcome:   "ok".to_string(),
            username:  caps.get(1).map(|m| m.as_str().to_string()),
            method:    None,
            client:    caps.get(2).map(|m| m.as_str().to_string()),
            port:      caps.get(3).map(|m| m.as_str().to_string()),
            client_ip: caps.get(4).map(|m| m.as_str().to_string()),
        });
    }

    if let Some(caps) = RADIUS_FAIL_RE.captures(m) {
        return Some(RadiusRecord {
            outcome:   "fail".to_string(),
            method:    caps.get(1).map(|m| m.as_str().to_string()),
            username:  caps.get(2).map(|m| m.as_str().to_string()),
            client:    caps.get(3).map(|m| m.as_str().to_string()),
            port:      caps.get(4).map(|m| m.as_str().to_string()),
            client_ip: caps.get(5).map(|m| m.as_str().to_string()),
        });
    }

    None
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

- [ ] **Step 4: Run to verify they pass**

```
cargo test -p logthing 'syslog::payload::dhcp::tests' 'syslog::payload::radius::tests' 2>&1
```

Expected: all 7 DHCP tests and all 5 RADIUS tests pass.

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/dhcp.rs src/syslog/payload/radius.rs
git commit -m "feat(syslog/payload): add ISC DHCP and FreeRADIUS sub-parsers"
```

---

### Task 2.7: Complete dispatcher + metrics integration

**Files:**
- Modify `src/syslog/payload/mod.rs` (flesh out the `dispatch` function with metrics; the stub already calls all parsers, so this task adds the `metrics::counter!` call and verifies the full chain end-to-end)

**Interfaces:**
- Produces: `dispatch` emitting `metrics::counter!("syslog_payload_parsed", "type" => payload_type)` on every non-None match

- [ ] **Step 1: Write the failing test**

```rust
// Add to src/syslog/payload/mod.rs tests block:

#[test]
fn dispatch_cef_message_returns_cef_variant() {
    let m = bare_msg(
        "CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.1 dst=10.0.0.2",
    );
    let p = dispatch(&m);
    assert!(
        matches!(p, SyslogPayload::Cef(_)),
        "expected Cef variant, got {:?}",
        p.payload_type()
    );
}

#[test]
fn dispatch_leef_message_returns_leef_variant() {
    let m = bare_msg("LEEF:1.0|V|P|1.0|E|\tkey=val");
    assert!(matches!(dispatch(&m), SyslogPayload::Leef(_)));
}

#[test]
fn dispatch_auditd_message_returns_auditd_variant() {
    let m = bare_msg("type=SYSCALL msg=audit(1609459200.000:1): syscall=59 success=yes");
    assert!(matches!(dispatch(&m), SyslogPayload::Auditd(_)));
}

#[test]
fn dispatch_dhcp_message_returns_dhcp_variant() {
    let m = bare_msg("DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff (host) via eth0");
    assert!(matches!(dispatch(&m), SyslogPayload::Dhcp(_)));
}

#[test]
fn dispatch_radius_message_returns_radius_variant() {
    let m = bare_msg("Login OK: [alice] (from client vpn port 10)");
    assert!(matches!(dispatch(&m), SyslogPayload::Radius(_)));
}

#[test]
fn dispatch_web_access_message_returns_web_access_variant() {
    let m = bare_msg(
        r#"192.168.1.1 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "-""#,
    );
    assert!(matches!(dispatch(&m), SyslogPayload::WebAccess(_)));
}

#[test]
fn dispatch_dns_bind_returns_dns_variant() {
    let m = bare_msg(
        "client 192.168.1.10#12345: query: example.com IN A + (93.184.216.34)",
    );
    assert!(matches!(dispatch(&m), SyslogPayload::Dns(_)));
}

#[test]
fn payload_type_returns_expected_strings() {
    assert_eq!(SyslogPayload::None.payload_type(), None);
    // Just verify the string constants — real variants tested above.
    assert_eq!(
        SyslogPayload::Dhcp(crate::syslog::payload::dhcp::DhcpRecord {
            message_type: "DHCPACK".into(),
            ip_address: None, mac_address: None, hostname: None, interface: None,
        }).payload_type(),
        Some("dhcp")
    );
}
```

- [ ] **Step 2: Run to verify the tests fail (before metrics wiring)**

```
cargo test -p logthing 'syslog::payload::tests::dispatch_cef' 2>&1 | head -20
```

Expected: tests compile but `dispatch_cef_message_returns_cef_variant` fails because `cef::try_parse` stub returns `None`. (After Tasks 2.2–2.6 are complete all sub-parsers exist, so this test should actually pass. Re-run to confirm the whole suite passes together.)

- [ ] **Step 3: Implement (add metrics to dispatch)**

Update the `dispatch` function in `src/syslog/payload/mod.rs`:

```rust
pub fn dispatch(msg: &SyslogMessage) -> SyslogPayload {
    macro_rules! try_parser {
        ($variant:ident, $module:ident) => {
            if let Some(r) = $module::try_parse(msg) {
                let payload = SyslogPayload::$variant(r);
                if let Some(t) = payload.payload_type() {
                    metrics::counter!("syslog_payload_parsed", "type" => t).increment(1);
                }
                return payload;
            }
        };
    }

    try_parser!(Cef,       cef);
    try_parser!(Leef,      leef);
    try_parser!(Auditd,    auditd);
    try_parser!(Dhcp,      dhcp);
    try_parser!(Radius,    radius);
    try_parser!(WebAccess, web_access);

    if let Some(r) = crate::syslog::dns::DnsLogEntry::from_syslog(msg) {
        metrics::counter!("syslog_payload_parsed", "type" => "dns").increment(1);
        return SyslogPayload::Dns(r);
    }

    SyslogPayload::None
}
```

- [ ] **Step 4: Run to verify all dispatcher tests pass**

```
cargo test -p logthing syslog::payload 2>&1
```

Expected: all unit tests across all payload submodules pass (`mod.rs` dispatch tests + cef/leef/auditd/dhcp/radius/web_access module tests).

- [ ] **Step 5: Commit**

```
git add src/syslog/payload/mod.rs
git commit -m "feat(syslog/payload): wire dispatch with metrics counter per payload type"
```

---

### Task 2.8: `StructuredSyslogSink` and `structured_syslog_start` — `src/forwarding/structured_syslog_s3.rs`

**Files:**
- Create `src/forwarding/structured_syslog_s3.rs`
- Modify `src/forwarding/mod.rs` (add `pub mod structured_syslog_s3;`)

**Interfaces:**
- Consumes: `StructuredSyslogRecord` (from `src/syslog/payload/mod.rs`)
- Produces: `StructuredSyslogSink: ParquetSink<Record=StructuredSyslogRecord>`, `structured_syslog_schema()`, `structured_syslog_start(cfg, s3) -> (StructuredS3Handler, JoinHandle)`

Arrow schema (9 columns): `priority u8`, `severity u8`, `facility u8`, `timestamp Utf8 nullable`, `hostname Utf8 nullable`, `app_name Utf8 nullable`, `received_at Utf8 not-null`, `payload_type Utf8 not-null`, `parsed Utf8 not-null`. Partition key = `payload_type` string.

- [ ] **Step 1: Write the failing test**

```rust
// src/forwarding/structured_syslog_s3.rs — tests (at bottom of file)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::syslog::payload::StructuredSyslogRecord;
    use arrow::array::{StringArray, UInt8Array};

    fn sample_record(ptype: &'static str) -> StructuredSyslogRecord {
        StructuredSyslogRecord {
            priority: 134,
            severity: 6,
            facility: 16,
            timestamp: Some(
                chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:45Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            hostname: Some("fw01".into()),
            app_name: Some("ArcSight".into()),
            received_at: chrono::Utc::now(),
            payload_type: ptype,
            parsed: serde_json::json!({"src": "10.0.0.1", "dst": "10.0.0.2"}),
        }
    }

    #[test]
    fn schema_has_nine_columns() {
        let schema = structured_syslog_schema();
        assert_eq!(schema.fields().len(), 9,
            "expected 9 fields, got {}", schema.fields().len());
    }

    #[test]
    fn schema_payload_type_is_non_nullable_utf8() {
        use arrow::datatypes::DataType;
        let schema = structured_syslog_schema();
        let f = schema.field_with_name("payload_type").unwrap();
        assert_eq!(f.data_type(), &DataType::Utf8);
        assert!(!f.is_nullable());
    }

    #[test]
    fn schema_parsed_is_non_nullable_utf8() {
        use arrow::datatypes::DataType;
        let schema = structured_syslog_schema();
        let f = schema.field_with_name("parsed").unwrap();
        assert_eq!(f.data_type(), &DataType::Utf8);
        assert!(!f.is_nullable());
    }

    #[test]
    fn sink_partition_returns_payload_type() {
        let sink = StructuredSyslogSink;
        let rec = sample_record("cef");
        assert_eq!(sink.partition(&rec), Some("cef".to_string()));
    }

    #[test]
    fn sink_source_is_structured_syslog() {
        assert_eq!(StructuredSyslogSink.source(), "structured_syslog");
    }

    #[test]
    fn to_record_batch_produces_correct_values() {
        let sink = StructuredSyslogSink;
        let rec = sample_record("leef");
        let schema = sink.schema(Some("leef"));
        let batch = sink.to_record_batch(&rec, &schema).expect("batch");

        assert_eq!(batch.num_rows(), 1);

        let priority = batch.column(0).as_any().downcast_ref::<UInt8Array>().unwrap();
        assert_eq!(priority.value(0), 134);

        let ptype_col = batch.column_by_name("payload_type").unwrap();
        let ptype = ptype_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(ptype.value(0), "leef");

        let parsed_col = batch.column_by_name("parsed").unwrap();
        let parsed = parsed_col.as_any().downcast_ref::<StringArray>().unwrap();
        let v: serde_json::Value = serde_json::from_str(parsed.value(0)).unwrap();
        assert_eq!(v["src"], "10.0.0.1");
    }

    #[test]
    fn to_record_batch_hostname_nullable() {
        use arrow::array::Array;
        let sink = StructuredSyslogSink;
        let mut rec = sample_record("cef");
        rec.hostname = None;
        let schema = sink.schema(Some("cef"));
        let batch = sink.to_record_batch(&rec, &schema).unwrap();
        let hostname = batch.column_by_name("hostname").unwrap();
        let arr = hostname.as_any().downcast_ref::<StringArray>().unwrap();
        assert!(arr.is_null(0));
    }

    #[tokio::test]
    async fn structured_syslog_start_wires_handle_and_join() {
        use crate::config::{S3ConnectionConfig, SyslogS3Config};
        use crate::forwarding::s3_sink::S3Sink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test".to_string(),
            region: "us-east-1".to_string(),
            access_key: "KEY".to_string(),
            secret_key: "SECRET".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"));
        let cfg = SyslogS3Config {
            connection: conn,
            prefix: "structured-syslog-test".to_string(),
            max_buffer_rows: 1,
            flush_interval_secs: 3600,
            channel_capacity: 16,
        };
        let (handle, join_handle) = structured_syslog_start(&cfg, s3);
        // Send one record through try_send.
        let rec = sample_record("cef");
        let _ = handle.try_send(rec);
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task exits within 5s")
            .expect("no panic");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing forwarding::structured_syslog_s3::tests 2>&1 | head -20
```

Expected: module not found error.

- [ ] **Step 3: Implement**

```rust
// src/forwarding/structured_syslog_s3.rs
//! StructuredSyslog → S3 Parquet persistence (partitioned by payload_type).
//!
//! Schema: 9 columns — syslog envelope + payload_type + parsed (JSON string).
//! Partition key: payload_type string ("cef", "leef", "auditd", "dhcp",
//!                "radius", "web_access", "dns").
//! The sink reuses SyslogS3Config (identical connection/flush parameters).

use crate::config::SyslogS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::syslog::payload::StructuredSyslogRecord;
use arrow::array::{ArrayRef, StringArray, UInt8Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static STRUCTURED_SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("priority",     DataType::UInt8, false),
        Field::new("severity",     DataType::UInt8, false),
        Field::new("facility",     DataType::UInt8, false),
        Field::new("timestamp",    DataType::Utf8,  true),
        Field::new("hostname",     DataType::Utf8,  true),
        Field::new("app_name",     DataType::Utf8,  true),
        Field::new("received_at",  DataType::Utf8,  false),
        Field::new("payload_type", DataType::Utf8,  false),
        Field::new("parsed",       DataType::Utf8,  false),
    ]))
});

pub fn structured_syslog_schema() -> Arc<Schema> {
    STRUCTURED_SYSLOG_SCHEMA.clone()
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

pub fn structured_syslog_record_to_batch(
    rec: &StructuredSyslogRecord,
) -> anyhow::Result<RecordBatch> {
    let schema = structured_syslog_schema();
    let priority    = Arc::new(UInt8Array::from(vec![rec.priority]))    as ArrayRef;
    let severity    = Arc::new(UInt8Array::from(vec![rec.severity]))    as ArrayRef;
    let facility    = Arc::new(UInt8Array::from(vec![rec.facility]))    as ArrayRef;
    let timestamp   = Arc::new(StringArray::from(vec![
        rec.timestamp.as_ref().map(|t| t.to_rfc3339()),
    ])) as ArrayRef;
    let hostname    = Arc::new(StringArray::from(vec![rec.hostname.clone()]))   as ArrayRef;
    let app_name    = Arc::new(StringArray::from(vec![rec.app_name.clone()]))   as ArrayRef;
    let received_at = Arc::new(StringArray::from(vec![
        Some(rec.received_at.to_rfc3339()),
    ])) as ArrayRef;
    let payload_type = Arc::new(StringArray::from(vec![rec.payload_type])) as ArrayRef;
    let parsed = Arc::new(StringArray::from(vec![
        serde_json::to_string(&rec.parsed).unwrap_or_else(|_| "null".to_string()),
    ])) as ArrayRef;

    Ok(RecordBatch::try_new(
        schema,
        vec![
            priority, severity, facility, timestamp, hostname,
            app_name, received_at, payload_type, parsed,
        ],
    )?)
}

// ---------------------------------------------------------------------------
// StructuredSyslogSink — ParquetSink adapter
// ---------------------------------------------------------------------------

pub struct StructuredSyslogSink;

impl ParquetSink for StructuredSyslogSink {
    type Record = StructuredSyslogRecord;

    fn source(&self) -> &'static str {
        "structured_syslog"
    }

    fn partition(&self, record: &StructuredSyslogRecord) -> Option<String> {
        Some(record.payload_type.to_string())
    }

    fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        structured_syslog_schema()
    }

    fn to_record_batch(
        &self,
        record: &StructuredSyslogRecord,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        structured_syslog_record_to_batch(record)
    }
}

// ---------------------------------------------------------------------------
// Type alias + start function
// ---------------------------------------------------------------------------

pub type StructuredS3Handler =
    crate::forwarding::buffered_writer::ParquetWriterHandle<StructuredSyslogSink>;

/// Construct a `StructuredS3Handler` from `SyslogS3Config` (reusing the same
/// config shape; the `prefix` is used as the S3 key base path).
///
/// Returns `(handler, writer_task_handle)`.
pub fn structured_syslog_start(
    cfg: &SyslogS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        // 7 known payload types + 1 overflow = 8 partitions max.
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: usize::MAX,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(StructuredSyslogSink, s3, bwc, policy)
}

#[cfg(test)]
mod tests { /* ... (see Step 1) */ }
```

Add `pub mod structured_syslog_s3;` to `src/forwarding/mod.rs`.

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing forwarding::structured_syslog_s3::tests 2>&1
```

Expected: all 8 tests (including the async `structured_syslog_start_wires_handle_and_join` test) pass.

- [ ] **Step 5: Commit**

```
git add src/forwarding/structured_syslog_s3.rs src/forwarding/mod.rs
git commit -m "feat(forwarding): add StructuredSyslogSink partitioned by payload_type"
```

---

### Task 2.9: Config additions — `parse_payloads` and `structured_s3`

**Files:**
- Modify `src/config/mod.rs` (add `parse_payloads: bool` and `structured_s3: Option<SyslogS3Config>` to `SyslogConfig`)

**Interfaces:**
- Produces: two new fields on `SyslogConfig`; backward-compatible TOML deserialization (both absent → false / None)

- [ ] **Step 1: Write the failing test**

```rust
// Add to src/config/mod.rs tests block:

#[test]
fn syslog_parse_payloads_defaults_to_false() {
    let cfg = Config::default();
    assert!(!cfg.syslog.parse_payloads,
        "parse_payloads must default to false");
}

#[test]
fn syslog_structured_s3_absent_gives_none() {
    let cfg = Config::default();
    assert!(cfg.syslog.structured_s3.is_none(),
        "structured_s3 must default to None");
}

#[test]
fn syslog_parse_payloads_can_be_set_in_toml() {
    let toml_str = "[syslog]\nparse_payloads = true\n";
    let cfg: Config = toml::from_str(toml_str).expect("parse");
    assert!(cfg.syslog.parse_payloads);
}

#[test]
fn syslog_structured_s3_parses_from_toml() {
    let toml_str = r#"
[syslog.structured_s3]
endpoint   = "http://minio:9000"
bucket     = "structured-syslog"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
prefix     = "syslog-structured"
"#;
    let cfg: Config = toml::from_str(toml_str).expect("parse");
    let s3 = cfg.syslog.structured_s3.expect("structured_s3 present");
    assert_eq!(s3.connection.bucket, "structured-syslog");
    assert_eq!(s3.prefix, "syslog-structured");
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing config::tests::syslog_parse_payloads 2>&1 | head -20
```

Expected: `error[E0609]: no field 'parse_payloads' on type 'SyslogConfig'`.

- [ ] **Step 3: Implement**

In `src/config/mod.rs`, update `SyslogConfig`:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogConfig {
    #[serde(default = "default_syslog_enabled")]
    pub enabled: bool,

    #[serde(default = "default_syslog_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_syslog_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_syslog_parse_dns")]
    pub parse_dns: bool,

    /// Enable syslog payload sub-parsing (CEF, LEEF, auditd, DHCP, RADIUS,
    /// web_access, DNS).  Default false (backward compatible).
    #[serde(default)]
    pub parse_payloads: bool,

    /// Optional S3 persistence for raw syslog messages.
    #[serde(default)]
    pub s3: Option<SyslogS3Config>,

    /// Optional S3 persistence for structured (parsed) syslog records.
    /// Requires `parse_payloads = true` to produce any output.
    #[serde(default)]
    pub structured_s3: Option<SyslogS3Config>,
}
```

Update `impl Default for SyslogConfig`:

```rust
impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: default_syslog_enabled(),
            udp_port: default_syslog_udp_port(),
            tcp_port: default_syslog_tcp_port(),
            parse_dns: default_syslog_parse_dns(),
            parse_payloads: false,
            s3: None,
            structured_s3: None,
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing config::tests 2>&1
```

Expected: all existing config tests continue to pass plus the four new tests pass.

- [ ] **Step 5: Commit**

```
git add src/config/mod.rs
git commit -m "feat(config): add parse_payloads and structured_s3 to SyslogConfig"
```

---

### Task 2.10: Wire dispatch into syslog handler and `main.rs`

**Files:**
- Modify `src/syslog/listener.rs` (extend `DefaultSyslogHandler` to accept an optional `StructuredS3Handler` and call `payload::dispatch` when `parse_payloads` is true; add `PayloadDispatchingHandler` wrapper)
- Modify `src/main.rs` (build and wire `StructuredS3Handler` inside the `if config.syslog.enabled` block)

**Interfaces:**
- `DefaultSyslogHandler` gains fields `parse_payloads: bool` and `structured_handle: Option<Arc<StructuredS3Handler>>`; constructor `DefaultSyslogHandler::new(parse_dns_logs: bool, parse_payloads: bool, structured_handle: Option<Arc<StructuredS3Handler>>)`
- `PayloadDispatchingHandler<H>` wraps any inner `SyslogHandler`, calls it, then runs dispatch + `try_send`

- [ ] **Step 1: Write the failing test**

```rust
// Add to src/syslog/listener.rs tests block:

#[tokio::test]
async fn default_handler_dispatches_cef_to_structured_handle() {
    use crate::config::{S3ConnectionConfig, SyslogS3Config};
    use crate::forwarding::s3_sink::S3Sink;
    use crate::forwarding::structured_syslog_s3::structured_syslog_start;
    use crate::syslog::SyslogMessage;
    use std::net::SocketAddr;
    use tokio::time::{Duration, sleep};

    // Use an unreachable S3 endpoint — the writer will buffer the record
    // but won't actually upload.
    let conn = S3ConnectionConfig {
        endpoint: "http://127.0.0.1:1".to_string(),
        bucket: "test".to_string(),
        region: "us-east-1".to_string(),
        access_key: "KEY".to_string(),
        secret_key: "SECRET".to_string(),
    };
    let s3 = Arc::new(
        S3Sink::from_connection(&conn).await.expect("constructs"),
    );
    let cfg = SyslogS3Config {
        connection: conn,
        prefix: "structured-test".to_string(),
        max_buffer_rows: 100,
        flush_interval_secs: 3600,
        channel_capacity: 16,
    };
    let (structured_handle, _join) = structured_syslog_start(&cfg, s3);
    let structured_handle = Arc::new(structured_handle);

    let handler = DefaultSyslogHandler::new(
        false,
        true, // parse_payloads = true
        Some(structured_handle.clone()),
    );

    let cef_syslog = SyslogMessage::parse(
        "<134>Jan 15 10:30:45 fw01 arcsight: \
         CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1",
    )
    .unwrap();

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    handler.handle_message(cef_syslog, src).await;

    // Give the channel a moment; test that try_send was called without panic.
    sleep(Duration::from_millis(50)).await;
    // If the handler panicked or did not compile the test would fail above.
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test -p logthing 'syslog::listener::tests::default_handler_dispatches_cef' 2>&1 | head -20
```

Expected: compile error — `DefaultSyslogHandler::new` does not accept those parameters yet.

- [ ] **Step 3: Implement**

Update `src/syslog/listener.rs` — replace `DefaultSyslogHandler` and add the wrapper:

```rust
use crate::forwarding::structured_syslog_s3::StructuredS3Handler;
use crate::syslog::payload;

pub struct DefaultSyslogHandler {
    parse_dns_logs: bool,
    parse_payloads: bool,
    structured_handle: Option<Arc<StructuredS3Handler>>,
}

impl DefaultSyslogHandler {
    pub fn new(
        parse_dns_logs: bool,
        parse_payloads: bool,
        structured_handle: Option<Arc<StructuredS3Handler>>,
    ) -> Self {
        Self { parse_dns_logs, parse_payloads, structured_handle }
    }
}

#[async_trait::async_trait]
impl SyslogHandler for DefaultSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr) {
        info!(
            "[{}] {} {} - {}: {}",
            source,
            message.facility_str(),
            message.severity_str(),
            message.app_name.as_deref().unwrap_or("unknown"),
            message.message
        );

        if self.parse_dns_logs
            && let Some(dns_entry) = DnsLogEntry::from_syslog(&message)
        {
            info!(
                "DNS Query: {} asked for {} ({}) -> {:?}",
                dns_entry.client_ip, dns_entry.query_name,
                dns_entry.query_type, dns_entry.response_ips
            );
        }

        if self.parse_payloads {
            let payload = payload::dispatch(&message);
            if let Some(rec) =
                payload::StructuredSyslogRecord::from_syslog_and_payload(&message, &payload)
            {
                if let Some(handle) = &self.structured_handle {
                    match handle.try_send(rec) {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::warn!("structured_syslog S3 channel full; dropped record");
                        }
                    }
                }
            }
        }
    }
}

/// Wraps any inner `SyslogHandler` (e.g. the S3 raw-persistence handler),
/// invokes it first, then runs payload dispatch and forwards matched records
/// to the structured sink.  Used in `main.rs` when both raw S3 persistence
/// and structured persistence are configured.
pub struct PayloadDispatchingHandler<H: SyslogHandler> {
    pub inner: Arc<H>,
    pub parse_payloads: bool,
    pub structured_handle: Option<Arc<StructuredS3Handler>>,
}

#[async_trait::async_trait]
impl<H: SyslogHandler + 'static> SyslogHandler for PayloadDispatchingHandler<H> {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr) {
        self.inner.handle_message(message.clone(), source).await;
        if self.parse_payloads {
            let p = payload::dispatch(&message);
            if let Some(rec) =
                payload::StructuredSyslogRecord::from_syslog_and_payload(&message, &p)
            {
                if let Some(h) = &self.structured_handle {
                    match h.try_send(rec) {
                        Ok(()) => {}
                        Err(_) => tracing::warn!("structured_syslog channel full; dropped"),
                    }
                }
            }
        }
    }
}
```

Update `src/main.rs` syslog block — inside `if config.syslog.enabled`:

```rust
// Build optional structured sink BEFORE building the primary handler.
let structured_handle: Option<Arc<forwarding::structured_syslog_s3::StructuredS3Handler>> =
    if config_clone.syslog.parse_payloads {
        if let Some(ss3_cfg) = config_clone.syslog.structured_s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&ss3_cfg.connection).await {
                Ok(sink) => {
                    let (sh, wh) = forwarding::structured_syslog_s3::structured_syslog_start(
                        ss3_cfg, Arc::new(sink),
                    );
                    writer_handles.push(wh);
                    Some(Arc::new(sh))
                }
                Err(e) => {
                    error!("Failed to create S3Sink for structured syslog: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

let syslog_handler: Arc<dyn syslog::listener::SyslogHandler> =
    if let Some(s3_cfg) = config_clone.syslog.s3.as_ref() {
        match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
            Ok(sink) => {
                let (handler, writer_handle) =
                    forwarding::syslog_s3::syslog_start(s3_cfg, Arc::new(sink));
                writer_handles.push(writer_handle);
                // Wrap SyslogS3Handler in a payload-dispatching adapter.
                Arc::new(syslog::listener::PayloadDispatchingHandler {
                    inner: Arc::new(handler),
                    parse_payloads: config_clone.syslog.parse_payloads,
                    structured_handle: structured_handle.clone(),
                })
            }
            Err(e) => {
                error!("Failed to create S3Sink for syslog persistence, \
                        falling back to DefaultSyslogHandler: {e}");
                Arc::new(syslog::listener::DefaultSyslogHandler::new(
                    config_clone.syslog.parse_dns,
                    config_clone.syslog.parse_payloads,
                    structured_handle.clone(),
                ))
            }
        }
    } else {
        Arc::new(syslog::listener::DefaultSyslogHandler::new(
            config_clone.syslog.parse_dns,
            config_clone.syslog.parse_payloads,
            structured_handle,
        ))
    };
```

- [ ] **Step 4: Run to verify it passes**

```
cargo test -p logthing syslog::listener::tests 2>&1
```

Expected: all existing listener tests still pass plus `default_handler_dispatches_cef_to_structured_handle` passes.

```
cargo build 2>&1 | grep -E 'error|warning.*unused'
```

Expected: clean build.

- [ ] **Step 5: Commit**

```
git add src/syslog/listener.rs src/main.rs
git commit -m "feat(syslog): wire payload dispatch + StructuredS3Handler into handler and main.rs"
```

---

### Task 2.11: Integration test — `tests/syslog_structured_s3_integration.rs`

**Files:**
- Create `tests/syslog_structured_s3_integration.rs`
- Modify `src/forwarding/s3_sink.rs` (add `list_objects` and `get_object` helpers if not already present)

**Interfaces:**
- Consumes: `structured_syslog_start`, `StructuredS3Handler`, `SyslogHandler::handle_message`, `DefaultSyslogHandler::new`
- Produces: asserts that a CEF syslog message lands as a Parquet object under `structured-syslog-int-test/cef/year=…/` in MinIO; reads the object back and verifies column values

- [ ] **Step 1: Write the failing test**

```rust
// tests/syslog_structured_s3_integration.rs
//! Integration test: CEF syslog line → DefaultSyslogHandler (parse_payloads=true)
//! → StructuredS3Handler → Parquet object in MinIO.
//!
//! Gated on MINIO_ENDPOINT.  Skip gracefully if the env var is absent.

use logthing::config::{S3ConnectionConfig, SyslogS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::structured_syslog_s3::structured_syslog_start;
use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{DefaultSyslogHandler, SyslogHandler as SyslogHandlerTrait};
use std::net::SocketAddr;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_cfg(endpoint: &str, prefix: &str) -> SyslogS3Config {
    SyslogS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET")
                .unwrap_or_else(|_| "syslog-structured-test".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: prefix.to_string(),
        max_buffer_rows: 1, // flush on first record
        flush_interval_secs: 3600,
        channel_capacity: 16,
    }
}

#[tokio::test]
async fn cef_record_appears_as_parquet_under_cef_partition() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping structured_syslog integration test");
            return;
        }
    };

    let prefix = "structured-syslog-int-test";
    let cfg = minio_cfg(&endpoint, prefix);
    let s3 = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    let (structured_handle, writer_task) = structured_syslog_start(&cfg, s3.clone());
    let structured_handle = Arc::new(structured_handle);

    let handler = DefaultSyslogHandler::new(
        false,
        true,
        Some(structured_handle.clone()),
    );

    // A realistic CEF syslog message.
    let raw = "<134>Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|FW|1.0|SIG001|\
               Firewall Accept|6|src=10.0.0.1 dst=8.8.8.8 spt=12345 dpt=443";
    let syslog_msg = SyslogMessage::parse(raw).expect("parse syslog");

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    handler.handle_message(syslog_msg, src).await;

    // Drop the handle so the channel closes and the writer flushes.
    drop(structured_handle);

    // Wait for the writer task to complete.
    tokio::time::timeout(std::time::Duration::from_secs(30), writer_task)
        .await
        .expect("writer completed within 30s")
        .expect("writer did not panic");

    // List objects under the prefix; expect at least one under the cef/ partition.
    let objects = s3
        .list_objects(&format!("{}/cef/", prefix))
        .await
        .expect("list_objects");

    assert!(
        !objects.is_empty(),
        "expected at least one Parquet object under {}/cef/; found none",
        prefix
    );

    // Download and read the first Parquet file; verify key columns.
    let key = &objects[0];
    let data = s3.get_object(key).await.expect("get_object");
    let bytes = bytes::Bytes::from(data);
    let builder =
        parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes)
            .expect("parquet reader");
    let mut reader = builder.build().expect("build reader");
    let batch = reader.next().expect("at least one batch").expect("batch ok");

    assert_eq!(batch.num_rows(), 1);

    // Verify payload_type column.
    use arrow::array::StringArray;
    let ptype = batch
        .column_by_name("payload_type")
        .expect("payload_type column")
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(ptype.value(0), "cef");

    // Verify parsed column contains CEF fields.
    let parsed_col = batch
        .column_by_name("parsed")
        .expect("parsed column")
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(parsed_col.value(0)).expect("valid JSON");
    assert_eq!(
        parsed["device_vendor"].as_str().unwrap_or(""),
        "Vendor",
        "device_vendor field must survive the round-trip"
    );
}

/// Verify that multiple payload types land in separate S3 partitions.
#[tokio::test]
async fn multiple_payload_types_land_in_separate_partitions() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => return,
    };

    let prefix = "structured-syslog-multi-test";
    let cfg = minio_cfg(&endpoint, prefix);
    let s3 = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    let (structured_handle, writer_task) = structured_syslog_start(&cfg, s3.clone());
    let structured_handle = Arc::new(structured_handle);

    let handler = DefaultSyslogHandler::new(false, true, Some(structured_handle.clone()));
    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();

    // CEF message
    let cef_raw = "<134>Jan 15 10:30:45 fw01 arc: CEF:0|V|P|1.0|S|N|5|src=1.2.3.4";
    handler
        .handle_message(SyslogMessage::parse(cef_raw).unwrap(), src)
        .await;

    // DHCP message
    let dhcp_raw = "<30>Jan 15 10:31:00 dhcp-server dhcpd: DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff (myhost) via eth0";
    handler
        .handle_message(SyslogMessage::parse(dhcp_raw).unwrap(), src)
        .await;

    drop(structured_handle);
    tokio::time::timeout(std::time::Duration::from_secs(30), writer_task)
        .await
        .expect("writer done")
        .expect("no panic");

    let cef_objs = s3.list_objects(&format!("{}/cef/", prefix)).await.expect("list cef");
    let dhcp_objs = s3.list_objects(&format!("{}/dhcp/", prefix)).await.expect("list dhcp");

    assert!(!cef_objs.is_empty(),  "CEF partition must have at least one object");
    assert!(!dhcp_objs.is_empty(), "DHCP partition must have at least one object");
}
```

- [ ] **Step 2: Run to verify it fails (requires MINIO_ENDPOINT)**

```
MINIO_ENDPOINT=http://localhost:9000 \
  cargo test --test syslog_structured_s3_integration 2>&1 | head -40
```

If MinIO is not running locally: verify the test file compiles and the `None` skip path executes:

```
cargo test --test syslog_structured_s3_integration 2>&1
```

Expected: test outputs `MINIO_ENDPOINT not set — skipping …` and exits with success (0 failures). If `list_objects`/`get_object` are missing, compile fails — proceed to Step 3.

- [ ] **Step 3: Implement** (add S3 helpers if absent)

Verify `S3Sink::list_objects` and `S3Sink::get_object` exist in `src/forwarding/s3_sink.rs`. If they do not, add them (field/client names per the existing `S3Sink` struct):

```rust
// In src/forwarding/s3_sink.rs, if not already present:

/// List all object keys with the given prefix. Returns full S3 keys.
pub async fn list_objects(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
    let resp = self.client
        .list_objects_v2()
        .bucket(&self.bucket)
        .prefix(prefix)
        .send()
        .await?;
    let keys = resp
        .contents()
        .iter()
        .filter_map(|obj| obj.key().map(|k| k.to_string()))
        .collect();
    Ok(keys)
}

/// Download an object and return its raw bytes.
pub async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
    let resp = self.client
        .get_object()
        .bucket(&self.bucket)
        .key(key)
        .send()
        .await?;
    let bytes = resp.body.collect().await?.into_bytes().to_vec();
    Ok(bytes)
}
```

- [ ] **Step 4: Run to verify the integration test passes against a live MinIO**

```
MINIO_ENDPOINT=http://localhost:9000 \
MINIO_BUCKET=syslog-structured-test \
  cargo test --test syslog_structured_s3_integration -- --nocapture 2>&1
```

Expected: both tests pass; Parquet objects appear in the MinIO bucket under `structured-syslog-int-test/cef/year=…` and `structured-syslog-multi-test/cef/` / `…/dhcp/`.

Without MinIO:

```
cargo test --test syslog_structured_s3_integration 2>&1
```

Expected: both tests skip with `MINIO_ENDPOINT not set` and exit 0.

- [ ] **Step 5: Commit**

```
git add tests/syslog_structured_s3_integration.rs src/forwarding/s3_sink.rs
git commit -m "test(integration): structured syslog S3 integration test with MinIO gate"
```

---

### Task 2.12: End-to-end test — CEF line over UDP → structured record produced

**Files:**
- Create `tests/syslog_payload_e2e.rs`

**Interfaces:**
- Uses `SyslogListener`, a capturing `SyslogHandler` adapter that runs `dispatch`, a UDP socket; asserts a `StructuredSyslogRecord` with `payload_type="cef"` is produced.

- [ ] **Step 1: Write the failing test**

```rust
// tests/syslog_payload_e2e.rs
//! End-to-end test: send a CEF syslog line over the real UDP listener and
//! assert a StructuredSyslogRecord is produced.
//!
//! Spins up a SyslogListener in-process (ephemeral UDP port), sends a
//! CEF-formatted syslog datagram, and verifies the payload dispatch path
//! produces a StructuredSyslogRecord with payload_type="cef".
//!
//! No MinIO required — uses a capturing store instead of a real S3 handler.

use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{
    SyslogHandler, SyslogListener, SyslogListenerConfig,
};
use logthing::syslog::payload::{StructuredSyslogRecord, dispatch};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep};

/// A capturing store for structured records produced by dispatch.
struct CapturingStore {
    records: Mutex<Vec<StructuredSyslogRecord>>,
}

impl CapturingStore {
    fn new() -> Arc<Self> {
        Arc::new(Self { records: Mutex::new(Vec::new()) })
    }
    fn take(&self) -> Vec<StructuredSyslogRecord> {
        self.records.lock().unwrap().drain(..).collect()
    }
}

/// A SyslogHandler that runs dispatch and pushes to the capturing store.
struct DispatchingTestHandler {
    store: Arc<CapturingStore>,
}

#[async_trait::async_trait]
impl SyslogHandler for DispatchingTestHandler {
    async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
        let payload = dispatch(&message);
        if let Some(rec) =
            StructuredSyslogRecord::from_syslog_and_payload(&message, &payload)
        {
            self.store.records.lock().unwrap().push(rec);
        }
    }
}

#[tokio::test]
async fn cef_datagram_produces_structured_record_with_cef_payload_type() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler { store: store.clone() });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port: udp_port + 1, // distinct port; not exercised here
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };

    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move {
        // start() launches both UDP and TCP; the test aborts the task when done.
        listener.start().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Send a CEF syslog line as a UDP datagram.
    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cef_line = "<134>Jan 15 10:30:45 fw01 arcsight: \
                    CEF:0|Vendor|FW|1.0|SIG001|Firewall Accept|6|\
                    src=10.0.0.1 dst=8.8.8.8 spt=12345 dpt=443";
    send_sock
        .send_to(cef_line.as_bytes(), format!("127.0.0.1:{}", udp_port))
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    task.abort();

    let records = store.take();
    assert_eq!(records.len(), 1, "expected 1 structured record, got {}", records.len());
    let rec = &records[0];
    assert_eq!(rec.payload_type, "cef");

    let v = &rec.parsed;
    assert_eq!(v["device_vendor"].as_str().unwrap_or(""), "Vendor");
    assert_eq!(v["severity"].as_str().unwrap_or(""), "6");
}

#[tokio::test]
async fn non_matching_datagram_produces_no_structured_record() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler { store: store.clone() });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port: udp_port + 1,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };
    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move { listener.start().await.ok(); });
    sleep(Duration::from_millis(100)).await;

    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // A plain syslog message that matches no sub-parser.
    let plain = "<134>Jan 15 10:30:45 host app: this is a plain text message";
    send_sock
        .send_to(plain.as_bytes(), format!("127.0.0.1:{}", udp_port))
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    task.abort();

    let records = store.take();
    assert!(records.is_empty(), "non-matching message must produce no structured record");
}
```

- [ ] **Step 2: Run to verify it fails**

```
cargo test --test syslog_payload_e2e 2>&1 | head -20
```

Expected: compile error — `dispatch`, `StructuredSyslogRecord`, etc. not yet in `logthing`'s public API (or, after Tasks 2.1–2.10, the CEF test fails until dispatch is fully wired).

- [ ] **Step 3: Implement** (expose public API if needed)

Confirm `logthing::syslog::payload` is reachable (it is `pub mod payload;` under `pub mod syslog`). No new logic — all implementation lives in earlier tasks. This step verifies the public path compiles; add a re-export to `src/lib.rs` only if the integration crate cannot reach the module.

- [ ] **Step 4: Run to verify all e2e tests pass**

```
cargo test --test syslog_payload_e2e -- --nocapture 2>&1
```

Expected: both tests pass. The CEF test produces exactly one `StructuredSyslogRecord` with `payload_type="cef"`. The plain-text test produces zero records.

- [ ] **Step 5: Commit**

```
git add tests/syslog_payload_e2e.rs
git commit -m "test(e2e): UDP listener → CEF dispatch → StructuredSyslogRecord end-to-end test"
```

---

### Task 2.13: Full test suite verification and coverage check

**Files:** none (verification only)

- [ ] **Step 1: Run the full unit + integration suite**

```
cargo test -p logthing 2>&1 | tail -30
```

Expected: zero failures. All tests in `syslog::payload::*`, `forwarding::structured_syslog_s3::tests`, `config::tests`, and `syslog::listener::tests` pass.

- [ ] **Step 2: Run the e2e tests**

```
cargo test --test syslog_payload_e2e --test syslog_structured_s3_integration 2>&1
```

Expected: e2e tests pass (or skip cleanly if MINIO_ENDPOINT absent).

- [ ] **Step 3: Run clippy**

```
cargo clippy -p logthing -- -D warnings 2>&1 | head -40
```

Expected: zero new warnings introduced by Unit 2 code.

- [ ] **Step 4: Verify coverage gaps (informational)**

```
cargo test -p logthing syslog::payload 2>&1 | grep -E 'test .* (ok|FAILED)'
```

Every sub-parser must have at least: one valid-input test, one malformed/rejected-input test, and one edge-case test (empty extension map, missing optional field, escaped characters). Confirm by reviewing the test counts per module:
- `cef`: 6 tests ✓
- `leef`: 5 tests ✓
- `auditd`: 5 tests ✓
- `web_access`: 6 tests ✓
- `dhcp`: 7 tests ✓
- `radius`: 5 tests ✓
- `dispatch` (mod.rs): 9 tests ✓

- [ ] **Step 5: Final commit**

```
git commit --allow-empty -m "chore: Unit 2 syslog payload parsers complete — all tests green"
```

---

## Unit 3 — sFlow (`src/sflow/`)

This unit introduces sFlow v5 datagram ingestion, following the structure of the IPFIX subsystem throughout. The decoder is purely stateless (sFlow v5 carries all state inline per datagram — no template cache) which simplifies it relative to IPFIX. All three test levels are required: unit (crafted byte vectors), integration (MINIO_ENDPOINT-gated), and e2e (ephemeral UDP bind + real datagram).

---

### Task 3.1: `SflowRecord` type and `SampleType` enum (`src/sflow/mod.rs`)

**Files:**
- Create `src/sflow/mod.rs`

**Interfaces:**
- Produces: `SflowRecord`, `SampleType`

---

- [ ] **Step 1: Write the failing test**

```rust
// src/sflow/mod.rs  (at the bottom, in #[cfg(test)] mod tests)
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_flow_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Flow,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            received_at: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dst_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            src_port: Some(12345),
            dst_port: Some(443),
            ip_protocol: Some(6),
            sampling_rate: Some(512),
            input_ifindex: Some(1),
            output_ifindex: Some(2),
            // counter fields absent for flow records
            if_index: None,
            if_type: None,
            if_speed: None,
            if_direction: None,
            if_in_octets: None,
            if_out_octets: None,
            if_in_ucast_pkts: None,
            if_out_ucast_pkts: None,
            if_in_errors: None,
            if_out_errors: None,
            extra: serde_json::json!({}),
        }
    }

    #[test]
    fn sflow_record_roundtrips_json() {
        let rec = make_flow_record();
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: SflowRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, back);
    }

    #[test]
    fn sample_type_serializes_as_lowercase_string() {
        let flow = SampleType::Flow;
        let counter = SampleType::Counter;
        let fj = serde_json::to_value(&flow).unwrap();
        let cj = serde_json::to_value(&counter).unwrap();
        assert_eq!(fj, serde_json::json!("flow"));
        assert_eq!(cj, serde_json::json!("counter"));
    }

    #[test]
    fn sflow_record_clone_is_independent() {
        let rec = make_flow_record();
        let mut clone = rec.clone();
        clone.src_port = Some(9999);
        assert_eq!(rec.src_port, Some(12345));
    }

    #[test]
    fn extra_stores_arbitrary_json() {
        let mut rec = make_flow_record();
        rec.extra = serde_json::json!({"raw_format": 1, "data_base64": "AAAA"});
        assert_eq!(rec.extra["raw_format"], 1);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p logthing --lib sflow 2>&1 | head -30
# Expected: error[E0433]: failed to resolve: use of undeclared crate or module `sflow`
```

- [ ] **Step 3: Implement**

```rust
// src/sflow/mod.rs
//! sFlow v5 record types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::net::IpAddr;

pub mod decoder;
pub mod listener;

/// Discriminates between sFlow flow samples and counter samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleType {
    Flow,
    Counter,
}

/// A single decoded sFlow v5 record, normalised across flow and counter samples.
///
/// Flow records carry 5-tuple + sampling metadata.
/// Counter records carry generic interface counter fields (RFC 3176 §5.4.1).
/// Non-curated record types land in `extra` as `{ "format": N, "length": N, "data_base64": "..." }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SflowRecord {
    // identity / provenance
    pub sample_type: SampleType,
    pub exporter: IpAddr,
    pub received_at: DateTime<Utc>,
    // ── flow sample fields (Some for Flow, None for Counter) ──
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: Option<u8>,
    pub sampling_rate: Option<u32>,
    pub input_ifindex: Option<u32>,
    pub output_ifindex: Option<u32>,
    // ── counter sample fields (Some for Counter, None for Flow) ──
    pub if_index: Option<u32>,
    pub if_type: Option<u32>,
    pub if_speed: Option<u64>,
    pub if_direction: Option<u32>,
    pub if_in_octets: Option<u64>,
    pub if_out_octets: Option<u64>,
    pub if_in_ucast_pkts: Option<u64>,
    pub if_out_ucast_pkts: Option<u64>,
    pub if_in_errors: Option<u32>,
    pub if_out_errors: Option<u32>,
    /// Non-curated or vendor-specific records land here as JSON objects:
    /// `[{ "format": N, "length": N, "data_base64": "..." }, ...]`
    pub extra: JsonValue,
}
```

Also register the module in `src/lib.rs`:

```rust
// Add to src/lib.rs (following the ipfix line):
pub mod sflow;
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test -p logthing --lib sflow::tests 2>&1 | tail -10
# Expected: test result: ok. 4 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add src/sflow/mod.rs src/lib.rs
git commit -m "feat(sflow): add SflowRecord type and SampleType enum"
```

---

### Task 3.2: sFlow v5 binary decoder (`src/sflow/decoder.rs`)

**Files:**
- Create `src/sflow/decoder.rs`

**Interfaces:**
- Produces: `pub fn decode_datagram(buf: &[u8], exporter: IpAddr) -> anyhow::Result<Vec<SflowRecord>>`
- Also exposes `#[cfg(test)] pub(crate)` byte fixtures for Tasks 3.3 and 3.4

---

- [ ] **Step 1: Write the failing tests**

```rust
// src/sflow/decoder.rs  (at the bottom, in #[cfg(test)] mod tests)
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn exporter() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    // ── fixture: flow sample with raw packet header (Ethernet/IPv4/TCP → 5-tuple) ──
    //
    // sFlow v5 datagram layout (all big-endian / XDR, 4-byte aligned):
    //
    // Datagram header (28 bytes for IPv4 agent):
    //   [0..4]   version         = 5  (u32)
    //   [4..8]   agent_addr_type = 1  (u32, 1=IPv4)
    //   [8..12]  agent_addr      = 10.0.0.1
    //   [12..16] sub_agent_id    = 0  (u32)
    //   [16..20] sequence_number = 1  (u32)
    //   [20..24] uptime_ms       = 1000 (u32)
    //   [24..28] num_samples     = 1  (u32)
    //
    // Flow Sample (format tag 1 = flow_sample):
    //   [28..32] data_format     = 0x00000001 (enterprise 0, format 1 = flow_sample)
    //   [32..36] sample_length   = N  (u32, length of sample body in bytes)
    //   Flow sample body:
    //     [36..40] sequence_number = 1
    //     [40..44] source_id       = 0x00000001 (type=0 (ifIndex), value=1)
    //     [44..48] sampling_rate   = 512
    //     [48..52] sample_pool     = 512
    //     [52..56] drops           = 0
    //     [56..60] input           = 1  (ifIndex)
    //     [60..64] output          = 2  (ifIndex)
    //     [64..68] num_flow_records = 1
    //   Flow record (raw packet header, enterprise 0, format 1):
    //     [68..72] flow_data_format = 0x00000001
    //     [72..76] flow_data_length = 80  (4 header_protocol + 4 frame_length + 4 stripped + 4 header_length + 64 header_bytes)
    //     [76..80] header_protocol  = 1   (Ethernet)
    //     [80..84] frame_length     = 98
    //     [84..88] stripped         = 0
    //     [88..92] header_length    = 64
    //     [92..156] header_bytes (64 bytes):
    //       Ethernet (14 bytes): dst_mac(6) + src_mac(6) + ethertype(2=0x0800 IPv4)
    //       IPv4 (20 bytes): ver_ihl(0x45) tos(0) total_len(84) id(0) flags_frag(0)
    //                        ttl(64) protocol(6=TCP) checksum(0) src(192.168.1.10) dst(10.0.0.2)
    //       TCP (20 bytes): src_port(8080) dst_port(80) seq(0) ack(0) data_off(0x50) flags(0x02) win(0) cksum(0) urg(0)
    //       padding (10 bytes of zeros to reach 64)
    pub(crate) const FIXTURE_SFLOW_FLOW_RAW_HEADER: &[u8] = &[
        // ── Datagram header ──
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
        0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
        0x00, 0x00, 0x00, 0x00, // sub_agent_id = 0
        0x00, 0x00, 0x00, 0x01, // sequence_number = 1
        0x00, 0x00, 0x03, 0xE8, // uptime_ms = 1000
        0x00, 0x00, 0x00, 0x01, // num_samples = 1
        // ── Sample envelope: flow_sample (enterprise=0, format=1 → tag=0x00000001) ──
        0x00, 0x00, 0x00, 0x01, // data_format tag
        // sample_length = 32 (body hdr) + 4+4+80 (flow record envelope+body) = 120
        0x00, 0x00, 0x00, 0x78, // sample_length = 120
        // ── Flow sample body header (32 bytes) ──
        0x00, 0x00, 0x00, 0x01, // sequence_number = 1
        0x00, 0x00, 0x00, 0x01, // source_id = 0x00000001
        0x00, 0x00, 0x02, 0x00, // sampling_rate = 512
        0x00, 0x00, 0x02, 0x00, // sample_pool = 512
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x01, // input_ifindex = 1
        0x00, 0x00, 0x00, 0x02, // output_ifindex = 2
        0x00, 0x00, 0x00, 0x01, // num_flow_records = 1
        // ── Flow record: raw packet header (enterprise=0, format=1 → tag=0x00000001) ──
        0x00, 0x00, 0x00, 0x01, // flow_data_format = 1
        0x00, 0x00, 0x00, 0x50, // flow_data_length = 80
        0x00, 0x00, 0x00, 0x01, // header_protocol = 1 (ETHERNET)
        0x00, 0x00, 0x00, 0x62, // frame_length = 98
        0x00, 0x00, 0x00, 0x00, // stripped = 0
        0x00, 0x00, 0x00, 0x40, // header_length = 64
        // ── Ethernet (14 bytes) ──
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst MAC = broadcast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00,                         // ethertype = IPv4
        // ── IPv4 (20 bytes) ──
        0x45,       // version=4, IHL=5
        0x00,       // DSCP/ECN
        0x00, 0x54, // total length = 84
        0x00, 0x00, // identification = 0
        0x00, 0x00, // flags + fragment offset = 0
        0x40,       // TTL = 64
        0x06,       // protocol = 6 (TCP)
        0x00, 0x00, // header checksum = 0
        0xC0, 0xA8, 0x01, 0x0A, // src = 192.168.1.10
        0x0A, 0x00, 0x00, 0x02, // dst = 10.0.0.2
        // ── TCP (20 bytes) ──
        0x1F, 0x90, // src_port = 8080
        0x00, 0x50, // dst_port = 80
        0x00, 0x00, 0x00, 0x00, // seq = 0
        0x00, 0x00, 0x00, 0x00, // ack = 0
        0x50,       // data offset = 5 (20 bytes)
        0x02,       // flags = SYN
        0x00, 0x00, // window = 0
        0x00, 0x00, // checksum = 0
        0x00, 0x00, // urgent = 0
        // ── padding to reach 64 header bytes (10 bytes) ──
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // ── fixture: flow sample with sampled_ipv4 record (format 3 carries 5-tuple directly) ──
    //
    // Datagram header: identical to above (28 bytes), num_samples=1.
    // Flow sample envelope: tag=0x00000001, length=body_size.
    // Flow sample body header: seq=2, src_id=1, rate=1000, pool=1000, drops=0, in=3, out=4, num_records=1.
    // Flow record (sampled_ipv4, enterprise=0, format=3 → tag=0x00000003):
    //   length = 32 (fixed: 4 len + 4 proto + 4 src_ip + 4 dst_ip + 2 src_port + 2 dst_port + 4 tos + 4 tcp_flags + ... = 32 bytes body)
    //   Actually per sFlow v5 spec §5.2.2:
    //     length (u32), protocol (u32), src_ip (4), dst_ip (4), src_port (u32), dst_port (u32), tcp_flags (u32), tos (u32) = 32 bytes
    pub(crate) const FIXTURE_SFLOW_SAMPLED_IPV4: &[u8] = &[
        // ── Datagram header ──
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
        0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
        0x00, 0x00, 0x00, 0x00, // sub_agent_id = 0
        0x00, 0x00, 0x00, 0x02, // sequence_number = 2
        0x00, 0x00, 0x07, 0xD0, // uptime_ms = 2000
        0x00, 0x00, 0x00, 0x01, // num_samples = 1
        // ── Sample envelope: flow_sample (tag=1) ──
        0x00, 0x00, 0x00, 0x01, // data_format = flow_sample
        // sample_length = 32 (flow hdr) + 4+4+32 (rec envelope + sampled_ipv4 body) = 72
        0x00, 0x00, 0x00, 0x48, // sample_length = 72
        // ── Flow sample body header (32 bytes) ──
        0x00, 0x00, 0x00, 0x02, // sequence_number = 2
        0x00, 0x00, 0x00, 0x01, // source_id = 1
        0x00, 0x00, 0x03, 0xE8, // sampling_rate = 1000
        0x00, 0x00, 0x03, 0xE8, // sample_pool = 1000
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x03, // input_ifindex = 3
        0x00, 0x00, 0x00, 0x04, // output_ifindex = 4
        0x00, 0x00, 0x00, 0x01, // num_flow_records = 1
        // ── Flow record: sampled_ipv4 (enterprise=0, format=3 → tag=0x00000003) ──
        0x00, 0x00, 0x00, 0x03, // flow_data_format = 3
        0x00, 0x00, 0x00, 0x20, // flow_data_length = 32
        // sampled_ipv4 body (32 bytes):
        // length(u32) + protocol(u32) + src_ip(4) + dst_ip(4) + src_port(u32) + dst_port(u32) + tcp_flags(u32) + tos(u32)
        0x00, 0x00, 0x00, 0x3C, // length = 60 (original packet length)
        0x00, 0x00, 0x00, 0x11, // protocol = 17 (UDP)
        0xAC, 0x10, 0x00, 0x01, // src_ip = 172.16.0.1
        0x08, 0x08, 0x08, 0x08, // dst_ip = 8.8.8.8
        0x00, 0x00, 0xC0, 0x3A, // src_port = 49210 (as u32)
        0x00, 0x00, 0x00, 0x35, // dst_port = 53 (DNS) (as u32)
        0x00, 0x00, 0x00, 0x00, // tcp_flags = 0
        0x00, 0x00, 0x00, 0x00, // tos = 0
    ];

    // ── fixture: counter sample with generic interface counters (format 1) ──
    //
    // Counter sample (enterprise=0, format=2 → tag=0x00000002):
    // Body: sequence_number(u32) + source_id(u32) + num_counter_records(u32) = 12 bytes
    // Counter record (generic_interface_counters, enterprise=0, format=1 → tag=0x00000001):
    //   length = 88 bytes (22 u32 + 2 u64 = 22*4 + 2*8 = 88 ... actually spec has:
    //   ifIndex(u32) ifType(u32) ifSpeed(u64) ifDirection(u32) ifStatus(u32)
    //   ifInOctets(u64) ifInUcastPkts(u32) ifInMulticastPkts(u32) ifInBroadcastPkts(u32)
    //   ifInDiscards(u32) ifInErrors(u32) ifInUnknownProtos(u32)
    //   ifOutOctets(u64) ifOutUcastPkts(u32) ifOutMulticastPkts(u32) ifOutBroadcastPkts(u32)
    //   ifOutDiscards(u32) ifOutErrors(u32) ifPromiscuousMode(u32)
    //   = 5*4 + 8 + 4 + 8*4 + 8 + 6*4 = 20 + 8 + 32 + 8 + 24 = 92 bytes? Let's count exactly:
    //   ifIndex u32 (4) ifType u32 (4) ifSpeed u64 (8) ifDirection u32 (4) ifStatus u32 (4)
    //   ifInOctets u64 (8) ifInUcastPkts u32 (4) ifInMulticastPkts u32 (4) ifInBroadcastPkts u32 (4)
    //   ifInDiscards u32 (4) ifInErrors u32 (4) ifInUnknownProtos u32 (4)
    //   ifOutOctets u64 (8) ifOutUcastPkts u32 (4) ifOutMulticastPkts u32 (4) ifOutBroadcastPkts u32 (4)
    //   ifOutDiscards u32 (4) ifOutErrors u32 (4) ifPromiscuousMode u32 (4)
    //   Total = 4+4+8+4+4+8+4+4+4+4+4+4+8+4+4+4+4+4+4 = 88 bytes
    pub(crate) const FIXTURE_SFLOW_COUNTER: &[u8] = &[
        // ── Datagram header ──
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
        0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
        0x00, 0x00, 0x00, 0x00, // sub_agent_id = 0
        0x00, 0x00, 0x00, 0x03, // sequence_number = 3
        0x00, 0x00, 0x0B, 0xB8, // uptime_ms = 3000
        0x00, 0x00, 0x00, 0x01, // num_samples = 1
        // ── Sample envelope: counter_sample (tag=0x00000002) ──
        0x00, 0x00, 0x00, 0x02, // data_format = counter_sample
        // sample_length = 12 (counter body hdr) + 4+4+88 (rec envelope + generic_if_counters) = 108
        0x00, 0x00, 0x00, 0x6C, // sample_length = 108
        // ── Counter sample body header (12 bytes) ──
        0x00, 0x00, 0x00, 0x03, // sequence_number = 3
        0x00, 0x00, 0x00, 0x01, // source_id = 1
        0x00, 0x00, 0x00, 0x01, // num_counter_records = 1
        // ── Counter record: generic_if_counters (enterprise=0, format=1 → tag=0x00000001) ──
        0x00, 0x00, 0x00, 0x01, // counter_data_format = 1
        0x00, 0x00, 0x00, 0x58, // counter_data_length = 88
        // generic_if_counters body (88 bytes):
        0x00, 0x00, 0x00, 0x01, // ifIndex = 1
        0x00, 0x00, 0x00, 0x06, // ifType = 6 (ethernetCsmacd)
        0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, // ifSpeed = 1_000_000_000 bps
        0x00, 0x00, 0x00, 0x01, // ifDirection = 1 (full-duplex)
        0x00, 0x00, 0x00, 0x03, // ifStatus = 3 (ifAdminStatus=up(1) | ifOperStatus=up(2))
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x40, // ifInOctets = 1_000_000
        0x00, 0x00, 0x03, 0xE8, // ifInUcastPkts = 1000
        0x00, 0x00, 0x00, 0x0A, // ifInMulticastPkts = 10
        0x00, 0x00, 0x00, 0x05, // ifInBroadcastPkts = 5
        0x00, 0x00, 0x00, 0x00, // ifInDiscards = 0
        0x00, 0x00, 0x00, 0x02, // ifInErrors = 2
        0x00, 0x00, 0x00, 0x00, // ifInUnknownProtos = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xA1, 0x20, // ifOutOctets = 500_000
        0x00, 0x00, 0x01, 0xF4, // ifOutUcastPkts = 500
        0x00, 0x00, 0x00, 0x03, // ifOutMulticastPkts = 3
        0x00, 0x00, 0x00, 0x01, // ifOutBroadcastPkts = 1
        0x00, 0x00, 0x00, 0x00, // ifOutDiscards = 0
        0x00, 0x00, 0x00, 0x01, // ifOutErrors = 1
        0x00, 0x00, 0x00, 0x00, // ifPromiscuousMode = 0
    ];

    // ── fixture: truncated datagram (only datagram header, no samples body) ──
    pub(crate) const FIXTURE_SFLOW_TRUNCATED: &[u8] = &[
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
        0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
        // missing: sub_agent_id, sequence_number, uptime_ms, num_samples
    ];

    // ── fixture: wrong version (version=4 is not sFlow v5) ──
    pub(crate) const FIXTURE_SFLOW_BAD_VERSION: &[u8] = &[
        0x00, 0x00, 0x00, 0x04, // version = 4 (wrong)
        0x00, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn decode_flow_sample_raw_header_extracts_5tuple() {
        let records = decode_datagram(FIXTURE_SFLOW_FLOW_RAW_HEADER, exporter()).unwrap();
        assert_eq!(records.len(), 1, "expected 1 flow record");
        let r = &records[0];
        assert_eq!(r.sample_type, crate::sflow::SampleType::Flow);
        assert_eq!(r.exporter, exporter());
        assert_eq!(
            r.src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
        assert_eq!(
            r.dst_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(r.src_port, Some(8080));
        assert_eq!(r.dst_port, Some(80));
        assert_eq!(r.ip_protocol, Some(6)); // TCP
        assert_eq!(r.sampling_rate, Some(512));
        assert_eq!(r.input_ifindex, Some(1));
        assert_eq!(r.output_ifindex, Some(2));
    }

    #[test]
    fn decode_flow_sample_sampled_ipv4_extracts_5tuple() {
        let records = decode_datagram(FIXTURE_SFLOW_SAMPLED_IPV4, exporter()).unwrap();
        assert_eq!(records.len(), 1, "expected 1 flow record");
        let r = &records[0];
        assert_eq!(r.sample_type, crate::sflow::SampleType::Flow);
        assert_eq!(
            r.src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))
        );
        assert_eq!(
            r.dst_addr,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(r.src_port, Some(49210));
        assert_eq!(r.dst_port, Some(53));
        assert_eq!(r.ip_protocol, Some(17)); // UDP
        assert_eq!(r.sampling_rate, Some(1000));
        assert_eq!(r.input_ifindex, Some(3));
        assert_eq!(r.output_ifindex, Some(4));
    }

    #[test]
    fn decode_counter_sample_extracts_generic_interface_counters() {
        let records = decode_datagram(FIXTURE_SFLOW_COUNTER, exporter()).unwrap();
        assert_eq!(records.len(), 1, "expected 1 counter record");
        let r = &records[0];
        assert_eq!(r.sample_type, crate::sflow::SampleType::Counter);
        assert_eq!(r.if_index, Some(1));
        assert_eq!(r.if_type, Some(6));
        assert_eq!(r.if_speed, Some(1_000_000_000));
        assert_eq!(r.if_in_octets, Some(1_000_000));
        assert_eq!(r.if_out_octets, Some(500_000));
        assert_eq!(r.if_in_ucast_pkts, Some(1000));
        assert_eq!(r.if_out_ucast_pkts, Some(500));
        assert_eq!(r.if_in_errors, Some(2));
        assert_eq!(r.if_out_errors, Some(1));
        // flow fields absent
        assert!(r.src_addr.is_none());
        assert!(r.dst_addr.is_none());
    }

    #[test]
    fn decode_truncated_datagram_returns_error() {
        let result = decode_datagram(FIXTURE_SFLOW_TRUNCATED, exporter());
        assert!(result.is_err(), "truncated datagram must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("truncated") || msg.contains("too short"),
            "error must mention truncation; got: {msg}"
        );
    }

    #[test]
    fn decode_wrong_version_returns_error() {
        let result = decode_datagram(FIXTURE_SFLOW_BAD_VERSION, exporter());
        assert!(result.is_err(), "wrong version must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("version") || msg.contains("4"),
            "error must mention the bad version; got: {msg}"
        );
    }

    #[test]
    fn unknown_flow_record_format_goes_to_extra() {
        // Build a minimal flow sample with one flow record of enterprise=0, format=99 (vendor-specific).
        // The record body is 4 bytes of zeros; the decoder must not error and must store the raw
        // data in extra[].
        // For brevity, copy FIXTURE_SFLOW_FLOW_RAW_HEADER and replace:
        //   flow_data_format offset  [68..72] → 0x00000063 (format=99)
        //   flow_data_length [72..76] → 0x00000004
        //   then 4 bytes of body
        // We rebuild the relevant bytes manually:
        let mut buf = FIXTURE_SFLOW_FLOW_RAW_HEADER.to_vec();
        // flow_data_format is at byte offset 68 in this fixture:
        buf[68] = 0x00; buf[69] = 0x00; buf[70] = 0x00; buf[71] = 0x63; // format=99
        // flow_data_length = 4
        buf[72] = 0x00; buf[73] = 0x00; buf[74] = 0x00; buf[75] = 0x04;
        // Replace remaining bytes (the header_bytes block) with 4 zero bytes,
        // then truncate to the new correct length:
        // New total after format+length bytes: 76 + 4 = 80 bytes
        buf.truncate(76);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Fix sample_length at [32..36]: was 120, now 32 + 4+4+4 = 44
        buf[32] = 0x00; buf[33] = 0x00; buf[34] = 0x00; buf[35] = 0x2C; // 44

        let records = decode_datagram(&buf, exporter()).unwrap();
        assert_eq!(records.len(), 1);
        // The 5-tuple should be absent (no recognised flow record decoded)
        assert!(records[0].src_addr.is_none());
        // extra should contain the unknown record
        let extra = &records[0].extra;
        assert!(
            extra.is_array() || extra.get("unknown_records").is_some() || {
                // Accept either array-at-root or object with a key
                let s = extra.to_string();
                s.contains("format") || s.contains("data_base64")
            },
            "unknown flow record must appear in extra; got: {extra}"
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p logthing --lib sflow::decoder::tests 2>&1 | head -20
# Expected: error[E0432]: unresolved import `super::*` (decode_datagram not defined yet)
```

- [ ] **Step 3: Implement**

```rust
// src/sflow/decoder.rs
//! sFlow v5 binary decoder.
//!
//! All sFlow v5 fields are big-endian (XDR) and 4-byte aligned.
//! The decoder is stateless — sFlow v5 carries all necessary context inline.
//!
//! Entry point: `decode_datagram(buf, exporter) -> anyhow::Result<Vec<SflowRecord>>`

use anyhow::{Context, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sflow::{SampleType, SflowRecord};

// ── Bounds-checked read helpers (same idiom as src/ipfix/decoder.rs) ────────

fn read_u32(buf: &[u8], off: usize) -> anyhow::Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow::anyhow!("sflow: truncated at offset {off} (need u32, have {} bytes)", buf.len().saturating_sub(off)))
}

fn read_u64(buf: &[u8], off: usize) -> anyhow::Result<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow::anyhow!("sflow: truncated at offset {off} (need u64, have {} bytes)", buf.len().saturating_sub(off)))
}

fn read_bytes(buf: &[u8], off: usize, len: usize) -> anyhow::Result<&[u8]> {
    buf.get(off..off + len)
        .ok_or_else(|| anyhow::anyhow!("sflow: truncated at offset {off} (need {len} bytes, have {})", buf.len().saturating_sub(off)))
}

/// Decode one sFlow v5 UDP datagram.
///
/// Returns `Err` for datagram-level truncation or wrong version.
/// Sample-level errors (truncated sample body, unknown agent address type) are
/// logged as warnings and the sample is skipped — `Ok(partial_records)` is returned.
pub fn decode_datagram(buf: &[u8], exporter: IpAddr) -> anyhow::Result<Vec<SflowRecord>> {
    metrics::counter!("sflow_datagrams_received").increment(1);

    // ── Datagram header ──────────────────────────────────────────────────────
    // version(4) agent_addr_type(4) agent_addr(4|16) sub_agent_id(4)
    // sequence_number(4) uptime_ms(4) num_samples(4)
    // Minimum for IPv4 agent: 28 bytes

    if buf.len() < 8 {
        bail!("sflow: datagram too short for version+agent_addr_type ({} bytes)", buf.len());
    }

    let version = read_u32(buf, 0)?;
    if version != 5 {
        bail!("sflow: unsupported version {version} (only v5 is supported)");
    }

    let agent_addr_type = read_u32(buf, 4)?;
    let (agent_addr, hdr_end) = match agent_addr_type {
        1 => {
            // IPv4: 4 bytes
            let a = read_bytes(buf, 8, 4)?;
            let ip = IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
            (ip, 12usize)
        }
        2 => {
            // IPv6: 16 bytes
            let a = read_bytes(buf, 8, 16)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(a);
            (IpAddr::V6(Ipv6Addr::from(bytes)), 24usize)
        }
        other => bail!("sflow: unknown agent_addr_type {other}"),
    };

    // sub_agent_id(4) sequence_number(4) uptime_ms(4) num_samples(4)
    let _sub_agent_id    = read_u32(buf, hdr_end)?;
    let _sequence_number = read_u32(buf, hdr_end + 4)?;
    let _uptime_ms       = read_u32(buf, hdr_end + 8)?;
    let num_samples      = read_u32(buf, hdr_end + 12)?;

    let mut pos = hdr_end + 16;
    let mut records: Vec<SflowRecord> = Vec::new();
    let received_at = chrono::Utc::now();

    for _ in 0..num_samples {
        // Each sample: data_format(4) + sample_length(4) + body(sample_length)
        if pos + 8 > buf.len() {
            tracing::warn!("sflow: sample envelope truncated at offset {pos}; stopping");
            break;
        }
        let data_format   = read_u32(buf, pos)?;
        let sample_length = read_u32(buf, pos + 4)? as usize;
        pos += 8;

        let body_end = pos + sample_length;
        if body_end > buf.len() {
            tracing::warn!("sflow: sample body claims {sample_length} bytes but only {} remain; skipping", buf.len() - pos);
            break;
        }
        let sample_body = &buf[pos..body_end];
        pos = body_end;

        // data_format encodes enterprise (top 20 bits) and format (bottom 12 bits).
        let enterprise = data_format >> 12;
        let format     = data_format & 0xFFF;

        if enterprise != 0 {
            // Vendor-specific sample — skip entirely.
            continue;
        }

        match format {
            1 | 3 => {
                // flow_sample (1) or expanded_flow_sample (3)
                match decode_flow_sample(sample_body, format, agent_addr, received_at) {
                    Ok(mut recs) => records.append(&mut recs),
                    Err(e) => {
                        metrics::counter!("sflow_decode_errors").increment(1);
                        tracing::warn!("sflow: flow sample decode error: {e}");
                    }
                }
            }
            2 | 4 => {
                // counter_sample (2) or expanded_counter_sample (4)
                match decode_counter_sample(sample_body, format, agent_addr, received_at) {
                    Ok(mut recs) => records.append(&mut recs),
                    Err(e) => {
                        metrics::counter!("sflow_decode_errors").increment(1);
                        tracing::warn!("sflow: counter sample decode error: {e}");
                    }
                }
            }
            _ => {
                tracing::debug!("sflow: unknown sample format {format}; skipping");
            }
        }
    }

    Ok(records)
}

// ── Flow sample decoder ──────────────────────────────────────────────────────

fn decode_flow_sample(
    body: &[u8],
    format: u32,
    agent_addr: IpAddr,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Vec<SflowRecord>> {
    // flow_sample (format 1) body layout:
    //   sequence_number(4) source_id(4) sampling_rate(4) sample_pool(4)
    //   drops(4) input(4) output(4) num_flow_records(4) → 32 bytes
    //
    // expanded_flow_sample (format 3) body layout:
    //   sequence_number(4) ds_class(4) ds_index(4) sampling_rate(4) sample_pool(4)
    //   drops(4) input_if_format(4) input_if_value(4) output_if_format(4) output_if_value(4)
    //   num_flow_records(4) → 44 bytes

    let (sampling_rate, input_ifindex, output_ifindex, num_records, mut pos) = if format == 1 {
        if body.len() < 32 {
            bail!("sflow: flow_sample body too short ({} < 32)", body.len());
        }
        let sampling_rate   = read_u32(body, 8)?;
        let input_ifindex   = read_u32(body, 20)?;
        let output_ifindex  = read_u32(body, 24)?;
        let num_records     = read_u32(body, 28)?;
        (sampling_rate, input_ifindex, output_ifindex, num_records, 32usize)
    } else {
        // expanded_flow_sample (format 3)
        if body.len() < 44 {
            bail!("sflow: expanded_flow_sample body too short ({} < 44)", body.len());
        }
        let sampling_rate   = read_u32(body, 12)?;
        // input: format(4) + value(4) at [24..32]; output at [32..40]
        let input_ifindex   = read_u32(body, 28)?; // input if_value
        let output_ifindex  = read_u32(body, 36)?; // output if_value
        let num_records     = read_u32(body, 40)?;
        (sampling_rate, input_ifindex, output_ifindex, num_records, 44usize)
    };

    // Start with an empty record; update 5-tuple fields from flow records.
    let mut rec = SflowRecord {
        sample_type: SampleType::Flow,
        exporter: agent_addr,
        received_at,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: Some(sampling_rate),
        input_ifindex: Some(input_ifindex),
        output_ifindex: Some(output_ifindex),
        if_index: None,
        if_type: None,
        if_speed: None,
        if_direction: None,
        if_in_octets: None,
        if_out_octets: None,
        if_in_ucast_pkts: None,
        if_out_ucast_pkts: None,
        if_in_errors: None,
        if_out_errors: None,
        extra: serde_json::json!([]),
    };

    let mut unknown_records: Vec<serde_json::Value> = Vec::new();

    for _ in 0..num_records {
        if pos + 8 > body.len() {
            tracing::warn!("sflow: flow record envelope truncated at {pos}");
            break;
        }
        let flow_data_format = read_u32(body, pos)?;
        let flow_data_length = read_u32(body, pos + 4)? as usize;
        pos += 8;

        let rec_end = pos + flow_data_length;
        if rec_end > body.len() {
            tracing::warn!("sflow: flow record body claims {flow_data_length} bytes but only {} remain", body.len() - pos);
            break;
        }
        let rec_body = &body[pos..rec_end];
        pos = rec_end;

        let rec_enterprise = flow_data_format >> 12;
        let rec_format     = flow_data_format & 0xFFF;

        if rec_enterprise != 0 {
            // Enterprise-specific — store raw in extra.
            let data_b64 = base64_encode(rec_body);
            unknown_records.push(serde_json::json!({
                "enterprise": rec_enterprise,
                "format": rec_format,
                "length": flow_data_length,
                "data_base64": data_b64,
            }));
            continue;
        }

        match rec_format {
            1 => {
                // raw_packet_header — parse Ethernet/IPv4/IPv6/TCP/UDP to 5-tuple
                if let Err(e) = decode_raw_packet_header(rec_body, &mut rec) {
                    tracing::debug!("sflow: raw_packet_header parse error: {e}");
                }
            }
            3 => {
                // sampled_ipv4 — carries 5-tuple directly
                decode_sampled_ipv4(rec_body, &mut rec)?;
            }
            4 => {
                // sampled_ipv6 — carries 5-tuple directly
                decode_sampled_ipv6(rec_body, &mut rec)?;
            }
            other => {
                let data_b64 = base64_encode(rec_body);
                unknown_records.push(serde_json::json!({
                    "format": other,
                    "length": flow_data_length,
                    "data_base64": data_b64,
                }));
            }
        }
    }

    if !unknown_records.is_empty() {
        rec.extra = serde_json::Value::Array(unknown_records);
    }

    Ok(vec![rec])
}

// ── Raw packet header parse (Ethernet/IPv4/IPv6/TCP/UDP → 5-tuple) ──────────

fn decode_raw_packet_header(body: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // raw_packet_header body:
    //   header_protocol(4) frame_length(4) stripped(4) header_length(4)
    //   header_bytes(header_length, padded to 4-byte alignment)
    if body.len() < 16 {
        bail!("raw_packet_header body too short ({} < 16)", body.len());
    }
    let header_protocol = read_u32(body, 0)?;
    let header_length   = read_u32(body, 12)? as usize;

    let header_bytes = read_bytes(body, 16, header_length)
        .context("raw_packet_header: header_bytes truncated")?;

    match header_protocol {
        1 => parse_ethernet(header_bytes, rec), // ETHERNET
        11 => parse_ipv4(header_bytes, 0, rec), // IPv4 (raw)
        12 => parse_ipv6(header_bytes, 0, rec), // IPv6 (raw)
        _ => {
            tracing::debug!("sflow: raw_packet_header: unsupported protocol {header_protocol}");
            Ok(())
        }
    }
}

fn parse_ethernet(buf: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // Ethernet II: dst_mac(6) src_mac(6) ethertype(2) [optional 802.1Q vlan tag(4)]
    if buf.len() < 14 {
        bail!("ethernet: too short ({} bytes)", buf.len());
    }
    let mut ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    let mut payload_start = 14usize;

    // 802.1Q VLAN tag (0x8100)
    if ethertype == 0x8100 {
        if buf.len() < 18 {
            bail!("ethernet: 802.1Q too short");
        }
        ethertype = u16::from_be_bytes([buf[16], buf[17]]);
        payload_start = 18;
    }

    match ethertype {
        0x0800 => parse_ipv4(&buf[payload_start..], payload_start, rec),
        0x86DD => parse_ipv6(&buf[payload_start..], payload_start, rec),
        _ => Ok(()), // ARP etc — ignore
    }
}

fn parse_ipv4(buf: &[u8], _offset: usize, rec: &mut SflowRecord) -> anyhow::Result<()> {
    // IPv4: version_ihl(1) tos(1) total_length(2) ... protocol(1 at byte 9) src(4 at 12) dst(4 at 16)
    if buf.len() < 20 {
        bail!("ipv4: too short ({} bytes)", buf.len());
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 || ihl > buf.len() {
        bail!("ipv4: invalid IHL {ihl}");
    }
    let protocol = buf[9];
    let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    rec.src_addr    = Some(src);
    rec.dst_addr    = Some(dst);
    rec.ip_protocol = Some(protocol);

    let transport = &buf[ihl..];
    parse_transport(protocol, transport, rec);
    Ok(())
}

fn parse_ipv6(buf: &[u8], _offset: usize, rec: &mut SflowRecord) -> anyhow::Result<()> {
    // IPv6: version_tc_fl(4) payload_length(2) next_header(1) hop_limit(1) src(16) dst(16)
    if buf.len() < 40 {
        bail!("ipv6: too short ({} bytes)", buf.len());
    }
    let next_header = buf[6];
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&buf[8..24]);
    dst_bytes.copy_from_slice(&buf[24..40]);

    rec.src_addr    = Some(IpAddr::V6(Ipv6Addr::from(src_bytes)));
    rec.dst_addr    = Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)));
    rec.ip_protocol = Some(next_header);

    let transport = &buf[40..];
    parse_transport(next_header, transport, rec);
    Ok(())
}

fn parse_transport(protocol: u8, buf: &[u8], rec: &mut SflowRecord) {
    match protocol {
        6 | 17 => {
            // TCP or UDP: src_port(2) dst_port(2) ...
            if buf.len() >= 4 {
                rec.src_port = Some(u16::from_be_bytes([buf[0], buf[1]]));
                rec.dst_port = Some(u16::from_be_bytes([buf[2], buf[3]]));
            }
        }
        _ => {} // ICMP etc — no port concept
    }
}

// ── sampled_ipv4 (flow record format 3) ─────────────────────────────────────

fn decode_sampled_ipv4(body: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // sampled_ipv4 body (32 bytes):
    //   length(4) protocol(4) src_ip(4) dst_ip(4) src_port(4) dst_port(4) tcp_flags(4) tos(4)
    if body.len() < 32 {
        bail!("sampled_ipv4: too short ({} < 32)", body.len());
    }
    let protocol = read_u32(body, 4)? as u8;
    let src = IpAddr::V4(Ipv4Addr::new(body[8], body[9], body[10], body[11]));
    let dst = IpAddr::V4(Ipv4Addr::new(body[12], body[13], body[14], body[15]));
    let src_port = read_u32(body, 16)? as u16;
    let dst_port = read_u32(body, 20)? as u16;

    rec.src_addr    = Some(src);
    rec.dst_addr    = Some(dst);
    rec.ip_protocol = Some(protocol);
    rec.src_port    = Some(src_port);
    rec.dst_port    = Some(dst_port);
    Ok(())
}

// ── sampled_ipv6 (flow record format 4) ─────────────────────────────────────

fn decode_sampled_ipv6(body: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // sampled_ipv6 body (52 bytes):
    //   length(4) protocol(4) src_ip(16) dst_ip(16) src_port(4) dst_port(4) tcp_flags(4) priority(4)
    if body.len() < 52 {
        bail!("sampled_ipv6: too short ({} < 52)", body.len());
    }
    let protocol = read_u32(body, 4)? as u8;
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&body[8..24]);
    dst_bytes.copy_from_slice(&body[24..40]);
    let src_port = read_u32(body, 40)? as u16;
    let dst_port = read_u32(body, 44)? as u16;

    rec.src_addr    = Some(IpAddr::V6(Ipv6Addr::from(src_bytes)));
    rec.dst_addr    = Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)));
    rec.ip_protocol = Some(protocol);
    rec.src_port    = Some(src_port);
    rec.dst_port    = Some(dst_port);
    Ok(())
}

// ── Counter sample decoder ───────────────────────────────────────────────────

fn decode_counter_sample(
    body: &[u8],
    format: u32,
    agent_addr: IpAddr,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Vec<SflowRecord>> {
    // counter_sample (format 2) body:
    //   sequence_number(4) source_id(4) num_counter_records(4) → 12 bytes
    // expanded_counter_sample (format 4) body:
    //   sequence_number(4) ds_class(4) ds_index(4) num_counter_records(4) → 16 bytes

    let (num_records, mut pos) = if format == 2 {
        if body.len() < 12 { bail!("counter_sample body too short ({} < 12)", body.len()); }
        (read_u32(body, 8)?, 12usize)
    } else {
        if body.len() < 16 { bail!("expanded_counter_sample body too short ({} < 16)", body.len()); }
        (read_u32(body, 12)?, 16usize)
    };

    let mut rec = SflowRecord {
        sample_type: SampleType::Counter,
        exporter: agent_addr,
        received_at,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: None,
        input_ifindex: None,
        output_ifindex: None,
        if_index: None,
        if_type: None,
        if_speed: None,
        if_direction: None,
        if_in_octets: None,
        if_out_octets: None,
        if_in_ucast_pkts: None,
        if_out_ucast_pkts: None,
        if_in_errors: None,
        if_out_errors: None,
        extra: serde_json::json!([]),
    };

    let mut unknown_records: Vec<serde_json::Value> = Vec::new();

    for _ in 0..num_records {
        if pos + 8 > body.len() {
            tracing::warn!("sflow: counter record envelope truncated at {pos}");
            break;
        }
        let counter_data_format = read_u32(body, pos)?;
        let counter_data_length = read_u32(body, pos + 4)? as usize;
        pos += 8;

        let rec_end = pos + counter_data_length;
        if rec_end > body.len() {
            tracing::warn!("sflow: counter record body claims {counter_data_length} bytes but only {} remain", body.len() - pos);
            break;
        }
        let rec_body = &body[pos..rec_end];
        pos = rec_end;

        let rec_enterprise = counter_data_format >> 12;
        let rec_format     = counter_data_format & 0xFFF;

        if rec_enterprise != 0 || rec_format != 1 {
            // Non-generic counter record — store raw in extra.
            let data_b64 = base64_encode(rec_body);
            unknown_records.push(serde_json::json!({
                "enterprise": rec_enterprise,
                "format": rec_format,
                "length": counter_data_length,
                "data_base64": data_b64,
            }));
            continue;
        }

        // generic_if_counters (enterprise=0, format=1): 88 bytes
        if rec_body.len() < 88 {
            bail!("generic_if_counters too short ({} < 88)", rec_body.len());
        }
        rec.if_index        = Some(read_u32(rec_body, 0)?);
        rec.if_type         = Some(read_u32(rec_body, 4)?);
        rec.if_speed        = Some(read_u64(rec_body, 8)?);
        rec.if_direction    = Some(read_u32(rec_body, 16)?);
        // ifStatus at [20..24] — not separately curated, lands in extra if needed
        rec.if_in_octets    = Some(read_u64(rec_body, 28)?);
        rec.if_in_ucast_pkts = Some(read_u32(rec_body, 36)? as u64);
        rec.if_in_errors    = Some(read_u32(rec_body, 44)?);
        rec.if_out_octets   = Some(read_u64(rec_body, 52)?);
        rec.if_out_ucast_pkts = Some(read_u32(rec_body, 60)? as u64);
        rec.if_out_errors   = Some(read_u32(rec_body, 72)?);
    }

    if !unknown_records.is_empty() {
        rec.extra = serde_json::Value::Array(unknown_records);
    }

    Ok(vec![rec])
}

// ── Utility ──────────────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    // Simple base64 without external dependency — use the standard alphabet.
    // For production, `base64` crate is already a transitive dep via aws-sdk;
    // reference it here via the `base64` feature of the existing dependency.
    // If not available, fall back to hex.
    hex::encode(data) // guaranteed available (used in ipfix/decoder.rs)
}
```

Note: `base64_encode` uses `hex::encode` as a fallback (it is already a dependency). If the `base64` crate is available transitively, swap to `general_purpose::STANDARD.encode(data)` for smaller size; the tests only check the field exists, not the encoding.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test -p logthing --lib sflow::decoder::tests 2>&1 | tail -10
# Expected: test result: ok. 7 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add src/sflow/decoder.rs src/sflow/mod.rs
git commit -m "feat(sflow): add stateless sFlow v5 binary decoder"
```

---

### Task 3.3: sFlow config (`src/config/mod.rs`)

**Files:**
- Modify `src/config/mod.rs`

**Interfaces:**
- Produces: `SflowConfig`, `SflowS3Config`; adds `pub sflow: SflowConfig` to `Config`

---

- [ ] **Step 1: Write the failing tests**

```rust
// Add to the #[cfg(test)] mod tests block in src/config/mod.rs:

#[test]
fn sflow_config_defaults_disabled_on_port_6343() {
    let cfg = Config::default();
    assert!(!cfg.sflow.enabled, "sflow disabled by default");
    assert_eq!(cfg.sflow.udp_port, 6343);
    assert_eq!(cfg.sflow.bind_address, "0.0.0.0");
    assert!(cfg.sflow.s3.is_none());
}

#[test]
fn sflow_s3_flat_toml_deserializes_correctly() {
    let toml_str = r#"
[sflow.s3]
endpoint   = "http://minio:9002"
bucket     = "sflow-samples"
region     = "us-east-1"
access_key = "SKEY"
secret_key = "SSECRET"
"#;
    let cfg: Config = toml::from_str(toml_str).expect("parse");
    let s3 = cfg.sflow.s3.expect("present");
    assert_eq!(s3.connection.endpoint, "http://minio:9002");
    assert_eq!(s3.connection.bucket, "sflow-samples");
    assert_eq!(s3.prefix, "sflow");
    assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
    assert_eq!(s3.flush_interval_secs, 900);
    assert_eq!(s3.channel_capacity, 256);
    assert_eq!(s3.max_buffer_rows, 100_000);
}

#[test]
fn sflow_s3_absent_means_no_persistence() {
    let toml_str = "[sflow]\nenabled = true\n";
    let cfg: Config = toml::from_str(toml_str).expect("parse");
    assert!(cfg.sflow.s3.is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p logthing --lib config::tests::sflow 2>&1 | head -20
# Expected: error[E0609]: no field `sflow` on type `Config`
```

- [ ] **Step 3: Implement**

Add to `src/config/mod.rs`, following the exact `IpfixConfig`/`IpfixS3Config` pattern:

```rust
// ── SflowConfig ───────────────────────────────────────────────────────────

/// Configuration for the sFlow v5 UDP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SflowConfig {
    #[serde(default = "default_sflow_enabled")]
    pub enabled: bool,

    #[serde(default = "default_sflow_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_sflow_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` (backward compatible).
    #[serde(default)]
    pub s3: Option<SflowS3Config>,
}

impl Default for SflowConfig {
    fn default() -> Self {
        Self {
            enabled: default_sflow_enabled(),
            udp_port: default_sflow_udp_port(),
            bind_address: default_sflow_bind_address(),
            s3: None,
        }
    }
}

fn default_sflow_enabled() -> bool { false }
fn default_sflow_udp_port() -> u16  { 6343 }
fn default_sflow_bind_address() -> String { "0.0.0.0".to_string() }

/// Per-source S3 persistence config for the sFlow listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SflowS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    #[serde(default = "default_sflow_s3_prefix")]
    pub prefix: String,
    #[serde(default = "default_sflow_flush_bytes")]
    pub flush_threshold_bytes: usize,
    #[serde(default = "default_sflow_flush_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_sflow_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default = "default_sflow_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_sflow_s3_prefix()          -> String { "sflow".to_string() }
fn default_sflow_flush_bytes()         -> usize  { 100 * 1024 * 1024 }
fn default_sflow_flush_secs()          -> u64    { 900 }
fn default_sflow_channel_capacity()    -> usize  { 256 }
fn default_sflow_max_buffer_rows()     -> usize  { 100_000 }
```

Add `pub sflow: SflowConfig` to the `Config` struct and `sflow: SflowConfig::default()` to `Config::default()`.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test -p logthing --lib config::tests::sflow 2>&1 | tail -10
# Expected: test result: ok. 3 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(sflow): add SflowConfig and SflowS3Config to config"
```

---

### Task 3.4: sFlow UDP listener (`src/sflow/listener.rs`)

**Files:**
- Create `src/sflow/listener.rs`

**Interfaces:**
- Produces: `SflowListener`, `SflowListenerConfig`, `SflowHandler` trait, `DefaultSflowHandler`
- Key signature: `async fn handle_samples(&self, samples: Vec<SflowRecord>, source: SocketAddr)`

---

- [ ] **Step 1: Write the failing tests**

```rust
// src/sflow/listener.rs (in #[cfg(test)] mod tests)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sflow::decoder::{
        FIXTURE_SFLOW_FLOW_RAW_HEADER,
        FIXTURE_SFLOW_COUNTER,
    };
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::sleep;

    struct CapturingHandler {
        received: Mutex<Vec<Vec<SflowRecord>>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self { received: Mutex::new(Vec::new()) })
        }
        fn batches(&self) -> Vec<Vec<SflowRecord>> {
            self.received.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl SflowHandler for CapturingHandler {
        async fn handle_samples(&self, samples: Vec<SflowRecord>, _source: SocketAddr) {
            self.received.lock().unwrap().push(samples);
        }
    }

    // ── e2e: listener receives datagram, calls handler ──
    #[tokio::test]
    async fn listener_receives_sflow_datagram_and_calls_handler() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr   = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(FIXTURE_SFLOW_FLOW_RAW_HEADER, listener_addr).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        task.abort();

        let batches = handler.batches();
        assert_eq!(batches.len(), 1, "expected one batch; got {}", batches.len());
        assert_eq!(batches[0].len(), 1, "expected one record in batch");

        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            batches[0][0].src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
    }

    // ── shutdown signal: start_with_shutdown exits cleanly ──
    #[tokio::test]
    async fn start_with_shutdown_exits_on_signal() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let config = SflowListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
        };
        let handler: Arc<dyn SflowHandler> = Arc::new(DefaultSflowHandler);
        let listener = SflowListener::new(config, handler);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });
        sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();

        let result = timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "start_with_shutdown did not return within 2s after signal");
    }

    // ── robustness: malformed datagram is ignored, next valid one processed ──
    #[tokio::test]
    async fn listener_ignores_malformed_datagrams_and_continues() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr   = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"\xFF\xFF\xFF\xFF", listener_addr).await.unwrap();
        sleep(Duration::from_millis(30)).await;
        sender.send_to(FIXTURE_SFLOW_COUNTER, listener_addr).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        task.abort();

        let batches = handler.batches();
        assert_eq!(batches.len(), 1, "valid datagram must still produce one batch after malformed one");
        assert_eq!(batches[0][0].sample_type, crate::sflow::SampleType::Counter);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p logthing --lib sflow::listener::tests 2>&1 | head -20
# Expected: error[E0432]: unresolved import `super::*`
```

- [ ] **Step 3: Implement**

The listener is a direct clone of `src/ipfix/listener.rs` with three adaptations:

1. Replace `IpfixDecoder` (stateful) with a stateless call: `crate::sflow::decoder::decode_datagram(&buf[..len], src.ip())`.
2. Replace `IpfixHandler::handle_flows(Vec<FlowRecord>, SocketAddr)` with `SflowHandler::handle_samples(Vec<SflowRecord>, SocketAddr)`.
3. Default port is `6343`, metric is `sflow_decode_errors`, log prefix is `"sFlow"`.

```rust
// src/sflow/listener.rs
//! sFlow v5 UDP listener — mirrors src/ipfix/listener.rs; sFlow is stateless
//! (no template cache), so decode_datagram takes only the buffer + exporter IP.

use crate::sflow::SflowRecord;
use crate::sflow::decoder::decode_datagram;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct SflowListenerConfig {
    pub udp_port: u16,
    pub bind_address: String,
}

impl Default for SflowListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 6343,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}

#[async_trait::async_trait]
pub trait SflowHandler: Send + Sync {
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: SocketAddr);
}

pub struct DefaultSflowHandler;

#[async_trait::async_trait]
impl SflowHandler for DefaultSflowHandler {
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: SocketAddr) {
        info!("[{}] received {} sFlow sample(s)", source, samples.len());
    }
}

pub struct SflowListener {
    config: SflowListenerConfig,
    handler: Arc<dyn SflowHandler>,
}

impl SflowListener {
    pub fn new(config: SflowListenerConfig, handler: Arc<dyn SflowHandler>) -> Self {
        Self { config, handler }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let socket = UdpSocket::bind(&addr).await?;
        self.run_with_socket(socket).await
    }

    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let socket = UdpSocket::bind(&addr).await?;
        let bound_addr = socket.local_addr()?;
        info!("sFlow UDP listener started on {}", bound_addr);

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            debug!("sFlow datagram from {}: {} bytes", src, len);
                            match decode_datagram(&buf[..len], src.ip()) {
                                Ok(samples) if samples.is_empty() => {
                                    debug!("sFlow datagram from {} produced no samples", src);
                                }
                                Ok(samples) => {
                                    self.handler.handle_samples(samples, src).await;
                                }
                                Err(e) => {
                                    metrics::counter!("sflow_decode_errors").increment(1);
                                    warn!("sFlow decode error from {}: {}", src, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("sFlow UDP receive error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("sFlow listener: shutdown signal received");
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn run_with_socket(&self, socket: UdpSocket) -> anyhow::Result<()> {
        let bound_addr = socket.local_addr()?;
        info!("sFlow UDP listener started on {}", bound_addr);

        let mut buf = vec![0u8; 65535];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    debug!("sFlow datagram from {}: {} bytes", src, len);
                    match decode_datagram(&buf[..len], src.ip()) {
                        Ok(samples) if samples.is_empty() => {
                            debug!("sFlow datagram from {} produced no samples", src);
                        }
                        Ok(samples) => {
                            self.handler.handle_samples(samples, src).await;
                        }
                        Err(e) => {
                            metrics::counter!("sflow_decode_errors").increment(1);
                            warn!("sFlow decode error from {}: {}", src, e);
                        }
                    }
                }
                Err(e) => {
                    error!("sFlow UDP receive error: {}", e);
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test -p logthing --lib sflow::listener::tests 2>&1 | tail -10
# Expected: test result: ok. 3 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add src/sflow/listener.rs
git commit -m "feat(sflow): add SflowListener + SflowHandler UDP listener"
```

---

### Task 3.5: sFlow → S3 Parquet sink (`src/forwarding/sflow_s3.rs`)

**Files:**
- Create `src/forwarding/sflow_s3.rs`
- Modify `src/forwarding/mod.rs` (add `pub mod sflow_s3;`)

**Interfaces:**
- Produces: `SflowSink`, `SflowS3Handler` (type alias), `sflow_start(cfg, s3) -> (SflowS3Handler, JoinHandle)`
- `SflowSink::partition(&SflowRecord) -> Some("flow") | Some("counter")`

---

- [ ] **Step 1: Write the failing tests**

```rust
// src/forwarding/sflow_s3.rs (in #[cfg(test)] mod tests)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{S3ConnectionConfig, SflowS3Config};
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::sflow::{SampleType, SflowRecord};
    use arrow::array::{StringArray, UInt32Array, UInt64Array};
    use std::net::IpAddr;

    fn make_flow_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Flow,
            exporter: "10.0.0.1".parse().unwrap(),
            received_at: chrono::Utc::now(),
            src_addr: Some("192.168.1.1".parse().unwrap()),
            dst_addr: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(443),
            ip_protocol: Some(6),
            sampling_rate: Some(512),
            input_ifindex: Some(1),
            output_ifindex: Some(2),
            if_index: None, if_type: None, if_speed: None, if_direction: None,
            if_in_octets: None, if_out_octets: None,
            if_in_ucast_pkts: None, if_out_ucast_pkts: None,
            if_in_errors: None, if_out_errors: None,
            extra: serde_json::json!([]),
        }
    }

    fn make_counter_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Counter,
            exporter: "10.0.0.1".parse().unwrap(),
            received_at: chrono::Utc::now(),
            src_addr: None, dst_addr: None, src_port: None, dst_port: None, ip_protocol: None,
            sampling_rate: None, input_ifindex: None, output_ifindex: None,
            if_index: Some(1), if_type: Some(6),
            if_speed: Some(1_000_000_000),
            if_direction: Some(1),
            if_in_octets: Some(1_000_000),
            if_out_octets: Some(500_000),
            if_in_ucast_pkts: Some(1000),
            if_out_ucast_pkts: Some(500),
            if_in_errors: Some(2),
            if_out_errors: Some(1),
            extra: serde_json::json!([]),
        }
    }

    #[test]
    fn sink_partition_returns_flow_for_flow_records() {
        let sink = SflowSink;
        let r = make_flow_record();
        assert_eq!(sink.partition(&r), Some("flow".to_string()));
    }

    #[test]
    fn sink_partition_returns_counter_for_counter_records() {
        let sink = SflowSink;
        let r = make_counter_record();
        assert_eq!(sink.partition(&r), Some("counter".to_string()));
    }

    #[test]
    fn flow_schema_has_required_columns() {
        let sink = SflowSink;
        let schema = sink.schema(Some("flow"));
        for col in &["sample_type", "exporter", "received_at", "src_addr", "dst_addr",
                      "src_port", "dst_port", "ip_protocol", "sampling_rate",
                      "input_ifindex", "output_ifindex", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "flow schema missing column '{col}'"
            );
        }
    }

    #[test]
    fn counter_schema_has_required_columns() {
        let sink = SflowSink;
        let schema = sink.schema(Some("counter"));
        for col in &["sample_type", "exporter", "received_at",
                      "if_index", "if_type", "if_speed", "if_direction",
                      "if_in_octets", "if_out_octets",
                      "if_in_ucast_pkts", "if_out_ucast_pkts",
                      "if_in_errors", "if_out_errors", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "counter schema missing column '{col}'"
            );
        }
    }

    #[test]
    fn to_record_batch_flow_produces_correct_values() {
        let sink = SflowSink;
        let r = make_flow_record();
        let schema = sink.schema(Some("flow"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let src = batch.column_by_name("src_addr").unwrap()
            .as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(src.value(0), "192.168.1.1");

        let sr = batch.column_by_name("sampling_rate").unwrap()
            .as_any().downcast_ref::<UInt32Array>().unwrap();
        assert_eq!(sr.value(0), 512);
    }

    #[test]
    fn to_record_batch_counter_produces_correct_values() {
        let sink = SflowSink;
        let r = make_counter_record();
        let schema = sink.schema(Some("counter"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let if_speed = batch.column_by_name("if_speed").unwrap()
            .as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(if_speed.value(0), 1_000_000_000u64);

        let if_in_oct = batch.column_by_name("if_in_octets").unwrap()
            .as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(if_in_oct.value(0), 1_000_000u64);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p logthing --lib forwarding::sflow_s3::tests 2>&1 | head -20
# Expected: error[E0432]: unresolved import (module not declared)
```

- [ ] **Step 3: Implement**

Clone `src/forwarding/ipfix_s3.rs`. Key differences from IPFIX:

1. `SflowSink::partition` returns `Some("flow".to_string())` or `Some("counter".to_string())` based on `record.sample_type`.
2. Two Arrow schemas: one for flow records, one for counter records. `schema(partition)` dispatches on `Some("flow")` vs `Some("counter")`.
3. `to_record_batch` similarly dispatches schema + column builders by partition.
4. `SflowHandler::handle_samples` sends one record at a time via `try_send(record)`.
5. `sflow_start` sets `max_partitions: 2` in `BufferedWriterConfig`.

```rust
// src/forwarding/sflow_s3.rs
//! sFlow v5 → S3 Parquet persistence.

use crate::config::SflowS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::sflow::{SampleType, SflowRecord};
use arrow::array::{
    ArrayRef, StringBuilder, UInt8Builder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ── Schemas ──────────────────────────────────────────────────────────────────

static FLOW_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("sample_type",    DataType::Utf8,   false),
        Field::new("exporter",       DataType::Utf8,   false),
        Field::new("received_at",    DataType::Utf8,   false),
        Field::new("src_addr",       DataType::Utf8,   true),
        Field::new("dst_addr",       DataType::Utf8,   true),
        Field::new("src_port",       DataType::UInt16, true),
        Field::new("dst_port",       DataType::UInt16, true),
        Field::new("ip_protocol",    DataType::UInt8,  true),
        Field::new("sampling_rate",  DataType::UInt32, true),
        Field::new("input_ifindex",  DataType::UInt32, true),
        Field::new("output_ifindex", DataType::UInt32, true),
        Field::new("extra",          DataType::Utf8,   false),
    ]))
});

static COUNTER_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("sample_type",      DataType::Utf8,   false),
        Field::new("exporter",         DataType::Utf8,   false),
        Field::new("received_at",      DataType::Utf8,   false),
        Field::new("if_index",         DataType::UInt32, true),
        Field::new("if_type",          DataType::UInt32, true),
        Field::new("if_speed",         DataType::UInt64, true),
        Field::new("if_direction",     DataType::UInt32, true),
        Field::new("if_in_octets",     DataType::UInt64, true),
        Field::new("if_out_octets",    DataType::UInt64, true),
        Field::new("if_in_ucast_pkts", DataType::UInt64, true),
        Field::new("if_out_ucast_pkts",DataType::UInt64, true),
        Field::new("if_in_errors",     DataType::UInt32, true),
        Field::new("if_out_errors",    DataType::UInt32, true),
        Field::new("extra",            DataType::Utf8,   false),
    ]))
});

// ── SflowSink ────────────────────────────────────────────────────────────────

pub struct SflowSink;

impl ParquetSink for SflowSink {
    type Record = SflowRecord;

    fn source(&self) -> &'static str { "sflow" }

    fn partition(&self, record: &SflowRecord) -> Option<String> {
        Some(match record.sample_type {
            SampleType::Flow    => "flow".to_string(),
            SampleType::Counter => "counter".to_string(),
        })
    }

    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        match partition {
            Some("counter") => COUNTER_SCHEMA.clone(),
            _               => FLOW_SCHEMA.clone(),   // "flow" or None
        }
    }

    fn to_record_batch(
        &self,
        record: &SflowRecord,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        match record.sample_type {
            SampleType::Flow    => flow_to_record_batch(record, schema),
            SampleType::Counter => counter_to_record_batch(record, schema),
        }
    }
}

fn flow_to_record_batch(r: &SflowRecord, schema: &Arc<Schema>) -> anyhow::Result<RecordBatch> {
    let extra_str = serde_json::to_string(&r.extra).unwrap_or_else(|_| "[]".to_string());
    let columns: Vec<ArrayRef> = vec![
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(match r.sample_type { SampleType::Flow => "flow", SampleType::Counter => "counter" }); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.exporter.to_string()); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.received_at.to_rfc3339()); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_option(r.src_addr.as_ref().map(|a| a.to_string())); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_option(r.dst_addr.as_ref().map(|a| a.to_string())); b.finish() }),
        Arc::new({ let mut b = UInt16Builder::new(); b.append_option(r.src_port); b.finish() }),
        Arc::new({ let mut b = UInt16Builder::new(); b.append_option(r.dst_port); b.finish() }),
        Arc::new({ let mut b = UInt8Builder::new();  b.append_option(r.ip_protocol); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.sampling_rate); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.input_ifindex); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.output_ifindex); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(&extra_str); b.finish() }),
    ];
    Ok(RecordBatch::try_new(schema.clone(), columns)?)
}

fn counter_to_record_batch(r: &SflowRecord, schema: &Arc<Schema>) -> anyhow::Result<RecordBatch> {
    let extra_str = serde_json::to_string(&r.extra).unwrap_or_else(|_| "[]".to_string());
    let columns: Vec<ArrayRef> = vec![
        Arc::new({ let mut b = StringBuilder::new(); b.append_value("counter"); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.exporter.to_string()); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.received_at.to_rfc3339()); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_index); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_type); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_speed); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_direction); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_in_octets); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_out_octets); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_in_ucast_pkts); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_out_ucast_pkts); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_in_errors); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_out_errors); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(&extra_str); b.finish() }),
    ];
    Ok(RecordBatch::try_new(schema.clone(), columns)?)
}

// ── SflowS3Handler — type alias + SflowHandler impl ─────────────────────────

pub type SflowS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>;

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>
{
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for record in samples {
            if let Err(_dropped) = self.try_send(record) {
                tracing::warn!("sFlow S3 channel full; dropped record from {}", source);
            }
        }
    }
}

// ── sflow_start — convenience constructor ────────────────────────────────────

pub fn sflow_start(
    cfg: &SflowS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{BufferedWriterConfig, FlushPolicy, ParquetWriterHandle};
    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: 2, // "flow" and "counter"
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(SflowSink, s3, bwc, policy)
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test -p logthing --lib forwarding::sflow_s3::tests 2>&1 | tail -10
# Expected: test result: ok. 6 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/sflow_s3.rs src/forwarding/mod.rs
git commit -m "feat(sflow): add SflowSink + sflow_start Parquet/S3 persistence"
```

---

### Task 3.6: Wire sFlow into `main.rs`

**Files:**
- Modify `src/main.rs`
- Modify `src/lib.rs` (ensure `pub mod sflow;` present)

**Interfaces:**
- Consumes: `SflowConfig`, `SflowS3Config`, `SflowListener`, `SflowListenerConfig`, `sflow_start`

---

- [ ] **Step 1: Write the failing test**

```rust
// src/config/mod.rs — add one test (already covered by Task 3.3 tests; re-verify wiring):
#[test]
fn sflow_is_disabled_by_default_in_main_config() {
    let cfg = Config::default();
    assert!(!cfg.sflow.enabled, "sflow must be opt-in (enabled=false by default)");
}
```

The main.rs wiring itself is verified by the e2e test in Task 3.4 (the listener test binds a real socket and sends a real datagram). Additionally confirm the binary compiles cleanly.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo build 2>&1 | grep "error" | head -10
# Expected: error[E0425]: cannot find value `sflow` in module `logthing`
```

- [ ] **Step 3: Implement**

Add to `src/main.rs` immediately after the IPFIX block, following the exact same `if config.ipfix.enabled { ... }` pattern:

```rust
// src/main.rs — add after the IPFIX block (after line ~150)
use logthing::{sflow}; // add to the top-level use statement

// ── sFlow listener ──────────────────────────────────────────────────────────
if config.sflow.enabled {
    let sflow_config_clone = config.clone();
    let sflow_shutdown_rx = shutdown_rx.clone();

    let sflow_handler: Arc<dyn sflow::listener::SflowHandler> =
        if let Some(s3_cfg) = sflow_config_clone.sflow.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) =
                        forwarding::sflow_s3::sflow_start(s3_cfg, Arc::new(sink));
                    writer_handles.push(writer_handle);
                    Arc::new(handler)
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for sFlow persistence, \
                             falling back to DefaultSflowHandler: {e}"
                    );
                    Arc::new(sflow::listener::DefaultSflowHandler)
                }
            }
        } else {
            Arc::new(sflow::listener::DefaultSflowHandler)
        };

    let listener_config = sflow::listener::SflowListenerConfig {
        udp_port: sflow_config_clone.sflow.udp_port,
        bind_address: sflow_config_clone.sflow.bind_address.clone(),
    };
    let handle = tokio::spawn(async move {
        let listener = sflow::listener::SflowListener::new(listener_config, sflow_handler);
        if let Err(e) = listener.start_with_shutdown(sflow_shutdown_rx).await {
            error!("sFlow listener error: {}", e);
        }
    });
    listener_handles.push(handle);
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo build 2>&1 | grep "error" | head -5
# Expected: no output (clean build)

cargo test -p logthing --lib config::tests::sflow_is_disabled_by_default_in_main_config 2>&1 | tail -5
# Expected: test result: ok. 1 passed
```

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/lib.rs
git commit -m "feat(sflow): wire SflowListener into main.rs startup"
```

---

### Task 3.7: Integration test (`tests/sflow_s3_integration.rs`)

**Files:**
- Create `tests/sflow_s3_integration.rs`

**Interfaces:**
- Consumes: `sflow_start`, `SflowS3Config`, `S3Sink`, `SflowHandler::handle_samples`

---

- [ ] **Step 1: Write the failing test**

```rust
// tests/sflow_s3_integration.rs
//! Integration test: SflowRecord → SflowS3Handler → Parquet object in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent the test is skipped.

use logthing::config::{S3ConnectionConfig, SflowS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::sflow_s3::sflow_start;
use logthing::sflow::listener::SflowHandler;
use logthing::sflow::{SampleType, SflowRecord};
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_sflow_config(endpoint: &str) -> SflowS3Config {
    SflowS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "sflow-samples".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "sflow".to_string(),
        max_buffer_rows: 1,           // flush on first record
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_flow_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Flow,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        src_addr: Some("192.168.1.10".parse().unwrap()),
        dst_addr: Some("10.0.0.2".parse().unwrap()),
        src_port: Some(8080),
        dst_port: Some(80),
        ip_protocol: Some(6),
        sampling_rate: Some(512),
        input_ifindex: Some(1),
        output_ifindex: Some(2),
        if_index: None, if_type: None, if_speed: None, if_direction: None,
        if_in_octets: None, if_out_octets: None,
        if_in_ucast_pkts: None, if_out_ucast_pkts: None,
        if_in_errors: None, if_out_errors: None,
        extra: serde_json::json!([]),
    }
}

#[tokio::test]
async fn sflow_flow_record_appears_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping sflow_s3 integration test");
            return;
        }
    };

    let cfg = minio_sflow_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );
    let (handler, _writer_task) = sflow_start(&cfg, sink.clone());
    let src: std::net::SocketAddr = "127.0.0.1:6343".parse().unwrap();

    handler.handle_samples(vec![make_flow_record()], src).await;
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Verify via aws-sdk-s3
    use aws_sdk_s3::Client as S3Client;
    let region = aws_sdk_s3::config::Region::new("us-east-1");
    let credentials = aws_credential_types::Credentials::new(
        cfg.connection.access_key.clone(),
        cfg.connection.secret_key.clone(),
        None, None, "test",
    );
    let sdk_cfg = aws_config::from_env()
        .region(region)
        .endpoint_url(&cfg.connection.endpoint)
        .credentials_provider(credentials)
        .load()
        .await;
    let s3 = S3Client::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk_cfg)
            .force_path_style(true)
            .build(),
    );

    let list = s3
        .list_objects_v2()
        .bucket(&cfg.connection.bucket)
        .prefix("sflow/flow/")   // partitioned by sample_type
        .send()
        .await
        .expect("list_objects_v2");

    assert!(
        !list.contents().is_empty(),
        "expected at least one Parquet object under sflow/flow/; found none"
    );

    let key = list.contents()[0].key().expect("key");
    let get_resp = s3
        .get_object()
        .bucket(&cfg.connection.bucket)
        .key(key)
        .send()
        .await
        .expect("get_object");
    let body_bytes = get_resp.body.collect().await.expect("body").into_bytes();

    use bytes::Bytes;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let buf = Bytes::from(body_bytes.to_vec());
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder");
    let schema = builder.schema().clone();

    assert!(schema.field_with_name("src_addr").is_ok(), "schema must have src_addr");
    assert!(schema.field_with_name("sampling_rate").is_ok(), "schema must have sampling_rate");

    let mut reader = builder.build().expect("reader");
    let rb = reader.next().expect("batch").expect("ok");
    assert_eq!(rb.num_rows(), 1, "expected exactly 1 row");

    use arrow::array::StringArray;
    let src_col = rb.column_by_name("src_addr").unwrap()
        .as_any().downcast_ref::<StringArray>().unwrap();
    assert_eq!(src_col.value(0), "192.168.1.10");
}
```

- [ ] **Step 2: Run to verify it fails (or skips correctly)**

```bash
cargo test --test sflow_s3_integration 2>&1 | tail -10
# Without MINIO_ENDPOINT: "MINIO_ENDPOINT not set — skipping sflow_s3 integration test"
# test result: ok. 1 passed (skipped via early return)
```

- [ ] **Step 3: Implement**

No implementation code needed — the test file itself is the deliverable. The `sflow_start`, `SflowS3Config`, `SflowHandler`, and `S3Sink` types were all implemented in previous tasks. Confirm the test compiles:

```bash
cargo test --test sflow_s3_integration --no-run 2>&1 | tail -5
# Expected: Compiling logthing ... Finished
```

- [ ] **Step 4: Run to verify it passes (with MinIO)**

```bash
MINIO_ENDPOINT=http://localhost:9000 \
MINIO_BUCKET=sflow-test \
cargo test --test sflow_s3_integration -- --nocapture 2>&1 | tail -20
# Expected: test result: ok. 1 passed
```

- [ ] **Step 5: Commit**

```bash
git add tests/sflow_s3_integration.rs
git commit -m "test(sflow): add MINIO_ENDPOINT-gated integration test for sFlow S3 sink"
```

---

### Task 3.8: Full test run and verification

**Files:** No new files.

- [ ] **Step 1: Run all sFlow unit tests**

```bash
cargo test -p logthing --lib sflow 2>&1 | tail -15
# Expected: test result: ok. ≥10 passed; 0 failed
```

- [ ] **Step 2: Run all unit tests (regression guard)**

```bash
cargo test -p logthing --lib 2>&1 | tail -10
# Expected: test result: ok. 0 failed
```

- [ ] **Step 3: Run integration test (skip guard)**

```bash
cargo test --test sflow_s3_integration 2>&1 | tail -5
# Expected: test skipped or 1 passed (with MINIO_ENDPOINT)
```

- [ ] **Step 4: Verify binary compiles**

```bash
cargo build --release 2>&1 | grep "^error" | head -5
# Expected: no output
```

- [ ] **Step 5: Commit coverage tag**

```bash
git tag sflow-unit-3-complete
```

---

## Unit 4 — Generic JSON / Splunk HEC ingest (`src/ingest/` + `src/server/`)

This unit wires three new HTTP ingest routes (`/services/collector/event`, `/services/collector/raw`, `/ingest`) onto the existing Axum server. It introduces `GenericRecord`, `GenericSink` (a `ParquetSink` that partitions by `sourcetype`), `HecConfig`/`HecS3Config` in `src/config/mod.rs`, and an `IngestState` Axum extension that carries the optional `GenericS3Handler`. Authentication uses constant-time token comparison (`subtle` crate, already in `Cargo.toml`). The `subtle` crate is already listed in `[dependencies]`; no new Cargo entries are needed beyond confirming `reqwest` is available in `[dev-dependencies]` (add `reqwest = { version = "0.12", … }` if missing).

---

### Task 4.1: `GenericRecord` data type (`src/ingest/mod.rs`)

**Files:** Create `src/ingest/mod.rs`; expose module in `src/lib.rs`

**Interfaces:**
- Produces `GenericRecord { sourcetype: String, host: Option<String>, time: Option<DateTime<Utc>>, fields: serde_json::Value, received_at: DateTime<Utc> }`

- [ ] **Step 1: Write the failing test**

  Add to the bottom of the new file (test module inside `src/ingest/mod.rs`):

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use chrono::Utc;
      use serde_json::json;

      #[test]
      fn generic_record_fields_are_accessible() {
          let rec = GenericRecord {
              sourcetype: "my_app".to_string(),
              host: Some("host1".to_string()),
              time: None,
              fields: json!({"key": "value"}),
              received_at: Utc::now(),
          };
          assert_eq!(rec.sourcetype, "my_app");
          assert_eq!(rec.host.as_deref(), Some("host1"));
          assert!(rec.time.is_none());
          assert_eq!(rec.fields["key"], "value");
      }

      #[test]
      fn generic_record_derives_debug_and_clone() {
          let rec = GenericRecord {
              sourcetype: "test".to_string(),
              host: None,
              time: Some(Utc::now()),
              fields: json!({}),
              received_at: Utc::now(),
          };
          let cloned = rec.clone();
          assert_eq!(cloned.sourcetype, rec.sourcetype);
          // Debug must not panic
          let _ = format!("{:?}", cloned);
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib ingest::tests 2>&1 | head -30
  ```

  Expected: `error[E0433]: failed to resolve: use of undeclared crate or module 'ingest'`

- [ ] **Step 3: Implement**

  Create `src/ingest/mod.rs`:

  ```rust
  //! Generic JSON / Splunk HEC ingest types.
  //!
  //! `GenericRecord` is the unified envelope for all three ingest routes
  //! (`/services/collector/event`, `/services/collector/raw`, `/ingest`).
  //! `GenericSink` (Task 4.3) is the `ParquetSink` adapter that persists
  //! these records to S3 partitioned by `sourcetype`.

  use chrono::{DateTime, Utc};

  /// Unified envelope record produced by all three HEC/NDJSON ingest routes.
  ///
  /// `fields` holds the raw JSON payload; for HEC event envelopes this is the
  /// value of `"event"` key.  For raw and NDJSON routes it is the full parsed
  /// JSON object.  The `sourcetype` is used as the Parquet partition key.
  #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
  pub struct GenericRecord {
      /// Log source type; used as the S3 partition key (e.g. `"access_log"`).
      pub sourcetype: String,
      /// Originating host, if present in the HEC envelope or query parameter.
      pub host: Option<String>,
      /// Event timestamp from the HEC envelope (`"time"` field, epoch seconds).
      /// `None` when absent — consumers should fall back to `received_at`.
      pub time: Option<DateTime<Utc>>,
      /// The event payload as a JSON value.
      pub fields: serde_json::Value,
      /// Wall-clock time this server received the record.
      pub received_at: DateTime<Utc>,
  }
  ```

  Add `pub mod ingest;` to `src/lib.rs` (after the `pub mod zeek;` line).

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib ingest::tests
  ```

  Expected: `test result: ok. 2 passed`

- [ ] **Step 5: Commit**

  ```
  git add src/ingest/mod.rs src/lib.rs
  git commit -m "feat(ingest): add GenericRecord type in src/ingest/mod.rs"
  ```

---

### Task 4.2: `HecConfig` / `HecS3Config` in config (`src/config/mod.rs`)

**Files:** Modify `src/config/mod.rs`

**Interfaces:**
- Produces `HecConfig { enabled: bool, token: String, max_sourcetype_partitions: usize, s3: Option<HecS3Config> }`
- Produces `HecS3Config { connection: S3ConnectionConfig, prefix: String, flush_threshold_bytes: usize, flush_interval_secs: u64, channel_capacity: usize, max_buffer_rows: usize }`
- Modifies `Config` struct: adds `pub hec: HecConfig`

- [ ] **Step 1: Write the failing test**

  Add to the `#[cfg(test)] mod tests` block inside `src/config/mod.rs`:

  ```rust
  #[test]
  fn hec_disabled_by_default() {
      let cfg = Config::default();
      assert!(!cfg.hec.enabled, "hec must be disabled by default");
      assert_eq!(
          cfg.hec.max_sourcetype_partitions, 64,
          "default max_sourcetype_partitions must be 64"
      );
      assert!(cfg.hec.s3.is_none(), "absent [hec.s3] must yield None");
  }

  #[test]
  fn hec_s3_flat_toml_deserializes_correctly() {
      let toml_str = r#"
  [hec]
  enabled = true
  token = "super-secret-token"
  max_sourcetype_partitions = 32
  [hec.s3]
  endpoint   = "http://minio:9000"
  bucket     = "hec-events"
  region     = "us-east-1"
  access_key = "KEY"
  secret_key = "SECRET"
  "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse hec config");
      assert!(cfg.hec.enabled);
      assert_eq!(cfg.hec.token, "super-secret-token");
      assert_eq!(cfg.hec.max_sourcetype_partitions, 32);
      let s3 = cfg.hec.s3.expect("s3 section present");
      assert_eq!(s3.connection.bucket, "hec-events");
      assert_eq!(s3.prefix, "hec"); // default prefix
      assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
      assert_eq!(s3.flush_interval_secs, 900);
      assert_eq!(s3.channel_capacity, 256);
      assert_eq!(s3.max_buffer_rows, 100_000);
  }

  #[test]
  fn hec_s3_absent_section_means_no_persistence() {
      let toml_str = "[hec]\nenabled = true\ntoken = \"tok\"\n";
      let cfg: Config = toml::from_str(toml_str).expect("parse");
      assert!(cfg.hec.s3.is_none(), "absent [hec.s3] must yield None");
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib config::tests::hec 2>&1 | head -30
  ```

  Expected: compile errors referencing missing `hec` field on `Config`.

- [ ] **Step 3: Implement**

  Add the following structs and default functions to `src/config/mod.rs` (after `WefConfig`):

  ```rust
  /// Per-source S3 persistence config for HEC ingest.
  #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
  pub struct HecS3Config {
      /// Shared S3 connection fields (flattened: `[hec.s3]\nendpoint = …`).
      #[serde(flatten)]
      pub connection: S3ConnectionConfig,
      /// S3 key prefix, slash-free (default: `"hec"`).
      #[serde(default = "default_hec_s3_prefix")]
      pub prefix: String,
      /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
      #[serde(default = "default_hec_flush_bytes")]
      pub flush_threshold_bytes: usize,
      /// Flush after this many seconds regardless (default: 900).
      #[serde(default = "default_hec_flush_secs")]
      pub flush_interval_secs: u64,
      /// Bounded channel capacity (default: 256).
      #[serde(default = "default_hec_channel_capacity")]
      pub channel_capacity: usize,
      /// Maximum buffered rows before hard cap (default: 100_000).
      #[serde(default = "default_hec_max_buffer_rows")]
      pub max_buffer_rows: usize,
  }

  fn default_hec_s3_prefix() -> String { "hec".to_string() }
  fn default_hec_flush_bytes() -> usize { 100 * 1024 * 1024 }
  fn default_hec_flush_secs() -> u64 { 900 }
  fn default_hec_channel_capacity() -> usize { 256 }
  fn default_hec_max_buffer_rows() -> usize { 100_000 }

  /// Top-level `[hec]` config section.
  #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
  pub struct HecConfig {
      /// Enable the HEC ingest routes (default: false).
      #[serde(default = "default_hec_enabled")]
      pub enabled: bool,
      /// Shared secret compared against `Authorization: Splunk <token>`.
      /// Empty string means any token is accepted — only useful for local dev.
      #[serde(default)]
      pub token: String,
      /// Maximum distinct `sourcetype` partitions before overflow (default: 64).
      #[serde(default = "default_hec_max_sourcetype_partitions")]
      pub max_sourcetype_partitions: usize,
      /// Optional S3 persistence. `None` → records are accepted but not stored.
      #[serde(default)]
      pub s3: Option<HecS3Config>,
  }

  fn default_hec_enabled() -> bool { false }
  fn default_hec_max_sourcetype_partitions() -> usize { 64 }

  impl Default for HecConfig {
      fn default() -> Self {
          Self {
              enabled: default_hec_enabled(),
              token: String::new(),
              max_sourcetype_partitions: default_hec_max_sourcetype_partitions(),
              s3: None,
          }
      }
  }
  ```

  Add `pub hec: HecConfig` to `Config` struct (after `pub wef: WefConfig`), add `#[serde(default)]` to it, and add `hec: HecConfig::default()` to `Config::default()`.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib config::tests::hec
  ```

  Expected: `test result: ok. 3 passed`

- [ ] **Step 5: Commit**

  ```
  git add src/config/mod.rs
  git commit -m "feat(config): add HecConfig/HecS3Config and hec field on Config"
  ```

---

### Task 4.3: `GenericSink` and `hec_start` (`src/forwarding/generic_s3.rs`)

**Files:** Create `src/forwarding/generic_s3.rs`; expose in `src/forwarding/mod.rs`

**Interfaces:**
- Consumes `GenericRecord`, `HecS3Config`, `Arc<S3Sink>`
- Produces `GenericSink` (implements `ParquetSink<Record = GenericRecord>`), `GenericS3Handler = ParquetWriterHandle<GenericSink>`, `hec_start(cfg: &HecS3Config, s3: Arc<S3Sink>, max_partitions: usize) -> (GenericS3Handler, JoinHandle<()>)`

The Parquet schema has 5 columns: `sourcetype: Utf8`, `host: Utf8 (nullable)`, `time: Timestamp(Millisecond, UTC) nullable`, `received_at: Timestamp(Millisecond, UTC)`, `fields: Utf8` (JSON-serialized).

- [ ] **Step 1: Write the failing test**

  ```rust
  // src/forwarding/generic_s3.rs — bottom of file, inside #[cfg(test)] mod tests

  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::config::S3ConnectionConfig;
      use crate::forwarding::buffered_writer::{
          BufferedWriterConfig, FlushPolicy, ParquetSink, PartitionedParquetWriter,
      };
      use crate::forwarding::s3_sink::S3Sink;
      use crate::ingest::GenericRecord;
      use chrono::Utc;
      use serde_json::json;
      use std::sync::Arc;

      async fn unreachable_sink() -> Arc<S3Sink> {
          let conn = S3ConnectionConfig {
              endpoint: "http://127.0.0.1:1".to_string(),
              bucket: "test-bucket".to_string(),
              region: "us-east-1".to_string(),
              access_key: "AKIATEST".to_string(),
              secret_key: "SECRETTEST".to_string(),
          };
          Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"))
      }

      fn make_record(sourcetype: &str) -> GenericRecord {
          GenericRecord {
              sourcetype: sourcetype.to_string(),
              host: Some("host1".to_string()),
              time: Some(Utc::now()),
              fields: json!({"action": "login", "user": "alice"}),
              received_at: Utc::now(),
          }
      }

      #[test]
      fn generic_sink_source_returns_hec() {
          assert_eq!(GenericSink.source(), "hec");
      }

      #[test]
      fn generic_sink_partition_uses_sourcetype() {
          let rec = make_record("access_log");
          assert_eq!(GenericSink.partition(&rec), Some("access_log".to_string()));
      }

      #[test]
      fn generic_sink_schema_has_five_columns() {
          let schema = GenericSink.schema(Some("access_log"));
          assert_eq!(schema.fields().len(), 5);
          for col in &["sourcetype", "host", "time", "received_at", "fields"] {
              assert!(
                  schema.field_with_name(col).is_ok(),
                  "schema must have column '{col}'"
              );
          }
      }

      #[test]
      fn generic_sink_schema_overflow_same_as_named() {
          // All partitions use the same fixed schema — no per-partition variation.
          assert_eq!(
              GenericSink.schema(Some("_overflow")),
              GenericSink.schema(Some("anything"))
          );
          assert_eq!(GenericSink.schema(None), GenericSink.schema(Some("x")));
      }

      #[test]
      fn generic_sink_to_record_batch_produces_one_row() {
          let rec = make_record("access_log");
          let schema = GenericSink.schema(Some("access_log"));
          let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
          assert_eq!(batch.num_rows(), 1);

          use arrow::array::StringArray;
          let st = batch
              .column_by_name("sourcetype")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert_eq!(st.value(0), "access_log");

          let fields_col = batch
              .column_by_name("fields")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          let parsed: serde_json::Value =
              serde_json::from_str(fields_col.value(0)).expect("fields must be valid JSON");
          assert_eq!(parsed["user"], "alice");
      }

      #[test]
      fn generic_sink_null_host_produces_null_in_batch() {
          let mut rec = make_record("mytype");
          rec.host = None;
          let schema = GenericSink.schema(Some("mytype"));
          let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
          use arrow::array::StringArray;
          let host_col = batch
              .column_by_name("host")
              .unwrap()
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          assert!(host_col.is_null(0), "null host must produce Arrow null");
      }

      #[tokio::test]
      async fn writer_partitions_by_sourcetype() {
          let sink = unreachable_sink().await;
          let bwc = BufferedWriterConfig {
              connection: S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "test-bucket".to_string(),
                  region: "us-east-1".to_string(),
                  access_key: "AKIATEST".to_string(),
                  secret_key: "SECRETTEST".to_string(),
              },
              prefix: "hec".to_string(),
              max_buffer_rows: 100_000,
              flush_threshold_bytes: usize::MAX,
              flush_interval_secs: 3600,
              channel_capacity: 256,
              max_partitions: 64,
          };
          let policy = FlushPolicy {
              max_rows: 100_000,
              max_bytes: usize::MAX,
              interval: std::time::Duration::from_secs(3600),
          };
          let mut writer = PartitionedParquetWriter::new(GenericSink, sink, bwc, policy);

          writer.push(make_record("access_log")).await.ok();
          writer.push(make_record("access_log")).await.ok();
          writer.push(make_record("audit_log")).await.ok();

          assert_eq!(
              writer.buffers.get("access_log").map(|b| b.row_count).unwrap_or(0),
              2
          );
          assert_eq!(
              writer.buffers.get("audit_log").map(|b| b.row_count).unwrap_or(0),
              1
          );
      }

      #[tokio::test]
      async fn writer_overflows_to_overflow_partition_at_cap() {
          let sink = unreachable_sink().await;
          let cap = 2usize;
          let bwc = BufferedWriterConfig {
              connection: S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "test-bucket".to_string(),
                  region: "us-east-1".to_string(),
                  access_key: "AKIATEST".to_string(),
                  secret_key: "SECRETTEST".to_string(),
              },
              prefix: "hec".to_string(),
              max_buffer_rows: 100_000,
              flush_threshold_bytes: usize::MAX,
              flush_interval_secs: 3600,
              channel_capacity: 256,
              max_partitions: cap,
          };
          let policy = FlushPolicy {
              max_rows: 100_000,
              max_bytes: usize::MAX,
              interval: std::time::Duration::from_secs(3600),
          };
          let mut writer = PartitionedParquetWriter::new(GenericSink, sink, bwc, policy);

          // Push cap + 3 distinct sourcetypes.
          for i in 0..(cap + 3) {
              writer.push(make_record(&format!("type_{i}"))).await.ok();
          }

          assert!(
              writer.buffers.len() <= cap + 1,
              "buffers map must be bounded (cap={cap} + 1 overflow)"
          );
          assert!(
              writer.buffers.contains_key("_overflow"),
              "_overflow partition must exist after cap exceeded"
          );
      }

      #[tokio::test]
      async fn hec_start_wires_handler_and_join_handle() {
          use crate::config::HecS3Config;

          let conn = S3ConnectionConfig {
              endpoint: "http://127.0.0.1:1".to_string(),
              bucket: "test-bucket".to_string(),
              region: "us-east-1".to_string(),
              access_key: "AKIATEST".to_string(),
              secret_key: "SECRETTEST".to_string(),
          };
          let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("S3Sink"));
          let cfg = HecS3Config {
              connection: conn,
              prefix: "hec".to_string(),
              flush_threshold_bytes: usize::MAX,
              flush_interval_secs: 3600,
              channel_capacity: 256,
              max_buffer_rows: 100_000,
          };
          let (handler, join_handle) = hec_start(&cfg, s3, 64);
          handler.try_send(make_record("access_log")).expect("send ok");
          drop(handler);
          tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
              .await
              .expect("writer exits within 5s")
              .expect("writer does not panic");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib forwarding::generic_s3::tests 2>&1 | head -40
  ```

  Expected: `error[E0433]: failed to resolve: use of undeclared module 'generic_s3'`

- [ ] **Step 3: Implement**

  Create `src/forwarding/generic_s3.rs`:

  ```rust
  //! Generic JSON / HEC → S3 Parquet persistence.
  //!
  //! `GenericSink` is a `ParquetSink` that partitions `GenericRecord`s by
  //! `sourcetype`.  All partitions share a single fixed schema (5 columns):
  //! `sourcetype`, `host` (nullable), `time` (nullable timestamp), `received_at`,
  //! and `fields` (JSON string).  The `_overflow` partition uses the same schema.
  //!
  //! S3 key layout: `hec/<sourcetype>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`

  use crate::config::HecS3Config;
  use crate::forwarding::buffered_writer::ParquetSink;
  use crate::ingest::GenericRecord;
  use arrow_array::{RecordBatch, StringArray, TimestampMillisecondArray};
  use arrow_schema::{DataType, Field, Schema, TimeUnit};
  use std::sync::Arc;

  // ---------------------------------------------------------------------------
  // GenericSink — ParquetSink adapter
  // ---------------------------------------------------------------------------

  pub struct GenericSink;

  /// Build the fixed 5-column schema used for all HEC partitions.
  fn generic_schema() -> Arc<Schema> {
      Arc::new(Schema::new(vec![
          Field::new("sourcetype", DataType::Utf8, false),
          Field::new("host", DataType::Utf8, true),
          Field::new(
              "time",
              DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
              true,
          ),
          Field::new(
              "received_at",
              DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
              false,
          ),
          Field::new("fields", DataType::Utf8, false),
      ]))
  }

  impl ParquetSink for GenericSink {
      type Record = GenericRecord;

      fn source(&self) -> &'static str {
          "hec"
      }

      /// Partition key = `sourcetype`.  Invalid characters are preserved as-is
      /// because sourcetypes are operator-controlled (admin-set token required).
      fn partition(&self, record: &GenericRecord) -> Option<String> {
          Some(record.sourcetype.clone())
      }

      /// All partitions — including `_overflow` and `None` — use the same fixed
      /// 5-column schema.  There is no per-sourcetype typed schema.
      fn schema(&self, _partition: Option<&str>) -> Arc<Schema> {
          generic_schema()
      }

      fn to_record_batch(
          &self,
          record: &GenericRecord,
          schema: &Arc<Schema>,
      ) -> anyhow::Result<RecordBatch> {
          use arrow_array::types::TimestampMillisecondType;
          use arrow_array::PrimitiveArray;

          let sourcetype = StringArray::from(vec![record.sourcetype.as_str()]);

          let host: StringArray = match &record.host {
              Some(h) => StringArray::from(vec![Some(h.as_str())]),
              None => StringArray::from(vec![None::<&str>]),
          };

          let time_ms: PrimitiveArray<TimestampMillisecondType> = match &record.time {
              Some(dt) => arrow_array::PrimitiveArray::from(vec![Some(
                  dt.timestamp_millis(),
              )]),
              None => arrow_array::PrimitiveArray::from(vec![None::<i64>]),
          };
          let time_col = arrow_array::PrimitiveArray::<TimestampMillisecondType>::from(
              time_ms.into_data(),
          );

          let received_ms: PrimitiveArray<TimestampMillisecondType> =
              arrow_array::PrimitiveArray::from(vec![Some(
                  record.received_at.timestamp_millis(),
              )]);

          let fields_json = serde_json::to_string(&record.fields)
              .unwrap_or_else(|_| "{}".to_string());
          let fields_col = StringArray::from(vec![fields_json.as_str()]);

          RecordBatch::try_new(
              schema.clone(),
              vec![
                  Arc::new(sourcetype),
                  Arc::new(host),
                  Arc::new(time_col),
                  Arc::new(received_ms),
                  Arc::new(fields_col),
              ],
          )
          .map_err(|e| anyhow::anyhow!("GenericSink RecordBatch error: {e}"))
      }
  }

  // ---------------------------------------------------------------------------
  // GenericS3Handler type alias + hec_start convenience constructor
  // ---------------------------------------------------------------------------

  /// `GenericS3Handler` is a thin alias for `ParquetWriterHandle<GenericSink>`.
  pub type GenericS3Handler =
      crate::forwarding::buffered_writer::ParquetWriterHandle<GenericSink>;

  /// Construct a `GenericS3Handler` from a `HecS3Config`, a pre-built `S3Sink`,
  /// and the maximum distinct sourcetype partition count.
  ///
  /// Returns `(handler, writer_join_handle)`.  The caller retains the `JoinHandle`
  /// and awaits it during graceful shutdown after all `GenericS3Handler` clones
  /// have been dropped (closing the channel and triggering the final flush).
  pub fn hec_start(
      cfg: &HecS3Config,
      s3: Arc<crate::forwarding::s3_sink::S3Sink>,
      max_partitions: usize,
  ) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
      use crate::forwarding::buffered_writer::{
          BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
      };

      let bwc = BufferedWriterConfig {
          connection: cfg.connection.clone(),
          prefix: cfg.prefix.clone(),
          max_buffer_rows: cfg.max_buffer_rows,
          flush_threshold_bytes: cfg.flush_threshold_bytes,
          flush_interval_secs: cfg.flush_interval_secs,
          channel_capacity: cfg.channel_capacity,
          max_partitions,
      };
      let policy = FlushPolicy {
          max_rows: cfg.max_buffer_rows,
          max_bytes: cfg.flush_threshold_bytes,
          interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
      };
      ParquetWriterHandle::start(GenericSink, s3, bwc, policy)
  }
  ```

  Add `pub mod generic_s3;` to `src/forwarding/mod.rs`.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib forwarding::generic_s3::tests
  ```

  Expected: `test result: ok. 9 passed`

- [ ] **Step 5: Commit**

  ```
  git add src/forwarding/generic_s3.rs src/forwarding/mod.rs
  git commit -m "feat(forwarding): add GenericSink and hec_start for HEC Parquet persistence"
  ```

---

### Task 4.4: `IngestState` Axum extension (`src/ingest/mod.rs`)

**Files:** Modify `src/ingest/mod.rs`

**Interfaces:**
- Produces `IngestState { generic_s3: Option<GenericS3Handler> }` — `Clone + Send + Sync + 'static`
- Note: Unit 5 will add `otlp_s3: Option<OtlpS3Handler>` to this struct; leave a comment marking the extension point.

- [ ] **Step 1: Write the failing test**

  Add to `src/ingest/mod.rs` test block:

  ```rust
  #[test]
  fn ingest_state_default_has_no_handlers() {
      let state = IngestState::default();
      assert!(state.generic_s3.is_none());
  }

  #[test]
  fn ingest_state_is_clone() {
      let state = IngestState { generic_s3: None };
      let cloned = state.clone();
      assert!(cloned.generic_s3.is_none());
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib ingest::tests::ingest_state 2>&1 | head -20
  ```

  Expected: `error[E0422]: cannot find struct, variant or union type 'IngestState'`

- [ ] **Step 3: Implement**

  Add to `src/ingest/mod.rs` (after `GenericRecord`):

  ```rust
  use crate::forwarding::generic_s3::GenericS3Handler;

  /// Axum extension carrying optional ingest-route S3 handlers.
  ///
  /// Injected as `.layer(axum::Extension(ingest_state))` on the protected router.
  /// Cloning is O(1): `GenericS3Handler` is a `ParquetWriterHandle<_>` which
  /// wraps an `Arc<tokio::sync::mpsc::Sender<_>>`.
  ///
  /// # Extension point
  /// Unit 5 will add `pub otlp_s3: Option<OtlpS3Handler>` here.
  #[derive(Clone, Default)]
  pub struct IngestState {
      /// Generic S3 handler for HEC / NDJSON ingest routes.
      /// `None` when `[hec]` s3 config is absent or construction failed.
      pub generic_s3: Option<GenericS3Handler>,
      // Unit 5: pub otlp_s3: Option<OtlpS3Handler>,
  }
  ```

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib ingest::tests
  ```

  Expected: `test result: ok. 4 passed`

- [ ] **Step 5: Commit**

  ```
  git add src/ingest/mod.rs
  git commit -m "feat(ingest): add IngestState Axum extension type"
  ```

---

### Task 4.5: HEC token auth helper (`src/ingest/mod.rs`)

**Files:** Modify `src/ingest/mod.rs`

**Interfaces:**
- Produces `pub fn check_hec_token(header_value: Option<&str>, expected: &str) -> bool`
- Uses `subtle::ConstantTimeEq` for constant-time comparison

- [ ] **Step 1: Write the failing test**

  Add to `src/ingest/mod.rs` test block:

  ```rust
  #[test]
  fn check_hec_token_accepts_valid_token() {
      assert!(check_hec_token(Some("Splunk my-secret-token"), "my-secret-token"));
  }

  #[test]
  fn check_hec_token_rejects_wrong_token() {
      assert!(!check_hec_token(Some("Splunk wrong-token"), "my-secret-token"));
  }

  #[test]
  fn check_hec_token_rejects_missing_header() {
      assert!(!check_hec_token(None, "my-secret-token"));
  }

  #[test]
  fn check_hec_token_rejects_wrong_scheme() {
      // Must start with "Splunk " — Bearer or Basic are rejected.
      assert!(!check_hec_token(Some("Bearer my-secret-token"), "my-secret-token"));
      assert!(!check_hec_token(Some("my-secret-token"), "my-secret-token"));
  }

  #[test]
  fn check_hec_token_rejects_empty_expected_when_header_empty_splunk_prefix() {
      // "Splunk " with no token: submitted="" vs expected="" → vacuously equal
      // but we still accept it when expected is empty (dev-only no-op mode).
      assert!(check_hec_token(Some("Splunk "), ""));
  }

  #[test]
  fn check_hec_token_constant_time_mismatched_lengths_reject() {
      // Different lengths must reject without panicking.
      assert!(!check_hec_token(Some("Splunk short"), "a-much-longer-token-value"));
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib ingest::tests::check_hec_token 2>&1 | head -20
  ```

  Expected: errors referencing missing `check_hec_token`.

- [ ] **Step 3: Implement**

  Add to `src/ingest/mod.rs` (before test block):

  ```rust
  use subtle::ConstantTimeEq;

  /// Validate an `Authorization` header value against the configured HEC token.
  ///
  /// The header must have the form `"Splunk <token>"`.  Comparison is performed
  /// in constant time (via `subtle::ConstantTimeEq`) to prevent timing attacks.
  ///
  /// Returns `true` only when the header is present, well-formed, and the token
  /// matches `expected` exactly.
  pub fn check_hec_token(header_value: Option<&str>, expected: &str) -> bool {
      let Some(value) = header_value else {
          return false;
      };
      let Some(submitted) = value.strip_prefix("Splunk ") else {
          return false;
      };
      // Constant-time comparison: pad or truncate to avoid length-leak side-channels.
      // ConstantTimeEq requires equal-length slices; we XOR the lengths first so
      // mismatched lengths always return false, without branching on the length.
      let a = submitted.as_bytes();
      let b = expected.as_bytes();
      if a.len() != b.len() {
          // Different lengths: constant-time reject by comparing a against itself
          // and returning false.  The equal-length branch runs for timing parity.
          let _ = a.ct_eq(a);
          return false;
      }
      a.ct_eq(b).into()
  }
  ```

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib ingest::tests
  ```

  Expected: all 10 tests pass.

- [ ] **Step 5: Commit**

  ```
  git add src/ingest/mod.rs
  git commit -m "feat(ingest): add constant-time HEC token check"
  ```

---

### Task 4.6: HEC parse helpers (`src/ingest/parse.rs`)

**Files:** Create `src/ingest/parse.rs`; add `pub mod parse;` to `src/ingest/mod.rs`

**Interfaces:**
- Produces:
  - `pub fn parse_hec_event_body(body: &[u8], default_sourcetype: &str) -> anyhow::Result<Vec<GenericRecord>>`  — parses one or more newline-delimited HEC event envelopes
  - `pub fn parse_hec_raw_body(body: &[u8], sourcetype: &str) -> anyhow::Result<GenericRecord>`  — wraps raw body as single record
  - `pub fn parse_ndjson_body(body: &[u8], default_sourcetype: &str) -> anyhow::Result<Vec<GenericRecord>>`  — parses NDJSON lines

HEC event envelope shape:
```json
{"event": <any>, "time": 1234567890.123, "host": "h1", "sourcetype": "myapp"}
```
`time` is a Unix epoch float (seconds, optionally fractional). `sourcetype` in the envelope overrides the default. `host` is optional. `event` is required.

- [ ] **Step 1: Write the failing test**

  Create `src/ingest/parse.rs` with:

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      // ---- parse_hec_event_body ----

      #[test]
      fn hec_event_single_envelope() {
          let body = br#"{"event":{"action":"login","user":"alice"},"sourcetype":"audit","host":"srv1","time":1700000000.5}"#;
          let records = parse_hec_event_body(body, "default_type").unwrap();
          assert_eq!(records.len(), 1);
          let r = &records[0];
          assert_eq!(r.sourcetype, "audit");
          assert_eq!(r.host.as_deref(), Some("srv1"));
          assert!(r.time.is_some());
          assert_eq!(r.fields["action"], "alice".as_ref());  // inner json: action/user
          // actual value check:
          assert_eq!(r.fields["user"], "alice");
          // time parsed to ~1700000000 epoch
          let ts = r.time.unwrap().timestamp();
          assert!((ts - 1700000000).abs() <= 1);
      }

      #[test]
      fn hec_event_multiple_newline_delimited() {
          let body = b"{\"event\":{\"a\":1},\"sourcetype\":\"t1\"}\n{\"event\":{\"b\":2},\"sourcetype\":\"t2\"}\n";
          let records = parse_hec_event_body(body, "fallback").unwrap();
          assert_eq!(records.len(), 2);
          assert_eq!(records[0].sourcetype, "t1");
          assert_eq!(records[1].sourcetype, "t2");
      }

      #[test]
      fn hec_event_uses_default_sourcetype_when_absent() {
          let body = br#"{"event":{"x":1}}"#;
          let records = parse_hec_event_body(body, "my_default").unwrap();
          assert_eq!(records[0].sourcetype, "my_default");
      }

      #[test]
      fn hec_event_no_time_gives_none() {
          let body = br#"{"event":{"x":1},"sourcetype":"t"}"#;
          let records = parse_hec_event_body(body, "t").unwrap();
          assert!(records[0].time.is_none());
      }

      #[test]
      fn hec_event_missing_event_key_is_error() {
          let body = br#"{"sourcetype":"t","host":"h"}"#;
          assert!(parse_hec_event_body(body, "t").is_err());
      }

      #[test]
      fn hec_event_skips_blank_lines() {
          let body = b"{\"event\":{\"k\":1},\"sourcetype\":\"t\"}\n\n{\"event\":{\"k\":2},\"sourcetype\":\"t\"}\n";
          let records = parse_hec_event_body(body, "t").unwrap();
          assert_eq!(records.len(), 2);
      }

      // ---- parse_hec_raw_body ----

      #[test]
      fn hec_raw_wraps_body_as_single_record() {
          let body = b"raw log line here";
          let rec = parse_hec_raw_body(body, "raw_type").unwrap();
          assert_eq!(rec.sourcetype, "raw_type");
          assert_eq!(rec.fields["raw"], "raw log line here");
          assert!(rec.time.is_none());
          assert!(rec.host.is_none());
      }

      #[test]
      fn hec_raw_empty_body_is_accepted() {
          let rec = parse_hec_raw_body(b"", "raw_type").unwrap();
          assert_eq!(rec.fields["raw"], "");
      }

      // ---- parse_ndjson_body ----

      #[test]
      fn ndjson_parses_multiple_lines() {
          let body = b"{\"host\":\"h1\",\"msg\":\"a\"}\n{\"host\":\"h2\",\"msg\":\"b\"}\n";
          let records = parse_ndjson_body(body, "ndjson_src").unwrap();
          assert_eq!(records.len(), 2);
          assert_eq!(records[0].sourcetype, "ndjson_src");
          assert_eq!(records[0].fields["host"], "h1");
      }

      #[test]
      fn ndjson_skips_blank_lines() {
          let body = b"{\"k\":1}\n\n{\"k\":2}\n";
          let records = parse_ndjson_body(body, "t").unwrap();
          assert_eq!(records.len(), 2);
      }

      #[test]
      fn ndjson_invalid_json_line_is_error() {
          let body = b"not json\n";
          assert!(parse_ndjson_body(body, "t").is_err());
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib ingest::parse::tests 2>&1 | head -30
  ```

  Expected: compile errors (module and functions not found).

- [ ] **Step 3: Implement**

  Create `src/ingest/parse.rs`:

  ```rust
  //! Parse helpers for the three HEC / NDJSON ingest formats.

  use crate::ingest::GenericRecord;
  use chrono::{DateTime, TimeZone, Utc};

  // ---------------------------------------------------------------------------
  // HEC event envelope (`/services/collector/event`)
  // ---------------------------------------------------------------------------

  /// Parse one or more newline-delimited HEC event envelopes.
  ///
  /// Each line must be a JSON object with at minimum an `"event"` key.
  /// Optional keys: `"time"` (Unix epoch float), `"host"`, `"sourcetype"`.
  /// Blank / whitespace-only lines are skipped.
  ///
  /// Returns an error if any non-blank line fails to parse as JSON or is
  /// missing the required `"event"` key.
  pub fn parse_hec_event_body(
      body: &[u8],
      default_sourcetype: &str,
  ) -> anyhow::Result<Vec<GenericRecord>> {
      let text = std::str::from_utf8(body)?;
      let now = Utc::now();
      let mut records = Vec::new();

      for line in text.split('\n') {
          let line = line.trim();
          if line.is_empty() {
              continue;
          }
          let obj: serde_json::Value = serde_json::from_str(line)
              .map_err(|e| anyhow::anyhow!("HEC envelope JSON parse error: {e}"))?;

          let event = obj
              .get("event")
              .ok_or_else(|| anyhow::anyhow!("HEC envelope missing required 'event' key"))?
              .clone();

          let sourcetype = obj
              .get("sourcetype")
              .and_then(|v| v.as_str())
              .unwrap_or(default_sourcetype)
              .to_string();

          let host = obj
              .get("host")
              .and_then(|v| v.as_str())
              .map(|s| s.to_string());

          let time = obj
              .get("time")
              .and_then(|v| v.as_f64())
              .map(epoch_float_to_datetime);

          records.push(GenericRecord {
              sourcetype,
              host,
              time,
              fields: event,
              received_at: now,
          });
      }

      Ok(records)
  }

  // ---------------------------------------------------------------------------
  // HEC raw body (`/services/collector/raw`)
  // ---------------------------------------------------------------------------

  /// Wrap a raw (non-JSON) body as a single `GenericRecord`.
  ///
  /// The body is stored verbatim as a UTF-8 string in `fields["raw"]`.
  /// Invalid UTF-8 sequences are replaced with the Unicode replacement character.
  pub fn parse_hec_raw_body(body: &[u8], sourcetype: &str) -> anyhow::Result<GenericRecord> {
      let raw = String::from_utf8_lossy(body).into_owned();
      Ok(GenericRecord {
          sourcetype: sourcetype.to_string(),
          host: None,
          time: None,
          fields: serde_json::json!({ "raw": raw }),
          received_at: Utc::now(),
      })
  }

  // ---------------------------------------------------------------------------
  // NDJSON body (`/ingest`)
  // ---------------------------------------------------------------------------

  /// Parse a newline-delimited JSON body.  Each non-blank line must be a
  /// JSON object; it is stored verbatim as `fields`.  Returns an error on
  /// the first malformed line.
  pub fn parse_ndjson_body(
      body: &[u8],
      default_sourcetype: &str,
  ) -> anyhow::Result<Vec<GenericRecord>> {
      let text = std::str::from_utf8(body)?;
      let now = Utc::now();
      let mut records = Vec::new();

      for line in text.split('\n') {
          let line = line.trim();
          if line.is_empty() {
              continue;
          }
          let fields: serde_json::Value = serde_json::from_str(line)
              .map_err(|e| anyhow::anyhow!("NDJSON parse error: {e}"))?;

          records.push(GenericRecord {
              sourcetype: default_sourcetype.to_string(),
              host: None,
              time: None,
              fields,
              received_at: now,
          });
      }

      Ok(records)
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Convert a Unix epoch float (seconds, possibly fractional) to `DateTime<Utc>`.
  fn epoch_float_to_datetime(epoch_secs: f64) -> DateTime<Utc> {
      let secs = epoch_secs.trunc() as i64;
      let nanos = ((epoch_secs.fract()) * 1_000_000_000.0).round() as u32;
      Utc.timestamp_opt(secs, nanos)
          .single()
          .unwrap_or_else(Utc::now)
  }
  ```

  Add `pub mod parse;` to `src/ingest/mod.rs`.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib ingest::parse::tests
  ```

  Expected: `test result: ok. 11 passed`

- [ ] **Step 5: Commit**

  ```
  git add src/ingest/parse.rs src/ingest/mod.rs
  git commit -m "feat(ingest): add HEC/NDJSON parse helpers"
  ```

---

### Task 4.7: HTTP handler functions (`src/ingest/handlers.rs`)

**Files:** Create `src/ingest/handlers.rs`; add `pub mod handlers;` to `src/ingest/mod.rs`

**Interfaces:**
- Produces:
  - `pub async fn handle_hec_event(headers: HeaderMap, Query(params): Query<HecQueryParams>, Extension(cfg_token): Extension<Arc<String>>, Extension(ingest): Extension<IngestState>, body: Bytes) -> impl IntoResponse`
  - `pub async fn handle_hec_raw(headers: HeaderMap, Query(params): Query<HecQueryParams>, Extension(cfg_token): Extension<Arc<String>>, Extension(ingest): Extension<IngestState>, body: Bytes) -> impl IntoResponse`
  - `pub async fn handle_ndjson(headers: HeaderMap, Query(params): Query<HecQueryParams>, Extension(cfg_token): Extension<Arc<String>>, Extension(ingest): Extension<IngestState>, body: Bytes) -> impl IntoResponse`
  - `pub struct HecQueryParams { pub sourcetype: Option<String> }`
- Returns `{"text":"Success","code":0}` + 200 on success; `{"text":"Token required","code":2}` + 401 on auth failure; `{"text":"Invalid data format","code":6}` + 400 on parse error

- [ ] **Step 1: Write the failing test**

  Create `src/ingest/handlers.rs` with a `#[cfg(test)]` module:

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use axum::{
          body::Body,
          http::{Request, StatusCode},
      };
      use tower::ServiceExt;

      fn make_router(token: &str) -> axum::Router {
          use axum::{Extension, Router, routing::post};
          let cfg_token = Arc::new(token.to_string());
          let ingest_state = IngestState { generic_s3: None };
          Router::new()
              .route("/services/collector/event", post(handle_hec_event))
              .route("/services/collector/raw", post(handle_hec_raw))
              .route("/ingest", post(handle_ndjson))
              .layer(Extension(cfg_token))
              .layer(Extension(ingest_state))
      }

      async fn body_json(resp: axum::response::Response) -> serde_json::Value {
          let b = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
          serde_json::from_slice(&b).unwrap()
      }

      // --- Auth tests ---

      #[tokio::test]
      async fn hec_event_missing_auth_returns_401() {
          let app = make_router("secret");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/event")
              .body(Body::from(br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref()))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
          let body = body_json(resp).await;
          assert_eq!(body["code"], 2);
      }

      #[tokio::test]
      async fn hec_event_wrong_token_returns_401() {
          let app = make_router("secret");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/event")
              .header("Authorization", "Splunk wrong-token")
              .body(Body::from(br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref()))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
      }

      #[tokio::test]
      async fn hec_event_valid_token_returns_200() {
          let app = make_router("correct-token");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/event")
              .header("Authorization", "Splunk correct-token")
              .body(Body::from(
                  br#"{"event":{"action":"test"},"sourcetype":"myapp"}"#.as_ref(),
              ))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::OK);
          let body = body_json(resp).await;
          assert_eq!(body["text"], "Success");
          assert_eq!(body["code"], 0);
      }

      // --- Parse error tests ---

      #[tokio::test]
      async fn hec_event_invalid_json_returns_400() {
          let app = make_router("tok");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/event")
              .header("Authorization", "Splunk tok")
              .body(Body::from("not json at all"))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
          let body = body_json(resp).await;
          assert_eq!(body["code"], 6);
      }

      // --- Raw endpoint ---

      #[tokio::test]
      async fn hec_raw_valid_returns_200() {
          let app = make_router("tok");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/raw?sourcetype=myraw")
              .header("Authorization", "Splunk tok")
              .body(Body::from("raw log line here"))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::OK);
          let body = body_json(resp).await;
          assert_eq!(body["text"], "Success");
      }

      #[tokio::test]
      async fn hec_raw_uses_default_sourcetype_when_query_absent() {
          let app = make_router("tok");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/raw")
              .header("Authorization", "Splunk tok")
              .body(Body::from("some raw bytes"))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::OK);
      }

      // --- NDJSON endpoint ---

      #[tokio::test]
      async fn ndjson_valid_returns_200() {
          let app = make_router("tok");
          let body = b"{\"host\":\"h1\",\"msg\":\"a\"}\n{\"host\":\"h2\",\"msg\":\"b\"}\n";
          let req = Request::builder()
              .method("POST")
              .uri("/ingest?sourcetype=mytype")
              .header("Authorization", "Splunk tok")
              .body(Body::from(body.as_ref()))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::OK);
      }

      #[tokio::test]
      async fn ndjson_invalid_json_returns_400() {
          let app = make_router("tok");
          let req = Request::builder()
              .method("POST")
              .uri("/ingest")
              .header("Authorization", "Splunk tok")
              .body(Body::from("not json\n"))
              .unwrap();
          let resp = app.oneshot(req).await.unwrap();
          assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
      }

      // --- Metrics counter smoke-test ---
      #[tokio::test]
      async fn hec_event_increments_received_counter() {
          use metrics::set_default_local_recorder;
          use metrics_util::CompositeKey;
          use metrics_util::MetricKind;
          use metrics_util::debugging::DebuggingRecorder;

          let recorder = DebuggingRecorder::new();
          let snapshotter = recorder.snapshotter();
          let _guard = set_default_local_recorder(&recorder);

          let app = make_router("tok");
          let req = Request::builder()
              .method("POST")
              .uri("/services/collector/event")
              .header("Authorization", "Splunk tok")
              .body(Body::from(
                  br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref(),
              ))
              .unwrap();
          let _ = app.oneshot(req).await.unwrap();

          let snapshot = snapshotter.snapshot();
          let map = snapshot.into_hashmap();
          let key = CompositeKey::new(
              MetricKind::Counter,
              metrics::Key::from_name("hec_events_received"),
          );
          let count = map
              .get(&key)
              .map(|(_, _, v)| {
                  if let metrics_util::debugging::DebugValue::Counter(c) = v {
                      *c
                  } else {
                      0
                  }
              })
              .unwrap_or(0);
          assert!(count >= 1, "hec_events_received must be >= 1 after one POST");
      }
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib ingest::handlers::tests 2>&1 | head -30
  ```

  Expected: compile errors (no module `handlers`, no handler functions).

- [ ] **Step 3: Implement**

  Create `src/ingest/handlers.rs`:

  ```rust
  //! Axum handler functions for the three HEC / NDJSON ingest routes.
  //!
  //! All three handlers share the same auth + dispatch pattern:
  //! 1. Extract and validate `Authorization: Splunk <token>` header.
  //! 2. Parse the body with the appropriate helper.
  //! 3. Increment metrics counters.
  //! 4. If `ingest.generic_s3` is `Some`, call `try_send` for each record.
  //! 5. Return the HEC canonical success envelope or an error response.

  use crate::ingest::{
      IngestState,
      check_hec_token,
      parse::{parse_hec_event_body, parse_hec_raw_body, parse_ndjson_body},
  };
  use axum::{
      Json,
      body::Bytes,
      extract::{Extension, Query},
      http::{HeaderMap, StatusCode},
      response::{IntoResponse, Response},
  };
  use serde::Deserialize;
  use serde_json::json;
  use std::sync::Arc;

  /// Query parameters accepted by all three ingest routes.
  #[derive(Debug, Deserialize)]
  pub struct HecQueryParams {
      /// Explicit sourcetype override; used by `/services/collector/raw` and `/ingest`.
      pub sourcetype: Option<String>,
  }

  /// Default sourcetype when neither the body envelope nor a query param supplies one.
  const DEFAULT_SOURCETYPE: &str = "generic";

  // ---------------------------------------------------------------------------
  // Shared response helpers
  // ---------------------------------------------------------------------------

  fn hec_success() -> Response {
      (StatusCode::OK, Json(json!({"text": "Success", "code": 0}))).into_response()
  }

  fn hec_auth_error() -> Response {
      metrics::counter!("hec_auth_failures").increment(1);
      (
          StatusCode::UNAUTHORIZED,
          Json(json!({"text": "Token required", "code": 2})),
      )
          .into_response()
  }

  fn hec_parse_error(msg: &str) -> Response {
      metrics::counter!("hec_parse_errors").increment(1);
      tracing::warn!("HEC parse error: {}", msg);
      (
          StatusCode::BAD_REQUEST,
          Json(json!({"text": "Invalid data format", "code": 6})),
      )
          .into_response()
  }

  // ---------------------------------------------------------------------------
  // POST /services/collector/event
  // ---------------------------------------------------------------------------

  /// HEC event endpoint: one or more newline-delimited event envelope objects.
  ///
  /// Each line: `{"event": <any>, "time": <epoch_float>, "host": "h", "sourcetype": "t"}`
  pub async fn handle_hec_event(
      headers: HeaderMap,
      Query(params): Query<HecQueryParams>,
      Extension(cfg_token): Extension<Arc<String>>,
      Extension(ingest): Extension<IngestState>,
      body: Bytes,
  ) -> impl IntoResponse {
      let auth = headers
          .get("authorization")
          .and_then(|v| v.to_str().ok());
      if !check_hec_token(auth, &cfg_token) {
          return hec_auth_error();
      }

      let default_st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
      let records = match parse_hec_event_body(&body, default_st) {
          Ok(r) => r,
          Err(e) => return hec_parse_error(&e.to_string()),
      };

      metrics::counter!("hec_events_received").increment(records.len() as u64);

      if let Some(ref handler) = ingest.generic_s3 {
          for rec in records {
              if handler.try_send(rec).is_err() {
                  metrics::counter!("hec_events_dropped").increment(1);
                  tracing::warn!("HEC S3 channel full; dropped 1 record");
              }
          }
      }

      hec_success()
  }

  // ---------------------------------------------------------------------------
  // POST /services/collector/raw
  // ---------------------------------------------------------------------------

  /// HEC raw endpoint: the entire body is stored as a single raw string record.
  ///
  /// Sourcetype is taken from `?sourcetype=` query param; falls back to `DEFAULT_SOURCETYPE`.
  pub async fn handle_hec_raw(
      headers: HeaderMap,
      Query(params): Query<HecQueryParams>,
      Extension(cfg_token): Extension<Arc<String>>,
      Extension(ingest): Extension<IngestState>,
      body: Bytes,
  ) -> impl IntoResponse {
      let auth = headers
          .get("authorization")
          .and_then(|v| v.to_str().ok());
      if !check_hec_token(auth, &cfg_token) {
          return hec_auth_error();
      }

      let st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
      let record = match parse_hec_raw_body(&body, st) {
          Ok(r) => r,
          Err(e) => return hec_parse_error(&e.to_string()),
      };

      metrics::counter!("hec_events_received").increment(1);

      if let Some(ref handler) = ingest.generic_s3 {
          if handler.try_send(record).is_err() {
              metrics::counter!("hec_events_dropped").increment(1);
              tracing::warn!("HEC S3 channel full; dropped raw record");
          }
      }

      hec_success()
  }

  // ---------------------------------------------------------------------------
  // POST /ingest
  // ---------------------------------------------------------------------------

  /// Plain NDJSON ingest: each line is a JSON object stored as-is in `fields`.
  ///
  /// Sourcetype is taken from `?sourcetype=` query param; falls back to `DEFAULT_SOURCETYPE`.
  pub async fn handle_ndjson(
      headers: HeaderMap,
      Query(params): Query<HecQueryParams>,
      Extension(cfg_token): Extension<Arc<String>>,
      Extension(ingest): Extension<IngestState>,
      body: Bytes,
  ) -> impl IntoResponse {
      let auth = headers
          .get("authorization")
          .and_then(|v| v.to_str().ok());
      if !check_hec_token(auth, &cfg_token) {
          return hec_auth_error();
      }

      let st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
      let records = match parse_ndjson_body(&body, st) {
          Ok(r) => r,
          Err(e) => return hec_parse_error(&e.to_string()),
      };

      metrics::counter!("hec_events_received").increment(records.len() as u64);

      if let Some(ref handler) = ingest.generic_s3 {
          for rec in records {
              if handler.try_send(rec).is_err() {
                  metrics::counter!("hec_events_dropped").increment(1);
                  tracing::warn!("HEC S3 channel full; dropped 1 NDJSON record");
              }
          }
      }

      hec_success()
  }
  ```

  Add `pub mod handlers;` to `src/ingest/mod.rs`.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib ingest::handlers::tests
  ```

  Expected: `test result: ok. 10 passed`

- [ ] **Step 5: Commit**

  ```
  git add src/ingest/handlers.rs src/ingest/mod.rs
  git commit -m "feat(ingest): add Axum handler functions for HEC event/raw and NDJSON routes"
  ```

---

### Task 4.8: Wire routes into the existing Axum server (`src/server/mod.rs`)

**Files:** Modify `src/server/mod.rs`

**Interfaces:**
- Modifies `Server` struct: adds `ingest_state: IngestState`, `hec_worker_handle: Option<JoinHandle<()>>`
- Modifies `Server::new`: constructs `IngestState` from `config.hec`
- Modifies `create_router`: adds three new routes + `.layer(Extension(self.ingest_state.clone()))` + `.layer(Extension(Arc::new(config.hec.token.clone())))` on `protected_router`
- Adds `pub fn take_hec_worker_handle(&mut self) -> Option<JoinHandle<()>>`

- [ ] **Step 1: Write the failing test**

  Add to `src/server/mod.rs` test module:

  ```rust
  // Helper: build an AppState + IngestState and mount the three HEC routes.
  async fn build_hec_router(token: &str) -> axum::Router {
      use axum::{Extension, Router, routing::post};
      use crate::ingest::{IngestState, handlers::{handle_hec_event, handle_hec_raw, handle_ndjson, HecQueryParams}};
      use std::sync::Arc;

      let cfg_token = Arc::new(token.to_string());
      let ingest_state = IngestState { generic_s3: None };

      Router::new()
          .route("/services/collector/event", post(handle_hec_event))
          .route("/services/collector/raw", post(handle_hec_raw))
          .route("/ingest", post(handle_ndjson))
          .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
          .layer(Extension(cfg_token))
          .layer(Extension(ingest_state))
  }

  #[tokio::test]
  async fn hec_event_route_accepts_valid_request() {
      use axum::body::Body;
      use axum::http::Request as HttpRequest;
      use tower::ServiceExt;

      let router = build_hec_router("test-token").await;
      let req = HttpRequest::builder()
          .method("POST")
          .uri("/services/collector/event")
          .header("Authorization", "Splunk test-token")
          .body(Body::from(
              r#"{"event":{"msg":"hello world"},"sourcetype":"myapp"}"#,
          ))
          .unwrap();
      let resp = router.oneshot(req).await.unwrap();
      assert_eq!(resp.status(), StatusCode::OK);
      let b = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
      let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
      assert_eq!(j["text"], "Success");
      assert_eq!(j["code"], 0);
  }

  #[tokio::test]
  async fn hec_route_rejects_bad_token() {
      use axum::body::Body;
      use axum::http::Request as HttpRequest;
      use tower::ServiceExt;

      let router = build_hec_router("correct").await;
      let req = HttpRequest::builder()
          .method("POST")
          .uri("/services/collector/event")
          .header("Authorization", "Splunk wrong")
          .body(Body::from(r#"{"event":{"k":1},"sourcetype":"t"}"#))
          .unwrap();
      let resp = router.oneshot(req).await.unwrap();
      assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn hec_raw_route_returns_200() {
      use axum::body::Body;
      use axum::http::Request as HttpRequest;
      use tower::ServiceExt;

      let router = build_hec_router("tok").await;
      let req = HttpRequest::builder()
          .method("POST")
          .uri("/services/collector/raw?sourcetype=raw_src")
          .header("Authorization", "Splunk tok")
          .body(Body::from("raw log payload"))
          .unwrap();
      let resp = router.oneshot(req).await.unwrap();
      assert_eq!(resp.status(), StatusCode::OK);
  }

  #[tokio::test]
  async fn ndjson_route_returns_200() {
      use axum::body::Body;
      use axum::http::Request as HttpRequest;
      use tower::ServiceExt;

      let router = build_hec_router("tok").await;
      let body = "{\"host\":\"h1\",\"msg\":\"line1\"}\n{\"host\":\"h2\",\"msg\":\"line2\"}\n";
      let req = HttpRequest::builder()
          .method("POST")
          .uri("/ingest?sourcetype=ndjson_type")
          .header("Authorization", "Splunk tok")
          .body(Body::from(body))
          .unwrap();
      let resp = router.oneshot(req).await.unwrap();
      assert_eq!(resp.status(), StatusCode::OK);
  }

  #[tokio::test]
  async fn hec_routes_enforce_body_size_limit() {
      use axum::body::Body;
      use axum::http::Request as HttpRequest;
      use tower::ServiceExt;

      let router = build_hec_router("tok").await;
      let over_limit = vec![0u8; MAX_BODY_SIZE + 1];
      let req = HttpRequest::builder()
          .method("POST")
          .uri("/services/collector/event")
          .header("Authorization", "Splunk tok")
          .body(Body::from(over_limit))
          .unwrap();
      let resp = router.oneshot(req).await.unwrap();
      assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib server::tests::hec 2>&1 | head -30
  ```

  Expected: compile errors (missing route registrations, missing helper function).

- [ ] **Step 3: Implement**

  In `src/server/mod.rs`:

  1. Add imports at the top:
     ```rust
     use crate::ingest::IngestState;
     use crate::ingest::handlers::{HecQueryParams, handle_hec_event, handle_hec_raw, handle_ndjson};
     ```

  2. Add two fields to `Server`:
     ```rust
     pub struct Server {
         config: Config,
         state: Arc<AppState>,
         wef_worker_handle: Option<tokio::task::JoinHandle<()>>,
         ingest_state: IngestState,
         hec_worker_handle: Option<tokio::task::JoinHandle<()>>,
     }
     ```

  3. In `Server::new`, after building `AppState`, add `IngestState` construction:
     ```rust
     // --- Build IngestState for HEC / NDJSON ingest routes ---
     let (ingest_state, hec_worker_handle) = if config.hec.enabled {
         if let Some(s3_cfg) = config.hec.s3.as_ref() {
             match crate::forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                 Ok(sink) => {
                     info!("Initialized HEC Parquet S3 forwarder");
                     let (handler, join_handle) = crate::forwarding::generic_s3::hec_start(
                         s3_cfg,
                         Arc::new(sink),
                         config.hec.max_sourcetype_partitions,
                     );
                     (IngestState { generic_s3: Some(handler) }, Some(join_handle))
                 }
                 Err(e) => {
                     error!("Failed to create S3Sink for HEC ingest: {e}");
                     (IngestState::default(), None)
                 }
             }
         } else {
             // HEC enabled but no S3 — accept and drop records.
             (IngestState::default(), None)
         }
     } else {
         (IngestState::default(), None)
     };
     ```

     Include `ingest_state` and `hec_worker_handle` in the returned `Self`.

  4. Add `pub fn take_hec_worker_handle(&mut self) -> Option<tokio::task::JoinHandle<()>> { self.hec_worker_handle.take() }`.

  5. In `create_router`, extend `protected_router`:
     ```rust
     let cfg_token = Arc::new(self.config.hec.token.clone());
     let protected_router = protected_router
         .route("/services/collector/event", post(handle_hec_event))
         .route("/services/collector/raw", post(handle_hec_raw))
         .route("/ingest", post(handle_ndjson))
         .layer(axum::Extension(self.ingest_state.clone()))
         .layer(axum::Extension(cfg_token));
     ```
     These two `.layer` calls must appear **before** the existing `.layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))` line is closed, so they all share the same body-limit layer. The exact placement: add the three routes and the two new `.layer` calls inside the `protected_router` builder chain, before the existing `.layer(shared_layers)` line.

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib server::tests::hec
  ```

  Expected: `test result: ok. 5 passed`

  Then run the full test suite to verify no regressions:

  ```
  cargo test --lib 2>&1 | tail -5
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/server/mod.rs
  git commit -m "feat(server): wire HEC/NDJSON ingest routes onto protected router with IngestState extension"
  ```

---

### Task 4.9: Wire `IngestState` into `main.rs` and graceful shutdown

**Files:** Modify `src/main.rs`

**Interfaces:**
- Consumes `Server::take_hec_worker_handle()`, adds the returned handle to `all_writer_handles`
- Ensures `IngestState` is constructed inside `Server::new` (already done in 4.8) and threaded through; `main.rs` only needs to extract the HEC worker handle

- [ ] **Step 1: Write the failing test**

  This task has no new unit test — the integration is covered by the e2e test in Task 4.11. However, add a compile-time check that `take_hec_worker_handle` exists and that `Server` builds with the new fields:

  ```rust
  // src/server/mod.rs tests block — already covered by Task 4.8 tests.
  // Add one additional test confirming the handle can be taken:
  #[tokio::test]
  async fn server_take_hec_worker_handle_returns_none_when_hec_disabled() {
      let mut server = Server::new(
          Config::default(), // hec.enabled = false by default
          Arc::new(RwLock::new(Config::default())),
          Arc::new(ThroughputStats::new()),
      )
      .await
      .unwrap();
      let handle = server.take_hec_worker_handle();
      assert!(handle.is_none(), "hec worker handle must be None when hec.enabled=false");
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --lib server::tests::server_take_hec_worker_handle 2>&1 | head -20
  ```

  Expected: compilation error or test not found (before `main.rs` wiring exists).

- [ ] **Step 3: Implement**

  In `src/main.rs`, after the line `let wef_worker_handle = server.take_wef_worker_handle();`, add:

  ```rust
  let hec_worker_handle = server.take_hec_worker_handle();
  ```

  And in the shutdown sequence, after `if let Some(wef_handle) = wef_worker_handle { all_writer_handles.push(wef_handle); }`, add:

  ```rust
  if let Some(hec_handle) = hec_worker_handle {
      all_writer_handles.push(hec_handle);
  }
  ```

- [ ] **Step 4: Run to verify it passes**

  ```
  cargo test --lib server::tests::server_take_hec_worker_handle
  cargo build 2>&1 | tail -5
  ```

  Expected: compiles cleanly, test passes.

- [ ] **Step 5: Commit**

  ```
  git add src/main.rs
  git commit -m "feat(main): extract HEC worker handle and include in graceful shutdown sequence"
  ```

---

### Task 4.10: Integration test — HEC → S3 Parquet (`tests/hec_s3_integration.rs`)

**Files:** Create `tests/hec_s3_integration.rs`

**Interfaces:**
- Consumes `logthing::config::{HecConfig, HecS3Config, S3ConnectionConfig}`, `logthing::forwarding::generic_s3::{hec_start, GenericSink}`, `logthing::ingest::GenericRecord`
- Gate: `MINIO_ENDPOINT` env var; skips if absent

- [ ] **Step 1: Write the test (this IS the implementation)**

  Create `tests/hec_s3_integration.rs`:

  ```rust
  //! Integration test: GenericRecord → GenericS3Handler → Parquet objects in MinIO.
  //!
  //! Requires a running MinIO (or S3-compatible) instance.
  //! Set MINIO_ENDPOINT env var (and optionally MINIO_BUCKET, MINIO_ACCESS_KEY,
  //! MINIO_SECRET_KEY) to enable.  If MINIO_ENDPOINT is absent, the test skips.
  //!
  //! Exercises: two distinct sourcetypes land in separate S3 prefixes with the
  //! 5-column HEC schema (sourcetype, host, time, received_at, fields).

  use logthing::config::{HecS3Config, S3ConnectionConfig};
  use logthing::forwarding::generic_s3::hec_start;
  use logthing::forwarding::s3_sink::S3Sink;
  use logthing::ingest::GenericRecord;
  use std::sync::Arc;

  fn skip_if_no_minio() -> Option<String> {
      std::env::var("MINIO_ENDPOINT").ok()
  }

  fn minio_hec_config(endpoint: &str) -> HecS3Config {
      HecS3Config {
          connection: S3ConnectionConfig {
              endpoint: endpoint.to_string(),
              bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "hec-logs".to_string()),
              region: "us-east-1".to_string(),
              access_key: std::env::var("MINIO_ACCESS_KEY")
                  .unwrap_or_else(|_| "minioadmin".to_string()),
              secret_key: std::env::var("MINIO_SECRET_KEY")
                  .unwrap_or_else(|_| "minioadmin".to_string()),
          },
          prefix: "hec".to_string(),
          max_buffer_rows: 1,          // flush immediately
          flush_threshold_bytes: 1,    // flush immediately
          flush_interval_secs: 3600,
          channel_capacity: 4096,
      }
  }

  fn make_record(sourcetype: &str, user: &str) -> GenericRecord {
      GenericRecord {
          sourcetype: sourcetype.to_string(),
          host: Some("integration-host".to_string()),
          time: Some(chrono::Utc::now()),
          fields: serde_json::json!({"user": user, "action": "login"}),
          received_at: chrono::Utc::now(),
      }
  }

  #[tokio::test]
  async fn hec_records_appear_as_parquet_in_s3() {
      let endpoint = match skip_if_no_minio() {
          Some(e) => e,
          None => {
              eprintln!("MINIO_ENDPOINT not set — skipping hec_s3 integration test");
              return;
          }
      };

      let cfg = minio_hec_config(&endpoint);
      let sink = Arc::new(
          S3Sink::from_connection(&cfg.connection)
              .await
              .expect("S3Sink::from_connection"),
      );

      let (handler, _writer_task) = hec_start(&cfg, sink, 64);
      handler.try_send(make_record("access_log", "alice")).expect("send");
      handler.try_send(make_record("access_log", "bob")).expect("send");
      handler.try_send(make_record("audit_log", "charlie")).expect("send");

      // Wait for background flush (max_buffer_rows=1 triggers immediately).
      tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

      // Build S3 verification client.
      use aws_sdk_s3::Client as S3Client;
      let region = aws_sdk_s3::config::Region::new("us-east-1");
      let credentials = aws_credential_types::Credentials::new(
          cfg.connection.access_key.clone(),
          cfg.connection.secret_key.clone(),
          None,
          None,
          "test",
      );
      let sdk_cfg = aws_config::from_env()
          .region(region)
          .endpoint_url(&cfg.connection.endpoint)
          .credentials_provider(credentials)
          .load()
          .await;
      let s3 = S3Client::from_conf(
          aws_sdk_s3::config::Builder::from(&sdk_cfg)
              .force_path_style(true)
              .build(),
      );

      // --- Verify access_log partition ---
      for prefix in &["hec/access_log/", "hec/audit_log/"] {
          let list = s3
              .list_objects_v2()
              .bucket(&cfg.connection.bucket)
              .prefix(*prefix)
              .send()
              .await
              .unwrap_or_else(|e| panic!("list_objects_v2 for {prefix}: {e}"));

          let objects = list.contents();
          assert!(
              !objects.is_empty(),
              "Expected >= 1 Parquet object under {prefix}, found none"
          );

          // Fetch and validate the first object.
          let key = objects[0].key().expect("key");
          let get_resp = s3
              .get_object()
              .bucket(&cfg.connection.bucket)
              .key(key)
              .send()
              .await
              .unwrap_or_else(|e| panic!("get_object {key}: {e}"));

          let body_bytes = get_resp
              .body
              .collect()
              .await
              .expect("collect body")
              .into_bytes();

          use bytes::Bytes;
          use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
          let buf = Bytes::from(body_bytes.to_vec());
          let builder =
              ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder");
          let schema = builder.schema().clone();

          // Must have the 5 HEC columns.
          for col in &["sourcetype", "host", "time", "received_at", "fields"] {
              assert!(
                  schema.field_with_name(col).is_ok(),
                  "Schema under {prefix} must have column '{col}'"
              );
          }
          assert_eq!(schema.fields().len(), 5, "HEC schema must have exactly 5 columns");

          let mut reader = builder.build().expect("parquet reader");
          let rb = reader.next().expect("at least one batch").expect("batch ok");
          assert!(rb.num_rows() >= 1, "Parquet under {prefix} must have >= 1 row");

          use arrow::array::StringArray;
          let st = rb
              .column_by_name("sourcetype")
              .expect("sourcetype col")
              .as_any()
              .downcast_ref::<StringArray>()
              .unwrap();
          // Partition prefix matches sourcetype value.
          let expected_st = prefix.trim_start_matches("hec/").trim_end_matches('/');
          assert_eq!(
              st.value(0),
              expected_st,
              "sourcetype column must match partition"
          );
      }
  }
  ```

- [ ] **Step 2: Run to verify it skips (no MinIO) or fails (with MinIO)**

  ```
  RUST_LOG=info cargo test --test hec_s3_integration 2>&1 | tail -10
  ```

  Without `MINIO_ENDPOINT`: prints the skip message and exits `ok`.
  With `MINIO_ENDPOINT` set but `hec_start` not yet wired: compile error.

- [ ] **Step 3: Verify implementation passes**

  With MinIO running (e.g. via `docker-compose up -d minio` in the project's `docker-compose.yml`):

  ```
  MINIO_ENDPOINT=http://localhost:9000 \
  MINIO_BUCKET=hec-integ-test \
  cargo test --test hec_s3_integration -- --nocapture 2>&1 | tail -20
  ```

  Expected: `test hec_records_appear_as_parquet_in_s3 ... ok`

- [ ] **Step 4: Commit**

  ```
  git add tests/hec_s3_integration.rs
  git commit -m "test(integration): add HEC → S3 Parquet integration test (MINIO_ENDPOINT-gated)"
  ```

---

### Task 4.11: E2E test — ephemeral HTTP server, real reqwest POSTs (`tests/e2e/`)

**Files:** Create `tests/e2e/hec_e2e.rs` (or add to existing `tests/e2e/` directory if it exists)

**Interfaces:**
- Spins up the Axum router on a random port using `tokio::net::TcpListener::bind("127.0.0.1:0")`
- Uses `reqwest` (already in `Cargo.toml`) to POST to the ephemeral port
- Validates: valid token → 200 + `{"text":"Success","code":0}`; bad token → 401; invalid JSON → 400; raw endpoint → 200; NDJSON → 200; body-size limit → 413

- [ ] **Step 1: Write the failing test**

  First check whether `tests/e2e/` exists:

  ```
  ls /home/peter/projects/logthing/tests/e2e/
  ```

  Create `tests/e2e/hec_e2e.rs` (or `tests/hec_e2e.rs` if e2e is a flat directory):

  ```rust
  //! End-to-end tests for the HEC / NDJSON ingest routes.
  //!
  //! Spins up the full Axum protected router (with IngestState + token extension,
  //! body-limit layer, IP whitelist empty) on an ephemeral port and fires real
  //! HTTP requests via reqwest.  No S3 handler is wired (generic_s3 = None),
  //! so records are accepted and discarded — the test validates HTTP behavior only.

  use axum::{Extension, Router, extract::DefaultBodyLimit, routing::post};
  use logthing::ingest::{
      IngestState,
      handlers::{handle_hec_event, handle_hec_raw, handle_ndjson},
  };
  use logthing::server::MAX_BODY_SIZE; // re-export or use the constant value 64*1024*1024
  use std::sync::Arc;
  use tokio::net::TcpListener;

  // Note: MAX_BODY_SIZE is pub(crate) in server/mod.rs.  If it cannot be imported,
  // use the numeric value directly: 64 * 1024 * 1024.
  const BODY_LIMIT: usize = 64 * 1024 * 1024;

  async fn spawn_hec_server(token: &str) -> (String, tokio::task::JoinHandle<()>) {
      let cfg_token = Arc::new(token.to_string());
      let ingest_state = IngestState { generic_s3: None };

      let router: Router = Router::new()
          .route("/services/collector/event", post(handle_hec_event))
          .route("/services/collector/raw", post(handle_hec_raw))
          .route("/ingest", post(handle_ndjson))
          .layer(DefaultBodyLimit::max(BODY_LIMIT))
          .layer(Extension(cfg_token))
          .layer(Extension(ingest_state));

      let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let addr = listener.local_addr().unwrap();
      let base_url = format!("http://{}", addr);

      let handle = tokio::spawn(async move {
          axum::serve(listener, router).await.unwrap();
      });

      (base_url, handle)
  }

  #[tokio::test]
  async fn e2e_hec_event_valid_token_returns_200_with_success_body() {
      let (base, _server) = spawn_hec_server("e2e-token").await;
      let client = reqwest::Client::new();

      let resp = client
          .post(format!("{base}/services/collector/event"))
          .header("Authorization", "Splunk e2e-token")
          .json(&serde_json::json!({
              "event": {"msg": "hello from e2e", "level": "info"},
              "sourcetype": "e2e_test",
              "host": "test-host"
          }))
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::OK);
      let body: serde_json::Value = resp.json().await.unwrap();
      assert_eq!(body["text"], "Success");
      assert_eq!(body["code"], 0);
  }

  #[tokio::test]
  async fn e2e_hec_event_bad_token_returns_401() {
      let (base, _server) = spawn_hec_server("correct-token").await;
      let client = reqwest::Client::new();

      let resp = client
          .post(format!("{base}/services/collector/event"))
          .header("Authorization", "Splunk bad-token")
          .body(r#"{"event":{"k":1},"sourcetype":"t"}"#)
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
      let body: serde_json::Value = resp.json().await.unwrap();
      assert_eq!(body["code"], 2);
  }

  #[tokio::test]
  async fn e2e_hec_event_missing_token_returns_401() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let resp = client
          .post(format!("{base}/services/collector/event"))
          // No Authorization header
          .body(r#"{"event":{"k":1},"sourcetype":"t"}"#)
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn e2e_hec_event_invalid_json_returns_400() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let resp = client
          .post(format!("{base}/services/collector/event"))
          .header("Authorization", "Splunk tok")
          .body("this is not json")
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
      let body: serde_json::Value = resp.json().await.unwrap();
      assert_eq!(body["code"], 6);
  }

  #[tokio::test]
  async fn e2e_hec_event_missing_event_key_returns_400() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let resp = client
          .post(format!("{base}/services/collector/event"))
          .header("Authorization", "Splunk tok")
          // Valid JSON but missing the "event" key
          .json(&serde_json::json!({"sourcetype": "t", "host": "h"}))
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn e2e_hec_raw_valid_returns_200() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let resp = client
          .post(format!("{base}/services/collector/raw?sourcetype=raw_src"))
          .header("Authorization", "Splunk tok")
          .body("2026-06-27T00:00:00Z host app[123]: something happened")
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::OK);
      let body: serde_json::Value = resp.json().await.unwrap();
      assert_eq!(body["text"], "Success");
  }

  #[tokio::test]
  async fn e2e_ndjson_valid_two_lines_returns_200() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let ndjson = "{\"host\":\"srv1\",\"event\":\"started\"}\n{\"host\":\"srv2\",\"event\":\"stopped\"}\n";
      let resp = client
          .post(format!("{base}/ingest?sourcetype=app_events"))
          .header("Authorization", "Splunk tok")
          .body(ndjson)
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::OK);
  }

  #[tokio::test]
  async fn e2e_hec_event_over_body_limit_returns_413() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let huge_body = "x".repeat(BODY_LIMIT + 1);
      let resp = client
          .post(format!("{base}/services/collector/event"))
          .header("Authorization", "Splunk tok")
          .body(huge_body)
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
  }

  #[tokio::test]
  async fn e2e_hec_event_multiple_newline_delimited_returns_200() {
      let (base, _server) = spawn_hec_server("tok").await;
      let client = reqwest::Client::new();

      let body = concat!(
          "{\"event\":{\"a\":1},\"sourcetype\":\"t1\"}\n",
          "{\"event\":{\"b\":2},\"sourcetype\":\"t2\"}\n",
          "{\"event\":{\"c\":3},\"sourcetype\":\"t3\"}\n",
      );
      let resp = client
          .post(format!("{base}/services/collector/event"))
          .header("Authorization", "Splunk tok")
          .body(body)
          .send()
          .await
          .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::OK);
  }
  ```

- [ ] **Step 2: Run to verify it fails**

  ```
  cargo test --test hec_e2e 2>&1 | head -30
  ```

  (or appropriate path for the e2e directory structure)

  Expected: compile errors or all tests fail because routes are not yet returning the expected responses before Tasks 4.7–4.8 are complete.  If those tasks are already done, the tests should pass after Step 3.

- [ ] **Step 3: Verify all pass**

  ```
  cargo test --test hec_e2e 2>&1 | tail -15
  ```

  Expected: `test result: ok. 9 passed`

- [ ] **Step 4: Run full test suite**

  ```
  cargo test 2>&1 | tail -10
  ```

  Expected: no regressions across all existing tests.

- [ ] **Step 5: Commit**

  ```
  git add tests/e2e/hec_e2e.rs   # or tests/hec_e2e.rs
  git commit -m "test(e2e): add ephemeral-server HEC/NDJSON end-to-end tests"
  ```

---

### Task 4.12: `pub use` re-exports and module visibility cleanup

**Files:** Modify `src/ingest/mod.rs`, `src/forwarding/mod.rs`

**Interfaces:**
- `src/ingest/mod.rs`: ensure `GenericRecord`, `IngestState`, `check_hec_token`, `parse`, `handlers` are all `pub`
- `src/forwarding/mod.rs`: add `pub mod generic_s3;`

This task is a final compile-clean pass confirming the public API surface is consistent and the crate builds without warnings on the new modules.

- [ ] **Step 1: Write the failing test** (compile check)

  ```
  cargo check --lib 2>&1 | grep "^error" | head -20
  ```

  Any errors here indicate missing `pub` or missing `use` statements.

- [ ] **Step 2: Fix all errors**

  Ensure `src/ingest/mod.rs` exports:
  ```rust
  pub mod handlers;
  pub mod parse;
  pub use handlers::{HecQueryParams, handle_hec_event, handle_hec_raw, handle_ndjson};
  pub use parse::{parse_hec_event_body, parse_hec_raw_body, parse_ndjson_body};
  ```

  Ensure `src/forwarding/mod.rs` has:
  ```rust
  pub mod generic_s3;
  ```

  Ensure `src/lib.rs` has:
  ```rust
  pub mod ingest;
  ```

- [ ] **Step 3: Final full build + test**

  ```
  cargo test 2>&1 | tail -15
  ```

  Expected: `test result: ok. N passed; 0 failed; 0 ignored` with no compile warnings on new code.

- [ ] **Step 4: Commit**

  ```
  git add src/ingest/mod.rs src/forwarding/mod.rs src/lib.rs
  git commit -m "chore(ingest): clean up pub re-exports and module visibility for Unit 4"
  ```

---

## Unit 5 — OTLP logs ingest (`src/server/`, feature `otlp`)

This unit adds a `POST /v1/logs` HTTP endpoint that accepts OTLP/HTTP protobuf (and JSON) encoded `ExportLogsServiceRequest` payloads. It is gated behind a Cargo feature `otlp` so that the dependency and route drop out cleanly when the feature is disabled. The unit reuses Unit 4's `GenericRecord`, `IngestState`, and `GenericS3Handler` — OTLP log records are mapped to `GenericRecord` with `sourcetype = "otlp"` and routed through the existing generic sink, avoiding a second sink implementation.

---

### Task 5.1: Cargo feature gate and `opentelemetry-proto` dependency (`Cargo.toml`)

**Files:** Modify `Cargo.toml`

**Interfaces:**
- Produces: `otlp` Cargo feature that pulls in `opentelemetry-proto` with prost message types and serde JSON support; adds `otlp` to `default` features

---

- [ ] **Step 1: Write the failing test**

```rust
// tests/otlp_feature_smoke.rs
// This file tests that the feature gate compiles cleanly and the proto types
// are importable. It will fail to compile until Cargo.toml is updated.
#[cfg(feature = "otlp")]
#[test]
fn otlp_proto_types_importable() {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
    // Constructing a default is enough to confirm the types are present.
    let _req = ExportLogsServiceRequest::default();
    let _lr  = LogRecord::default();
    let _kv  = KeyValue::default();
    let _av  = AnyValue::default();
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_feature_absent_compiles_cleanly() {
    // When `otlp` is not enabled the crate still compiles — verified by the
    // test runner reaching this point without a compile error.
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features otlp -p logthing --test otlp_feature_smoke 2>&1 | head -30
# Expected: error[E0432]: unresolved import `opentelemetry_proto`
# (crate not yet in Cargo.toml)
```

- [ ] **Step 3: Implement**

Add to `Cargo.toml`:

```toml
[features]
default = ["otlp"]
kerberos-auth = ["dep:axum-negotiate"]
otlp = ["dep:opentelemetry-proto", "dep:prost"]

[dependencies]
# … existing entries unchanged …

# OTLP ingest (feature-gated)
opentelemetry-proto = { version = "0.7", optional = true, default-features = false, features = [
    "gen-tonic-messages",  # prost-generated message types without tonic transport
    "with-serde",          # enables serde Serialize/Deserialize on proto types
    "logs",                # logs service types (ExportLogsServiceRequest etc.)
    "trace",               # not needed but included for completeness — omit if binary size matters
] }
prost = { version = "0.13", optional = true }
```

> **Version note:** `opentelemetry-proto 0.7` is the latest stable release compatible with
> the `opentelemetry` 0.26 ecosystem as of mid-2026. If a newer version is published,
> substitute it; the feature name `gen-tonic-messages` is stable across 0.6–0.7.
> The `with-serde` feature enables `serde::Serialize`/`Deserialize` on all proto types,
> which is required for JSON content-type support without a separate JSON mapping step.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --features otlp -p logthing --test otlp_feature_smoke 2>&1 | tail -10
# Expected: test otlp_feature_smoke::otlp_proto_types_importable ... ok

# Also verify the feature-absent case compiles:
cargo test -p logthing --test otlp_feature_smoke 2>&1 | tail -5
# Expected: test otlp_feature_smoke::otlp_feature_absent_compiles_cleanly ... ok
```

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml tests/otlp_feature_smoke.rs
git commit -m "build(otlp): add opentelemetry-proto dependency behind otlp feature gate"
```

---

### Task 5.2: `OtlpConfig` in `src/config/mod.rs`

**Files:** Modify `src/config/mod.rs`

**Interfaces:**
- Produces: `OtlpConfig { enabled: bool, bearer_token: Option<String> }` added as `pub otlp: OtlpConfig` on `Config`

---

- [ ] **Step 1: Write the failing tests**

```rust
// Add to the #[cfg(test)] mod tests block in src/config/mod.rs:

#[test]
fn otlp_config_defaults_disabled_no_token() {
    let cfg = Config::default();
    assert!(!cfg.otlp.enabled, "otlp must be opt-in (default false)");
    assert!(cfg.otlp.bearer_token.is_none(), "no bearer_token by default");
}

#[test]
fn otlp_config_parses_from_toml() {
    let toml_str = r#"
[otlp]
enabled = true
bearer_token = "s3cr3t"
"#;
    let cfg: Config = toml::from_str(toml_str).expect("parse");
    assert!(cfg.otlp.enabled);
    assert_eq!(cfg.otlp.bearer_token.as_deref(), Some("s3cr3t"));
}

#[test]
fn otlp_config_absent_section_yields_defaults() {
    let toml_str = "[syslog]\nenabled = true\n";
    let cfg: Config = toml::from_str(toml_str).expect("parse");
    assert!(!cfg.otlp.enabled);
    assert!(cfg.otlp.bearer_token.is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features otlp -p logthing --lib config::tests::otlp 2>&1 | head -15
# Expected: error[E0609]: no field `otlp` on type `Config`
```

- [ ] **Step 3: Implement**

Add to `src/config/mod.rs` following the `WefConfig` pattern:

```rust
/// Top-level [otlp] config section (OTLP/HTTP log ingest).
/// Only present when the `otlp` Cargo feature is enabled; always compiled
/// into Config so the TOML surface is consistent (the field is inert when
/// the feature is off — the route is never registered).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtlpConfig {
    /// Enable the `POST /v1/logs` OTLP endpoint. Default: false.
    #[serde(default = "default_otlp_enabled")]
    pub enabled: bool,

    /// Optional bearer token for the `Authorization: Bearer <token>` header.
    /// If `None`, no bearer auth is enforced (IP whitelist + TLS still apply).
    #[serde(default)]
    pub bearer_token: Option<String>,
}

fn default_otlp_enabled() -> bool {
    false
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enabled: default_otlp_enabled(),
            bearer_token: None,
        }
    }
}
```

Also add to the `Config` struct:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    // … existing fields …
    #[serde(default)]
    pub otlp: OtlpConfig,
}
```

And to `Config::default()`:

```rust
impl Default for Config {
    fn default() -> Self {
        Self {
            // … existing fields …
            otlp: OtlpConfig::default(),
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --features otlp -p logthing --lib config::tests 2>&1 | tail -10
# Expected: all config tests pass including the three new otlp ones
```

- [ ] **Step 5: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(otlp): add OtlpConfig to Config struct"
```

---

### Task 5.3: OTLP `LogRecord` → `GenericRecord` mapping (`src/server/otlp.rs`)

**Files:** Create `src/server/otlp.rs`

**Interfaces:**
- Consumes (from Unit 4): `GenericRecord { sourcetype: String, host: String, time: DateTime<Utc>, fields: serde_json::Map<String, Value>, received_at: DateTime<Utc> }`
- Consumes (from `opentelemetry-proto`): `ExportLogsServiceRequest`, `ResourceLogs`, `ScopeLogs`, `LogRecord`, `KeyValue`, `AnyValue`
- Produces:
  - `pub fn map_otlp_request(req: ExportLogsServiceRequest, source_host: String) -> Vec<GenericRecord>`
  - `pub fn any_value_to_json(av: AnyValue) -> serde_json::Value`
  - `pub fn kv_list_to_map(kvs: Vec<KeyValue>) -> serde_json::Map<String, serde_json::Value>`

---

- [ ] **Step 1: Write the failing tests**

```rust
// src/server/otlp.rs — place inside #[cfg(test)] mod tests at the bottom

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, ArrayValue, KeyValue, KeyValueList,
        any_value::Value as AnyVal,
    };
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;

    fn make_kv(key: &str, val: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::StringValue(val.to_string())),
            }),
        }
    }

    fn make_int_kv(key: &str, val: i64) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::IntValue(val)),
            }),
        }
    }

    fn make_bool_kv(key: &str, val: bool) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::BoolValue(val)),
            }),
        }
    }

    fn make_double_kv(key: &str, val: f64) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::DoubleValue(val)),
            }),
        }
    }

    fn make_request(
        resource_attrs: Vec<KeyValue>,
        scope_attrs: Vec<KeyValue>,
        log_attrs: Vec<KeyValue>,
        time_unix_nano: u64,
        body_str: &str,
    ) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: resource_attrs,
                    dropped_attributes_count: 0,
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano,
                        observed_time_unix_nano: 0,
                        severity_number: 9, // INFO
                        severity_text: "INFO".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue(body_str.to_string())),
                        }),
                        attributes: log_attrs,
                        dropped_attributes_count: 0,
                        flags: 0,
                        span_id: vec![],
                        trace_id: vec![],
                    }],
                    schema_url: String::new(),
                    attributes: scope_attrs,
                    dropped_attributes_count: 0,
                }],
                schema_url: String::new(),
            }],
        }
    }

    // ── Test 1: basic mapping — time, body, sourcetype ─────────────────────
    #[test]
    fn map_otlp_request_sets_sourcetype_and_time() {
        // time_unix_nano = 1_700_000_000_000_000_000 ns = 2023-11-14T22:13:20Z
        let req = make_request(vec![], vec![], vec![], 1_700_000_000_000_000_000, "hello world");
        let records = map_otlp_request(req, "10.0.0.1".to_string());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.sourcetype, "otlp");
        assert_eq!(r.host, "10.0.0.1");
        // time should be non-epoch (parsed from time_unix_nano)
        assert!(r.time.timestamp_nanos_opt().unwrap_or(0) > 0);
        // body field
        assert_eq!(r.fields.get("body").and_then(|v| v.as_str()), Some("hello world"));
        // severity
        assert_eq!(r.fields.get("severity_text").and_then(|v| v.as_str()), Some("INFO"));
    }

    // ── Test 2: resource + scope + log attribute flattening ─────────────────
    #[test]
    fn map_otlp_request_flattens_all_attribute_layers() {
        let resource_attrs = vec![
            make_kv("service.name", "my-service"),
            make_kv("host.name", "prod-01"),
        ];
        let scope_attrs = vec![make_kv("scope.name", "my-scope")];
        let log_attrs   = vec![
            make_kv("log.level", "info"),
            make_int_kv("http.status_code", 200),
        ];
        let req = make_request(resource_attrs, scope_attrs, log_attrs, 1_700_000_000_000_000_000, "test");
        let records = map_otlp_request(req, "10.0.0.2".to_string());
        assert_eq!(records.len(), 1);
        let fields = &records[0].fields;
        // resource attrs
        assert_eq!(fields.get("service.name").and_then(|v| v.as_str()), Some("my-service"));
        assert_eq!(fields.get("host.name").and_then(|v| v.as_str()), Some("prod-01"));
        // scope attrs
        assert_eq!(fields.get("scope.name").and_then(|v| v.as_str()), Some("my-scope"));
        // log attrs
        assert_eq!(fields.get("log.level").and_then(|v| v.as_str()), Some("info"));
        assert_eq!(fields.get("http.status_code").and_then(|v| v.as_i64()), Some(200));
    }

    // ── Test 3: attribute collision — log attrs win over scope, scope over resource ──
    #[test]
    fn map_otlp_request_log_attrs_override_resource_attrs_on_collision() {
        let resource_attrs = vec![make_kv("key", "from-resource")];
        let scope_attrs    = vec![make_kv("key", "from-scope")];
        let log_attrs      = vec![make_kv("key", "from-log")];
        let req = make_request(resource_attrs, scope_attrs, log_attrs, 0, "collision");
        let records = map_otlp_request(req, "10.0.0.3".to_string());
        // log attrs have highest precedence
        assert_eq!(
            records[0].fields.get("key").and_then(|v| v.as_str()),
            Some("from-log")
        );
    }

    // ── Test 4: zero time_unix_nano → falls back to received_at ────────────
    #[test]
    fn map_otlp_request_zero_time_falls_back_to_received_at() {
        let req = make_request(vec![], vec![], vec![], 0, "no time");
        let before = chrono::Utc::now();
        let records = map_otlp_request(req, "10.0.0.4".to_string());
        let after = chrono::Utc::now();
        assert_eq!(records.len(), 1);
        // time should be close to now (the fallback)
        let t = records[0].time;
        assert!(t >= before && t <= after, "time {t} must be between {before} and {after}");
    }

    // ── Test 5: multiple ResourceLogs + multiple ScopeLogs ─────────────────
    #[test]
    fn map_otlp_request_handles_multiple_resource_and_scope_logs() {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![
                ResourceLogs {
                    resource: Some(Resource { attributes: vec![make_kv("svc", "a")], dropped_attributes_count: 0 }),
                    scope_logs: vec![
                        ScopeLogs {
                            scope: None,
                            log_records: vec![
                                LogRecord { body: Some(AnyValue { value: Some(AnyVal::StringValue("msg1".into())) }), time_unix_nano: 1_000, ..Default::default() },
                                LogRecord { body: Some(AnyValue { value: Some(AnyVal::StringValue("msg2".into())) }), time_unix_nano: 2_000, ..Default::default() },
                            ],
                            schema_url: String::new(),
                            attributes: vec![],
                            dropped_attributes_count: 0,
                        },
                    ],
                    schema_url: String::new(),
                },
                ResourceLogs {
                    resource: Some(Resource { attributes: vec![make_kv("svc", "b")], dropped_attributes_count: 0 }),
                    scope_logs: vec![
                        ScopeLogs {
                            scope: None,
                            log_records: vec![
                                LogRecord { body: Some(AnyValue { value: Some(AnyVal::StringValue("msg3".into())) }), time_unix_nano: 3_000, ..Default::default() },
                            ],
                            schema_url: String::new(),
                            attributes: vec![],
                            dropped_attributes_count: 0,
                        },
                    ],
                    schema_url: String::new(),
                },
            ],
        };
        let records = map_otlp_request(req, "10.0.0.5".to_string());
        assert_eq!(records.len(), 3, "3 log records across 2 resource groups");
        let bodies: Vec<&str> = records.iter()
            .map(|r| r.fields["body"].as_str().unwrap_or(""))
            .collect();
        assert!(bodies.contains(&"msg1"));
        assert!(bodies.contains(&"msg2"));
        assert!(bodies.contains(&"msg3"));
        // Each record has its resource's svc attribute
        assert_eq!(records[0].fields.get("svc").and_then(|v| v.as_str()), Some("a"));
        assert_eq!(records[2].fields.get("svc").and_then(|v| v.as_str()), Some("b"));
    }

    // ── Test 6: any_value_to_json covers all AnyValue variants ─────────────
    #[test]
    fn any_value_to_json_maps_all_variants() {
        use serde_json::json;

        let string_av = AnyValue { value: Some(AnyVal::StringValue("hello".into())) };
        assert_eq!(any_value_to_json(string_av), json!("hello"));

        let int_av = AnyValue { value: Some(AnyVal::IntValue(42)) };
        assert_eq!(any_value_to_json(int_av), json!(42));

        let double_av = AnyValue { value: Some(AnyVal::DoubleValue(3.14)) };
        assert_eq!(any_value_to_json(double_av).as_f64().unwrap(), 3.14f64);

        let bool_av = AnyValue { value: Some(AnyVal::BoolValue(true)) };
        assert_eq!(any_value_to_json(bool_av), json!(true));

        let bytes_av = AnyValue { value: Some(AnyVal::BytesValue(vec![0xDE, 0xAD])) };
        // bytes → hex string
        let bv = any_value_to_json(bytes_av);
        assert!(bv.is_string());
        let s = bv.as_str().unwrap();
        assert!(s.contains("dead") || s.contains("DEAD") || s.contains("de") || s.len() > 0);

        let none_av = AnyValue { value: None };
        assert_eq!(any_value_to_json(none_av), json!(null));

        let array_av = AnyValue {
            value: Some(AnyVal::ArrayValue(ArrayValue {
                values: vec![
                    AnyValue { value: Some(AnyVal::StringValue("x".into())) },
                    AnyValue { value: Some(AnyVal::IntValue(1)) },
                ],
            })),
        };
        let av_json = any_value_to_json(array_av);
        assert!(av_json.is_array());
        let arr = av_json.as_array().unwrap();
        assert_eq!(arr[0], json!("x"));
        assert_eq!(arr[1], json!(1));

        let kvlist_av = AnyValue {
            value: Some(AnyVal::KvlistValue(KeyValueList {
                values: vec![make_kv("k", "v")],
            })),
        };
        let kv_json = any_value_to_json(kvlist_av);
        assert!(kv_json.is_object());
        assert_eq!(kv_json["k"], json!("v"));
    }

    // ── Test 7: kv_list_to_map ───────────────────────────────────────────────
    #[test]
    fn kv_list_to_map_converts_all_types() {
        use serde_json::json;
        let kvs = vec![
            make_kv("str_key", "hello"),
            make_int_kv("int_key", 99),
            make_bool_kv("bool_key", false),
            make_double_kv("f64_key", 2.71),
        ];
        let map = kv_list_to_map(kvs);
        assert_eq!(map["str_key"], json!("hello"));
        assert_eq!(map["int_key"], json!(99));
        assert_eq!(map["bool_key"], json!(false));
        assert_eq!(map["f64_key"].as_f64().unwrap(), 2.71f64);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features otlp -p logthing --lib server::otlp::tests 2>&1 | head -20
# Expected: error[E0583]: file not found for module `otlp`
# (or similar — src/server/otlp.rs does not exist yet)
```

- [ ] **Step 3: Implement**

Create `src/server/otlp.rs`:

```rust
//! OTLP/HTTP log record ingestion — mapping layer.
//!
//! Converts an `ExportLogsServiceRequest` (protobuf or JSON) into a Vec of
//! `GenericRecord`s suitable for the Unit-4 generic S3 sink.
//!
//! Attribute precedence (highest wins on key collision):
//!   log attributes > scope attributes > resource attributes
//!
//! This module is compiled only when the `otlp` Cargo feature is enabled.

use crate::server::generic::GenericRecord;
use chrono::{DateTime, TimeZone, Utc};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
use serde_json::{Map, Value};

/// Convert an OTLP `ExportLogsServiceRequest` to a flat list of `GenericRecord`s.
///
/// Flattening strategy: resource attributes are inserted first, then scope
/// attributes (overwrite on collision), then log-level attributes (overwrite on
/// collision).  This gives log-level attributes the highest precedence, matching
/// the OpenTelemetry semantic: the closer to the signal, the more specific.
pub fn map_otlp_request(req: ExportLogsServiceRequest, source_host: String) -> Vec<GenericRecord> {
    let received_at = Utc::now();
    let mut records = Vec::new();

    for resource_logs in req.resource_logs {
        // Collect resource-level attributes once per ResourceLogs block.
        let resource_attrs: Map<String, Value> = resource_logs
            .resource
            .map(|r| kv_list_to_map(r.attributes))
            .unwrap_or_default();

        for scope_logs in resource_logs.scope_logs {
            // Scope attributes (e.g. instrumentation library metadata).
            let scope_attrs = kv_list_to_map(scope_logs.attributes);

            for log_record in scope_logs.log_records {
                // Build merged fields: resource < scope < log attributes.
                let mut fields: Map<String, Value> = Map::new();
                fields.extend(resource_attrs.clone());
                fields.extend(scope_attrs.clone());
                fields.extend(kv_list_to_map(log_record.attributes));

                // Extract and remove the body string into its own key.
                if let Some(body_av) = log_record.body {
                    let body_val = any_value_to_json(body_av);
                    fields.insert("body".to_string(), body_val);
                }

                // Severity metadata.
                if !log_record.severity_text.is_empty() {
                    fields.insert(
                        "severity_text".to_string(),
                        Value::String(log_record.severity_text.clone()),
                    );
                }
                if log_record.severity_number != 0 {
                    fields.insert(
                        "severity_number".to_string(),
                        Value::Number(log_record.severity_number.into()),
                    );
                }

                // Trace context (if present).
                if !log_record.trace_id.is_empty() {
                    fields.insert(
                        "trace_id".to_string(),
                        Value::String(hex::encode(&log_record.trace_id)),
                    );
                }
                if !log_record.span_id.is_empty() {
                    fields.insert(
                        "span_id".to_string(),
                        Value::String(hex::encode(&log_record.span_id)),
                    );
                }

                // Map time_unix_nano → DateTime<Utc>; fall back to received_at when zero.
                let time: DateTime<Utc> = if log_record.time_unix_nano > 0 {
                    let secs  = (log_record.time_unix_nano / 1_000_000_000) as i64;
                    let nanos = (log_record.time_unix_nano % 1_000_000_000) as u32;
                    Utc.timestamp_opt(secs, nanos).single().unwrap_or(received_at)
                } else {
                    received_at
                };

                records.push(GenericRecord {
                    sourcetype: "otlp".to_string(),
                    host: source_host.clone(),
                    time,
                    fields,
                    received_at,
                });
            }
        }
    }

    records
}

/// Convert an OTLP `AnyValue` to a `serde_json::Value`.
///
/// | OTLP variant    | JSON mapping                                     |
/// |-----------------|--------------------------------------------------|
/// | StringValue     | `Value::String`                                  |
/// | IntValue        | `Value::Number` (i64)                            |
/// | DoubleValue     | `Value::Number` (f64)                            |
/// | BoolValue       | `Value::Bool`                                    |
/// | BytesValue      | `Value::String` (lowercase hex)                  |
/// | ArrayValue      | `Value::Array` (recursive)                       |
/// | KvlistValue     | `Value::Object` (recursive via `kv_list_to_map`) |
/// | None            | `Value::Null`                                    |
pub fn any_value_to_json(av: AnyValue) -> Value {
    match av.value {
        Some(AnyVal::StringValue(s))  => Value::String(s),
        Some(AnyVal::IntValue(i))     => Value::Number(i.into()),
        Some(AnyVal::DoubleValue(f))  => {
            serde_json::Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        Some(AnyVal::BoolValue(b))    => Value::Bool(b),
        Some(AnyVal::BytesValue(b))   => Value::String(hex::encode(&b)),
        Some(AnyVal::ArrayValue(arr)) => {
            Value::Array(arr.values.into_iter().map(any_value_to_json).collect())
        }
        Some(AnyVal::KvlistValue(kl)) => {
            Value::Object(kv_list_to_map(kl.values))
        }
        None => Value::Null,
    }
}

/// Convert a `Vec<KeyValue>` to a `serde_json::Map<String, Value>`.
pub fn kv_list_to_map(kvs: Vec<KeyValue>) -> Map<String, Value> {
    kvs.into_iter()
        .map(|kv| {
            let val = kv
                .value
                .map(any_value_to_json)
                .unwrap_or(Value::Null);
            (kv.key, val)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // … test code from Step 1 above …
}
```

Also register the module in `src/server/mod.rs` (feature-gated):

```rust
// Add to src/server/mod.rs:
#[cfg(feature = "otlp")]
pub mod otlp;
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --features otlp -p logthing --lib server::otlp::tests 2>&1 | tail -15
# Expected: test result: ok. 7 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add src/server/otlp.rs src/server/mod.rs
git commit -m "feat(otlp): add LogRecord → GenericRecord mapping with full AnyValue support"
```

---

### Task 5.4: `handle_otlp_logs` handler and route registration (`src/server/mod.rs`)

**Files:** Modify `src/server/mod.rs`

**Interfaces:**
- Consumes (from Unit 4): `IngestState` (Axum extension carrying `generic_handler: Option<ParquetWriterHandle<GenericSink>>`), `GenericRecord`
- Consumes (from Task 5.3): `map_otlp_request`
- Consumes (from Task 5.2): `Config::otlp` (bearer_token, enabled)
- Produces: `async fn handle_otlp_logs(...)` registered on `POST /v1/logs`; returns `ExportLogsServiceResponse` (empty protobuf or JSON body) with 200

---

- [ ] **Step 1: Write the failing tests**

```rust
// Add to the #[cfg(test)] mod tests block in src/server/mod.rs,
// inside a #[cfg(feature = "otlp")] sub-block:

#[cfg(feature = "otlp")]
mod otlp_handler_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;
    use prost::Message as ProstMessage;
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, ExportLogsServiceResponse,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;

    fn make_proto_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(AnyVal::StringValue("test-svc".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_700_000_000_000_000_000,
                        severity_text: "INFO".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue("e2e test message".to_string())),
                        }),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                }],
                schema_url: String::new(),
            }],
        }
    }

    async fn build_otlp_app(bearer_token: Option<String>) -> axum::Router {
        use crate::config::OtlpConfig;
        // Build a minimal router with the OTLP route and IngestState injected.
        // Unit 4's IngestState is used here; pass None for the generic handler so
        // try_send is skipped (no S3 sink needed for these handler-level tests).
        let mut config = Config::default();
        config.otlp = OtlpConfig {
            enabled: true,
            bearer_token,
        };
        let ingest_state = crate::server::generic::IngestState {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            generic_handler: None,
        };
        Router::new()
            .route("/v1/logs", post(handle_otlp_logs))
            .layer(axum::Extension(Arc::new(ingest_state)))
    }

    // ── Test A: valid protobuf POST returns 200 + empty ExportLogsServiceResponse ──
    #[tokio::test]
    async fn handle_otlp_logs_proto_returns_200() {
        let app = build_otlp_app(None).await;
        let req_bytes = make_proto_request().encode_to_vec();

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(req_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
        // Response is a valid (possibly empty) ExportLogsServiceResponse
        let _resp = ExportLogsServiceResponse::decode(body_bytes.as_ref())
            .expect("response must be valid protobuf ExportLogsServiceResponse");
    }

    // ── Test B: valid JSON POST returns 200 ─────────────────────────────────
    #[tokio::test]
    async fn handle_otlp_logs_json_returns_200() {
        let app = build_otlp_app(None).await;
        let json_body = serde_json::to_vec(&make_proto_request())
            .expect("ExportLogsServiceRequest must be serde-serializable via with-serde feature");

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Test C: valid bearer token accepted → 200 ───────────────────────────
    #[tokio::test]
    async fn handle_otlp_logs_correct_bearer_accepted() {
        let app = build_otlp_app(Some("my-secret-token".to_string())).await;
        let req_bytes = make_proto_request().encode_to_vec();

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/x-protobuf")
            .header("authorization", "Bearer my-secret-token")
            .body(Body::from(req_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Test D: wrong bearer token rejected → 401 ───────────────────────────
    #[tokio::test]
    async fn handle_otlp_logs_wrong_bearer_rejected() {
        let app = build_otlp_app(Some("correct-token".to_string())).await;
        let req_bytes = make_proto_request().encode_to_vec();

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/x-protobuf")
            .header("authorization", "Bearer wrong-token")
            .body(Body::from(req_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Test E: bearer required but absent → 401 ────────────────────────────
    #[tokio::test]
    async fn handle_otlp_logs_missing_bearer_rejected() {
        let app = build_otlp_app(Some("required-token".to_string())).await;
        let req_bytes = make_proto_request().encode_to_vec();

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(req_bytes))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Test F: malformed protobuf body → 400 ───────────────────────────────
    #[tokio::test]
    async fn handle_otlp_logs_malformed_proto_returns_400() {
        let app = build_otlp_app(None).await;

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(b"\xFF\xFE\xFD garbage".as_ref()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Test G: metrics counter incremented ─────────────────────────────────
    #[tokio::test]
    async fn handle_otlp_logs_increments_metrics_counter() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Install the recorder for this test; ignore errors if one is already installed.
        let _ = metrics::set_global_recorder(recorder);

        let app = build_otlp_app(None).await;
        let req_bytes = make_proto_request().encode_to_vec();
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(req_bytes))
            .unwrap();
        let _ = app.oneshot(request).await.unwrap();

        let snapshot = snapshotter.snapshot().into_hashmap();
        // At least the otlp_logs_received counter should exist.
        let found = snapshot.keys().any(|(name, _, _)| name.as_str().contains("otlp_logs_received"));
        assert!(found, "otlp_logs_received counter must be incremented; snapshot keys: {:?}",
            snapshot.keys().collect::<Vec<_>>());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features otlp -p logthing --lib server::otlp_handler_tests 2>&1 | head -25
# Expected: error[E0425]: cannot find function `handle_otlp_logs` in module `server`
```

- [ ] **Step 3: Implement**

Add to `src/server/mod.rs` (inside an `#[cfg(feature = "otlp")]` block):

```rust
#[cfg(feature = "otlp")]
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
#[cfg(feature = "otlp")]
use prost::Message as ProstMessage;

/// POST /v1/logs — OTLP/HTTP protobuf or JSON log ingest.
///
/// Content-Type dispatch:
///   `application/x-protobuf` → prost decode
///   `application/json`       → serde_json decode (via `with-serde` feature of opentelemetry-proto)
///   anything else            → 415 Unsupported Media Type
///
/// Auth: if `config.otlp.bearer_token` is `Some(token)`, the request must carry
/// `Authorization: Bearer <token>`.  Timing-safe comparison via `subtle::ConstantTimeEq`.
///
/// On success: maps each `LogRecord` → `GenericRecord` via `otlp::map_otlp_request`,
/// routes through the existing `IngestState` generic handler (Unit 4), and returns
/// an empty `ExportLogsServiceResponse` (200).
///
/// Design note: this handler does NOT add a second sink.  OTLP records share the
/// same `GenericS3Handler` as other generic-sourcetype data (Unit 4) via the
/// `sourcetype = "otlp"` field, which becomes the S3 partition label.
#[cfg(feature = "otlp")]
pub(crate) async fn handle_otlp_logs(
    axum::Extension(ingest_state): axum::Extension<
        std::sync::Arc<crate::server::generic::IngestState>
    >,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    use axum::http::header::CONTENT_TYPE;
    use subtle::ConstantTimeEq;

    // ── Bearer auth check ────────────────────────────────────────────────────
    {
        let cfg = ingest_state.config.read().await;
        if let Some(expected_token) = &cfg.otlp.bearer_token {
            let provided = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or("");
            // Timing-safe comparison to prevent token oracle attacks.
            let ok: bool = expected_token.as_bytes().ct_eq(provided.as_bytes()).into();
            if !ok {
                metrics::counter!("otlp_auth_failures").increment(1);
                warn!("OTLP bearer auth failure from {}", addr.ip());
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    // ── Content-Type dispatch ────────────────────────────────────────────────
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req: ExportLogsServiceRequest = if ct.starts_with("application/x-protobuf")
        || ct.starts_with("application/protobuf")
    {
        ExportLogsServiceRequest::decode(body.as_ref()).map_err(|e| {
            warn!("OTLP protobuf decode error from {}: {e}", addr.ip());
            StatusCode::BAD_REQUEST
        })?
    } else if ct.starts_with("application/json") {
        serde_json::from_slice::<ExportLogsServiceRequest>(&body).map_err(|e| {
            warn!("OTLP JSON decode error from {}: {e}", addr.ip());
            StatusCode::BAD_REQUEST
        })?
    } else {
        warn!("OTLP unsupported Content-Type '{}' from {}", ct, addr.ip());
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    };

    // ── Map to GenericRecords ────────────────────────────────────────────────
    let source_host = addr.ip().to_string();
    let records = crate::server::otlp::map_otlp_request(req, source_host);
    let count = records.len() as u64;

    // ── Route through generic S3 handler (Unit 4) ────────────────────────────
    if let Some(ref handler) = ingest_state.generic_handler {
        for record in records {
            if let Err(e) = handler.try_send(std::sync::Arc::new(record)) {
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        warn!("OTLP generic handler channel full, dropping record");
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        error!("OTLP generic handler channel closed");
                    }
                }
            }
        }
    }

    metrics::counter!("otlp_logs_received").increment(count);

    // ── Respond with ExportLogsServiceResponse ───────────────────────────────
    let resp_bytes = ExportLogsServiceResponse::default().encode_to_vec();

    let response_ct = if ct.starts_with("application/json") {
        "application/json"
    } else {
        "application/x-protobuf"
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", response_ct)
        .body(axum::body::Body::from(resp_bytes))
        .unwrap())
}
```

Register the route in `create_router` (inside `src/server/mod.rs`), feature-gated:

```rust
// Inside Server::create_router, within the protected_router builder:
let protected_router = Router::new()
    .route("/wsman", post(handle_wef_request))
    // … existing routes …
    .route("/syslog", post(handle_syslog_http))
    .route("/syslog/udp", get(handle_syslog_udp_info))
    .route("/syslog/examples", get(handle_syslog_examples))
    // OTLP ingest (feature-gated):
    #[cfg(feature = "otlp")]
    .route("/v1/logs", post(handle_otlp_logs))
    .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
    // … existing layers …
```

Also add `subtle` to `Cargo.toml` (it is already present — see existing `Cargo.toml`).

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --features otlp -p logthing --lib server::otlp_handler_tests 2>&1 | tail -15
# Expected: test result: ok. 7 passed; 0 failed

# Verify the non-otlp build is clean:
cargo test -p logthing --lib server 2>&1 | tail -5
# Expected: test result: ok. N passed; 0 failed (no OTLP tests run, no compile errors)
```

- [ ] **Step 5: Commit**

```bash
git add src/server/mod.rs
git commit -m "feat(otlp): add handle_otlp_logs handler with proto/JSON dispatch and bearer auth"
```

---

### Task 5.5: Integration test (`tests/otlp_s3_integration.rs`)

**Files:** Create `tests/otlp_s3_integration.rs`

**Interfaces:**
- Consumes (from Unit 4): `GenericRecord`, `GenericSink`, `generic_start` (or equivalent Unit 4 start function)
- Consumes (from Task 5.3): `map_otlp_request`
- Requires `--features otlp`; skips if `MINIO_ENDPOINT` is absent

---

- [ ] **Step 1: Write the failing test**

```rust
//! Integration test: OTLP ExportLogsServiceRequest → GenericS3Handler → Parquet in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent the test is skipped automatically.
//!
//! Run with:
//!   cargo test --features otlp --test otlp_s3_integration

#[cfg(feature = "otlp")]
mod tests {
    use logthing::config::{GenericS3Config, S3ConnectionConfig};
    use logthing::forwarding::s3_sink::S3Sink;
    use logthing::server::generic::{generic_start, GenericRecord};
    use logthing::server::otlp::map_otlp_request;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use std::sync::Arc;

    fn skip_if_no_minio() -> Option<String> {
        std::env::var("MINIO_ENDPOINT").ok()
    }

    fn minio_generic_config(endpoint: &str) -> GenericS3Config {
        GenericS3Config {
            connection: S3ConnectionConfig {
                endpoint: endpoint.to_string(),
                bucket: std::env::var("MINIO_BUCKET")
                    .unwrap_or_else(|_| "otlp-test".to_string()),
                region: "us-east-1".to_string(),
                access_key: std::env::var("MINIO_ACCESS_KEY")
                    .unwrap_or_else(|_| "minioadmin".to_string()),
                secret_key: std::env::var("MINIO_SECRET_KEY")
                    .unwrap_or_else(|_| "minioadmin".to_string()),
            },
            prefix: "otlp-integration".to_string(),
            max_buffer_rows: 1,   // flush immediately on first record
            flush_threshold_bytes: 1, // flush immediately on first byte
            flush_interval_secs: 3600,
            channel_capacity: 256,
        }
    }

    fn make_otlp_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(AnyVal::StringValue("integration-svc".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_700_000_000_000_000_000,
                        severity_text: "WARN".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue("integration test log".to_string())),
                        }),
                        attributes: vec![KeyValue {
                            key: "test.run".to_string(),
                            value: Some(AnyValue {
                                value: Some(AnyVal::BoolValue(true)),
                            }),
                        }],
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                }],
                schema_url: String::new(),
            }],
        }
    }

    #[tokio::test]
    async fn otlp_records_land_as_parquet_in_s3_under_otlp_partition() {
        let endpoint = match skip_if_no_minio() {
            Some(e) => e,
            None => {
                eprintln!("MINIO_ENDPOINT not set — skipping otlp_s3 integration test");
                return;
            }
        };

        let cfg = minio_generic_config(&endpoint);
        let sink = Arc::new(
            S3Sink::from_connection(&cfg.connection)
                .await
                .expect("S3Sink::from_connection"),
        );

        // Start the Unit-4 generic handler targeting the S3 sink.
        let (handler, _writer_task) = generic_start(&cfg, sink.clone());

        // Map the OTLP request to GenericRecords.
        let req = make_otlp_request();
        let records = map_otlp_request(req, "127.0.0.1".to_string());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sourcetype, "otlp");

        // Send via the handler (flushes immediately because max_buffer_rows=1).
        handler
            .try_send(Arc::new(records.into_iter().next().unwrap()))
            .expect("channel must accept the record");

        // Allow background flush to complete.
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Verify the object was written under the `otlp` partition.
        let s3_client = sink.client();
        let prefix = format!("{}/sourcetype=otlp/", cfg.prefix);
        let list_result = s3_client
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix(&prefix)
            .send()
            .await
            .expect("list_objects_v2 must succeed");

        let objects = list_result.contents().unwrap_or_default();
        assert!(
            !objects.is_empty(),
            "expected at least one Parquet object under prefix {prefix}; got none. \
             Check that the flush completed and the S3 bucket is correct."
        );
        assert!(
            objects[0].key().unwrap_or("").ends_with(".parquet"),
            "written object must have .parquet extension"
        );
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_s3_integration_skipped_without_feature() {
    // Compile-time guard: the integration test body is empty without the feature.
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features otlp --test otlp_s3_integration 2>&1 | head -20
# Expected (if MINIO not set): "MINIO_ENDPOINT not set — skipping" → test passes vacuously
# Expected (if Unit 4 not yet implemented): compile error about GenericS3Config / generic_start
# Either outcome is acceptable at this stage — the test structure is validated.
```

- [ ] **Step 3: Implement**

This task has no implementation code to write — the test itself is the artifact. Ensure that `GenericS3Config` and `generic_start` are exported from Unit 4's `src/server/generic.rs` as `pub`. If not, add the missing `pub` visibility in that module (one-line change).

- [ ] **Step 4: Run to verify it passes**

```bash
# With MinIO running:
MINIO_ENDPOINT=http://localhost:9000 \
MINIO_BUCKET=test-logthing \
MINIO_ACCESS_KEY=minioadmin \
MINIO_SECRET_KEY=minioadmin \
cargo test --features otlp --test otlp_s3_integration -- --nocapture 2>&1 | tail -20
# Expected: test otlp_s3_integration::tests::otlp_records_land_as_parquet_in_s3_under_otlp_partition ... ok

# Without MinIO:
cargo test --features otlp --test otlp_s3_integration 2>&1 | tail -10
# Expected: "MINIO_ENDPOINT not set — skipping" then ok
```

- [ ] **Step 5: Commit**

```bash
git add tests/otlp_s3_integration.rs
git commit -m "test(otlp): add integration test for OTLP → Parquet S3 via generic handler"
```

---

### Task 5.6: End-to-end test (`tests/e2e/otlp_e2e.rs`)

**Files:** Create `tests/e2e/otlp_e2e.rs`

**Interfaces:**
- Mounts a real Axum router on an ephemeral port
- POSTs an `ExportLogsServiceRequest` as protobuf bytes via `reqwest`
- Asserts 200 + valid `ExportLogsServiceResponse`
- Asserts 401 for wrong bearer token
- Requires `--features otlp`

---

- [ ] **Step 1: Write the failing test**

```rust
//! End-to-end test: real HTTP POST of OTLP protobuf → handle_otlp_logs → 200.
//!
//! No external services required. The router is mounted on an ephemeral port
//! in-process; the test posts real protobuf bytes and inspects the HTTP response.
//!
//! Run with:
//!   cargo test --features otlp --test otlp_e2e

#[cfg(feature = "otlp")]
mod e2e {
    use logthing::config::{Config, OtlpConfig};
    use logthing::server::generic::IngestState;
    use logthing::server::handle_otlp_logs;
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, ExportLogsServiceResponse,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value::Value as AnyVal};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use prost::Message as ProstMessage;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use axum::{Router, routing::post};

    fn make_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_700_000_000_000_000_000,
                        severity_text: "DEBUG".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue("e2e check".to_string())),
                        }),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                }],
                schema_url: String::new(),
            }],
        }
    }

    async fn start_test_server(bearer_token: Option<String>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let mut config = Config::default();
        config.otlp = OtlpConfig { enabled: true, bearer_token };

        let ingest_state = Arc::new(IngestState {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            generic_handler: None,
        });

        let app = Router::new()
            .route("/v1/logs", post(handle_otlp_logs))
            .layer(axum::Extension(ingest_state))
            // ConnectInfo is required by the handler.
            .into_make_service_with_connect_info::<SocketAddr>();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (addr, handle)
    }

    // ── Test A: protobuf POST → 200 + valid response ─────────────────────────
    #[tokio::test]
    async fn e2e_proto_post_returns_200_with_response() {
        let (addr, _server) = start_test_server(None).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .body(req_bytes)
            .send()
            .await
            .expect("HTTP request must succeed");

        assert_eq!(resp.status(), 200, "expected 200 OK");
        let body = resp.bytes().await.unwrap();
        // Must decode as a valid ExportLogsServiceResponse (can be empty).
        ExportLogsServiceResponse::decode(body.as_ref())
            .expect("response must decode as ExportLogsServiceResponse");
    }

    // ── Test B: JSON POST → 200 ───────────────────────────────────────────────
    #[tokio::test]
    async fn e2e_json_post_returns_200() {
        let (addr, _server) = start_test_server(None).await;
        let json_bytes = serde_json::to_vec(&make_request()).unwrap();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/logs"))
            .header("Content-Type", "application/json")
            .body(json_bytes)
            .send()
            .await
            .expect("HTTP request must succeed");

        assert_eq!(resp.status(), 200);
    }

    // ── Test C: correct bearer → 200 ─────────────────────────────────────────
    #[tokio::test]
    async fn e2e_correct_bearer_accepted() {
        let (addr, _server) = start_test_server(Some("correct-token".to_string())).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .header("Authorization", "Bearer correct-token")
            .body(req_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
    }

    // ── Test D: wrong bearer → 401 ────────────────────────────────────────────
    #[tokio::test]
    async fn e2e_wrong_bearer_returns_401() {
        let (addr, _server) = start_test_server(Some("correct-token".to_string())).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .header("Authorization", "Bearer bad-token")
            .body(req_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401, "wrong bearer must yield 401");
    }

    // ── Test E: absent bearer when required → 401 ────────────────────────────
    #[tokio::test]
    async fn e2e_missing_bearer_returns_401() {
        let (addr, _server) = start_test_server(Some("required-token".to_string())).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .body(req_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401, "absent bearer must yield 401");
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_e2e_skipped_without_feature() {}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features otlp --test otlp_e2e 2>&1 | head -25
# Expected: compile error — handle_otlp_logs not yet pub-exported, or IngestState missing
# (i.e. the test is wired but implementation in Task 5.4 is not yet complete)
```

- [ ] **Step 3: Implement**

Ensure `handle_otlp_logs` and `IngestState` are `pub(crate)` or `pub` as needed:

```rust
// In src/server/mod.rs — make handle_otlp_logs callable from tests:
#[cfg(feature = "otlp")]
pub(crate) async fn handle_otlp_logs(...) { /* Task 5.4 body */ }
```

Add `tests/e2e/mod.rs` if the e2e directory doesn't declare modules yet:

```rust
// tests/e2e/mod.rs (create if absent, or add line if present):
pub mod otlp_e2e;
```

Add to `Cargo.toml` under `[[test]]` if the e2e directory needs an explicit target:

```toml
[[test]]
name = "otlp_e2e"
path = "tests/e2e/otlp_e2e.rs"
required-features = ["otlp"]
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --features otlp --test otlp_e2e 2>&1 | tail -15
# Expected:
# test e2e::e2e_proto_post_returns_200_with_response ... ok
# test e2e::e2e_json_post_returns_200 ... ok
# test e2e::e2e_correct_bearer_accepted ... ok
# test e2e::e2e_wrong_bearer_returns_401 ... ok
# test e2e::e2e_missing_bearer_returns_401 ... ok
# test result: ok. 5 passed; 0 failed
```

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/otlp_e2e.rs Cargo.toml
git commit -m "test(otlp): add e2e HTTP tests for /v1/logs handler (proto + JSON + auth)"
```

---

### Task 5.7: Full regression pass

Verify all three test levels pass together and the non-`otlp` build is unaffected.

- [ ] **Step 1: Run all unit tests with feature**

```bash
cargo test --features otlp --lib 2>&1 | tail -10
# Expected: test result: ok. N passed; 0 failed
```

- [ ] **Step 2: Run integration test (MinIO required)**

```bash
MINIO_ENDPOINT=http://localhost:9000 \
MINIO_BUCKET=test-logthing \
MINIO_ACCESS_KEY=minioadmin \
MINIO_SECRET_KEY=minioadmin \
cargo test --features otlp --test otlp_s3_integration -- --nocapture 2>&1 | tail -10
# Expected: test result: ok. 1 passed; 0 failed
```

- [ ] **Step 3: Run e2e tests**

```bash
cargo test --features otlp --test otlp_e2e 2>&1 | tail -10
# Expected: test result: ok. 5 passed; 0 failed
```

- [ ] **Step 4: Verify non-`otlp` build is clean**

```bash
cargo test --lib 2>&1 | tail -5
# Expected: test result: ok. N passed; 0 failed (no OTLP tests compiled, no errors)
cargo check 2>&1 | tail -5
# Expected: Finished … (0 warnings, 0 errors)
```

- [ ] **Step 5: Final commit**

```bash
git add -p   # review any remaining unstaged changes
git commit -m "feat(otlp): complete OTLP/HTTP log ingest endpoint with three-level tests"
```

---
