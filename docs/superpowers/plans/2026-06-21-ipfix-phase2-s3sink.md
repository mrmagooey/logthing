# S3Sink Extraction (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract S3 client construction and `put_object` upload logic from `ParquetS3Forwarder` into a new `S3Sink` struct in `src/forwarding/s3_sink.rs`, then refactor `ParquetS3Forwarder` to delegate to it — with zero observable behavior change.

**Architecture:** A new `S3Sink` struct owns the `aws_sdk_s3::Client` and bucket name; it is constructed via `S3Sink::from_config(&ParquetS3Config)` which performs the identical region/endpoint/credential/`force_path_style` setup currently inlined in `ParquetS3Forwarder::new`. `ParquetS3Forwarder` is updated to hold an `S3Sink` field instead of an `S3Client`, and its `upload_to_s3` method delegates to `S3Sink::upload`. Nothing above `ParquetS3Forwarder` changes: `create_parquet_s3_forwarder`, the server wiring at `src/server/mod.rs:147–179`, the WEF Parquet schema, and all S3 key patterns remain identical.

**Tech Stack:** `aws-sdk-s3`, `aws-config`, `aws-credential-types`, `tokio`, `anyhow`, `tracing`

## Global Constraints

- Rust edition 2024; 100-column line limit; 4-space indentation.
- `cargo fmt` and `cargo clippy -- -D warnings` must pass after every task.
- Error handling via `anyhow::Result`; no `.unwrap()` in non-test production code.
- All tests live in `#[cfg(test)]` modules inside their respective source files.
- Conventional commits: `refactor(forwarding): ...`.
- **CRITICAL — behavior preservation:** WEF Parquet schema (5 Arrow columns: `event_id`, `timestamp`, `source_host`, `subscription_id`, `event_data`), S3 key pattern (`event_type={id}/year={Y}/month={MM}/day={DD}/{filename}`), `force_path_style(true)`, credential fallback logic, and the `local_buffer_path` directory creation must all be byte-for-byte equivalent to the current implementation. Existing tests in `src/forwarding/parquet_s3.rs` must pass without modification.

---

## Task 1 — Create `src/forwarding/s3_sink.rs` with `S3Sink`

**Files:**
- Create: `src/forwarding/s3_sink.rs`
- Modify: `src/forwarding/mod.rs` (add `pub mod s3_sink;`)

**Interfaces — exact public signatures (phases 3 and 4 depend on these verbatim):**

```rust
/// Thin wrapper around an aws_sdk_s3::Client that provides bucket-scoped upload.
pub struct S3Sink {
    client: aws_sdk_s3::Client,
    pub bucket: String,
}

impl S3Sink {
    /// Construct an S3Sink from a ParquetS3Config.
    /// Mirrors the client-construction logic currently in ParquetS3Forwarder::new.
    pub async fn from_config(cfg: &crate::forwarding::parquet_s3::ParquetS3Config) -> anyhow::Result<S3Sink>;

    /// Upload `body` bytes to `key` in the configured bucket.
    /// Mirrors the put_object logic currently in ParquetS3Forwarder::upload_to_s3,
    /// minus the key-generation and file-read (those remain in the caller).
    pub async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;
}
```

**Steps:**

- [ ] **1.1 — Write a failing unit test for `S3Sink::from_config` construction**

  Add the test module to the (not-yet-created) `s3_sink.rs`. Since the existing
  `parquet_s3` tests do not spin up a real MinIO instance (they test config
  parsing and buffer logic only — no live S3 call is made in the test suite),
  mirror that pattern: verify construction succeeds against the same synthetic
  `ParquetS3Config` used by the existing tests, and assert the bucket name is
  stored correctly. No live S3 call; client construction itself is the unit under
  test.

  ```rust
  // src/forwarding/s3_sink.rs  (full file at this point — only the skeleton + test)
  use crate::forwarding::parquet_s3::ParquetS3Config;
  use anyhow::Result;

  pub struct S3Sink {
      client: aws_sdk_s3::Client,
      pub bucket: String,
  }

  impl S3Sink {
      pub async fn from_config(_cfg: &ParquetS3Config) -> Result<Self> {
          todo!()
      }

      pub async fn upload(&self, _key: &str, _body: Vec<u8>) -> Result<()> {
          todo!()
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use std::path::PathBuf;

      fn test_config() -> ParquetS3Config {
          ParquetS3Config {
              endpoint: "http://localhost:9000".to_string(),
              bucket: "test-bucket".to_string(),
              region: "us-east-1".to_string(),
              access_key: "AKIATEST".to_string(),
              secret_key: "SECRETTEST".to_string(),
              max_file_size_mb: 10,
              flush_interval_secs: 60,
              local_buffer_path: PathBuf::from(std::env::temp_dir().join("s3sink-test")),
          }
      }

      #[tokio::test]
      async fn from_config_stores_bucket() {
          let cfg = test_config();
          let sink = S3Sink::from_config(&cfg).await.expect("should construct");
          assert_eq!(sink.bucket, "test-bucket");
      }

      #[tokio::test]
      async fn from_config_empty_credentials_skips_explicit_provider() {
          // When access_key/secret_key are empty the SDK falls back to env-chain.
          // Construction should still succeed (no live network call happens here).
          let mut cfg = test_config();
          cfg.access_key = String::new();
          cfg.secret_key = String::new();
          let sink = S3Sink::from_config(&cfg).await.expect("should construct with empty creds");
          assert_eq!(sink.bucket, "test-bucket");
      }
  }
  ```

- [ ] **1.2 — Run tests; expect compilation failure (`todo!()` is not the issue — the module isn't declared yet)**

  ```
  cargo test -p logthing forwarding::s3_sink 2>&1 | head -30
  ```
  Expected: `error[E0583]: file not found for module 's3_sink'` (or similar). Confirms the test drives the implementation.

- [ ] **1.3 — Declare the module in `src/forwarding/mod.rs`**

  Open `src/forwarding/mod.rs` and add after line 9 (`pub mod parquet_s3;`):

  ```rust
  pub mod s3_sink;
  ```

  Run again:
  ```
  cargo test -p logthing forwarding::s3_sink 2>&1 | head -30
  ```
  Expected: compiles but panics at `todo!()` in `from_config`.

- [ ] **1.4 — Implement `S3Sink::from_config`**

  Replace the `todo!()` stub with the exact logic extracted from
  `ParquetS3Forwarder::new` (lines 180–209 of the current `parquet_s3.rs`).
  The implementation must be identical — same region provider, same conditional
  credentials, same `force_path_style(true)`:

  ```rust
  use crate::forwarding::parquet_s3::ParquetS3Config;
  use anyhow::Result;
  use aws_config::meta::region::RegionProviderChain;
  use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};
  use aws_sdk_s3::Client as S3Client;
  use aws_sdk_s3::config::Builder as S3ConfigBuilder;
  use aws_sdk_s3::primitives::ByteStream;
  use tracing::info;

  pub struct S3Sink {
      client: S3Client,
      pub bucket: String,
  }

  impl S3Sink {
      pub async fn from_config(cfg: &ParquetS3Config) -> Result<Self> {
          let region_provider = RegionProviderChain::first_try(
              aws_sdk_s3::config::Region::new(cfg.region.clone()),
          );

          let credentials_provider =
              if !cfg.access_key.is_empty() && !cfg.secret_key.is_empty() {
                  Some(SharedCredentialsProvider::new(Credentials::new(
                      cfg.access_key.clone(),
                      cfg.secret_key.clone(),
                      None,
                      None,
                      "config",
                  )))
              } else {
                  None
              };

          let sdk_config = aws_config::from_env()
              .region(region_provider)
              .endpoint_url(&cfg.endpoint)
              .load()
              .await;

          let mut s3_conf_builder = S3ConfigBuilder::from(&sdk_config);
          if let Some(provider) = credentials_provider {
              s3_conf_builder = s3_conf_builder.credentials_provider(provider);
          }
          let s3_config = s3_conf_builder.force_path_style(true).build();

          let client = S3Client::from_conf(s3_config);

          info!(
              "S3Sink initialized: bucket={}, endpoint={}",
              cfg.bucket, cfg.endpoint
          );

          Ok(Self {
              client,
              bucket: cfg.bucket.clone(),
          })
      }

      pub async fn upload(&self, _key: &str, _body: Vec<u8>) -> Result<()> {
          todo!()
      }
  }
  ```

- [ ] **1.5 — Run `from_config` tests; expect green**

  ```
  cargo test -p logthing forwarding::s3_sink::tests::from_config 2>&1
  ```
  Both `from_config_stores_bucket` and `from_config_empty_credentials_skips_explicit_provider` must pass.

- [ ] **1.6 — Add a failing unit test for `upload` (construction + error-path only; no live S3)**

  Append to the `#[cfg(test)]` block in `s3_sink.rs`:

  ```rust
  #[tokio::test]
  async fn upload_returns_err_on_unreachable_endpoint() {
      // Uses an endpoint that will refuse the TCP connection immediately so
      // the test does not hang. This exercises the error-handling path of
      // upload without a live MinIO.
      let cfg = ParquetS3Config {
          endpoint: "http://127.0.0.1:1".to_string(), // port 1: always refused
          bucket: "test-bucket".to_string(),
          region: "us-east-1".to_string(),
          access_key: "AKIATEST".to_string(),
          secret_key: "SECRETTEST".to_string(),
          max_file_size_mb: 10,
          flush_interval_secs: 60,
          local_buffer_path: std::env::temp_dir().join("s3sink-upload-test"),
      };
      let sink = S3Sink::from_config(&cfg).await.expect("constructs");
      let result = sink.upload("some/key.parquet", b"hello".to_vec()).await;
      assert!(result.is_err(), "upload to unreachable endpoint must fail");
  }
  ```

  Run:
  ```
  cargo test -p logthing forwarding::s3_sink::tests::upload_returns_err 2>&1
  ```
  Expected: panics at `todo!()`.

- [ ] **1.7 — Implement `S3Sink::upload`**

  Replace the `todo!()` in `upload` with the `put_object` logic extracted from
  `ParquetS3Forwarder::upload_to_s3` (lines 384–419 of the current
  `parquet_s3.rs`), adapted so the caller supplies the already-computed key and
  a `Vec<u8>` body (key generation and file I/O stay in `ParquetS3Forwarder`):

  ```rust
  pub async fn upload(&self, key: &str, body: Vec<u8>) -> Result<()> {
      let byte_stream = ByteStream::from(body);

      self.client
          .put_object()
          .bucket(&self.bucket)
          .key(key)
          .body(byte_stream)
          .content_type("application/octet-stream")
          .send()
          .await
          .map_err(|e| anyhow::anyhow!("S3 put_object failed for key {}: {}", key, e))?;

      info!("Uploaded to S3: s3://{}/{}", self.bucket, key);
      Ok(())
  }
  ```

  Note: The current `upload_to_s3` reads the file with `ByteStream::from_path`.
  After refactoring, `ParquetS3Forwarder::upload_to_s3` will read the file into
  a `Vec<u8>` using `tokio::fs::read` and pass it to `S3Sink::upload`. This
  changes the internal mechanism (path-based stream → in-memory buffer) but not
  the observable S3 object content.

- [ ] **1.8 — Run all s3_sink tests; expect green**

  ```
  cargo test -p logthing forwarding::s3_sink 2>&1
  ```

---

## Task 2 — Refactor `ParquetS3Forwarder` to use `S3Sink`

**Files:**
- Modify: `src/forwarding/parquet_s3.rs`

**Steps:**

- [ ] **2.1 — Confirm existing tests still pass before touching anything**

  ```
  cargo test -p logthing forwarding::parquet_s3 2>&1
  ```
  All three existing tests must be green: `config_parses_destination_headers`,
  `buffered_event_requires_parsed_data`, `event_buffer_flushes_by_size_and_age`.

- [ ] **2.2 — Update `ParquetS3Forwarder` struct definition**

  In `parquet_s3.rs`, replace:

  ```rust
  // Old — lines 171–175
  pub struct ParquetS3Forwarder {
      config: ParquetS3Config,
      s3_client: S3Client,
      buffers: HashMap<u32, EventTypeBuffer>,
  }
  ```

  With:

  ```rust
  pub struct ParquetS3Forwarder {
      config: ParquetS3Config,
      sink: crate::forwarding::s3_sink::S3Sink,
      buffers: HashMap<u32, EventTypeBuffer>,
  }
  ```

- [ ] **2.3 — Update `ParquetS3Forwarder::new` to construct an `S3Sink`**

  Replace the S3 client construction block in `new` (lines 179–223) with a
  delegation to `S3Sink::from_config`. Remove the now-unused imports
  (`RegionProviderChain`, `SharedCredentialsProvider`, `Credentials`,
  `S3Client`, `S3ConfigBuilder`). The directory-creation and logging lines are
  unchanged.

  The new `new` body:

  ```rust
  pub async fn new(config: ParquetS3Config) -> Result<Self> {
      let sink = crate::forwarding::s3_sink::S3Sink::from_config(&config).await?;

      // Ensure buffer directory exists
      tokio::fs::create_dir_all(&config.local_buffer_path).await?;

      info!(
          "ParquetS3Forwarder initialized: bucket={}, endpoint={}, \
           flush_interval={}s, max_size={}MB",
          config.bucket, config.endpoint, config.flush_interval_secs, config.max_file_size_mb
      );

      Ok(Self {
          config,
          sink,
          buffers: HashMap::new(),
      })
  }
  ```

- [ ] **2.4 — Update `upload_to_s3` to delegate to `S3Sink::upload`**

  Replace the current `upload_to_s3` method body (lines 384–420) with a version
  that reads the file to bytes and delegates:

  ```rust
  async fn upload_to_s3(&self, filepath: &PathBuf, event_type: u32) -> Result<()> {
      let filename = filepath
          .file_name()
          .and_then(|n| n.to_str())
          .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

      // Generate S3 key with date partitioning (unchanged from before)
      let now = Utc::now();
      let s3_key = format!(
          "event_type={}/year={}/month={:02}/day={:02}/{}",
          event_type,
          now.year(),
          now.month(),
          now.day(),
          filename
      );

      // Read file into memory and delegate to S3Sink
      let body = tokio::fs::read(filepath).await?;
      self.sink.upload(&s3_key, body).await?;

      info!(
          "Uploaded parquet file to S3: s3://{}/{}",
          self.sink.bucket, s3_key
      );

      Ok(())
  }
  ```

- [ ] **2.5 — Remove now-unused imports from `parquet_s3.rs`**

  Delete the following lines from the import block at the top of `parquet_s3.rs`
  (they are all moved into `s3_sink.rs`):

  ```rust
  use aws_config::meta::region::RegionProviderChain;
  use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
  use aws_sdk_s3::Client as S3Client;
  use aws_sdk_s3::config::Builder as S3ConfigBuilder;
  ```

  `ByteStream` is also no longer used directly in `parquet_s3.rs` — remove it:

  ```rust
  use aws_sdk_s3::primitives::ByteStream;
  ```

  Verify with `cargo clippy -- -D warnings` that no unused-import warnings remain.

- [ ] **2.6 — Run the full forwarding test suite; expect all green**

  ```
  cargo test -p logthing forwarding:: 2>&1
  ```

  This runs both `forwarding::parquet_s3::tests::*` (the three existing tests —
  must be unchanged and green) and `forwarding::s3_sink::tests::*` (the four
  new tests). All must pass.

- [ ] **2.7 — Run `cargo fmt` and `cargo clippy`**

  ```
  cargo fmt --all && cargo clippy -- -D warnings 2>&1
  ```

  Must produce zero warnings or errors.

---

## Task 3 — Integration verification

**Files:** (read-only verification — no new files written)

**Context on existing test approach:** The current `parquet_s3.rs` tests are
pure unit tests — they do not spin up MinIO or make any live S3 call. The
`upload_returns_err_on_unreachable_endpoint` test added in Task 1 is the closest
integration-level coverage available without external infrastructure. True S3
integration tests (against a live MinIO) are intentionally deferred to the E2E
layer (the simulation environment at `tests/e2e/simulation-environment/run.sh`)
and to phase 3/4 writers that will add their own writer-level integration tests.
This is consistent with the existing project approach.

**Steps:**

- [ ] **3.1 — Run the full test suite to confirm no regressions outside forwarding**

  ```
  cargo test -p logthing 2>&1
  ```

  All tests must pass.

- [ ] **3.2 — Verify behavioral equivalence manually (code audit)**

  Confirm by code inspection (diff the before/after of `parquet_s3.rs`) that:
  - The WEF Parquet schema (5 Arrow columns, types, nullability) is unchanged.
  - The S3 key pattern `event_type={id}/year={Y}/month={MM}/day={DD}/{filename}` is unchanged.
  - `force_path_style(true)` is preserved (now in `s3_sink.rs`).
  - The conditional credential-provider logic (skip when access_key or secret_key is empty) is preserved.
  - `content_type("application/octet-stream")` is preserved in `S3Sink::upload`.
  - The `local_buffer_path` `create_dir_all` call still happens in `ParquetS3Forwarder::new`.
  - The `log` messages in `upload_to_s3` preserve the `s3://{bucket}/{key}` format (now referencing `self.sink.bucket`).

- [ ] **3.3 — Commit**

  ```
  git add src/forwarding/s3_sink.rs src/forwarding/mod.rs src/forwarding/parquet_s3.rs
  git commit -m "refactor(forwarding): extract S3Sink from ParquetS3Forwarder

  Move aws_sdk_s3::Client construction (region, endpoint override,
  force_path_style, credential chain) and put_object upload into a new
  S3Sink struct in src/forwarding/s3_sink.rs. ParquetS3Forwarder now
  holds an S3Sink and delegates upload. WEF Parquet schema, S3 key
  pattern, and all externally observable behavior are unchanged."
  ```

---

## Self-Review

### Spec compliance

| Spec requirement | Addressed? |
|---|---|
| New file `src/forwarding/s3_sink.rs` | Task 1 creates it |
| `S3Sink { client, bucket }` struct | Task 1, step 1.4 |
| `async fn from_config(cfg: &ParquetS3Config)` | Task 1, step 1.4 — exact signature |
| `async fn upload(&self, key: &str, body: Vec<u8>)` | Task 1, step 1.7 — exact signature |
| `ParquetS3Forwarder` refactored to hold/use `S3Sink` | Task 2 |
| WEF Parquet schema unchanged | Task 3.2 audit check |
| Existing `parquet_s3` tests stay green | Task 2.6, Task 3.1 |
| Pure refactor — no behavior change | Task 3.2 |

### Placeholder scan

No `todo!()` stubs remain in production paths after Task 1 and Task 2 steps are
complete. Test stubs are replaced before the task's own green-run step.

### Type consistency

- `S3Sink::from_config` accepts `&ParquetS3Config` (confirmed real name from
  `parquet_s3.rs` line 23).
- `S3Sink::upload` accepts `&str` key and `Vec<u8>` body — consistent with
  `ByteStream::from(Vec<u8>)` which is a valid `ByteStream` constructor in the
  `aws-sdk-s3` crate.
- Phase 3 (`SyslogS3Writer`) and phase 4 (`IpfixS3Writer`) can use `S3Sink` by
  calling `S3Sink::from_config` with their own config wrapper or a
  `ParquetS3Config`-equivalent (to be determined in their plans), and then
  `sink.upload(key, bytes)` — both signatures are stable as of this plan.

### WEF behavior unchanged

The five Parquet Arrow columns (`event_id: UInt32`, `timestamp: Utf8`,
`source_host: Utf8`, `subscription_id: Utf8 nullable`, `event_data: Utf8`),
ZSTD level-3 compression, the S3 key template, `force_path_style`, and
`content_type` are all unchanged. The only mechanical difference is that the
file is read with `tokio::fs::read` into a `Vec<u8>` rather than opened as a
`ByteStream::from_path` — the bytes written to S3 are identical.

### Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| S3 is never called in existing tests — `upload` path has no live test coverage at unit level | Low | `upload_returns_err_on_unreachable_endpoint` exercises the error path; the happy path is covered by E2E/simulation environment (unchanged from before this refactor) |
| `ByteStream::from(Vec<u8>)` loads the full Parquet file into memory before upload | Low | Current `ByteStream::from_path` is also fully buffered by the SDK; behavior is equivalent. Acceptable for the file sizes governed by `max_file_size_mb` |
| `self.sink.bucket` reference in the `info!` log line (previously `self.config.bucket`) | Trivial | `S3Sink.bucket` is `pub` and contains the same value; log output is identical |
