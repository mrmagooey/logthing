# Ponytail audit fixes

Spec: the ponytail-audit findings list (2026-08-26), reproduced verbatim inside each task below. Each task = review the finding against current code, then apply it if it holds. If a finding does not hold on inspection, report why instead of forcing the change.

## Global Constraints

- Branch: `ponytail-audit-fixes` (worktree at `/home/dev/projects/logthing-ponytail`). Never commit to master.
- Deletion only — no new features, no new abstractions. The diff's best outcome is getting shorter.
- Every task ends with `cargo check --all-targets` clean and the named test scope passing.
- Do not touch `.codegraph/`, `log/`, `profiling-results/`, `target/`.
- Keep existing code style; do not reformat untouched code.
- Commit per task with a conventional-commits message ending in the required Co-Authored-By/Claude-Session trailer.

## Task 1: Delete stale root files

Findings:
- `delete:` `test_parser.sh` — 38-line echo wrapper around `cargo test --lib parser::tests`, references `config/event_parsers.yaml` which no longer exists (it's a directory now).
- `delete:` root `PARSER_IMPLEMENTATION.md` + `SYSLOG_IMPLEMENTATION.md` — untouched since 2026-02-10 and drifted from reality; `docs/` holds the living design docs.

Steps:
1. Grep the repo (README.md, AGENTS.md, docs/, .github/, Dockerfile, scripts/) for references to each of the three files. Remove any dangling references you find (e.g. a README link).
2. `git rm test_parser.sh PARSER_IMPLEMENTATION.md SYSLOG_IMPLEMENTATION.md`.
3. Verify: `cargo check --all-targets` still clean (nothing should depend on these, prove it).

## Task 2: Delete dead code in ipfix and admin

Findings:
- `delete:` `read_u8` + `read_u64_be`, both `#[allow(dead_code)]` at src/ipfix/decoder.rs:157 and :203. Nothing replaces them.
- `delete:` `create_test_app` at src/admin/mod.rs:674 — `#[allow(dead_code)] // helper retained for future route tests`. Speculative; later can scaffold for itself.
- `yagni:` `AdminTlsConfig.ca_file` + `require_client_cert` dead fields at src/admin/state.rs:202-205 — config nobody reads; client-cert auth doesn't exist.

Steps:
1. For each item, first confirm it is genuinely unused (grep all of src/ tests/ benches/ for the name). If used anywhere, do not delete — report instead.
2. For the `AdminTlsConfig` fields: also remove every construction-site initializer of those fields (grep for `ca_file` / `require_client_cert`), including any config-file plumbing that only exists to populate them. If a config file key feeds them, note the removed key in the commit message body.
3. Verify: `cargo check --all-targets` clean, then `cargo test --lib admin ipfix` (or the nearest matching filter) passes.

## Task 3: Trim Cargo.toml dependencies

Findings:
- `delete:` `hyper = { features = ["full"] }` — zero direct `hyper::` uses anywhere in src/ tests/ benches/; axum owns it transitively.
- `delete:` `tokio-test` dev-dep — zero uses.
- `native:` `tower = { features = ["full"] }` — only `limit` (GlobalConcurrencyLimitLayer) and `util` (`ServiceExt`) are used.

Steps:
1. Confirm zero uses of `hyper::` and `tokio_test` across src/ tests/ benches/ tools/loadgen (check tools/loadgen/Cargo.toml too — it is a separate workspace member and may declare its own deps).
2. Remove `hyper` and `tokio-test` from Cargo.toml. Change `tower` features from `["full"]` to the minimal set that compiles (start with `["limit", "util"]`, add only what `cargo check --all-targets` demands).
3. Verify: `cargo check --all-targets` clean AND `cargo check --all-targets --all-features` clean (features `kerberos-auth`, `pprof`, `otlp` must still build — pprof may need C toolchain; if the pprof feature fails to build for toolchain reasons unrelated to this change, verify with `--features kerberos-auth,otlp` and say so in the report).
4. `cargo test --lib` passes.

## Task 4: Collapse duplicate start/local_start pairs in forwarding

Findings:
- `shrink:` 7 `*_start`/`*_local_start` pairs, each pair identical modulo cfg struct name — both already coerce to `Arc<dyn UploadSink>` for `start_writer` (src/forwarding/buffered_writer.rs:1448). One function per protocol taking `Arc<dyn UploadSink>`. Files: src/forwarding/{suricata,syslog,zeek,ipfix,sflow,parquet,generic}_s3.rs.
- `shrink:` (assess, do not blindly implement) `Multi*Handler` fan-out struct copy-pasted 5× (~20 lines each) across the same files. A `macro_rules!` could collapse them, but only implement if you judge the macro genuinely reduces complexity rather than trading boring duplication for indirection. If you decide against it, say so with one sentence of reasoning — that is a valid outcome.

Steps:
1. Read one pair fully (e.g. `suricata_start` / `suricata_local_start` in src/forwarding/suricata_s3.rs:183-230) plus `start_writer`'s signature, and every call site of all 14 functions (they are called from src/main.rs and possibly tests).
2. Collapse each pair to a single `X_start(cfg_fields..., sink: Arc<dyn UploadSink>, ...)` function. Choose the parameter shape that minimizes total diff — e.g. keep the per-protocol wrapper taking `(prefix, max_buffer_rows, flush_threshold_bytes, flush_interval_secs, channel_capacity)` scalars or a small shared struct if the config types already share those field names via a natural borrow. Do NOT introduce a new trait for config types.
3. Update all call sites in main.rs and tests. Behavior must be identical: same defaults, same DEFAULT_MAX_*_PARTITIONS constants, same metrics.
4. `structured_syslog_s3.rs` has only a single `structured_syslog_start` — leave it alone unless it trivially benefits from the same shape.
5. Verify: `cargo check --all-targets` clean, `cargo test --lib forwarding` (or nearest filter) passes, plus `cargo test --test zeek_local_integration --test sflow_local_integration` if those exercise the local-start paths (check first; skip with a note if they need external services).
