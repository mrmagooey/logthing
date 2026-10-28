# Contributing

Build, test, coverage and profiling instructions for working on logthing.

## Build and test

```bash
cargo build            # debug build
cargo test             # unit + integration tests
```

## End-to-end suite

Requires Docker with Compose v2. Builds the helper
images, launches `tests/e2e/simulation-environment/docker-compose.yml`, replays Windows event
fixtures, emits syslog traffic, sends IPFIX flows, emits Zeek NDJSON logs,
verifies throughput counters, and confirms Parquet files arrive in the SeaweedFS
bucket (the compose service is still named `minio`) for each protocol. Containers shut down
automatically once the generators and verifiers exit:

```bash
bash tests/e2e/simulation-environment/run.sh
```

Performance tests are part of that same suite; see
[tests/e2e/simulation-environment/performance-test/README.md](tests/e2e/simulation-environment/performance-test/README.md)
for how to run and interpret them.

## Coverage

Uses [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov):

```bash
rustup component add llvm-tools-preview    # one-time tool install
cargo install cargo-llvm-cov --locked
scripts/run_coverage.sh                    # runs tests with instrumentation
```

Prints a per-file summary and writes it to `target/coverage/summary.txt`, plus an HTML report
(`target/coverage/html/index.html`), `lcov.info` and `cobertura.xml` for CI. Line counts include
inline `#[cfg(test)]` modules, and tests that need Docker (real S3, the test KDC) are skipped unless
their environments are up.

## Profiling

Per-format CPU flame graphs of the ingest path. The sampler is behind the
off-by-default `pprof` cargo feature, so build a profiling binary and the load generator, then
drive each ingest source (syslog, zeek, suricata, ipfix, sflow, hec, generic, otlp, wef) at a
fixed rate into a local-disk Parquet sink:

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo build --profile profiling --features pprof
cargo build --release -p loadgen
scripts/profile-ingest.sh all            # or one or more formats, e.g. zeek ipfix
scripts/profile-ingest.sh --list         # format names; --print-config <fmt> shows the config
```

Results go to `profiling-results/` (gitignored): `index.html` plus, per format,
`flamegraph.svg`, `profile.pb`, `profile-metadata.json`, `loadgen.txt` and `summary.json`
(PASS/FAIL verdict: representative profile, no loadgen errors, loadgen achieved >= 0.9 x offered,
and records written / records loadgen reports sent >= 0.9; `written_ratio` in `summary.json`).
Knobs: `OUT`, `BIN`, `LOADGEN`, `DURATION` (25), `DELAY` (5), `HZ` (99) and `RATE_<FMT>`
(e.g. `RATE_ZEEK=40000`). Logging is forced to `error` and the WEF run is unauthenticated
HTTP (no Kerberos/TLS), so neither cost appears in the profile. Profiling builds
(--features pprof) use the system allocator, not jemalloc. Run `scripts/profile-ingest.sh` with
no arguments for usage.

Default rates were tuned on a 12-vCPU shared host with loadgen on the same machine; on a smaller
host a FAIL usually means the offered rate is too high, so lower `RATE_<FMT>`. A full `all` run
takes about 9 x 50 s. A few percent syslog loss (written/sent below 1.0) is expected on a loaded
host and is real UDP loss, not measurement error. Linux only.

See [AGENTS.md](AGENTS.md) for the full build/test/lint command reference and
repository conventions.
