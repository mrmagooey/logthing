# Container Image / Releases

The logthing container image is published to GitHub Container Registry on every `v*` tag push:

```bash
docker pull ghcr.io/mrmagooey/logthing:0.26.2   # pin to an exact release
docker pull ghcr.io/mrmagooey/logthing:latest  # most recent non-prerelease release
```

**Tags** (produced by the release workflow for tag `v0.26.2`):
- `:0.26.2` — exact version
- `:0.26` — minor series
- `:0` — major series
- `:latest` — the most recent non-prerelease release. `docker/metadata-action`'s
  default `flavor.latest=auto` adds this automatically for any non-prerelease
  semver tag (a pre-release such as `v0.23.0-rc1` would *not* move `:latest`).

**Platforms**: linux/amd64, linux/arm64 (multi-arch manifest).

**Static binaries**: each release also attaches static musl binaries (linux/amd64, linux/arm64).
Every musl build uses jemalloc as the global allocator (musl's own malloc is much slower under
load), and logs `allocator=jemalloc` at startup. Self-builds get it automatically with
`cargo build --release --target x86_64-unknown-linux-musl`; on a gnu host `--features jemalloc`
enables the same allocator. The binary ships a tuned `malloc_conf` (`background_thread`, 1 s
dirty/muzzy decay); set `_RJEM_MALLOC_CONF` at runtime to override it. The container image is
glibc and keeps the system allocator.

**Exposed ports** (Dockerfile `EXPOSE`): 5986 (HTTPS/TLS; the main server with
`[tls] enabled = true`, the default) or 5985 (plain HTTP, only when TLS is disabled), 9090
(Prometheus metrics).

The runtime listeners (syslog UDP 514/TCP 601, IPFIX UDP 4739) must be published separately via `-p` or the compose `ports:` mapping if they need to be reachable from outside the container.
