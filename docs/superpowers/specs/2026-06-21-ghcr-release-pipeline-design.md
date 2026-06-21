# GHCR Container Release Pipeline — Design

**Date:** 2026-06-21
**Status:** Approved (design), pending implementation plan
**Branch:** `feat/ghcr-release-pipeline`

## Goal

Build a container image for `logthing` and publish it to the GitHub
Container Registry (GHCR) automatically whenever a new release tag is
pushed. The image must be multi-architecture (`linux/amd64` +
`linux/arm64`).

## Scope

In scope:

- A new GitHub Actions workflow that builds and pushes the image to GHCR
  on semver tag pushes.
- A fix to the existing `Dockerfile` healthcheck, which is currently
  broken (calls `wget`, which is not installed in the runtime image).

Out of scope:

- Modernizing the stale `docker-compose.yml` (still references the old
  `wef-server` name and `/etc/wef-server/` paths). Noted for a future
  cleanup; not part of this work.
- Changing the existing CI workflow (`.github/workflows/rust.yml`),
  which continues to build and test on `master` and pull requests.

## Decisions

| Decision | Choice |
|----------|--------|
| Trigger | Pushed git tags matching `v*` (e.g. `v1.2.3`) |
| Architectures | `linux/amd64` + `linux/arm64` (multi-arch manifest) |
| Image tags | Full semver (`1.2.3`, `1.2`, `1`) + `latest` |
| Build strategy | Single job, `buildx` + QEMU emulation (Option A) |
| Authentication | Built-in `GITHUB_TOKEN` (no PAT/secret) |

## Workflow design

**File:** `.github/workflows/release.yml` (new, separate from `rust.yml`).

Keeping the release pipeline in its own file isolates its trigger and
elevated permissions from the existing CI workflow, which keeps working
unchanged.

### Trigger

```yaml
on:
  push:
    tags:
      - 'v*'
```

Tags are normally cut from already-tested `master`, so the workflow's
unit of work is building and publishing the image — it does not re-run
the test suite.

### Permissions (least privilege)

```yaml
permissions:
  contents: read
  packages: write
```

`packages: write` is required to push to GHCR. Authentication uses the
auto-provisioned `GITHUB_TOKEN`; no personal access token or repository
secret needs to be created or managed.

### Job: `build-and-push`

Runs on `ubuntu-latest`. Steps:

1. **Checkout** — `actions/checkout@v4`.
2. **Set up QEMU** — `docker/setup-qemu-action@v3` (enables arm64
   emulation).
3. **Set up Buildx** — `docker/setup-buildx-action@v3` (multi-arch
   builder).
4. **Log in to GHCR** — `docker/login-action@v3` against `ghcr.io`,
   using `${{ github.actor }}` and `${{ secrets.GITHUB_TOKEN }}`.
5. **Extract metadata** — `docker/metadata-action@v5` for image
   `ghcr.io/${{ github.repository_owner }}/logthing`, with the semver
   tag pattern producing `1.2.3`, `1.2`, `1`, and `latest`, plus OCI
   provenance labels.
6. **Build and push** — `docker/build-push-action@v6` with
   `platforms: linux/amd64,linux/arm64`, `push: true`, the tags and
   labels from step 5, and GitHub Actions layer caching
   (`cache-from: type=gha`, `cache-to: type=gha,mode=max`) to reuse the
   heavy Rust dependency compile across releases.

### Image reference

Published as `ghcr.io/<owner>/logthing` (owner is lowercased by
`metadata-action`).

### Image tagging

`docker/metadata-action` `type=semver` patterns:

- `{{version}}` → `1.2.3`
- `{{major}}.{{minor}}` → `1.2`
- `{{major}}` → `1`
- `latest` (on tag builds)

## Dockerfile healthcheck fix

The current runtime stage installs only `ca-certificates`, but the
`HEALTHCHECK` invokes `wget`, which is absent — so the container always
reports unhealthy. Fix: install `wget` in the runtime stage's
`apt-get install` line alongside `ca-certificates`. The existing
healthcheck command (HTTP spider against `http://localhost:5985/health`)
is otherwise correct and stays as-is.

## Trade-off accepted: arm64 build time

`logthing` has a large dependency tree (arrow, parquet, aws-sdk-s3,
rustls, etc.). Building `linux/arm64` under QEMU emulation is slow —
plausibly 30–60+ minutes per release. We accept this for now in
exchange for a simple, infra-free, single-job workflow. GitHub Actions
layer caching reduces the cost of repeat builds. If release latency
becomes a problem, a follow-up can migrate to native per-arch runners
with a manifest-merge step (Option B from brainstorming).

## Testing

CI/CD workflow changes cannot be meaningfully unit/integration/e2e
tested in the repo the way application code can; verification is done
through the pipeline itself:

- **Static validation** — lint the workflow YAML (e.g. `actionlint`) and
  confirm the `Dockerfile` builds locally for the native arch
  (`docker build .`).
- **Multi-arch build check** — locally verify a buildx multi-arch build
  succeeds: `docker buildx build --platform linux/amd64,linux/arm64 .`
  (no push).
- **Healthcheck check** — run the built image and confirm
  `docker inspect` reports the container as `healthy`.
- **End-to-end** — push a throwaway pre-release tag (e.g. `v0.0.0-rc1`)
  and confirm the workflow runs green and the multi-arch image appears
  in GHCR with the expected tags, then delete the test package/tag.

## Files changed

- `.github/workflows/release.yml` — new.
- `Dockerfile` — add `wget` to the runtime stage dependencies.
