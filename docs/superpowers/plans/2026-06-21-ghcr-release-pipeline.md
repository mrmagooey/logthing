# GHCR Container Release Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically build a multi-arch `logthing` container image and publish it to GHCR whenever a `v*` release tag is pushed.

**Architecture:** A new, self-contained GitHub Actions workflow (`release.yml`) triggers on `v*` tag pushes, builds the existing multi-stage `Dockerfile` for `linux/amd64` + `linux/arm64` via buildx/QEMU, and pushes to `ghcr.io/<owner>/logthing` using the built-in `GITHUB_TOKEN`. A one-line `Dockerfile` fix makes the existing HTTP healthcheck actually runnable.

**Tech Stack:** GitHub Actions, Docker Buildx, QEMU, GHCR, the `docker/*` official actions.

## Global Constraints

- Image name: `ghcr.io/<owner>/logthing` (owner lowercased by metadata-action).
- Trigger only on git tags matching `v*`.
- Architectures: `linux/amd64` and `linux/arm64`.
- Image tags: `{{version}}`, `{{major}}.{{minor}}`, `{{major}}`, and `latest`.
- Auth via built-in `GITHUB_TOKEN` only — no PAT, no repo secret.
- Job permissions: `contents: read`, `packages: write`.
- Do NOT modify the existing `.github/workflows/rust.yml`.
- Pin actions to the major versions named in each task.

---

### Task 1: Fix the Dockerfile healthcheck dependency

**Files:**
- Modify: `Dockerfile:26-28` (runtime stage `apt-get install`)

**Interfaces:**
- Consumes: nothing.
- Produces: a runtime image that contains `wget`, so the existing
  `HEALTHCHECK` on line 43-44 can execute. No interface other tasks depend on.

**Context:** The runtime stage currently installs only `ca-certificates`,
but the `HEALTHCHECK` (line 44) runs `wget ... http://localhost:5985/health`.
`wget` is not present in `debian:bookworm-slim`, so the container always
reports unhealthy. Adding `wget` to the install line fixes it; the
healthcheck command itself is already correct and must not change.

- [ ] **Step 1: Apply the edit**

Change the runtime-stage install block (currently lines 26-28):

```dockerfile
# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
```

to:

```dockerfile
# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*
```

- [ ] **Step 2: Verify the image builds and reports healthy**

Run:

```bash
docker build -t logthing:healthcheck-test .
docker run -d --name lt-hc-test logthing:healthcheck-test
# Wait past the 5s start-period plus one 30s interval, then check status:
sleep 40 && docker inspect --format '{{.State.Health.Status}}' lt-hc-test
docker rm -f lt-hc-test
```

Expected: build succeeds; the inspect command prints `healthy` (not
`unhealthy` or `starting`).

Note: if the local environment cannot run Docker, instead verify the edit
by confirming `wget` now appears in the runtime `apt-get install` line via
`grep -n wget Dockerfile`, and record that the runtime healthcheck check
was deferred to the CI end-to-end tag push (Task 2, Step 4).

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "fix(docker): install wget so the runtime healthcheck works"
```

---

### Task 2: Add the GHCR release workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: the existing `Dockerfile` at the repo root (build context `.`),
  including the Task 1 fix.
- Produces: a published multi-arch image at `ghcr.io/<owner>/logthing`
  tagged per the Global Constraints. No in-repo code depends on this.

- [ ] **Step 1: Create the workflow file**

Create `.github/workflows/release.yml` with exactly this content:

```yaml
name: Release container

on:
  push:
    tags:
      - 'v*'

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository_owner }}/logthing

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract image metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

Notes for the implementer:
- `latest` is emitted automatically by `metadata-action`'s `type=semver`
  patterns for non-prerelease tags; no explicit `type=raw,value=latest`
  line is needed.
- The build reads `Dockerfile` at the context root by default — no
  `file:` key required.

- [ ] **Step 2: Lint the workflow YAML**

Run (install actionlint if available; it catches schema and expression
errors before any push):

```bash
actionlint .github/workflows/release.yml
```

Expected: no output (exit 0). If `actionlint` is not installed, validate
YAML syntax instead:

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml')); print('yaml ok')"
```

Expected: prints `yaml ok`.

- [ ] **Step 3: Verify a multi-arch build succeeds locally (no push)**

Run:

```bash
docker buildx build --platform linux/amd64,linux/arm64 .
```

Expected: both platforms build successfully. (This exercises the same
Dockerfile/buildx path the workflow uses. The arm64 leg is slow under
emulation — this may take many minutes.)

Note: if the local environment cannot run buildx/QEMU, skip this step and
rely on Step 4's real tag-push end-to-end check; record the skip in the
commit/PR description.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build and push multi-arch container to GHCR on release tags"
```

- [ ] **Step 5: End-to-end verification (real tag push)**

After the branch is merged (or on the feature branch if acceptable), push
a throwaway pre-release tag and confirm the pipeline:

```bash
git tag v0.0.0-rc1
git push origin v0.0.0-rc1
```

Expected: the "Release container" workflow runs green; a multi-arch image
appears under the repo's GHCR packages tagged `0.0.0-rc1` (prerelease
tags do not move `latest`). Afterward, clean up:

```bash
git push origin :refs/tags/v0.0.0-rc1   # delete remote tag
git tag -d v0.0.0-rc1                    # delete local tag
# Delete the test package version in the GitHub Packages UI.
```

---

## Self-Review

**1. Spec coverage:**
- Trigger on `v*` tags → Task 2, Step 1 (`on.push.tags`). ✅
- Multi-arch amd64+arm64 → Task 2, Step 1 (`platforms`) + QEMU/Buildx setup. ✅
- Full semver + latest tags → Task 2, Step 1 (`metadata-action` patterns). ✅
- buildx + QEMU (Option A), single job → Task 2. ✅
- `GITHUB_TOKEN` auth, least-privilege permissions → Task 2, Step 1. ✅
- gha layer caching → Task 2, Step 1 (`cache-from`/`cache-to`). ✅
- Separate file, leave `rust.yml` untouched → new `release.yml`, Global Constraints. ✅
- Dockerfile healthcheck fix → Task 1. ✅
- Verification plan (lint, local multi-arch build, healthcheck, e2e tag) → Task 1 Step 2, Task 2 Steps 2/3/5. ✅

**2. Placeholder scan:** No TBD/TODO/"handle edge cases" placeholders; every code step shows full content. ✅

**3. Type consistency:** Image name `ghcr.io/${{ github.repository_owner }}/logthing` is consistent between `env.IMAGE_NAME` and the `metadata-action` `images:` input; `steps.meta` id matches its output references. ✅
