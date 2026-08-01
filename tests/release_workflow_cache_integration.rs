//! Guards the release container build cache configuration.
//!
//! The v0.9.0 release ran the full ~2h QEMU-emulated arm64 build and then died
//! with `buildx failed with: ERROR: failed to build: failed to solve: not_found`
//! — a `type=gha` cache blob that went missing mid-build. The repo's 10GB GHA
//! cache budget is shared with rust.yml and binaries.yml, so a `mode=max` export
//! of a multi-arch Rust build is a prime eviction candidate inside a two-hour
//! window. release.yml now uses a GHCR registry cache instead.
//!
//! ## On test levels for this fix
//!
//! Per the project's three-level standard, this is stated explicitly rather than
//! skipped silently: **the end-to-end level is not reachable outside CI.** Truly
//! exercising it means pushing a `v*` tag and letting a 1.5–2.5h multi-arch
//! emulated build run against a GitHub-hosted cache backend, and the original
//! failure was never locally reproducible — the diagnosis rests on the CI
//! annotation plus the timing evidence, which was disclosed as such.
//!
//! What *is* testable below that level, and is tested here, is the workflow
//! configuration itself: that the release job cannot silently regress to the
//! cache backend that caused the outage, and that a cache problem degrades to a
//! slow build rather than a failed release. That is the regression this file
//! exists to catch.

use std::path::PathBuf;

fn release_workflow() -> serde_yml::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yml::from_str(&raw).expect("release.yml is valid YAML")
}

/// The `with:` block of the docker/build-push-action step.
fn build_and_push_with() -> serde_yml::Value {
    let workflow = release_workflow();
    let steps = workflow
        .get("jobs")
        .and_then(|j| j.get("build-and-push"))
        .and_then(|j| j.get("steps"))
        .and_then(|s| s.as_sequence())
        .expect("build-and-push job has steps");

    steps
        .iter()
        .find(|step| {
            step.get("uses")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u.starts_with("docker/build-push-action"))
        })
        .and_then(|step| step.get("with"))
        .cloned()
        .expect("a docker/build-push-action step with a `with:` block")
}

fn cache_setting(key: &str) -> String {
    build_and_push_with()
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("build-push-action step sets `{key}`"))
        .trim()
        .to_string()
}

/// The actual regression guard: `type=gha` is what broke v0.9.0.
#[test]
fn release_build_does_not_use_the_evictable_gha_cache() {
    for key in ["cache-from", "cache-to"] {
        let value = cache_setting(key);
        assert!(
            !value.contains("type=gha"),
            "release.yml `{key}` is back on the GitHub Actions cache ({value:?}).\n\
             That backend evicted a blob partway through the ~2h emulated arm64 \
             build and failed the v0.9.0 release with `failed to solve: not_found`.\n\
             Use the GHCR registry cache instead."
        );
        assert!(
            value.contains("type=registry"),
            "release.yml `{key}` should use the GHCR registry cache, got {value:?}"
        );
    }
}

/// A cache problem must degrade to a slow build, never a failed release.
#[test]
fn cache_export_failures_cannot_fail_the_release() {
    let cache_to = cache_setting("cache-to");
    assert!(
        cache_to.contains("ignore-error=true"),
        "release.yml `cache-to` must set ignore-error=true so a registry cache \
         export problem does not fail an otherwise-good release, got {cache_to:?}"
    );
}

/// The cache ref must point at the registry the job authenticates against,
/// otherwise the export 401s on every run and silently stops caching.
///
/// Both sides are compared as written, `${{ env.REGISTRY }}` expressions and
/// all, rather than resolved: the point is that the two stay derived from the
/// same source, which is what actually keeps them in sync.
#[test]
fn cache_ref_targets_the_registry_the_job_logs_into() {
    let workflow = release_workflow();
    let steps = workflow
        .get("jobs")
        .and_then(|j| j.get("build-and-push"))
        .and_then(|j| j.get("steps"))
        .and_then(|s| s.as_sequence())
        .expect("build-and-push job has steps");

    let login_registry = steps
        .iter()
        .find(|step| {
            step.get("uses")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u.starts_with("docker/login-action"))
        })
        .and_then(|step| step.get("with"))
        .and_then(|w| w.get("registry"))
        .and_then(|r| r.as_str())
        .expect("a docker/login-action step declaring a registry")
        .trim()
        .to_string();

    for key in ["cache-from", "cache-to"] {
        let value = cache_setting(key);
        assert!(
            value.contains(&format!("ref={login_registry}/")),
            "release.yml `{key}` must reference {login_registry}, the registry \
             the job logs into, or the cache export will 401 and silently stop \
             caching. Got {value:?}"
        );
        // A bare `ref=<registry>/<image>` with no tag would collide with the
        // released image tags and overwrite a real release.
        assert!(
            value.contains(":buildcache"),
            "release.yml `{key}` must use a dedicated :buildcache tag so the \
             cache cannot overwrite a released image tag, got {value:?}"
        );
    }
}

/// The job needs `packages: write` for the registry cache export to succeed.
#[test]
fn job_can_write_to_the_registry_cache() {
    let workflow = release_workflow();
    let permissions = workflow
        .get("jobs")
        .and_then(|j| j.get("build-and-push"))
        .and_then(|j| j.get("permissions"))
        .expect("build-and-push declares permissions");

    assert_eq!(
        permissions.get("packages").and_then(|p| p.as_str()),
        Some("write"),
        "the registry cache export writes to GHCR, so the job needs \
         `packages: write`"
    );
}
