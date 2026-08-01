//! Guards the release container workflow's build topology and cache settings.
//!
//! Two production incidents are encoded here.
//!
//! **v0.9.0** ran the full build and then died with `buildx failed with: ERROR:
//! failed to build: failed to solve: not_found` — a `type=gha` cache blob that
//! went missing mid-build. The repo's 10GB GHA cache budget is shared with
//! rust.yml and binaries.yml, so a `mode=max` export of a Rust build is a prime
//! eviction candidate. release.yml now uses a GHCR registry cache.
//!
//! **The ~2h pipeline.** release.yml used to build `linux/amd64,linux/arm64` on
//! one x86 runner under QEMU, so rustc and every C dependency ran through an
//! instruction interpreter on the arm64 leg. Cold releases took 1.5–2.5h, of
//! which amd64 was ~5min; binaries.yml builds the same aarch64 target in ~6min
//! by cross-compiling instead. The workflow now builds one platform per native
//! runner and merges the digests into a manifest list. The tests below are what
//! stop it silently regressing to emulation — the failure mode is not a broken
//! release but a pipeline that quietly gets twenty times slower again.
//!
//! ## On test levels for this file
//!
//! Stated explicitly rather than skipped silently: **the end-to-end level is not
//! reachable outside CI.** Exercising it means pushing a `v*` tag and letting
//! GitHub schedule a real arm64 runner. Neither incident was locally
//! reproducible; the diagnoses rest on CI annotations and job timings. What is
//! testable below that level is the workflow configuration itself, which is what
//! this file covers.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn release_workflow() -> serde_yml::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yml::from_str(&raw).expect("release.yml is valid YAML")
}

fn job(name: &str) -> serde_yml::Value {
    release_workflow()
        .get("jobs")
        .and_then(|j| j.get(name))
        .cloned()
        .unwrap_or_else(|| panic!("release.yml declares a `{name}` job"))
}

fn steps_of(job_name: &str) -> Vec<serde_yml::Value> {
    job(job_name)
        .get("steps")
        .and_then(|s| s.as_sequence())
        .unwrap_or_else(|| panic!("`{job_name}` job has steps"))
        .clone()
}

/// Every `uses:` value across every job, e.g. `docker/setup-qemu-action@v3`.
fn all_action_uses() -> Vec<String> {
    let workflow = release_workflow();
    let jobs = workflow
        .get("jobs")
        .and_then(|j| j.as_mapping())
        .expect("workflow has jobs");

    jobs.iter()
        .filter_map(|(_, job)| job.get("steps").and_then(|s| s.as_sequence()))
        .flatten()
        .filter_map(|step| step.get("uses").and_then(|u| u.as_str()))
        .map(|u| u.to_string())
        .collect()
}

/// The `with:` block of the build job's docker/build-push-action step.
fn build_push_with() -> serde_yml::Value {
    steps_of("build")
        .into_iter()
        .find(|step| {
            step.get("uses")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u.starts_with("docker/build-push-action"))
        })
        .and_then(|step| step.get("with").cloned())
        .expect("build job has a docker/build-push-action step with a `with:` block")
}

fn build_push_setting(key: &str) -> String {
    build_push_with()
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("build-push-action step sets `{key}`"))
        .trim()
        .to_string()
}

/// The build matrix's (platform, runner) pairs.
fn matrix_platforms() -> Vec<(String, String)> {
    job("build")
        .get("strategy")
        .and_then(|s| s.get("matrix"))
        .and_then(|m| m.get("include"))
        .and_then(|i| i.as_sequence())
        .expect("build job has a matrix.include list")
        .iter()
        .map(|entry| {
            let platform = entry
                .get("platform")
                .and_then(|p| p.as_str())
                .expect("matrix entry has a platform");
            let runner = entry
                .get("runner")
                .and_then(|r| r.as_str())
                .expect("matrix entry has a runner");
            (platform.to_string(), runner.to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Emulation guards — the ~2h regression
// ---------------------------------------------------------------------------

/// QEMU is how the arm64 leg came to take ~2 hours. Nothing should reintroduce
/// it: on native runners it is not merely unnecessary, it is the slow path.
#[test]
fn release_build_does_not_set_up_qemu() {
    let qemu: Vec<String> = all_action_uses()
        .into_iter()
        .filter(|u| u.contains("setup-qemu"))
        .collect();

    assert!(
        qemu.is_empty(),
        "release.yml sets up QEMU ({qemu:?}). Emulating a platform is what made \
         cold releases take 1.5-2.5h instead of minutes. Each platform should \
         build on a runner whose architecture matches it."
    );
}

/// Each matrix leg must build exactly one platform. A comma-separated list on a
/// single runner means at least one platform is emulated.
#[test]
fn each_build_leg_targets_exactly_one_platform() {
    let platforms = build_push_setting("platforms");
    assert!(
        platforms.contains("matrix."),
        "the build step should build the matrix's platform, got {platforms:?}"
    );

    for (platform, _) in matrix_platforms() {
        assert!(
            !platform.contains(','),
            "matrix platform {platform:?} lists more than one platform, so one \
             of them will be emulated on the other's runner"
        );
    }
}

/// The actual invariant behind the speedup: arm64 images build on arm64
/// hardware. Pointing an arm64 platform at an x86 runner silently falls back to
/// emulation and restores the ~2h build.
#[test]
fn every_platform_builds_on_matching_hardware() {
    let platforms = matrix_platforms();
    assert!(!platforms.is_empty(), "build matrix is empty");

    for (platform, runner) in &platforms {
        let wants_arm = platform.contains("arm");
        let runner_is_arm = runner.contains("-arm");
        assert_eq!(
            wants_arm, runner_is_arm,
            "platform {platform:?} is scheduled on runner {runner:?}; an arm64 \
             image must build on an arm64 runner (and vice versa) or the build \
             is emulated"
        );
    }

    // Both architectures we publish must still be covered.
    let names: BTreeSet<&str> = platforms.iter().map(|(p, _)| p.as_str()).collect();
    assert!(
        names.contains("linux/amd64") && names.contains("linux/arm64"),
        "release must publish both linux/amd64 and linux/arm64, got {names:?}"
    );
}

// ---------------------------------------------------------------------------
// Cache guards — the v0.9.0 `not_found`
// ---------------------------------------------------------------------------

#[test]
fn release_build_does_not_use_the_evictable_gha_cache() {
    for key in ["cache-from", "cache-to"] {
        let value = build_push_setting(key);
        assert!(
            !value.contains("type=gha"),
            "release.yml `{key}` is back on the GitHub Actions cache ({value:?}).\n\
             That backend evicted a blob partway through the build and failed \
             the v0.9.0 release with `failed to solve: not_found`.\n\
             Use the GHCR registry cache instead."
        );
        assert!(
            value.contains("type=registry"),
            "release.yml `{key}` should use the GHCR registry cache, got {value:?}"
        );
    }
}

#[test]
fn cache_export_failures_cannot_fail_the_release() {
    let cache_to = build_push_setting("cache-to");
    assert!(
        cache_to.contains("ignore-error=true"),
        "release.yml `cache-to` must set ignore-error=true so a registry cache \
         export problem does not fail an otherwise-good release, got {cache_to:?}"
    );
}

/// The matrix legs run concurrently. A cache ref that does not vary by platform
/// has them overwriting each other's cache manifest every release.
#[test]
fn cache_refs_are_per_platform() {
    for key in ["cache-from", "cache-to"] {
        let value = build_push_setting(key);
        assert!(
            value.contains("steps.slug.outputs.value") || value.contains("matrix."),
            "release.yml `{key}` must vary by platform, or the concurrent amd64 \
             and arm64 legs will clobber each other's cache. Got {value:?}"
        );
    }
}

/// The cache ref must point at the registry the job authenticates against,
/// otherwise the export 401s on every run and silently stops caching.
///
/// Both sides are compared as written, `${{ env.REGISTRY }}` expressions and
/// all, rather than resolved: the point is that the two stay derived from the
/// same source, which is what actually keeps them in sync.
#[test]
fn cache_ref_targets_the_registry_the_job_logs_into() {
    let login_registry = steps_of("build")
        .into_iter()
        .find(|step| {
            step.get("uses")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u.starts_with("docker/login-action"))
        })
        .and_then(|step| step.get("with").and_then(|w| w.get("registry")).cloned())
        .and_then(|r| r.as_str().map(|s| s.trim().to_string()))
        .expect("build job logs into a registry");

    for key in ["cache-from", "cache-to"] {
        let value = build_push_setting(key);
        assert!(
            value.contains(&format!("ref={login_registry}/")),
            "release.yml `{key}` must reference {login_registry}, the registry \
             the job logs into, or the cache export will 401 and silently stop \
             caching. Got {value:?}"
        );
        assert!(
            value.contains(":buildcache"),
            "release.yml `{key}` must use a dedicated :buildcache tag so the \
             cache cannot overwrite a released image tag, got {value:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Manifest-list topology
// ---------------------------------------------------------------------------

/// Only the merge job may apply release tags. If a per-platform leg tagged the
/// image, a half-finished release would publish a tag resolving to a single
/// architecture — worse than failing, because it looks like it worked.
#[test]
fn only_the_merge_job_applies_release_tags() {
    let with = build_push_with();
    assert!(
        with.get("tags").is_none(),
        "the per-platform build step must not apply tags; tagging belongs to the \
         merge job, or a partial release publishes a single-arch tag"
    );

    let outputs = build_push_setting("outputs");
    assert!(
        outputs.contains("push-by-digest=true"),
        "the per-platform build step must push by digest, got {outputs:?}"
    );
    assert!(
        with.get("push").is_none(),
        "`push:` conflicts with the `outputs:` push-by-digest form; the latter \
         already pushes"
    );
}

/// The merge job is what turns the per-platform digests into a released image;
/// without the dependency it could run before or alongside the builds.
#[test]
fn merge_job_waits_for_every_build_leg() {
    let needs = job("merge")
        .get("needs")
        .cloned()
        .expect("merge job declares `needs`");

    let depends_on_build = match &needs {
        serde_yml::Value::String(s) => s == "build",
        serde_yml::Value::Sequence(items) => items.iter().any(|i| i.as_str() == Some("build")),
        other => panic!("unexpected `needs` shape: {other:?}"),
    };

    assert!(
        depends_on_build,
        "merge must depend on the build job, or it can assemble a manifest from \
         missing or stale digests. Got {needs:?}"
    );
}

/// Both jobs push to GHCR, so both need the token scope. A missing scope on the
/// merge job fails only at the very end of a release.
#[test]
fn both_jobs_can_write_to_the_registry() {
    for name in ["build", "merge"] {
        let permissions = job(name)
            .get("permissions")
            .cloned()
            .unwrap_or_else(|| panic!("`{name}` job declares permissions"));

        assert_eq!(
            permissions.get("packages").and_then(|p| p.as_str()),
            Some("write"),
            "`{name}` pushes to GHCR, so it needs `packages: write`"
        );
    }
}
