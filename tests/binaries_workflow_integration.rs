//! Guards `.github/workflows/binaries.yml`: the musl release job must build, assert jemalloc is
//! linked BEFORE `upload-rust-binary-action`, re-check AFTER it, and set the aarch64 jemalloc page
//! size for that matrix entry only. Only the workflow configuration is testable outside CI; the
//! real run is a `workflow_dispatch` dry-run (stated explicitly, not skipped silently).

use std::path::PathBuf;

fn build_steps() -> Vec<serde_yml::Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/binaries.yml");
    let raw = std::fs::read_to_string(&path).expect("read binaries.yml");
    let wf: serde_yml::Value = serde_yml::from_str(&raw).expect("binaries.yml is valid YAML");
    wf.get("jobs")
        .and_then(|j| j.get("build"))
        .and_then(|b| b.get("steps"))
        .and_then(|s| s.as_sequence())
        .expect("build job has steps")
        .clone()
}

fn run_of(step: &serde_yml::Value) -> &str {
    step.get("run").and_then(|r| r.as_str()).unwrap_or("")
}

fn upload_index(steps: &[serde_yml::Value]) -> usize {
    steps
        .iter()
        .position(|s| {
            s.get("uses")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u.starts_with("taiki-e/upload-rust-binary-action"))
        })
        .expect("upload-rust-binary-action step")
}

fn guard_indices(steps: &[serde_yml::Value]) -> Vec<usize> {
    steps
        .iter()
        .enumerate()
        .filter(|(_, s)| run_of(s).contains("scripts/check-jemalloc-symbols.sh"))
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn test_binaries_workflow_guards_before_and_after_upload() {
    let steps = build_steps();
    let up = upload_index(&steps);
    let guards = guard_indices(&steps);
    assert!(
        guards.iter().any(|&i| i < up),
        "no jemalloc guard before the upload action"
    );
    assert!(
        guards.iter().any(|&i| i > up),
        "no jemalloc guard after the upload action"
    );
}

#[test]
fn test_binaries_workflow_guard_builds_with_the_actions_invocation() {
    let steps = build_steps();
    let up = upload_index(&steps);
    let pre = steps[..up]
        .iter()
        .find(|s| run_of(s).contains("cargo zigbuild"))
        .expect("a pre-upload guard build step");
    let expected = "cargo zigbuild --release --target ${{ matrix.target }} --bin logthing";
    assert!(
        run_of(pre).contains(expected),
        "guard build must match the action's invocation: {}",
        run_of(pre)
    );
}

#[test]
fn test_binaries_workflow_needs_no_feature_flag() {
    let steps = build_steps();
    let with = steps[upload_index(&steps)]
        .get("with")
        .expect("upload step has `with`");
    assert!(
        with.get("features").is_none(),
        "musl gets jemalloc via the target dependency"
    );
}

#[test]
fn test_binaries_workflow_sets_lg_page_only_for_aarch64() {
    let steps = build_steps();
    let up = upload_index(&steps);
    let (idx, step) = steps
        .iter()
        .enumerate()
        .find(|(_, s)| run_of(s).contains("JEMALLOC_SYS_WITH_LG_PAGE=16"))
        .expect("a step exporting JEMALLOC_SYS_WITH_LG_PAGE=16");
    let cond = step.get("if").and_then(|c| c.as_str()).unwrap_or("");
    assert!(
        cond.contains("aarch64-unknown-linux-musl"),
        "must be aarch64-only, if: {cond:?}"
    );
    let first_guard = guard_indices(&steps)[0];
    assert!(
        idx < first_guard && idx < up,
        "page size must be exported before any build"
    );
}

#[test]
fn test_binaries_workflow_installs_tools_via_actions_not_pip() {
    let steps = build_steps();
    let build = steps
        .iter()
        .position(|s| run_of(s).contains("cargo zigbuild"))
        .expect("guard build step");
    let uses_before = |prefix: &str| {
        steps[..build].iter().any(|s| {
            s.get("uses")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u.starts_with(prefix))
        })
    };
    assert!(
        uses_before("mlugg/setup-zig@"),
        "zig must be installed by setup-zig"
    );
    assert!(
        uses_before("taiki-e/install-action@"),
        "cargo-zigbuild via install-action"
    );
    assert!(
        !steps.iter().any(|s| run_of(s).contains("pip install")),
        "no pip install steps"
    );
}
