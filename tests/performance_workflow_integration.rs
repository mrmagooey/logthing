//! Guards `.github/workflows/performance.yml`: it must run on every `v*` tag push as well as on
//! demand, and because a tag push carries no workflow inputs, every input use must fall back to the
//! same default as its `workflow_dispatch` input. Only the workflow configuration is testable
//! outside CI; the real run happens on the next tag push or a manual dispatch.

use std::path::PathBuf;

fn workflow() -> (String, serde_yml::Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/performance.yml");
    let raw = std::fs::read_to_string(&path).expect("read performance.yml");
    let wf: serde_yml::Value = serde_yml::from_str(&raw).expect("performance.yml is valid YAML");
    (raw, wf)
}

fn triggers(wf: &serde_yml::Value) -> &serde_yml::Value {
    wf.get("on").expect("performance.yml has an `on:` block")
}

/// `(name, default)` for each `workflow_dispatch` input.
fn dispatch_defaults(wf: &serde_yml::Value) -> Vec<(String, String)> {
    triggers(wf)
        .get("workflow_dispatch")
        .and_then(|d| d.get("inputs"))
        .and_then(|i| i.as_mapping())
        .expect("workflow_dispatch inputs")
        .iter()
        .map(|(k, v)| {
            let name = k.as_str().expect("input name").to_string();
            let default = v
                .get("default")
                .and_then(|d| d.as_str())
                .unwrap_or_else(|| panic!("input `{name}` has a string default"))
                .to_string();
            (name, default)
        })
        .collect()
}

#[test]
fn test_performance_workflow_runs_on_version_tags_and_on_demand() {
    let (_, wf) = workflow();
    let tags: Vec<&str> = triggers(&wf)
        .get("push")
        .and_then(|p| p.get("tags"))
        .and_then(|t| t.as_sequence())
        .expect("performance.yml must trigger on tag pushes")
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    assert_eq!(
        tags,
        ["v*"],
        "tag filter must match release.yml/binaries.yml"
    );
    assert!(
        triggers(&wf)
            .get("push")
            .and_then(|p| p.get("branches"))
            .is_none(),
        "performance.yml must not run on branch pushes"
    );
    assert!(
        !dispatch_defaults(&wf).is_empty(),
        "workflow_dispatch inputs must still be available"
    );
}

#[test]
fn test_performance_workflow_inputs_fall_back_to_dispatch_defaults() {
    let (raw, wf) = workflow();
    assert!(
        !raw.contains("github.event.inputs"),
        "github.event.inputs is empty on a tag push; use `inputs.<name> || '<default>'`"
    );
    let defaults = dispatch_defaults(&wf);
    let expr = regex::Regex::new(r"\$\{\{(.*?)\}\}").unwrap();
    let mut used = Vec::new();
    for cap in expr.captures_iter(&raw) {
        let body = cap[1].trim();
        if !body.contains("inputs.") {
            continue;
        }
        let (name, default) = defaults
            .iter()
            .find(|(n, _)| {
                body.starts_with(&format!("inputs.{n} ")) || body == format!("inputs.{n}")
            })
            .unwrap_or_else(|| panic!("`${{{{ {body} }}}}` reads an unknown input"));
        let canonical = format!("inputs.{name} || '{default}'");
        assert_eq!(
            body, canonical,
            "input use must fall back to the dispatch default (a tag run passes empty inputs)"
        );
        used.push(name.as_str());
    }
    for (name, _) in &defaults {
        assert!(
            used.contains(&name.as_str()),
            "dispatch input `{name}` is never used"
        );
    }
}

fn jobs(wf: &serde_yml::Value) -> &serde_yml::Mapping {
    wf.get("jobs")
        .and_then(|j| j.as_mapping())
        .expect("performance.yml has jobs")
}

#[test]
fn test_performance_workflow_inputs_are_formats_and_duration() {
    let (_, wf) = workflow();
    let mut defaults = dispatch_defaults(&wf);
    defaults.sort();
    assert_eq!(
        defaults,
        [
            ("duration_secs".to_string(), "25".to_string()),
            ("formats".to_string(), "all".to_string()),
        ]
    );
}

#[test]
fn test_performance_workflow_has_ingest_formats_job_not_syslog_baseline() {
    let (raw, wf) = workflow();
    let names: Vec<&str> = jobs(&wf).keys().filter_map(|k| k.as_str()).collect();
    assert!(names.contains(&"criterion"), "jobs: {names:?}");
    assert!(names.contains(&"ingest-formats"), "jobs: {names:?}");
    assert!(
        !names.contains(&"syslog-udp-baseline"),
        "the old syslog-only job must be gone"
    );
    assert!(raw.contains("scripts/profile-ingest.sh"));
    assert!(raw.contains("--features pprof"));
}

#[test]
fn test_performance_jobs_have_timeout_and_always_summary_step() {
    let (_, wf) = workflow();
    for (name, job) in jobs(&wf) {
        let name = name.as_str().unwrap();
        assert!(
            job.get("timeout-minutes").is_some(),
            "job `{name}` needs timeout-minutes"
        );
        let steps = job.get("steps").and_then(|s| s.as_sequence()).unwrap();
        let has_summary = steps.iter().any(|s| {
            s.get("if").and_then(|i| i.as_str()) == Some("always()")
                && s.get("run").and_then(|r| r.as_str()).is_some_and(|r| {
                    r.contains("perf-summary.py") && r.contains("GITHUB_STEP_SUMMARY")
                })
        });
        assert!(
            has_summary,
            "job `{name}` needs an `if: always()` step running perf-summary.py into \
             $GITHUB_STEP_SUMMARY"
        );
    }
}

#[test]
fn test_performance_criterion_summary_reads_the_saved_baseline() {
    let (raw, _) = workflow();
    assert!(raw.contains("--save-baseline ci-${{ github.sha }}"));
    assert!(
        raw.contains("--baseline ci-${{ github.sha }}"),
        "the summary must read the baseline the bench step saved"
    );
}
