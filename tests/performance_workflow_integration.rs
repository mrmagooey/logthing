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
