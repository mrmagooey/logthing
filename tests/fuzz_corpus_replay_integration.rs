//! Replays every committed fuzz seed and minimized crash input through the
//! same harness the fuzzer uses, on stable, on every `cargo test`. A crash
//! the fuzzer once found fails here if it regresses.

use std::path::Path;

use logthing::fuzz_harness;

type Target = fn(&[u8]) -> usize;

fn targets() -> Vec<(&'static str, Target)> {
    #[cfg_attr(not(feature = "otlp"), allow(unused_mut))]
    let mut t: Vec<(&'static str, Target)> = vec![
        ("ipfix", fuzz_harness::ipfix),
        ("sflow", fuzz_harness::sflow),
        ("syslog", fuzz_harness::syslog),
        ("wef_event", fuzz_harness::wef_event),
        ("wef_envelope", fuzz_harness::wef_envelope),
        ("zeek", fuzz_harness::zeek),
        ("suricata", fuzz_harness::suricata),
        ("hec", fuzz_harness::hec),
    ];
    #[cfg(feature = "otlp")]
    t.push(("otlp", fuzz_harness::otlp));
    t
}

fn files(dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<_> = rd
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    v
}

#[test]
fn test_fuzz_corpus_replay_every_committed_input_runs_clean() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let mut ran = 0;
    for (name, f) in targets() {
        let seeds = files(&root.join("seeds").join(name));
        assert!(!seeds.is_empty(), "no seeds for fuzz target {name}");
        for path in seeds
            .iter()
            .chain(&files(&root.join("regressions").join(name)))
        {
            let bytes = std::fs::read(path).unwrap();
            let r = std::panic::catch_unwind(|| f(&bytes));
            assert!(
                r.is_ok(),
                "fuzz target {name} panicked on {}",
                path.display()
            );
            ran += 1;
        }
    }
    assert!(ran >= 20, "suspiciously few corpus files replayed: {ran}");
}

#[test]
fn test_fuzz_corpus_replay_every_fuzz_target_has_a_shim() {
    // Keeps fuzz/fuzz_targets and this replay list in sync.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    let mut shims: Vec<String> = files(&dir)
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    shims.sort();
    let mut listed: Vec<String> = targets().iter().map(|(n, _)| n.to_string()).collect();
    #[cfg(not(feature = "otlp"))]
    listed.push("otlp".into());
    listed.sort();
    assert_eq!(shims, listed);
}
