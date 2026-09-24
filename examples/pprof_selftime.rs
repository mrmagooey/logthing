//! Self-time (leaf-sample) breakdown for a captured pprof `profile.pb`.
//!
//! `src/profiling/mod.rs` writes `profile.pb` (raw pprof protobuf) alongside
//! `flamegraph.svg` on every profiling run, but nothing in this repo turned
//! it back into a self-time-by-function table -- the closest prior attempt
//! parsed `flamegraph.svg`'s `<title>` attributes instead, and that
//! extraction script was never committed, so that breakdown could not be
//! regenerated or independently reproduced afterwards. This example closes
//! that gap by reading `profile.pb` directly instead.
//!
//! Per the pprof profile.proto spec, `Sample.location_id[0]` is always the
//! leaf frame (the docs above `pprof::protos::Sample::location_id` in the
//! `pprof` crate say so verbatim), so summing `Sample.value[0]` grouped by
//! that leaf's function name is exactly self-time, not inclusive time --
//! a distinction earlier profiling write-ups had to explain the limits of
//! without this tool available to compute it directly.
//!
//! Requires the crate's `pprof` feature (same one that produces `profile.pb`
//! in the first place):
//!
//! ```text
//! cargo run --release --features pprof --example pprof_selftime -- \
//!     profiling-results/profile.pb
//! ```
#[cfg(not(feature = "pprof"))]
fn main() {
    eprintln!("pprof_selftime requires --features pprof (same feature that produces profile.pb)");
    std::process::exit(1);
}

#[cfg(feature = "pprof")]
fn main() {
    use pprof::protos::{Message, Profile};
    use std::collections::HashMap;

    let path = std::env::args()
        .nth(1)
        .expect("usage: pprof_selftime <profile.pb>");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let profile =
        Profile::parse_from_bytes(&bytes).unwrap_or_else(|e| panic!("parsing {path}: {e}"));

    let string_at = |idx: i64| -> &str {
        profile
            .string_table
            .get(idx as usize)
            .map(String::as_str)
            .unwrap_or("<bad string index>")
    };
    let function_name = |function_id: u64| -> &str {
        profile
            .function
            .iter()
            .find(|f| f.id == function_id)
            .map(|f| string_at(f.name))
            .unwrap_or("<unknown function>")
    };
    // A location's first Line is its own innermost source position; that
    // line's function is the frame's name. (Inlined frames add further
    // Lines on the same Location, but the first is always the leaf-most
    // for that address.)
    let location_name = |location_id: u64| -> &str {
        profile
            .location
            .iter()
            .find(|l| l.id == location_id)
            .and_then(|l| l.line.first())
            .map(|line| function_name(line.function_id))
            .unwrap_or("<unknown location>")
    };

    let mut leaf_samples: HashMap<&str, i64> = HashMap::new();
    let mut total: i64 = 0;
    for sample in &profile.sample {
        let Some(&leaf) = sample.location_id.first() else {
            continue;
        };
        let value = *sample.value.first().unwrap_or(&0);
        *leaf_samples.entry(location_name(leaf)).or_insert(0) += value;
        total += value;
    }

    let mut rows: Vec<(&str, i64)> = leaf_samples.into_iter().collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.1));

    println!("total leaf samples: {total}");
    println!("{:>10}  {:>7}  frame", "samples", "self%");
    for (name, count) in rows {
        let pct = 100.0 * count as f64 / total as f64;
        println!("{count:>10}  {pct:>6.2}%  {name}");
    }
}
