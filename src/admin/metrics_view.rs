//! Turns `PrometheusHandle::render()` text into the admin console's metrics
//! page.
//!
//! Pure functions only — the handler (`crate::admin::routes::get_metrics`)
//! owns the I/O. Kept out of `routes.rs` because that file is already large
//! and because a parser is the part worth unit-testing directly.

use std::collections::BTreeMap;

use quick_xml::escape::escape;

use crate::config::CardinalityWatch;

/// One series: a metric name, the verbatim `{...}` label text from the
/// exposition line (empty when unlabelled), and the verbatim value text.
///
/// The value is kept as text rather than parsed into an `f64`: the exporter
/// already decided how to format it, and a round-trip through a float would
/// only introduce a way for the page to disagree with `/metrics`.
pub(crate) struct Sample {
    pub(crate) name: String,
    pub(crate) labels: String,
    pub(crate) value: String,
}

/// Every series sharing one metric name, plus that name's `# HELP` text when
/// the recorder has one (`crate::metrics_descriptions` registers them).
pub(crate) struct MetricGroup {
    pub(crate) name: String,
    pub(crate) help: Option<String>,
    pub(crate) samples: Vec<Sample>,
}

/// Parse Prometheus text exposition into name-grouped series.
///
/// Line handling mirrors the existing `crate::profiling::parse_counter`:
/// split on the LAST space (label values may contain spaces, the value may
/// not), then split the key at the first `{`. `# HELP` feeds the help map;
/// `# TYPE` is ignored — the page shows no type column, and every metric this
/// crate emits is a counter or a gauge anyway (`metrics_descriptions::Kind`).
///
/// Unparseable lines are skipped rather than propagated as an error: this
/// feeds an observability page, and a page missing one row beats a page that
/// returns 500 because the exporter emitted something unexpected.
pub(crate) fn parse_exposition(rendered: &str) -> Vec<MetricGroup> {
    let mut help: BTreeMap<&str, &str> = BTreeMap::new();
    let mut samples: BTreeMap<String, Vec<Sample>> = BTreeMap::new();

    for line in rendered.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("# HELP ") {
            if let Some((name, text)) = rest.split_once(' ') {
                help.insert(name, text);
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.rsplit_once(' ') else {
            continue;
        };
        // A sample line's value is a single number. Anything else is a line
        // shape this parser does not know, which is skipped, not guessed at.
        if value.trim().parse::<f64>().is_err() {
            continue;
        }
        let (name, labels) = match key.split_once('{') {
            Some((name, labels)) => (name, format!("{{{labels}")),
            None => (key, String::new()),
        };
        if name.is_empty() || name.contains(' ') {
            continue;
        }
        samples.entry(name.to_string()).or_default().push(Sample {
            name: name.to_string(),
            labels,
            value: value.trim().to_string(),
        });
    }

    samples
        .into_iter()
        .map(|(name, mut samples)| {
            samples.sort_by(|a, b| a.labels.cmp(&b.labels));
            MetricGroup {
                help: help.get(name.as_str()).map(|h| h.to_string()),
                name,
                samples,
            }
        })
        .collect()
}

/// Total series across all groups — what an operator means by "how many
/// metrics am I looking at", and a cheap sanity number for label growth.
pub(crate) fn series_count(groups: &[MetricGroup]) -> usize {
    groups.iter().map(|g| g.samples.len()).sum()
}

/// One table, one `<tbody>` per metric: the name and HELP text sit in
/// `rowspan` cells so they are stated once per metric instead of repeated on
/// every series.
///
/// Everything interpolated here is escaped with `quick_xml::escape::escape`,
/// the same helper `admin_page` uses for `{{CONFIG_TOML}}`. Label values are
/// partly derived from network input, so this is a trust boundary.
pub(crate) fn render_groups_html(groups: &[MetricGroup]) -> String {
    let mut out = String::new();
    for group in groups {
        let span = group.samples.len().max(1);
        for (i, sample) in group.samples.iter().enumerate() {
            out.push_str("<tr>");
            if i == 0 {
                out.push_str(&format!(
                    "<td rowspan=\"{span}\"><code>{}</code></td>\
                     <td rowspan=\"{span}\" class=\"help\">{}</td>",
                    escape(&sample.name),
                    escape(group.help.as_deref().unwrap_or("")),
                ));
            }
            out.push_str(&format!(
                "<td><code>{}</code></td><td>{}</td></tr>",
                escape(&sample.labels),
                escape(&sample.value),
            ));
        }
    }
    out
}

/// Does this series' label text name exactly this watch's triple?
///
/// Substring matching on `key="value"` rather than a full label parse: the
/// exporter's label order is not part of its contract, and the opening quote
/// anchors each match so one watch's `field` cannot match another's longer
/// one (`field="host"` does not occur inside `field="my_host"`).
fn labels_match(labels: &str, watch: &CardinalityWatch) -> bool {
    [
        format!("source=\"{}\"", watch.source),
        format!("stream=\"{}\"", watch.stream),
        format!("field=\"{}\"", watch.field),
    ]
    .iter()
    .all(|needle| labels.contains(needle.as_str()))
}

fn find_value<'a>(
    groups: &'a [MetricGroup],
    name: &str,
    watch: &CardinalityWatch,
) -> Option<&'a str> {
    groups
        .iter()
        .find(|g| g.name == name)?
        .samples
        .iter()
        .find(|s| labels_match(&s.labels, watch))
        .map(|s| s.value.as_str())
}

/// Rows for the configured `[[metrics.cardinality_watch]]` entries, joined
/// against the `field_distinct_values` samples that are actually present.
///
/// The "awaiting first window" state is the reason this section exists at all
/// rather than leaving `field_distinct_values` to the generic table:
/// `CardinalityWatcher::tick` publishes only at a window boundary, so for up
/// to `window_secs` after start a perfectly healthy watch has no series — and
/// an operator reading a table it is missing from concludes their config did
/// not take.
pub(crate) fn render_cardinality_html(
    watches: &[CardinalityWatch],
    groups: &[MetricGroup],
    window_secs: u64,
) -> String {
    if watches.is_empty() {
        return "<tr><td colspan=\"5\" class=\"help\">No cardinality watches are \
                configured. Add one or more <code>[[metrics.cardinality_watch]]</code> \
                entries to <code>logthing.toml</code> to count distinct values of a \
                field.</td></tr>"
            .to_string();
    }

    watches
        .iter()
        .map(|watch| {
            let distinct = find_value(groups, "field_distinct_values", watch)
                .map(|v| escape(v).to_string())
                .unwrap_or_else(|| {
                    format!("<span class=\"help\">awaiting first window ({window_secs}s)</span>")
                });
            let capped = find_value(groups, "field_distinct_values_capped", watch)
                .map(|v| escape(v).to_string())
                .unwrap_or_else(|| "—".to_string());
            format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                escape(&watch.source),
                escape(&watch.stream),
                escape(&watch.field),
                distinct,
                capped,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CardinalityWatch;

    /// Real exposition text: HELP before TYPE, a labelled series, an
    /// unlabelled series, a metric with no HELP at all, and a junk line.
    const SAMPLE: &str = "\
# HELP syslog_messages_received Syslog messages received by the listeners.
# TYPE syslog_messages_received counter
syslog_messages_received 42

# TYPE undescribed_gauge gauge
undescribed_gauge{source=\"zeek\"} 7
undescribed_gauge{source=\"wef\"} 3

this line is not a sample
";

    #[test]
    fn parse_exposition_groups_by_name_and_keeps_help() {
        let groups = parse_exposition(SAMPLE);
        assert_eq!(
            groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
            vec!["syslog_messages_received", "undescribed_gauge"],
            "groups must come back sorted by metric name"
        );
        assert_eq!(
            groups[0].help.as_deref(),
            Some("Syslog messages received by the listeners."),
        );
        assert_eq!(
            groups[1].help, None,
            "a metric with no HELP line has no help"
        );
    }

    #[test]
    fn parse_exposition_splits_labels_from_name_and_value() {
        let groups = parse_exposition(SAMPLE);
        let unlabelled = &groups[0].samples[0];
        assert_eq!(unlabelled.labels, "");
        assert_eq!(unlabelled.value, "42");

        let labelled = &groups[1].samples;
        assert_eq!(labelled.len(), 2);
        assert_eq!(
            labelled[0].labels, "{source=\"wef\"}",
            "samples sort by label text"
        );
        assert_eq!(labelled[0].value, "3");
        assert_eq!(labelled[1].labels, "{source=\"zeek\"}");
        assert_eq!(labelled[1].value, "7");
    }

    /// A malformed line must never be fatal: a metrics page that 500s is
    /// worse than one missing a row.
    #[test]
    fn parse_exposition_skips_junk_and_handles_empty_input() {
        let groups = parse_exposition(SAMPLE);
        assert!(
            !groups.iter().any(|g| g.name.contains(' ')),
            "the junk line must not have become a metric: {:?}",
            groups.iter().map(|g| &g.name).collect::<Vec<_>>()
        );
        assert!(parse_exposition("").is_empty());
        assert!(parse_exposition("# HELP lonely_help no samples for this one\n").is_empty());
    }

    #[test]
    fn series_count_counts_samples_not_metric_names() {
        assert_eq!(series_count(&parse_exposition(SAMPLE)), 3);
    }

    /// Label values are partly wire-derived, and this page interpolates them
    /// into server-rendered HTML. Anything that reaches the browser as raw
    /// markup is a stored-XSS bug in an authenticated console.
    #[test]
    fn render_groups_html_escapes_hostile_label_values() {
        let hostile = "field_distinct_values{stream=\"<img src=x onerror=alert(1)>\"} 1\n";
        let html = render_groups_html(&parse_exposition(hostile));
        assert!(
            !html.contains("<img"),
            "hostile label reached the page as raw markup:\n{html}"
        );
        assert!(
            html.contains("&lt;img"),
            "hostile label should appear escaped:\n{html}"
        );
    }

    #[test]
    fn render_groups_html_states_help_once_per_metric() {
        let html = render_groups_html(&parse_exposition(SAMPLE));
        assert_eq!(
            html.matches("Syslog messages received by the listeners.")
                .count(),
            1,
            "HELP text belongs in one rowspan cell, not repeated per series"
        );
        assert!(
            html.contains("rowspan=\"2\""),
            "the 2-series metric groups its rows:\n{html}"
        );
    }

    fn watch(source: &str, stream: &str, field: &str) -> CardinalityWatch {
        CardinalityWatch {
            source: source.to_string(),
            stream: stream.to_string(),
            field: field.to_string(),
        }
    }

    #[test]
    fn render_cardinality_html_shows_the_count_and_the_capped_total() {
        let rendered = "\
field_distinct_values{field=\"id.orig_h\",source=\"zeek\",stream=\"conn\"} 4823
field_distinct_values_capped{field=\"id.orig_h\",source=\"zeek\",stream=\"conn\"} 0
";
        let html = render_cardinality_html(
            &[watch("zeek", "conn", "id.orig_h")],
            &parse_exposition(rendered),
            3600,
        );
        assert!(html.contains("id.orig_h"), "{html}");
        assert!(html.contains("4823"), "{html}");
        assert!(
            !html.contains("awaiting"),
            "a sampled watch is not awaiting anything:\n{html}"
        );
    }

    /// `CardinalityWatcher::tick` only publishes at a window boundary, so a
    /// correctly configured watch is genuinely absent from the exposition for
    /// up to `cardinality_window_secs` after boot. That must not read as a
    /// missing or broken watch.
    #[test]
    fn render_cardinality_html_marks_an_unsampled_watch_as_awaiting_its_first_window() {
        let html = render_cardinality_html(&[watch("wef", "Security", "computer")], &[], 3600);
        assert!(html.contains("computer"), "{html}");
        assert!(html.contains("awaiting first window"), "{html}");
        assert!(
            html.contains("3600"),
            "the window length tells the operator how long to wait:\n{html}"
        );
    }

    #[test]
    fn render_cardinality_html_explains_itself_when_no_watches_are_configured() {
        let html = render_cardinality_html(&[], &[], 3600);
        assert!(
            html.to_lowercase().contains("no"),
            "an empty section must say the feature is off, not render blank:\n{html}"
        );
    }

    /// A watch's field name that is a suffix of another's must not match it.
    #[test]
    fn render_cardinality_html_does_not_confuse_one_watch_for_another() {
        let rendered =
            "field_distinct_values{field=\"my_host\",source=\"syslog\",stream=\"sshd\"} 9\n";
        let html = render_cardinality_html(
            &[watch("syslog", "sshd", "host")],
            &parse_exposition(rendered),
            600,
        );
        assert!(
            html.contains("awaiting first window"),
            "field=\"host\" must not match field=\"my_host\":\n{html}"
        );
    }
}
