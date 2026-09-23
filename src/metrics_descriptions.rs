//! Prometheus `# HELP` text for every metric this crate emits.
//!
//! The exporter already writes a `# TYPE` line for any series it has a
//! recorded sample for, but it only writes `# HELP` for names that were
//! passed to `Recorder::describe_*`. Nothing in the emit paths does that —
//! `counter!`/`gauge!` register a name, not a description — so this module
//! holds the descriptions in one table and [`describe_all`] registers them.
//!
//! `describe_*!` talks to whichever recorder is installed, so `describe_all`
//! must run *after* `metrics::set_global_recorder`. `install_metrics_recorder`
//! (`src/server/mod.rs`) is the single call site and does exactly that.
//! Describing a name that never gets a sample is harmless: `render` walks
//! recorded series and looks the description up, so an undescribed metric
//! loses its HELP line and a described-but-unrecorded one emits nothing.
//!
//! Every name a `counter!`/`gauge!` in `src/` emits must appear here — the
//! `describes_every_metric_emitted_in_src` test greps the tree and fails if
//! a new metric lands without a description.

use metrics::{describe_counter, describe_gauge};

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Counter,
    Gauge,
}

/// UDP listeners that run a `SocketDropStats` poller (`src/net.rs`). Each one
/// emits `<protocol>_socket_drops` and `<protocol>_socket_rx_queue_bytes`
/// under its own name, so the descriptions are generated per protocol.
pub(crate) const SOCKET_POLL_PROTOCOLS: &[&str] = &["syslog_udp", "ipfix", "sflow"];

/// `(kind, name, help)` for every statically-named metric in the crate.
pub(crate) const DESCRIPTIONS: &[(Kind, &str, &str)] = &[
    // ── syslog ────────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "syslog_messages_received",
        "Syslog messages received by the UDP/TCP listeners and handed to the parser.",
    ),
    (
        Kind::Counter,
        "syslog_parse_errors",
        "Syslog messages the parser rejected.",
    ),
    (
        Kind::Counter,
        "syslog_oversized_lines",
        "Syslog TCP lines that exceeded the maximum line length; the connection is closed.",
    ),
    (
        Kind::Counter,
        "syslog_recv_task_failed",
        "Syslog UDP receive tasks that exited with an error.",
    ),
    (
        Kind::Counter,
        "syslog_tcp_connections_rejected",
        "Syslog TCP connections refused because the concurrent-connection limit was reached.",
    ),
    (
        Kind::Counter,
        "syslog_tcp_idle_timeouts",
        "Syslog TCP connections closed after sitting idle past the read timeout.",
    ),
    (
        Kind::Counter,
        "syslog_payload_parsed",
        "Syslog payloads recognised by a structured payload parser, labelled by payload type.",
    ),
    // ── ipfix ─────────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "ipfix_datagrams_received",
        "IPFIX datagrams received by the UDP listener.",
    ),
    (
        Kind::Counter,
        "ipfix_flows_decoded",
        "Flow records successfully decoded from IPFIX data sets.",
    ),
    (
        Kind::Counter,
        "ipfix_decode_errors",
        "IPFIX datagrams that failed to decode.",
    ),
    (
        Kind::Counter,
        "ipfix_recv_task_failed",
        "IPFIX UDP receive tasks that exited with an error.",
    ),
    (
        Kind::Counter,
        "ipfix_templates_received",
        "IPFIX template records received and stored in the template cache.",
    ),
    (
        Kind::Counter,
        "ipfix_templates_missing",
        "IPFIX data sets dropped because no template was cached for their (exporter, observation domain, set id).",
    ),
    (
        Kind::Counter,
        "ipfix_templates_dropped",
        "IPFIX templates not cached because the cache was already at its maximum size.",
    ),
    (
        Kind::Counter,
        "ipfix_templates_evicted",
        "IPFIX templates evicted from the cache after going unused past their TTL.",
    ),
    // ── sflow ─────────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "sflow_datagrams_received",
        "sFlow datagrams received by the UDP listener.",
    ),
    (
        Kind::Counter,
        "sflow_decode_errors",
        "sFlow datagrams that failed to decode.",
    ),
    (
        Kind::Counter,
        "sflow_recv_task_failed",
        "sFlow UDP receive tasks that exited with an error.",
    ),
    (
        Kind::Counter,
        "sflow_unknown_records_dropped",
        "sFlow records discarded because the per-datagram unknown-record budget was exhausted.",
    ),
    // ── zeek ──────────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "zeek_records_received",
        "Zeek records parsed and handed to the forwarding handlers.",
    ),
    (
        Kind::Counter,
        "zeek_records_by_path",
        "Zeek records received, labelled by Zeek log path (label set is capped).",
    ),
    (
        Kind::Counter,
        "zeek_parse_errors",
        "Zeek lines that failed to parse as a record.",
    ),
    (
        Kind::Counter,
        "zeek_missing_path",
        "Zeek records dropped because the JSON carried no usable log path.",
    ),
    (
        Kind::Counter,
        "zeek_oversized_lines",
        "Zeek TCP lines that exceeded the maximum line length; the connection is closed.",
    ),
    (
        Kind::Counter,
        "zeek_tcp_budget_exhausted",
        "Zeek TCP connections closed because the aggregate line-buffer memory budget was exhausted.",
    ),
    (
        Kind::Counter,
        "zeek_tcp_connections_rejected",
        "Zeek TCP connections refused because the concurrent-connection limit was reached.",
    ),
    (
        Kind::Counter,
        "zeek_tcp_idle_timeouts",
        "Zeek TCP connections closed after sitting idle past the read timeout.",
    ),
    // ── suricata ──────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "suricata_records_received",
        "Suricata EVE records parsed and handed to the forwarding handlers.",
    ),
    (
        Kind::Counter,
        "suricata_records_by_event_type",
        "Suricata records received, labelled by EVE event type (label set is capped).",
    ),
    (
        Kind::Counter,
        "suricata_parse_errors",
        "Suricata lines that failed to parse as an EVE record.",
    ),
    (
        Kind::Counter,
        "suricata_missing_event_type",
        "Suricata records dropped because the JSON carried no event type.",
    ),
    (
        Kind::Counter,
        "suricata_oversized_lines",
        "Suricata TCP lines that exceeded the maximum line length; the connection is closed.",
    ),
    (
        Kind::Counter,
        "suricata_tcp_budget_exhausted",
        "Suricata TCP connections closed because the aggregate line-buffer memory budget was exhausted.",
    ),
    (
        Kind::Counter,
        "suricata_tcp_connections_rejected",
        "Suricata TCP connections refused because the concurrent-connection limit was reached.",
    ),
    (
        Kind::Counter,
        "suricata_tcp_idle_timeouts",
        "Suricata TCP connections closed after sitting idle past the read timeout.",
    ),
    // ── HTTP ingest ───────────────────────────────────────────────────────
    (
        Kind::Counter,
        "hec_events_received",
        "Splunk HEC events accepted by the collector endpoint.",
    ),
    (
        Kind::Counter,
        "hec_events_dropped",
        "HEC events dropped because a forwarding channel was full or closed.",
    ),
    (
        Kind::Counter,
        "hec_parse_errors",
        "HEC request bodies that failed to parse.",
    ),
    (
        Kind::Counter,
        "hec_auth_failures",
        "HEC requests rejected for a missing or incorrect token.",
    ),
    (
        Kind::Counter,
        "otlp_logs_received",
        "OTLP log records accepted by the logs endpoint.",
    ),
    (
        Kind::Counter,
        "otlp_auth_failures",
        "OTLP requests rejected for a missing or incorrect token.",
    ),
    (
        Kind::Counter,
        "body_budget_exhausted",
        "HTTP requests rejected because the in-flight request-body memory budget was exhausted.",
    ),
    // ── wef ───────────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "wef_xml_parse_errors",
        "WEF batches whose XML failed to parse; the unparsed remainder is kept as one raw event.",
    ),
    // ── listener access control ───────────────────────────────────────────
    (
        Kind::Counter,
        "listener_source_rejected",
        "Inbound datagrams or connections rejected because the source IP is not in the listener whitelist, labelled by protocol.",
    ),
    // ── stats ─────────────────────────────────────────────────────────────
    (
        Kind::Counter,
        "throughput_event_types_capped",
        "Throughput-stats updates folded into the `_other` bucket because the event-type cardinality cap was reached.",
    ),
    // ── parquet/S3 forwarding ─────────────────────────────────────────────
    (
        Kind::Counter,
        "parquet_s3_records_written",
        "Records durably written, counted when the Parquet object containing them uploads successfully.",
    ),
    (
        Kind::Counter,
        "parquet_s3_uploads",
        "Parquet objects uploaded successfully.",
    ),
    (
        Kind::Counter,
        "parquet_s3_upload_errors",
        "Parquet object uploads that returned an error.",
    ),
    (
        Kind::Counter,
        "parquet_s3_dropped",
        "Records dropped on the way to the writer task because its channel was full or closed.",
    ),
    (
        Kind::Counter,
        "parquet_s3_records_skipped",
        "Records the writer could not convert into its buffer's schema and skipped.",
    ),
    (
        Kind::Counter,
        "parquet_s3_buffer_dropped",
        "Buffered rows discarded to bring the writer's in-memory buffer back under its byte budget.",
    ),
    (
        Kind::Counter,
        "parquet_s3_partitions_capped",
        "Records routed to the `_overflow` partition because the per-writer partition cap was reached.",
    ),
    (
        Kind::Gauge,
        "parquet_s3_buffer_rows",
        "Rows currently buffered in memory, per partition.",
    ),
    (
        Kind::Gauge,
        "parquet_s3_channel_queued",
        "Records currently queued in the writer task's channel.",
    ),
    (
        Kind::Gauge,
        "parquet_s3_channel_available",
        "Remaining free capacity in the writer task's channel.",
    ),
    (
        Kind::Gauge,
        "parquet_s3_flushes_in_flight",
        "Buffer flushes currently uploading.",
    ),
    (
        Kind::Counter,
        "iceberg_descriptor_uploads",
        "Iceberg descriptor objects uploaded alongside a Parquet object.",
    ),
    (
        Kind::Counter,
        "iceberg_descriptor_upload_errors",
        "Iceberg descriptor uploads that returned an error.",
    ),
    // ── aggregation ───────────────────────────────────────────────────────
    (
        Kind::Counter,
        "aggregate_records_consumed",
        "Records fed into an aggregation rule, labelled by rule.",
    ),
    (
        Kind::Counter,
        "aggregate_rows_emitted",
        "Aggregated rows emitted downstream when a window closed, labelled by rule.",
    ),
    (
        Kind::Counter,
        "aggregate_overflow_records",
        "Records folded into the rule's overflow group because it was already at max_groups.",
    ),
    (
        Kind::Gauge,
        "aggregate_groups",
        "Groups present in the most recently closed window, labelled by rule.",
    ),
    // ── field cardinality watch ──────────────────────────────────────────
    (
        Kind::Gauge,
        "field_distinct_values",
        "Distinct values of a watched field (metrics.cardinality_watch) in the most recently \
         completed window, labelled by source/stream/field — a count of wire values (e.g. IPs \
         or hostnames), not a stable host identity: DHCP churn, NAT, and external traffic can \
         move it independently of ingestion health. A value pinned at cardinality_max_values \
         means the cap was hit; check field_distinct_values_capped rather than trusting the \
         number as-is. Prefer alerting on a sustained multi-window drop over exact equality to \
         a known host count.",
    ),
    (
        Kind::Counter,
        "field_distinct_values_capped",
        "Distinct values of a watched field discarded because cardinality_max_values was \
         already reached, labelled by source/stream/field — non-zero here means \
         field_distinct_values is undercounting the true cardinality.",
    ),
];

/// Register `# HELP` text for every metric the crate emits.
///
/// Must be called after the recorder is installed; see the module docs.
pub fn describe_all() {
    for (kind, name, help) in DESCRIPTIONS {
        match kind {
            Kind::Counter => describe_counter!(*name, *help),
            Kind::Gauge => describe_gauge!(*name, *help),
        }
    }

    for protocol in SOCKET_POLL_PROTOCOLS {
        describe_counter!(
            format!("{protocol}_socket_drops"),
            format!(
                "Datagrams the kernel discarded on the {protocol} listener socket, read from /proc/net/udp."
            )
        );
        describe_gauge!(
            format!("{protocol}_socket_rx_queue_bytes"),
            format!("Bytes currently queued in the {protocol} listener socket's receive buffer.")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::collections::HashSet;

    /// Every `counter!("x")` / `gauge!("x")` literal under `src/`, so a new
    /// metric added without a description fails here rather than silently
    /// shipping a HELP-less series.
    fn emitted_metric_names() -> HashSet<String> {
        fn walk(dir: &std::path::Path, out: &mut HashSet<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path
                    .file_name()
                    .is_some_and(|f| f == "metrics_descriptions.rs")
                {
                    // This file's own doc comments and tests mention metric
                    // macros; scanning it would feed the scraper its own noise.
                    continue;
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let src = std::fs::read_to_string(&path).unwrap();
                    for macro_name in ["counter!(\"", "gauge!(\""] {
                        for (idx, _) in src.match_indices(macro_name) {
                            let rest = &src[idx + macro_name.len()..];
                            if let Some(end) = rest.find('"') {
                                out.insert(rest[..end].to_string());
                            }
                        }
                    }
                }
            }
        }

        let mut names = HashSet::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut names,
        );
        names
    }

    #[test]
    fn describes_every_metric_emitted_in_src() {
        let described: HashSet<&str> = DESCRIPTIONS.iter().map(|(_, name, _)| *name).collect();
        let emitted = emitted_metric_names();

        // Sanity check the scraper itself before trusting its verdict.
        assert!(
            emitted.contains("syslog_messages_received"),
            "source scan found no metrics at all — the scraper is broken, not the table"
        );

        let missing: Vec<&String> = emitted
            .iter()
            .filter(|name| !described.contains(name.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "metrics emitted in src/ with no entry in DESCRIPTIONS: {missing:?}"
        );
    }

    #[test]
    fn stale_descriptions_do_not_accumulate() {
        let emitted = emitted_metric_names();
        let stale: Vec<&str> = DESCRIPTIONS
            .iter()
            .map(|(_, name, _)| *name)
            .filter(|name| !emitted.contains(*name))
            .collect();
        assert!(
            stale.is_empty(),
            "DESCRIPTIONS entries for metrics nothing in src/ emits: {stale:?}"
        );
    }

    #[test]
    fn descriptions_reach_the_prometheus_exposition() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            describe_all();
            // Only recorded series are rendered, so emit one of each kind
            // plus one of the per-protocol socket metrics.
            metrics::counter!("syslog_messages_received").increment(1);
            metrics::gauge!("parquet_s3_flushes_in_flight", "source" => "syslog", "target" => "s3")
                .set(1.0);
            metrics::counter!("ipfix_socket_drops").increment(1);
        });

        let rendered = handle.render();

        assert!(
            rendered.contains(
                "# HELP syslog_messages_received Syslog messages received by the UDP/TCP listeners"
            ),
            "counter HELP line missing:\n{rendered}"
        );
        assert!(
            rendered.contains("# TYPE syslog_messages_received counter"),
            "counter TYPE line missing:\n{rendered}"
        );
        assert!(
            rendered.contains("# HELP parquet_s3_flushes_in_flight"),
            "gauge HELP line missing:\n{rendered}"
        );
        assert!(
            rendered.contains("# TYPE parquet_s3_flushes_in_flight gauge"),
            "gauge TYPE line missing:\n{rendered}"
        );
        assert!(
            rendered.contains("# HELP ipfix_socket_drops"),
            "per-protocol socket HELP line missing:\n{rendered}"
        );
    }
}
