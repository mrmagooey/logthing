//! Decorator handlers: count a record and swallow it, or pass it through.
//!
//! These wrap each source's existing handler chain rather than sitting beside
//! it — suppression requires being upstream of the raw writer.

use std::net::SocketAddr;
use std::sync::Arc;

use super::Aggregator;

/// Zeek: single record per call.
pub struct AggregatingZeekHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::zeek::listener::ZeekHandler>,
}

#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler for AggregatingZeekHandler {
    async fn handle_record(&self, record: crate::zeek::ZeekRecord, source: SocketAddr) {
        if self.agg.consume("zeek", &record) {
            return;
        }
        self.inner.handle_record(record, source).await;
    }
}

/// Suricata: single record per call.
pub struct AggregatingSuricataHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::suricata::listener::SuricataHandler>,
}

#[async_trait::async_trait]
impl crate::suricata::listener::SuricataHandler for AggregatingSuricataHandler {
    async fn handle_record(&self, record: crate::suricata::SuricataRecord, source: SocketAddr) {
        if self.agg.consume("suricata", &record) {
            return;
        }
        self.inner.handle_record(record, source).await;
    }
}

/// Syslog: single message per call.
pub struct AggregatingSyslogHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::syslog::listener::SyslogHandler>,
}

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler for AggregatingSyslogHandler {
    async fn handle_message(&self, message: crate::syslog::SyslogMessage, source: SocketAddr) {
        if self.agg.consume("syslog", &message) {
            return;
        }
        self.inner.handle_message(message, source).await;
    }
}

/// IPFIX: a batch per call — forward only the unmatched remainder.
pub struct AggregatingIpfixHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::ipfix::listener::IpfixHandler>,
}

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler for AggregatingIpfixHandler {
    async fn handle_flows(&self, flows: Vec<crate::ipfix::FlowRecord>, source: SocketAddr) {
        let remainder: Vec<_> = flows
            .into_iter()
            .filter(|f| !self.agg.consume("ipfix", f))
            .collect();
        if remainder.is_empty() {
            return;
        }
        self.inner.handle_flows(remainder, source).await;
    }
}

/// sFlow: a batch per call — forward only the unmatched remainder.
pub struct AggregatingSflowHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::sflow::listener::SflowHandler>,
}

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler for AggregatingSflowHandler {
    async fn handle_samples(&self, samples: Vec<crate::sflow::SflowRecord>, source: SocketAddr) {
        let remainder: Vec<_> = samples
            .into_iter()
            .filter(|s| !self.agg.consume("sflow", s))
            .collect();
        if remainder.is_empty() {
            return;
        }
        self.inner.handle_samples(remainder, source).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::aggregate::{Aggregator, CompiledRule, rule_schema};
    use crate::zeek::ZeekRecord;
    use crate::zeek::listener::ZeekHandler;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dns_rule() -> CompiledRule {
        let group_by = vec!["query".to_string()];
        CompiledRule {
            name: std::sync::Arc::from("dns_by_query"),
            source: "zeek".to_string(),
            stream: Some("dns".to_string()),
            group_by: group_by.clone(),
            aggs: Vec::new(),
            schema: rule_schema(&group_by, &[]),
        }
    }

    struct CountingZeek(AtomicUsize);
    #[async_trait::async_trait]
    impl ZeekHandler for CountingZeek {
        async fn handle_record(&self, _r: ZeekRecord, _s: std::net::SocketAddr) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn zeek_rec(path: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: path.to_string(),
            fields: serde_json::json!({"query": "a.example"}),
            received_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn a_matched_record_is_counted_and_not_forwarded() {
        let agg = Arc::new(Aggregator::new(vec![dns_rule()], 1000));
        let inner = Arc::new(CountingZeek(AtomicUsize::new(0)));
        let h = AggregatingZeekHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        h.handle_record(zeek_rec("dns"), src).await;

        assert_eq!(
            inner.0.load(Ordering::SeqCst),
            0,
            "an aggregated record must NOT reach the raw writer"
        );
        let now = chrono::Utc::now();
        assert_eq!(agg.drain(now, now).len(), 1, "it must have been counted");
    }

    #[tokio::test]
    async fn an_unmatched_record_passes_through_untouched() {
        let agg = Arc::new(Aggregator::new(vec![dns_rule()], 1000));
        let inner = Arc::new(CountingZeek(AtomicUsize::new(0)));
        let h = AggregatingZeekHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        h.handle_record(zeek_rec("conn"), src).await;

        assert_eq!(
            inner.0.load(Ordering::SeqCst),
            1,
            "conn has no rule; must pass through"
        );
        let now = chrono::Utc::now();
        assert!(agg.drain(now, now).is_empty());
    }

    #[tokio::test]
    async fn a_batch_source_forwards_only_the_unmatched_remainder() {
        use crate::ipfix::FlowRecord;
        use crate::ipfix::listener::IpfixHandler;
        use std::net::{IpAddr, Ipv4Addr};

        fn flow(dst_port: u16) -> FlowRecord {
            FlowRecord {
                observation_domain_id: 0,
                template_id: 0,
                protocol_version: 10,
                exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                export_time: chrono::Utc::now(),
                src_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                dst_addr: None,
                src_port: None,
                dst_port: Some(dst_port),
                ip_protocol: None,
                octet_delta_count: None,
                packet_delta_count: None,
                flow_start: None,
                flow_end: None,
                tcp_flags: None,
                input_interface: None,
                output_interface: None,
                extra: serde_json::json!({}),
            }
        }

        struct CapturingIpfix(Mutex<Vec<FlowRecord>>);
        #[async_trait::async_trait]
        impl IpfixHandler for CapturingIpfix {
            async fn handle_flows(&self, flows: Vec<FlowRecord>, _s: std::net::SocketAddr) {
                self.0.lock().unwrap().extend(flows);
            }
        }

        // A rule with no stream filter matches EVERY ipfix record, so the
        // remainder is empty and the inner handler must not be called at all.
        let group_by = vec!["dst_port".to_string()];
        let rule = CompiledRule {
            name: std::sync::Arc::from("all_flows"),
            source: "ipfix".to_string(),
            stream: None,
            group_by: group_by.clone(),
            aggs: Vec::new(),
            schema: rule_schema(&group_by, &[]),
        };
        let agg = Arc::new(Aggregator::new(vec![rule], 1000));
        let inner = Arc::new(CapturingIpfix(Mutex::new(Vec::new())));
        let h = AggregatingIpfixHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();

        h.handle_flows(vec![flow(443), flow(443), flow(80)], src)
            .await;

        assert!(
            inner.0.lock().unwrap().is_empty(),
            "every flow matched, so nothing may reach the raw writer"
        );
        let now = chrono::Utc::now();
        let rows = agg.drain(now, now);
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 2, "two distinct dst_port groups");
    }

    #[tokio::test]
    async fn sflow_batch_offers_every_record_to_consume_and_forwards_only_the_remainder() {
        use crate::sflow::SflowRecord;
        use crate::sflow::listener::SflowHandler;
        use std::net::{IpAddr, Ipv4Addr};

        fn sample(sample_type: crate::sflow::SampleType, dst_port: u16) -> SflowRecord {
            SflowRecord {
                sample_type,
                exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                received_at: chrono::Utc::now(),
                src_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                dst_addr: None,
                src_port: None,
                dst_port: Some(dst_port),
                ip_protocol: None,
                sampling_rate: None,
                input_ifindex: None,
                output_ifindex: None,
                if_index: None,
                if_type: None,
                if_speed: None,
                if_direction: None,
                if_in_octets: None,
                if_out_octets: None,
                if_in_ucast_pkts: None,
                if_out_ucast_pkts: None,
                if_in_errors: None,
                if_out_errors: None,
                extra: serde_json::json!({}),
            }
        }

        struct CapturingSflow(Mutex<Vec<SflowRecord>>);
        #[async_trait::async_trait]
        impl SflowHandler for CapturingSflow {
            async fn handle_samples(&self, samples: Vec<SflowRecord>, _s: std::net::SocketAddr) {
                self.0.lock().unwrap().extend(samples);
            }
        }

        // The rule targets only "flow" samples, so "counter" samples in the
        // same batch must be offered to consume() (and not matched), then
        // still reach the inner handler as the unmatched remainder.
        let group_by = vec!["dst_port".to_string()];
        let rule = CompiledRule {
            name: std::sync::Arc::from("flow_by_port"),
            source: "sflow".to_string(),
            stream: Some("flow".to_string()),
            group_by: group_by.clone(),
            aggs: Vec::new(),
            schema: rule_schema(&group_by, &[]),
        };
        let agg = Arc::new(Aggregator::new(vec![rule], 1000));
        let inner = Arc::new(CapturingSflow(Mutex::new(Vec::new())));
        let h = AggregatingSflowHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:6343".parse().unwrap();

        h.handle_samples(
            vec![
                sample(crate::sflow::SampleType::Flow, 443),
                sample(crate::sflow::SampleType::Flow, 443),
                sample(crate::sflow::SampleType::Counter, 80),
            ],
            src,
        )
        .await;

        let forwarded = inner.0.lock().unwrap();
        assert_eq!(
            forwarded.len(),
            1,
            "only the unmatched counter sample must reach the raw writer"
        );
        assert_eq!(forwarded[0].sample_type, crate::sflow::SampleType::Counter);
        drop(forwarded);

        let now = chrono::Utc::now();
        let rows = agg.drain(now, now);
        assert_eq!(rows.len(), 1, "one group: the two matched flow samples");
        assert_eq!(
            rows[0].count, 2,
            "both flow samples were offered to consume() and counted"
        );
    }
}
