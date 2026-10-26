//! Integration: the real chain `AggregatingSyslogHandler -> PayloadDispatchingHandler ->
//! MultiSyslogHandler -> recording targets`, wired like `main.rs`. Pins that aggregation
//! consumption and target fan-out are unchanged by the move-instead-of-clone change, and that a
//! single-target datagram reaches the target without any deep clone (same allocation).

use async_trait::async_trait;
use logthing::forwarding::aggregate::handlers::AggregatingSyslogHandler;
use logthing::forwarding::aggregate::{Aggregator, CompiledRule, rule_schema};
use logthing::forwarding::structured_syslog_s3::StructuredS3Handler;
use logthing::forwarding::syslog_s3::MultiSyslogHandler;
use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{PayloadDispatchingHandler, SyslogHandler};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

type Log = Arc<Mutex<Vec<(usize, usize, serde_json::Value)>>>;

struct Target {
    idx: usize,
    log: Log,
}

#[async_trait]
impl SyslogHandler for Target {
    async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
        self.log.lock().unwrap().push((
            self.idx,
            message.message.as_ptr() as usize,
            serde_json::to_value(&message).unwrap(),
        ));
    }
}

fn src() -> SocketAddr {
    "127.0.0.1:5514".parse().unwrap()
}

fn sshd_message() -> SyslogMessage {
    SyslogMessage::parse("<34>Jan 15 10:30:45 h1 sshd[1]: Failed password for root")
        .expect("sshd line must parse")
}

fn cef_message() -> SyslogMessage {
    SyslogMessage::parse(
        "<134>Jan 15 10:30:45 loadgen-host loadgen: CEF:0|Loadgen|SyntheticFirewall|1.0|100|\
         Synthetic Blocked Connection|5|src=10.0.0.1 dst=10.1.0.1 spt=1024 dpt=443 cnt=1",
    )
    .expect("cef line must parse")
}

struct Chain {
    top: AggregatingSyslogHandler,
    agg: Arc<Aggregator>,
    log: Log,
    rx: tokio::sync::mpsc::Receiver<logthing::syslog::payload::StructuredSyslogRecord>,
}

fn chain(targets: usize) -> Chain {
    let group_by = vec!["hostname".to_string()];
    let rule = CompiledRule {
        name: Arc::from("sshd_by_host"),
        source: "syslog".to_string(),
        stream: Some("sshd".to_string()),
        group_by: group_by.clone(),
        aggs: Vec::new(),
        schema: rule_schema(&group_by, &[]),
    };
    let agg = Arc::new(Aggregator::new(vec![rule], 1000));
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let multi = Arc::new(MultiSyslogHandler(
        (0..targets)
            .map(|idx| {
                Arc::new(Target {
                    idx,
                    log: log.clone(),
                }) as Arc<dyn SyslogHandler>
            })
            .collect(),
    ));
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let dispatching = Arc::new(PayloadDispatchingHandler {
        inner: multi,
        parse_payloads: true,
        structured_handle: Some(Arc::new(StructuredS3Handler::for_test(
            tx,
            "syslog",
            "structured",
        ))),
    });
    Chain {
        top: AggregatingSyslogHandler {
            agg: agg.clone(),
            inner: dispatching,
        },
        agg,
        log,
        rx,
    }
}

#[tokio::test]
async fn test_chain_aggregated_message_is_consumed_and_never_reaches_targets() {
    let mut c = chain(2);
    c.top.handle_message(sshd_message(), src()).await;
    assert!(
        c.log.lock().unwrap().is_empty(),
        "swallowed by the aggregation rule"
    );
    assert!(c.rx.try_recv().is_err(), "no structured record either");
    let now = chrono::Utc::now();
    let rows = c.agg.drain(now, now);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].count, 1);
}

#[tokio::test]
async fn test_chain_fans_out_equal_messages_in_order_and_sends_structured_record() {
    let mut c = chain(2);
    let msg = cef_message();
    let expected = serde_json::to_value(&msg).unwrap();
    c.top.handle_message(msg, src()).await;
    let entries = c.log.lock().unwrap().clone();
    assert_eq!(entries.iter().map(|e| e.0).collect::<Vec<_>>(), vec![0, 1]);
    for (_, _, got) in &entries {
        assert_eq!(*got, expected);
    }
    let rec =
        c.rx.try_recv()
            .expect("structured record sent after the targets ran");
    assert_eq!(rec.payload_type, "cef");
}

#[tokio::test]
async fn test_chain_single_target_receives_original_allocation() {
    let c = chain(1);
    let msg = cef_message();
    let original = msg.message.as_ptr() as usize;
    c.top.handle_message(msg, src()).await;
    let entries = c.log.lock().unwrap().clone();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].1, original,
        "zero deep clones end to end for one target"
    );
}
