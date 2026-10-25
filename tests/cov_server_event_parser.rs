//! Server::new loads event parsers from paths relative to the working directory
//! (`config/event_parsers/` or `config/event_parsers.yaml`). The process cwd is global, so every
//! scenario runs sequentially inside one test of this dedicated binary.

use logthing::config::Config;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::RwLock;

static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[derive(Default)]
struct Visitor(String);

impl tracing::field::Visit for Visitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut v = Visitor::default();
        event.record(&mut v);
        EVENTS.lock().unwrap().push(v.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn install() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing::subscriber::set_global_default(Capture).expect("first subscriber");
    });
}

async fn build() {
    let config = Config::default();
    let shared = Arc::new(RwLock::new(config.clone()));
    Server::new(
        config,
        shared,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        logthing::forwarding::flush_registry::FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
        Vec::new(),
    )
    .await
    .map(drop)
    .expect("Server::new succeeds even when the parser config is unusable");
}

fn drain() -> Vec<String> {
    std::mem::take(&mut *EVENTS.lock().unwrap())
}

const GOOD_YAML: &str = r#"
event_parsers:
  9999:
    name: "test_parser"
    description: "test"
    fields:
      - name: "Msg"
        source: EventData
        xpath: "Data[@Name='Msg']"
    output_format: "MSG: {Msg} END"
"#;

#[tokio::test]
async fn parser_config_is_loaded_from_cwd_relative_paths() {
    install();
    let original = std::env::current_dir().unwrap();

    // 1. Only config/event_parsers.yaml exists: it is loaded.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("config")).unwrap();
    std::fs::write(tmp.path().join("config/event_parsers.yaml"), GOOD_YAML).unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();
    drain();
    build().await;
    let events = drain();
    assert!(
        events
            .iter()
            .any(|m| m.contains("Loaded event parser configuration with 1 parsers")),
        "{events:?}"
    );

    // 2. An unparseable config/event_parsers.yaml is reported and skipped.
    std::fs::write(
        tmp.path().join("config/event_parsers.yaml"),
        "event_parsers: [",
    )
    .unwrap();
    build().await;
    let events = drain();
    assert!(
        events
            .iter()
            .any(|m| m.starts_with("Failed to load event parser configuration:")),
        "{events:?}"
    );

    // 3. A config/event_parsers/ directory takes precedence; a malformed file in it is
    //    reported and skipped.
    let dir = tmp.path().join("config/event_parsers");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("bad.yaml"), "event_id: [").unwrap();
    build().await;
    let events = drain();
    assert!(
        events
            .iter()
            .any(|m| m.starts_with("Failed to load event parser configuration from directory")),
        "{events:?}"
    );

    std::env::set_current_dir(original).unwrap();
}
