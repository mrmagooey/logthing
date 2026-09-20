//! Shared `#[cfg(test)]`-only tracing capture used by the TCP parse-error
//! sanitization regression tests in `syslog::listener`, `zeek::listener`, and
//! `suricata::listener`.
//!
//! Not a per-test `tracing::subscriber::set_default` (the pattern used by
//! `forwarding::buffered_writer`'s `TestTracingCapture`): that technique was
//! empirically flaky here. `tracing-core` caches each callsite's `Interest`
//! -- and, more importantly, a single **global** max-level threshold --
//! across *every* thread in the process (see
//! `tracing_core::callsite::{register_dispatch, rebuild_interest_cache}`,
//! which fold `max_level_hint()`/`Interest` over every currently-live
//! `Dispatch` process-wide). Each `set_default` call creates a fresh
//! `Dispatch`, which forces a global rebuild of that fold; under this
//! suite's full parallelism the rebuild can transiently land on a
//! restrictive value, silently dropping a test's event before
//! `Subscriber::enabled`/`event` are even called. A subscriber installed
//! exactly **once**, globally (`set_global_default`, gated by a `OnceLock`
//! so only the first caller installs it), never triggers that rebuild
//! again, so this cache instability doesn't apply.
//!
//! Only one subscriber can win `set_global_default` process-wide -- later
//! calls are silently ignored (`Result` intentionally dropped). If each of
//! the three listener test modules installed its *own* independent
//! subscriber type, whichever test in whichever module happened to run
//! first would win the installation race, and the other two modules' own
//! subscribers would never install: their tests would then depend on
//! whether the winning subscriber happens to route events into a thread
//! local *they* can read, which it doesn't. Hence one subscriber, shared by
//! all three modules from here.
//!
//! Per-test isolation instead comes from routing captured messages through a
//! `thread_local!` buffer that each test clears before use -- safe because
//! the default (current-thread) `#[tokio::test]` flavor runs a given test's
//! whole body, including any `tokio::spawn`ed subtasks, on one OS thread,
//! and libtest never runs two tests concurrently on the same thread.

use std::cell::RefCell;
use std::sync::OnceLock;

thread_local! {
    static CAPTURED_EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

struct MessageOnlyVisitor(String);

impl tracing::field::Visit for MessageOnlyVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

struct GlobalCaptureSubscriber;

impl tracing::Subscriber for GlobalCaptureSubscriber {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MessageOnlyVisitor(String::new());
        event.record(&mut visitor);
        CAPTURED_EVENTS.with(|events| events.borrow_mut().push(visitor.0));
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Installs [`GlobalCaptureSubscriber`] as the process's global default
/// tracing subscriber (exactly once -- later calls, including from other
/// listener test modules, are no-ops) and clears this thread's captured
/// event buffer so the calling test starts from an empty slate.
pub(crate) fn install_and_clear() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(GlobalCaptureSubscriber);
    });
    CAPTURED_EVENTS.with(|events| events.borrow_mut().clear());
}

/// Returns the `message` field of every tracing event captured on this
/// thread since the last [`install_and_clear`] call.
pub(crate) fn captured_events() -> Vec<String> {
    CAPTURED_EVENTS.with(|events| events.borrow().clone())
}
