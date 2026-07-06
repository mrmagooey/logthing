# Architecture Review: HEC and WEF's "Concrete Handle in State" Shape

## Root cause (Q1): why don't HEC/WEF use the Handler-trait pattern?

**Verdict: deliberate and correct — not a historical accident, though the mechanism did originate from real historical asymmetry (WEF predates the pattern; HEC then rationally repeated WEF's shape rather than reinventing it for the same reason).**

The `Handler` trait (`ZeekHandler`, `SuricataHandler`, etc.) exists to solve one specific problem: a long-lived listener struct (`ZeekListener`, `src/zeek/listener.rs:68-76`) is constructed **once** at startup and needs an injectable, swappable destination for records it will decode over its own lifetime, without knowing at compile time whether that destination is `DefaultZeekHandler`, `ZeekS3Handler`, or (per the new local-disk plan) a `MultiZeekHandler` fan-out. `ZeekListener::new(config, handler: Arc<dyn ZeekHandler>)` (`zeek/listener.rs:74-76`) is the injection point; `main.rs` decides the concrete type once and hands it in.

HEC and WEF have no such struct. They are axum route handler *functions* — `handle_hec_event`, `handle_wef_request`, etc. — mounted directly on the shared server's `Router` (`src/server/mod.rs:329-360`, HEC routes gated at 344-349, WEF routes unconditional at 330-336). Each invocation is a fresh async call re-entered per request; there is no long-lived "HecListener" object whose constructor needs a trait object handed in. The axum `Router`/extractor machinery (`Extension<IngestState>`, `State<Arc<AppState>>`) already *is* the injection mechanism — it delivers whatever `S3Sink`-backed handle was built at startup to every invocation. Building a `Handler` trait here would mean wrapping something (a route function) that is never itself swapped for an alternative implementation — there is no second "concrete type" a route handler could ever be handed instead. **So the answer to "is there a real destination-swap point that's missing a trait" is no — the destination-swap point (config-driven, one-time, at `Server::new`) already exists and is served by the `Option<Handler>` construction, not by a trait object.**

The design spec (`docs/superpowers/specs/2026-06-27-ingestion-formats-expansion-design.md:20-27`) makes this explicit before either HEC or WEF's shape was debated ad hoc: it lists **four architectural mechanisms**, not one:

```
| NDJSON-over-TCP listener        | Suricata EVE JSON    | src/zeek/listener.rs   |
| Syslog-embedded payload parser  | CEF, LEEF, ...        | src/syslog/mod.rs      |
| UDP binary decoder              | sFlow                 | src/ipfix/listener.rs  |
| HTTP route on existing server   | Generic JSON (HEC), OTLP | src/server/mod.rs POST /syslog |
```

HEC is explicitly bucketed under "HTTP route on existing server," the same bucket WEF (and the pre-existing `/syslog` HTTP route) already occupied. Unit 4's wiring note (line 141-145) goes further and states the decision was made *consciously, in contrast to* just reusing `AppState`:

> "Wiring (resolves Concern H/5): new routes carry a separate `IngestState` Axum extension holding `Option<GenericS3Handler>`... The WEF `AppState.parquet_s3_sender` is **not** overloaded."

That sentence is direct evidence this was a reviewed design decision (a numbered "Concern" in an explicit review pass), not an unexamined copy-paste.

**Git-history timeline** confirms the sequencing and rules out "accidental copy because no other pattern existed yet":

| Commit | Date | What |
|---|---|---|
| `9a07598` "add core WEF server implementation" | 2026-02-07 | `AppState` (WEF's shape) — **the very first commit**, months before any Handler trait existed |
| `dc45917` IPFIX S3 handler | 2026-06-21 | |
| `17b3a21` "add ZeekHandler trait, DefaultZeekHandler..." | 2026-06-22 | Handler-trait pattern formalized |
| `026e147` Suricata module root | 2026-06-27 | |
| `0cf8e01`…`27cea1c` HEC config/sink/handlers | 2026-06-28 | HEC built **after** the trait pattern was well-established (Zeek, IPFIX, Suricata already existed) |

So WEF's shape is a genuine historical fact — it predates the trait pattern by four and a half months, simply because there was nothing else to compare it to. But HEC, built five weeks *after* the trait pattern was proven on three sources, did not copy it — it was deliberately assigned the WEF-like shape by the design spec because it's mechanistically identical to WEF (HTTP route, not listener). That is the correct call, not laziness: forcing an `Arc<dyn HecHandler>` onto a stateless per-request axum handler function would add a trait, a `DefaultHecHandler`, and a dynamic dispatch indirection with no swap point to justify it.

## HEC vs. WEF: same shape or different? (Q2)

They are the *same category* (concrete handle in state, no trait) but **not identical** in several concrete ways:

**Construction** — same overall pattern, same error handling on failed `S3Sink`:
- WEF: `server/mod.rs:172-196` — `if let Some(wef_s3_cfg) = config.wef.s3.as_ref() { match S3Sink::from_connection(...).await { Ok(sink) => ... wef_start(...) ..., Err(e) => { error!("Failed to create S3Sink for WEF persistence..."); (None, None) } } } else { (None, None) }`.
- HEC: `server/mod.rs:208-238` — same `match S3Sink::from_connection(...)` shape, same `Err(e) => { error!("Failed to create S3Sink for HEC ingest: {e}"); (IngestState::default(), None) }` fallback.

Both fail open (log-and-continue, never abort startup) — genuinely identical error-handling philosophy.

**But HEC has an extra gate WEF doesn't**: HEC's construction is nested inside `if config.hec.enabled { ... }` (`server/mod.rs:208`) — a *feature* toggle independent of whether S3 is configured — while WEF has no equivalent `config.wef.enabled` check; WEF's routes are mounted unconditionally (`server/mod.rs:330-336`) because, per the local-disk plan (`docs/superpowers/plans/2026-07-05-local-disk-all-sources.md:110`), WEF is "the original, founding feature... the binary's own identity is 'the WEF server'" — it's always on, whereas HEC is an opt-in bolt-on that defaults off and must not 404 → active unless explicitly enabled. This is a legitimate difference, not an oversight: it reflects that WEF and HEC have different product-maturity/opt-in status, not that one implementation is more careful than the other.

**Consumers and call-site count differ**: HEC has **4** consumers of `IngestState.generic_s3` across 2 files — `src/ingest/handlers.rs:94, 136-138, 176` (3 HEC/NDJSON routes) plus `src/server/mod.rs:2623` (the **OTLP** route, `handle_otlp_logs`, which maps `ExportLogsServiceRequest → GenericRecord` and shares this same field rather than having its own — the `otlp_s3: Option<OtlpS3Handler>` sibling field sketched in the design spec, `ingest/mod.rs:45,51` comment, was never actually built; OTLP was folded into `generic_s3` instead). WEF has exactly **1** consumer, `server/mod.rs:638-649`.

**Error-handling at the call sites is *not* uniform, even within the HEC family**:
- WEF (`server/mod.rs:638-649`) distinguishes the two `TrySendError` variants: `Full(_) => warn!("... dropping event")` vs `Closed(_) => error!("... channel closed")`.
- OTLP's HEC-shaped consumer (`server/mod.rs:2623-2636`) does the same `match e { Full => warn!, Closed => error! }`.
- But the three *actual* HEC routes in `ingest/handlers.rs:94-101, 136-141, 176-183` do **not** distinguish — each just does `if handler.try_send(rec).is_err() { metrics::counter!("hec_events_dropped").increment(1); tracing::warn!(...) }`, treating a closed channel identically to a full one.

So it's not just "HEC vs. WEF are subtly different" — the four consumers of the *same* `generic_s3` field disagree with each other on defensiveness. This is a small real inconsistency worth fixing regardless of any larger unification decision.

**Structural wrapper difference**: `AppState` is built once and shared as `Arc<AppState>` (`server/mod.rs:198-205`, extracted via `State<Arc<AppState>>`) — one shared instance behind one `Arc`. `IngestState` is `#[derive(Clone, Default)]` (`ingest/mod.rs:46`) and handed to axum as `Extension(ingest_state.clone())` per-layer — a plain `Clone` value type whose cheapness relies on its *field* (`GenericS3Handler` = `ParquetWriterHandle<GenericSink>`) already wrapping an `Arc<mpsc::Sender<_>>` internally (comment at `ingest/mod.rs:41-42` explicitly documents this: "Cloning is O(1)... wraps an `Arc<...Sender<_>>`"). Functionally equivalent cost, but a different idiom (wrap-the-struct-in-Arc vs. make-the-struct-Clone-because-its-fields-already-are) — cosmetic, not worth changing.

**Testability gap common to both**: neither HEC's nor WEF's route-handler test suites ever construct a state with the persistence branch populated. `ingest/handlers.rs:200` builds its test router with `IngestState { generic_s3: None }`; `server/mod.rs:720` builds its default test `AppState` with `parquet_s3_sender: None`. The `if let Some(...) { try_send(...) }` branch at the HTTP layer is **never exercised** by any handler-level test in either source. This isn't invisible risk, though — the underlying writer/`try_send`/Parquet-partition logic *is* unit tested, just one layer down, symmetrically for both: `generic_s3.rs:357-391` (`hec_start_wires_handler_and_join_handle`) and `parquet_s3.rs:266-303` (`wef_start_spawns_and_exits_cleanly`) both push a record through the real handle and assert it's processed. So the gap is narrowly "does the HTTP handler function actually call `try_send` when `Some`" — not "is persistence logic tested at all."

## Verdict: which pattern is better, and for what (Q3)

**Neither pattern is universally better — each is right for the concurrency shape it was built for, and swapping either one onto the other's problem would be worse, not equal.**

- **Testability**: The trait-object sources get a real advantage from `Arc<dyn Handler>` — `zeek/listener.rs:276-296`'s `CapturingHandler` can be constructed standalone and driven through `ZeekListener::run_with_listener` with zero HTTP/axum machinery, directly asserting on `handle_record` calls (`zeek/listener.rs:377-413` etc.). HEC/WEF *can't* get an equivalent because there's no polymorphic call to substitute a spy into — the record either goes into a real `try_send` on a real channel or it doesn't happen at all. That's not fixable by adding a trait; it's fixable (and *should* be fixed, cheaply) by adding one test per source that builds `IngestState { generic_s3: Some(handler) }` / `AppState { parquet_s3_sender: Some(handle), .. }` with a real (or in-process) receiver and asserts the record arrives — a straightforward gap-filler, not an architecture change.
- **Readability**: `if let Some(ref h) = state.x { h.try_send(record) }` (handlers.rs:94, server/mod.rs:638) is *more* readable than the alternative would be, not less. The trait alternative would require a `DefaultGenericHandler`/`DefaultWefHandler` that logs-and-drops, an `Arc<dyn Handler>` field, and a call through dynamic dispatch on every request — more types, one more allocation-adjacent indirection, for behavior that's already fully expressed by a plain `Option`. The trait's ceremony pays for itself only when there's a genuine "what concrete type is this" decision to make once; per-request HTTP handlers don't have that decision.
- **Startup-time-swap need**: The trait-object pattern's actual payoff — `main.rs` picks `Default`/S3/`Multi` once and the listener never re-decides — is irrelevant to a route handler that's re-entered on every request and reads whatever `Extension`/`State` axum resolved for it. There's nothing to "pick once" beyond what `Option` + `if let` already gives you.

**Overall: the split is correct engineering, sized to the actual concurrency shape of each source.** The naive instinct ("everything should look the same for consistency") is wrong here; the two shapes exist because the two problems are actually different.

## Should HEC and WEF unify with each other? (Q4)

**Recommendation: no generic `PersistenceTargets<S>` abstraction now — duplication here is genuinely cheap, and the abstraction cost is real, not free.** This falls on the "not worth it" side of the same spectrum the prior review used for `start_writer<S>` (worth it) vs. `MultiHandler<R>` (not worth it), and for a stronger reason than `MultiHandler<R>` was rejected on.

Size the actual upcoming diff, per the local-disk plan (`docs/superpowers/plans/2026-07-05-local-disk-all-sources.md:93-122`):
- **HEC**: add one sibling field `generic_local: Option<GenericS3Handler>` to `IngestState`, then at the 4 existing call sites add one more `if let Some(ref h) = ingest.generic_local { h.try_send(record.clone())...; }` line (plan §3.5, lines 97-102 spells the exact 2-line pattern). Plan explicitly notes: "This is **less new code** than a fan-out wrapper would be."
- **WEF**: same shape, 1 call site, 1 new field, 2 lines (plan §3.6, lines 114-118).

Total footprint: **2 new `Option` fields + 5 near-identical two-line `if let` blocks**, across two files each source already owns. A `PersistenceTargets<S: ParquetSink>` struct with `s3: Option<...>`, `local: Option<...>`, and `try_send_to_all(record)` would:
- Require `S` generic parameters to unify two *different* concrete sink types (`GenericSink` for HEC, `WefSink` for WEF) — meaning `PersistenceTargets<GenericSink>` and `PersistenceTargets<WefSink>` are still two distinct monomorphized types with no shared runtime behavior beyond the method body text; the "abstraction" only removes the boilerplate of two `if let` lines per call site, at the cost of introducing a new public(ish) type, its own field-visibility/construction API (needs a builder or two-arg constructor), and one more level of indirection every reader has to learn to see "oh, this just calls try_send on up to two handles."
- For HEC specifically, `try_send_to_all` would need to decide whether it clones `GenericRecord` internally (it must, to send to two channels) — that's fine, but it means the abstraction's one non-trivial job (deciding `record.clone()` vs move-into-last) is exactly the one-liner the plan already shows working correctly by hand.
- Buys real value only if a *third* consumer of the same two-handle pattern appears later (it might, if a source needs three destinations, or if the "generic_local" pattern gets reused for a source #8) — but right now there are exactly two call-site-counts (4 and 1), and the win is "save ~8 lines total, spread across 2 already-small PRs," for the cost of "add a new generic type + its own tests + a decision about how OTLP's differing error-handling (Full vs Closed distinction, see Q2) gets reconciled inside `try_send_to_all` before it can even be written."

That last point matters: unifying now would force resolving the HEC-vs-OTLP inconsistency found in Q2 (three HEC routes don't distinguish `Full`/`Closed`, OTLP and WEF do) as a *precondition* of writing one shared method — turning a "sizing" decision into a small behavior-change decision under time pressure, right as two independent PRs are about to land. That's backwards. Compare to `start_writer<S>`: that hoist was safe specifically because the duplicated code was **byte-for-byte identical** (`docs/superpowers/plans/2026-07-06-hoist-start-writer.md:5,13`) and the migration was a pure mechanical `find/replace` with no behavior decision embedded. `PersistenceTargets<S>` is not that — it has a genuine behavioral question (error-variant handling) baked into its one method, so it's closer to `MultiHandler<R>` territory (real, uncertain trait-boundary-shaped design work) than to `start_writer<S>` (safe mechanical hoist), just at a much smaller scale that makes the wrong call cheaper to reverse if made.

**If it's ever revisited**: the cheap, safe, small win to take *now, independent of any local-disk PR*, is fixing the error-handling inconsistency between HEC's 3 routes and WEF/OTLP (always distinguish `Full` vs `Closed`) — that's a genuine one-behavior, few-line fix with no new types, unlike introducing `PersistenceTargets<S>`.

## Should HEC/WEF move toward the Handler-trait pattern? (Q5)

**Explicitly reject.** Per Q1 and Q3: there is no polymorphic call point in an axum route handler function analogous to a listener's `handler.handle_record(...)` — the "polymorphism" a `Handler` trait buys is resolved once, at `Server::new`, by whichever `Option` gets populated, and every request already reads that resolved state through the extractor. Wrapping that in `Arc<dyn HecHandler>` would require inventing a `DefaultHecHandler`/`DefaultWefHandler` whose only job is "do nothing," and routing every request through a vtable call for behavior that a plain `if let Some` already expresses more directly. The one real benefit a trait *could* offer — a uniform `CapturingHandler`-style unit test across all 7 sources — is achievable more cheaply by just adding the missing "route handler with `Some(...)` state actually calls `try_send`" tests noted in Q2, without touching the type signature of `IngestState`/`AppState` at all. There is also no near-term composition need (no plan or spec anywhere proposes an "HEC-of-HECs" fan-out analogous to `MultiZeekHandler` — HEC/WEF's fan-out need, per the local-disk plan, is satisfied by two sibling `Option` fields, not a `Vec<Arc<dyn Handler>>`). Forcing the trait pattern here is ceremony without benefit — the local-disk plan's own reviewers reached the identical conclusion (`local-disk-all-sources.md:33`: "**A `MultiXxxHandler` wrapper is the wrong shape here** — there's nothing polymorphic to wrap").

## Overall recommendation, sequenced against the pending local-disk PRs

1. **Do not build `PersistenceTargets<S>` before, during, or after the HEC/WEF local-disk PRs land.** The sibling-`Option`-field-plus-inline-`try_send` shape the plan already specifies (§3.5, §3.6) is the right, cheap, low-risk approach — ship it as written.
2. **Do not migrate HEC/WEF toward `Arc<dyn Handler>`** at any point — there is no destination-swap problem for either to solve with it.
3. **Before or alongside the local-disk PRs** (cheap, no dependency on them): normalize the `Full`/`Closed` `TrySendError` handling across HEC's 3 route handlers to match WEF's and OTLP's existing pattern (`match e { Full => warn!, Closed => error! }`) — small, safe, improves observability, and removes the one real inconsistency found between "same-shaped" call sites before it gets copy-pasted into the upcoming `generic_local`/`parquet_local_sender` branches (otherwise the inconsistency doubles from 1 asymmetric site to 2).
4. **As a follow-on, not urgent**: add one handler-level test per source (HEC: a router built with `generic_s3: Some(handler)` asserting the record reaches a real/spy receiver; WEF: `AppState` with `parquet_s3_sender: Some(handle)` likewise) to close the testability gap identified in Q2/Q3 — this is orthogonal to the local-disk work and doesn't block it.
5. **Leave the OTLP-reads-`generic_s3`-directly wiring as-is** — it's a documented, deliberate design choice (`ingest/mod.rs` "Unit 5" comment notwithstanding — the team folded OTLP into the existing `generic_s3` field rather than adding the originally-sketched `otlp_s3` sibling, and nothing in the current architecture is worse off for it), but flag it explicitly in the eventual `generic_local` PR description so the reviewer knows OTLP will pick up local-disk persistence "for free" through the same field, without a fourth call site needing separate wiring.

### Critical Files for Implementation
- /home/dev/projects/logthing/src/ingest/mod.rs
- /home/dev/projects/logthing/src/ingest/handlers.rs
- /home/dev/projects/logthing/src/server/mod.rs
- /home/dev/projects/logthing/src/forwarding/generic_s3.rs
- /home/dev/projects/logthing/src/forwarding/parquet_s3.rs
