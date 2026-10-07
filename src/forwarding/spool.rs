//! Durable local spool for S3 uploads (`[spool]`): entry format, accounting, replay scan, the
//! [`SpoolingUploadSink`] decorator and the background uploader.
//!
//! Entry = `<id>.parquet` + optional `<id>.json` (descriptor) + `<id>.meta` (commit marker).
//! `<id>` = `{unix_micros:020}-{uuid}` so lexical order is age order. Every file is written
//! as `<name>.tmp`, fsynced, renamed; the directory is fsynced after the data renames and
//! again after the `.meta` rename. An entry is complete iff its `.meta` exists, and the
//! `.meta` is removed first on delete, so a crash never leaves a committed entry whose
//! data is missing.
//!
//! The uploader delivers entries one at a time, oldest first, retrying with exponential
//! backoff. Every attempt re-uploads under the SAME keys (idempotent), so a crash between the
//! Parquet and descriptor PUTs just repeats both on replay. Entries are independent and new
//! flushes interleave with replay; Iceberg registration is set-based, so order is irrelevant.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use async_trait::async_trait;
use metrics::{counter, gauge};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, watch};
use tracing::{error, warn};

use crate::config::SpoolConfig;
use crate::forwarding::buffered_writer::{DescriptorPayload, UploadDisposition, UploadSink};

const META_VERSION: u32 = 1;
const CORRUPT_DIR: &str = "corrupt";
/// Upper bound for one upload attempt (Parquet + descriptor).
const UPLOAD_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Why [`Spool::commit`] refused an entry.
#[derive(Debug)]
pub enum SpoolReject {
    /// Accepting the entry would exceed `max_bytes`.
    Full,
    /// Writing the entry failed (disk full, directory gone, permissions).
    Io(String),
}

/// The commit marker: where the entry is going and how to verify its bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntryMeta {
    version: u32,
    sink_id: String,
    key: String,
    descriptor_key: Option<String>,
    parquet_bytes: u64,
    descriptor_bytes: u64,
    sha256: String,
}

/// A committed entry awaiting upload, with its retry state.
struct Pending {
    meta: EntryMeta,
    attempts: u32,
    next_attempt: Instant,
}

/// Where entries of one sink go.
struct Dest {
    s3: Arc<dyn UploadSink>,
    descriptor: Option<Arc<dyn UploadSink>>,
}

/// Accounting shared with the blocking closures, so the bookkeeping for an entry completes
/// on the blocking thread even if the awaiting future (a flush, an upload attempt) is
/// cancelled mid-way: a cancelled `commit` still records its entry (or rolls back its byte
/// reservation) and a cancelled attempt never leaves a deleted entry in the pending map.
struct Shared {
    bytes: AtomicU64,
    pending: Mutex<BTreeMap<String, Pending>>,
    notify: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn publish(&self, entries: usize) {
        gauge!("spool_bytes").set(self.bytes.load(Ordering::SeqCst) as f64);
        gauge!("spool_entries").set(entries as f64);
    }

    /// Record a freshly committed entry and wake the uploader.
    fn insert(&self, id: String, meta: EntryMeta) {
        let entries = {
            let mut pending = self.lock();
            pending.insert(
                id,
                Pending {
                    meta,
                    attempts: 0,
                    next_attempt: Instant::now(),
                },
            );
            pending.len()
        };
        self.publish(entries);
        self.notify.notify_one();
    }

    /// Drop entry `id` and release its bytes. Idempotent.
    fn forget(&self, id: &str) {
        let entries = {
            let mut pending = self.lock();
            if let Some(p) = pending.remove(id) {
                self.bytes.fetch_sub(
                    p.meta.parquet_bytes + p.meta.descriptor_bytes,
                    Ordering::SeqCst,
                );
            }
            pending.len()
        };
        self.publish(entries);
    }
}

/// The spool. Cheap to share via `Arc`.
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    shared: Arc<Shared>,
    dests: RwLock<HashMap<String, Dest>>,
    backoff_base: Duration,
    backoff_cap: Duration,
    warned_sinks: Mutex<HashSet<String>>,
    #[cfg(test)]
    unknown_sink_attempts: AtomicU64,
}

/// Create `<name>.tmp`, write, fsync, then rename to `<name>`.
fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))
}

/// fsync a directory so renames/unlinks inside it are durable.
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Remove every file of entry `id`: unlink `.meta` (un-commits it), fsync the directory, then
/// unlink the data and tmp files and fsync again. A crash after the first fsync leaves only
/// uncommitted orphans (swept on open), never a committed entry with missing data. Best
/// effort; missing files are fine.
fn remove_entry_files(dir: &Path, id: &str) {
    let _ = std::fs::remove_file(dir.join(format!("{id}.meta")));
    let _ = fsync_dir(dir);
    for ext in ["meta.tmp", "parquet", "parquet.tmp", "json", "json.tmp"] {
        let _ = std::fs::remove_file(dir.join(format!("{id}.{ext}")));
    }
    let _ = fsync_dir(dir);
}

/// Write one entry crash-safely: data files, dir fsync, `.meta` last, dir fsync. On any error
/// every file of the entry is removed again.
fn write_entry_blocking(
    dir: &Path,
    id: &str,
    meta: &EntryMeta,
    parquet: &[u8],
    descriptor: Option<&[u8]>,
) -> std::io::Result<()> {
    let run = || -> std::io::Result<()> {
        write_durable(dir, &format!("{id}.parquet"), parquet)?;
        if let Some(d) = descriptor {
            write_durable(dir, &format!("{id}.json"), d)?;
        }
        fsync_dir(dir)?;
        let meta_bytes = serde_json::to_vec(meta).map_err(std::io::Error::other)?;
        write_durable(dir, &format!("{id}.meta"), &meta_bytes)?;
        fsync_dir(dir)
    };
    run().inspect_err(|_| remove_entry_files(dir, id))
}

fn new_entry_id() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    format!("{micros:020}-{}", uuid::Uuid::new_v4().simple())
}

/// Move every file of entry `id` into `<dir>/corrupt/` and count it.
fn quarantine(dir: &Path, id: &str, reason: &str) {
    error!(entry = id, reason, "quarantining corrupt spool entry");
    counter!("spool_corrupt").increment(1);
    let cdir = dir.join(CORRUPT_DIR);
    if let Err(e) = std::fs::create_dir_all(&cdir) {
        error!(error = %e, "cannot create spool corrupt/ directory");
        return;
    }
    for ext in ["meta", "parquet", "json"] {
        let name = format!("{id}.{ext}");
        let src = dir.join(&name);
        if src.exists()
            && let Err(e) = std::fs::rename(&src, cdir.join(&name))
        {
            error!(error = %e, file = %name, "cannot quarantine spool file");
        }
    }
    let _ = fsync_dir(dir);
}

/// Why [`validate_entry`] did not accept an entry.
enum Invalid {
    /// The entry is genuinely bad (missing file, size/hash mismatch, bad meta): quarantine it.
    Corrupt(String),
    /// A transient I/O error (EIO, EMFILE, permissions): leave the entry in place.
    Transient(String),
}

/// Read a required file: NotFound is corruption, any other error is transient.
fn read_required(path: &Path, what: &str) -> Result<Vec<u8>, Invalid> {
    std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Invalid::Corrupt(format!("{what} missing")),
        _ => Invalid::Transient(format!("{what} unreadable: {e}")),
    })
}

/// Validate a committed entry against its files.
fn validate_entry(dir: &Path, id: &str) -> Result<EntryMeta, Invalid> {
    let raw = read_required(&dir.join(format!("{id}.meta")), "meta")?;
    let meta: EntryMeta =
        serde_json::from_slice(&raw).map_err(|e| Invalid::Corrupt(format!("meta parse: {e}")))?;
    if meta.version != META_VERSION {
        return Err(Invalid::Corrupt(format!(
            "unknown meta version {}",
            meta.version
        )));
    }
    let parquet = read_required(&dir.join(format!("{id}.parquet")), "parquet")?;
    if parquet.len() as u64 != meta.parquet_bytes {
        return Err(Invalid::Corrupt(format!(
            "parquet length {} != {}",
            parquet.len(),
            meta.parquet_bytes
        )));
    }
    if hex::encode(Sha256::digest(&parquet)) != meta.sha256 {
        return Err(Invalid::Corrupt("parquet sha256 mismatch".into()));
    }
    if meta.descriptor_key.is_some() {
        let len = std::fs::metadata(dir.join(format!("{id}.json")))
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Invalid::Corrupt("descriptor missing".into()),
                _ => Invalid::Transient(format!("descriptor unreadable: {e}")),
            })?
            .len();
        if len != meta.descriptor_bytes {
            return Err(Invalid::Corrupt(format!(
                "descriptor length {len} != {}",
                meta.descriptor_bytes
            )));
        }
    }
    Ok(meta)
}

impl Spool {
    /// Create the directory if needed, clean partial writes, quarantine corrupt entries and
    /// load the complete ones (oldest first) with their byte accounting.
    pub fn open(cfg: &SpoolConfig) -> anyhow::Result<Arc<Spool>> {
        Self::open_with_backoff(cfg, Duration::from_secs(1), Duration::from_secs(60))
    }

    /// [`Spool::open`] with explicit retry backoff (`base * 2^(attempts-1)`, capped at `cap`).
    /// Production uses 1 s / 60 s; tests shrink it.
    #[doc(hidden)]
    pub fn open_with_backoff(
        cfg: &SpoolConfig,
        base: Duration,
        cap: Duration,
    ) -> anyhow::Result<Arc<Spool>> {
        let dir = cfg.dir.clone();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating spool dir {}", dir.display()))?;

        let mut metas: Vec<String> = Vec::new();
        let mut data_ids: Vec<(String, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&dir).context("scanning spool dir")? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
                continue;
            };
            if name.ends_with(".tmp") {
                let _ = std::fs::remove_file(&path);
            } else if let Some(id) = name.strip_suffix(".meta") {
                metas.push(id.to_owned());
            } else if let Some(id) = name
                .strip_suffix(".parquet")
                .or_else(|| name.strip_suffix(".json"))
            {
                data_ids.push((id.to_owned(), path));
            }
        }
        metas.sort();

        // Data files without a commit marker are uncommitted orphans.
        for (id, path) in data_ids {
            if metas.binary_search(&id).is_err() {
                let _ = std::fs::remove_file(path);
            }
        }

        let mut pending = BTreeMap::new();
        let mut total = 0u64;
        let mut unreadable = 0u64;
        for id in metas {
            match validate_entry(&dir, &id) {
                Ok(meta) => {
                    total += meta.parquet_bytes + meta.descriptor_bytes;
                    pending.insert(
                        id,
                        Pending {
                            meta,
                            attempts: 0,
                            next_attempt: Instant::now(),
                        },
                    );
                }
                Err(Invalid::Corrupt(reason)) => quarantine(&dir, &id, &reason),
                Err(Invalid::Transient(reason)) => {
                    error!(
                        entry = %id,
                        %reason,
                        "spool entry unreadable; left in place, retried on next open"
                    );
                    // Still on disk: count its bytes so the cap sees the real footprint.
                    unreadable += 1;
                    total += ["meta", "parquet", "json"]
                        .iter()
                        .filter_map(|e| std::fs::metadata(dir.join(format!("{id}.{e}"))).ok())
                        .map(|m| m.len())
                        .sum::<u64>();
                }
            }
        }
        let _ = fsync_dir(&dir);

        gauge!("spool_bytes").set(total as f64);
        gauge!("spool_entries").set(pending.len() as f64);
        gauge!("spool_unreadable").set(unreadable as f64);
        Ok(Arc::new(Spool {
            dir,
            max_bytes: cfg.max_bytes,
            shared: Arc::new(Shared {
                bytes: AtomicU64::new(total),
                pending: Mutex::new(pending),
                notify: Notify::new(),
            }),
            dests: RwLock::new(HashMap::new()),
            backoff_base: base,
            backoff_cap: cap,
            warned_sinks: Mutex::new(HashSet::new()),
            #[cfg(test)]
            unknown_sink_attempts: AtomicU64::new(0),
        }))
    }

    /// Register the destination sinks for `sink_id`. Errors on a duplicate id.
    pub fn register(
        &self,
        sink_id: &str,
        s3: Arc<dyn UploadSink>,
        descriptor: Option<Arc<dyn UploadSink>>,
    ) -> anyhow::Result<()> {
        let mut dests = self.dests.write().unwrap_or_else(|e| e.into_inner());
        if dests.contains_key(sink_id) {
            anyhow::bail!("spool sink id {sink_id:?} registered twice");
        }
        dests.insert(sink_id.to_owned(), Dest { s3, descriptor });
        Ok(())
    }

    /// Durably persist one file (+ optional descriptor). Returns only after the entry is
    /// committed on disk, so the caller may treat the data as owned by the spool.
    pub async fn commit(
        &self,
        sink_id: &str,
        key: &str,
        body: &[u8],
        descriptor: Option<&DescriptorPayload>,
    ) -> Result<(), SpoolReject> {
        let desc_len = descriptor.map_or(0, |d| d.body.len()) as u64;
        let total = body.len() as u64 + desc_len;
        let prev = self.shared.bytes.fetch_add(total, Ordering::SeqCst);
        if prev.saturating_add(total) > self.max_bytes {
            self.shared.bytes.fetch_sub(total, Ordering::SeqCst);
            counter!("spool_rejected", "reason" => "full").increment(1);
            return Err(SpoolReject::Full);
        }

        // The blocking closure owns the whole post-reservation bookkeeping (insert into
        // `pending`, or roll the reservation back), so cancelling this future while the write
        // is in flight can neither leak the reservation nor orphan a committed entry.
        let id = new_entry_id();
        let dir = self.dir.clone();
        let shared = self.shared.clone();
        let (sink_id, key) = (sink_id.to_owned(), key.to_owned());
        let (body, descriptor) = (body.to_vec(), descriptor.cloned());
        let res = tokio::task::spawn_blocking(move || {
            let meta = EntryMeta {
                version: META_VERSION,
                sink_id,
                key,
                descriptor_key: descriptor.as_ref().map(|d| d.key.clone()),
                parquet_bytes: body.len() as u64,
                descriptor_bytes: desc_len,
                sha256: hex::encode(Sha256::digest(&body)),
            };
            let desc = descriptor.as_ref().map(|d| d.body.as_slice());
            match write_entry_blocking(&dir, &id, &meta, &body, desc) {
                Ok(()) => {
                    shared.insert(id, meta);
                    Ok(())
                }
                Err(e) => {
                    shared.bytes.fetch_sub(total, Ordering::SeqCst);
                    Err(e.to_string())
                }
            }
        })
        .await;
        match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => {
                counter!("spool_rejected", "reason" => "io").increment(1);
                Err(SpoolReject::Io(msg))
            }
            Err(e) => {
                // The closure panicked before settling the reservation.
                self.shared.bytes.fetch_sub(total, Ordering::SeqCst);
                counter!("spool_rejected", "reason" => "io").increment(1);
                Err(SpoolReject::Io(format!("spool write task failed: {e}")))
            }
        }
    }

    /// Number of complete entries awaiting upload.
    pub fn pending_entries(&self) -> usize {
        self.shared.lock().len()
    }

    /// Bytes (Parquet + descriptors) held by complete entries.
    pub fn pending_bytes(&self) -> u64 {
        self.shared.bytes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn pending_keys_oldest_first(&self) -> Vec<String> {
        let pending = self.shared.lock();
        pending.values().map(|p| p.meta.key.clone()).collect()
    }

    /// Spawn the background uploader; it replays everything already pending first.
    pub fn spawn_uploader(self: &Arc<Self>) -> UploaderHandle {
        let (stop, stop_rx) = watch::channel(false);
        let spool = self.clone();
        let join = tokio::spawn(async move { spool.run_uploader(stop_rx).await });
        UploaderHandle { stop, join }
    }

    /// One immediate attempt per pending entry (ignoring backoff), oldest first, until every
    /// entry was tried or `budget` elapses. Returns the number of entries still pending.
    pub async fn drain(&self, budget: Duration) -> usize {
        let deadline = Instant::now() + budget;
        let ids: Vec<String> = self.shared.lock().keys().cloned().collect();
        for id in ids {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.attempt(&id, remaining.min(UPLOAD_ATTEMPT_TIMEOUT))
                .await;
        }
        self.pending_entries()
    }

    fn retry_delay(&self, attempts: u32) -> Duration {
        let factor = 1u32 << attempts.saturating_sub(1).min(20);
        self.backoff_base
            .saturating_mul(factor)
            .min(self.backoff_cap)
    }

    fn next_due(&self) -> Due {
        let now = Instant::now();
        let pending = self.shared.lock();
        let mut earliest: Option<Instant> = None;
        for (id, p) in pending.iter() {
            if p.next_attempt <= now {
                return Due::Now(id.clone());
            }
            earliest = Some(earliest.map_or(p.next_attempt, |e| e.min(p.next_attempt)));
        }
        earliest.map_or(Due::Idle, Due::At)
    }

    async fn run_uploader(&self, mut stop: watch::Receiver<bool>) {
        while !*stop.borrow() {
            match self.next_due() {
                Due::Now(id) => {
                    // A stop request cancels an in-flight attempt: safe, because uploads are
                    // idempotent and all bookkeeping happens in blocking closures.
                    tokio::select! {
                        () = self.attempt(&id, UPLOAD_ATTEMPT_TIMEOUT) => {}
                        r = stop.changed() => if r.is_err() { break },
                    }
                }
                Due::At(t) => {
                    tokio::select! {
                        () = self.shared.notify.notified() => {}
                        () = tokio::time::sleep_until(t.into()) => {}
                        r = stop.changed() => if r.is_err() { break },
                    }
                }
                Due::Idle => {
                    tokio::select! {
                        () = self.shared.notify.notified() => {}
                        r = stop.changed() => if r.is_err() { break },
                    }
                }
            }
        }
    }

    /// Schedule the next retry of `id` after a failure.
    fn record_failure(&self, id: &str, sink_id: &str, reason: &str) {
        counter!("spool_upload_errors", "sink" => sink_id.to_owned()).increment(1);
        if should_log_now() {
            warn!(
                sink = sink_id,
                entry = id,
                reason,
                "spool upload failed; will retry"
            );
        }
        let mut pending = self.shared.lock();
        if let Some(p) = pending.get_mut(id) {
            p.attempts = p.attempts.saturating_add(1);
            p.next_attempt = Instant::now() + self.retry_delay(p.attempts);
        }
    }

    /// One delivery attempt of entry `id`, bounded by `limit`.
    async fn attempt(&self, id: &str, limit: Duration) {
        let Some(meta) = self.shared.lock().get(id).map(|p| p.meta.clone()) else {
            return;
        };
        let dest = {
            let dests = self.dests.read().unwrap_or_else(|e| e.into_inner());
            dests
                .get(&meta.sink_id)
                .map(|d| (d.s3.clone(), d.descriptor.clone()))
        };
        let Some((s3, descriptor)) = dest else {
            #[cfg(test)]
            self.unknown_sink_attempts.fetch_add(1, Ordering::SeqCst);
            let first = self
                .warned_sinks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(meta.sink_id.clone());
            if first {
                warn!(
                    sink = %meta.sink_id,
                    "spool entry for a sink that is not registered; keeping it on disk"
                );
            }
            if let Some(p) = self.shared.lock().get_mut(id) {
                p.next_attempt = Instant::now() + self.backoff_cap;
            }
            return;
        };

        let (dir, shared, id_owned, meta2) = (
            self.dir.clone(),
            self.shared.clone(),
            id.to_owned(),
            meta.clone(),
        );
        let loaded =
            tokio::task::spawn_blocking(move || load_for_upload(&shared, &dir, &id_owned, &meta2))
                .await;
        let (parquet, desc_bytes) = match loaded {
            Ok(Loaded::Ready(p, d)) => (p, d),
            Ok(Loaded::Gone) => return,
            Ok(Loaded::Retry(reason)) => {
                self.record_failure(id, &meta.sink_id, &reason);
                return;
            }
            Err(e) => {
                self.record_failure(id, &meta.sink_id, &format!("read task failed: {e}"));
                return;
            }
        };

        let upload = async {
            s3.upload(&meta.key, parquet)
                .await
                .context("parquet upload")?;
            if let Some(dkey) = &meta.descriptor_key {
                match (&descriptor, desc_bytes) {
                    (Some(d), Some(bytes)) => {
                        d.upload(dkey, bytes).await.context("descriptor upload")?;
                    }
                    _ => warn!(
                        sink = %meta.sink_id,
                        "spool entry has a descriptor but no descriptor sink is configured; \
                         treating it as delivered"
                    ),
                }
            }
            anyhow::Ok(())
        };
        match tokio::time::timeout(limit, upload).await {
            Ok(Ok(())) => {
                let (dir, shared, id_owned) =
                    (self.dir.clone(), self.shared.clone(), id.to_owned());
                let done = tokio::task::spawn_blocking(move || {
                    remove_entry_files(&dir, &id_owned);
                    shared.forget(&id_owned);
                })
                .await;
                match done {
                    Ok(()) => counter!("spool_uploaded", "sink" => meta.sink_id).increment(1),
                    Err(e) => {
                        self.record_failure(id, &meta.sink_id, &format!("cleanup failed: {e}"))
                    }
                }
            }
            Ok(Err(e)) => self.record_failure(id, &meta.sink_id, &format!("{e:#}")),
            Err(_) => self.record_failure(id, &meta.sink_id, "attempt timed out"),
        }
    }
}

/// What the uploader loop should do next.
enum Due {
    Now(String),
    At(Instant),
    Idle,
}

/// Result of reading an entry's files for upload.
enum Loaded {
    Ready(Vec<u8>, Option<Vec<u8>>),
    /// Quarantined and forgotten.
    Gone,
    Retry(String),
}

/// Quarantine entry `id` and drop it from the pending map.
fn quarantine_entry(shared: &Shared, dir: &Path, id: &str, reason: &str) -> Loaded {
    quarantine(dir, id, reason);
    shared.forget(id);
    Loaded::Gone
}

/// Read the Parquet (and descriptor) of `id`, verifying length and sha256 against `meta`.
fn load_for_upload(shared: &Shared, dir: &Path, id: &str, meta: &EntryMeta) -> Loaded {
    let parquet = match read_required(&dir.join(format!("{id}.parquet")), "parquet") {
        Ok(b) => b,
        Err(Invalid::Corrupt(r)) => return quarantine_entry(shared, dir, id, &r),
        Err(Invalid::Transient(r)) => return Loaded::Retry(r),
    };
    if parquet.len() as u64 != meta.parquet_bytes
        || hex::encode(Sha256::digest(&parquet)) != meta.sha256
    {
        return quarantine_entry(shared, dir, id, "parquet length or sha256 mismatch");
    }
    let desc = if meta.descriptor_key.is_some() {
        match read_required(&dir.join(format!("{id}.json")), "descriptor") {
            Ok(b) if b.len() as u64 == meta.descriptor_bytes => Some(b),
            Ok(_) => return quarantine_entry(shared, dir, id, "descriptor length mismatch"),
            Err(Invalid::Corrupt(r)) => return quarantine_entry(shared, dir, id, &r),
            Err(Invalid::Transient(r)) => return Loaded::Retry(r),
        }
    } else {
        None
    };
    Loaded::Ready(parquet, desc)
}

/// Handle to the background uploader task.
#[derive(Debug)]
pub struct UploaderHandle {
    stop: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl UploaderHandle {
    /// Stop the uploader. An in-flight attempt is cancelled (uploads are idempotent and the
    /// entry stays pending), so this returns promptly.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.join.await;
    }
}

static GLOBAL: OnceLock<Arc<Spool>> = OnceLock::new();

/// Install the process-wide spool. The first call wins; later calls return it unchanged
/// (`main` and `Server::new` both call this).
pub fn init_global(cfg: &SpoolConfig) -> anyhow::Result<Arc<Spool>> {
    if let Some(s) = GLOBAL.get() {
        return Ok(s.clone());
    }
    let spool =
        Spool::open(cfg).with_context(|| format!("opening spool at {}", cfg.dir.display()))?;
    Ok(GLOBAL.get_or_init(|| spool).clone())
}

/// The installed spool, if `[spool]` is configured.
pub fn global() -> Option<Arc<Spool>> {
    GLOBAL.get().cloned()
}

/// Wrap a writer's S3 sink with the spool when one is installed. Local sinks and sinks whose
/// id is already registered are returned unchanged. `source` is the fixed ParquetSink label,
/// so the id (`"<source>.s3"`) is bounded and stable across restarts.
pub fn wrap_for_writer(
    s3: Arc<dyn UploadSink>,
    descriptor: Option<Arc<dyn UploadSink>>,
    source: &'static str,
) -> Arc<dyn UploadSink> {
    wrap_with(global(), s3, descriptor, source)
}

fn wrap_with(
    spool: Option<Arc<Spool>>,
    s3: Arc<dyn UploadSink>,
    descriptor: Option<Arc<dyn UploadSink>>,
    source: &'static str,
) -> Arc<dyn UploadSink> {
    let Some(spool) = spool else { return s3 };
    if s3.target_label() != "s3" {
        return s3;
    }
    let sink_id = format!("{source}.s3");
    if let Err(e) = spool.register(&sink_id, s3.clone(), descriptor) {
        warn!(sink_id, "spool: {e}; this sink will not be spooled");
        return s3;
    }
    Arc::new(SpoolingUploadSink::new(s3, spool, sink_id))
}

/// An [`UploadSink`] decorator that persists flushed files to the [`Spool`] instead of
/// uploading inline. If the spool refuses (full / I/O error) it uploads directly through
/// `inner` -- the pre-spool behaviour -- and returns that result, so a failure reaches the
/// writer's existing requeue path.
pub struct SpoolingUploadSink {
    inner: Arc<dyn UploadSink>,
    spool: Arc<Spool>,
    sink_id: String,
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spool")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SpoolingUploadSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpoolingUploadSink")
            .field("sink_id", &self.sink_id)
            .finish_non_exhaustive()
    }
}

impl SpoolingUploadSink {
    /// Decorate `inner`; entries are tagged with `sink_id` (must match `Spool::register`).
    pub fn new(inner: Arc<dyn UploadSink>, spool: Arc<Spool>, sink_id: impl Into<String>) -> Self {
        Self {
            inner,
            spool,
            sink_id: sink_id.into(),
        }
    }
}

/// Second-granularity gate so a full or broken spool logs once per second, not per flush.
fn should_log_now() -> bool {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    LAST.swap(now, Ordering::Relaxed) != now
}

#[async_trait]
impl UploadSink for SpoolingUploadSink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        self.inner.upload(key, body).await
    }

    fn target_label(&self) -> &'static str {
        self.inner.target_label()
    }

    fn location_hint(&self) -> String {
        self.inner.location_hint()
    }

    async fn upload_with_descriptor(
        &self,
        key: &str,
        body: Vec<u8>,
        descriptor: Option<DescriptorPayload>,
    ) -> anyhow::Result<UploadDisposition> {
        match self
            .spool
            .commit(&self.sink_id, key, &body, descriptor.as_ref())
            .await
        {
            Ok(()) => Ok(UploadDisposition::Spooled),
            Err(reject) => {
                if should_log_now() {
                    warn!(sink = %self.sink_id, ?reject, "spool refused entry; uploading directly");
                }
                self.inner.upload(key, body).await?;
                Ok(UploadDisposition::Delivered)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::buffered_writer::{DescriptorPayload, UploadDisposition, UploadSink};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    type Uploads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    type Events = Arc<Mutex<Vec<String>>>;

    /// In-memory sink double. `label` is its `target_label`; `tag` prefixes entries in the
    /// shared event log (`"<tag>:<key>"`, successful uploads only).
    struct MemSink {
        label: &'static str,
        tag: &'static str,
        uploads: Uploads,
        fail: Arc<AtomicBool>,
        fail_next: Arc<AtomicUsize>,
        events: Events,
        calls: Arc<Mutex<Vec<(Instant, String)>>>,
    }

    /// A sink plus the handles tests use to observe and script it.
    struct Mem {
        sink: Arc<dyn UploadSink>,
        uploads: Uploads,
        fail: Arc<AtomicBool>,
        fail_next: Arc<AtomicUsize>,
        calls: Arc<Mutex<Vec<(Instant, String)>>>,
    }

    impl Mem {
        fn build(label: &'static str, tag: &'static str, events: Events) -> Mem {
            let m = MemSink {
                label,
                tag,
                uploads: Arc::default(),
                fail: Arc::default(),
                fail_next: Arc::default(),
                events,
                calls: Arc::default(),
            };
            Mem {
                uploads: m.uploads.clone(),
                fail: m.fail.clone(),
                fail_next: m.fail_next.clone(),
                calls: m.calls.clone(),
                sink: Arc::new(m),
            }
        }

        fn keys(&self) -> Vec<String> {
            self.uploads
                .lock()
                .unwrap()
                .iter()
                .map(|(k, _)| k.clone())
                .collect()
        }
    }

    impl MemSink {
        #[allow(clippy::new_ret_no_self)]
        fn new(label: &'static str) -> (Arc<dyn UploadSink>, Uploads) {
            let m = Mem::build(label, "mem", Events::default());
            (m.sink, m.uploads)
        }

        fn with_switch(label: &'static str) -> (Arc<dyn UploadSink>, Uploads, Arc<AtomicBool>) {
            let m = Mem::build(label, "mem", Events::default());
            (m.sink, m.uploads, m.fail)
        }
    }

    #[async_trait]
    impl UploadSink for MemSink {
        async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((Instant::now(), key.to_string()));
            let scripted = self
                .fail_next
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if scripted || self.fail.load(Ordering::SeqCst) {
                anyhow::bail!("injected failure");
            }
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{key}", self.tag));
            self.uploads.lock().unwrap().push((key.to_string(), body));
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            self.label
        }
        fn location_hint(&self) -> String {
            "mem://".into()
        }
    }

    fn cfg(path: &Path, max_bytes: u64) -> SpoolConfig {
        SpoolConfig {
            dir: path.to_path_buf(),
            max_bytes,
        }
    }

    fn sorted_names(path: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "corrupt")
            .collect();
        v.sort();
        v
    }

    fn counter(
        snap: &metrics_util::debugging::Snapshotter,
        name: &str,
        label: Option<&str>,
    ) -> u64 {
        snap.snapshot()
            .into_vec()
            .into_iter()
            .filter(|(k, ..)| {
                k.key().name() == name
                    && label.is_none_or(|l| k.key().labels().any(|x| x.value() == l))
            })
            .map(|(_, _, _, v)| match v {
                DebugValue::Counter(c) => c,
                _ => 0,
            })
            .sum()
    }

    fn gauge(snap: &metrics_util::debugging::Snapshotter, name: &str) -> f64 {
        snap.snapshot()
            .into_vec()
            .into_iter()
            .find_map(|(k, _, _, v)| match v {
                DebugValue::Gauge(g) if k.key().name() == name => Some(g.into_inner()),
                _ => None,
            })
            .unwrap_or(f64::NAN)
    }

    fn corrupt_names(path: &Path) -> Vec<String> {
        let c = path.join("corrupt");
        if !c.exists() {
            return vec![];
        }
        sorted_names(&c)
    }

    #[tokio::test]
    async fn test_commit_writes_parquet_descriptor_and_meta_and_counts_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        let d = DescriptorPayload {
            key: "p/a.json".into(),
            body: b"{\"x\":1}".to_vec(),
        };
        spool
            .commit("hec.s3", "hec/a.parquet", b"PAR1data", Some(&d))
            .await
            .unwrap();
        let names = sorted_names(dir.path());
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(names.iter().any(|n| n.ends_with(".parquet")));
        assert!(names.iter().any(|n| n.ends_with(".json")));
        assert!(names.iter().any(|n| n.ends_with(".meta")));
        assert!(names.iter().all(|n| !n.ends_with(".tmp")));
        assert_eq!(spool.pending_entries(), 1);
        assert_eq!(spool.pending_bytes(), 8 + 7);
    }

    #[tokio::test]
    async fn test_commit_without_descriptor_writes_no_json() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        spool.commit("s", "k", b"abc", None).await.unwrap();
        let names = sorted_names(dir.path());
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.iter().any(|n| n.ends_with(".parquet")));
        assert!(names.iter().any(|n| n.ends_with(".meta")));
        assert_eq!(spool.pending_bytes(), 3);
    }

    #[tokio::test]
    async fn test_commit_rejects_full_without_writing_or_leaking_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 10)).unwrap();
        let r = spool.commit("s", "k", &[0u8; 11], None).await;
        assert!(matches!(r, Err(SpoolReject::Full)));
        assert!(sorted_names(dir.path()).is_empty());
        assert_eq!(spool.pending_bytes(), 0);
        // a smaller entry still fits afterwards (reservation was rolled back)
        spool.commit("s", "k2", &[0u8; 10], None).await.unwrap();
    }

    #[tokio::test]
    async fn test_commit_returns_io_reject_when_dir_vanishes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool");
        let spool = Spool::open(&cfg(&path, 1 << 20)).unwrap();
        std::fs::remove_dir_all(&path).unwrap();
        let r = spool.commit("s", "k", b"x", None).await;
        assert!(matches!(r, Err(SpoolReject::Io(_))), "{r:?}");
        assert_eq!(spool.pending_bytes(), 0);
        assert_eq!(spool.pending_entries(), 0);
    }

    #[tokio::test]
    async fn test_spool_rejected_metric_increments_for_full_and_io() {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool");
        let spool = Spool::open(&cfg(&path, 5)).unwrap();
        assert_eq!(counter(&snap, "spool_rejected", None), 0);
        let _ = spool.commit("s", "k", &[0u8; 6], None).await;
        assert_eq!(counter(&snap, "spool_rejected", Some("full")), 1);
        std::fs::remove_dir_all(&path).unwrap();
        let _ = spool.commit("s", "k", b"x", None).await;
        assert_eq!(counter(&snap, "spool_rejected", Some("io")), 1);
        assert_eq!(counter(&snap, "spool_rejected", None), 2);
    }

    #[test]
    fn test_open_deletes_partial_tmp_files_and_uncommitted_orphans() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("0001-a.parquet.tmp"), b"half").unwrap();
        std::fs::write(dir.path().join("0002-b.parquet"), b"no meta").unwrap();
        std::fs::write(dir.path().join("0002-b.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("0003-c.meta.tmp"), b"{").unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        assert!(
            sorted_names(dir.path()).is_empty(),
            "{:?}",
            sorted_names(dir.path())
        );
        assert_eq!(spool.pending_entries(), 0);
    }

    #[tokio::test]
    async fn test_open_loads_complete_entries_oldest_first_and_recounts_bytes() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
            s.commit("a", "k1", b"11", None).await.unwrap();
            s.commit("a", "k2", b"2222", None).await.unwrap();
        }
        let reopened = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        assert_eq!(reopened.pending_entries(), 2);
        assert_eq!(reopened.pending_bytes(), 6);
        assert_eq!(reopened.pending_keys_oldest_first(), vec!["k1", "k2"]);
    }

    /// Writes one valid entry, returns its id (file stem) after dropping the spool.
    async fn seed_entry(path: &Path, with_descriptor: bool) -> String {
        let s = Spool::open(&cfg(path, 1 << 20)).unwrap();
        let d = DescriptorPayload {
            key: "d.json".into(),
            body: b"{}".to_vec(),
        };
        s.commit("a", "k", b"PAR1", with_descriptor.then_some(&d))
            .await
            .unwrap();
        let name = sorted_names(path)
            .into_iter()
            .find(|n| n.ends_with(".meta"))
            .unwrap();
        name.trim_end_matches(".meta").to_string()
    }

    async fn assert_quarantined_on_open(path: &Path, id: &str) {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let s = Spool::open(&cfg(path, 1 << 20)).unwrap();
        assert_eq!(s.pending_entries(), 0);
        assert_eq!(s.pending_bytes(), 0);
        assert!(
            sorted_names(path).is_empty(),
            "main dir not clean: {:?}",
            sorted_names(path)
        );
        let moved = corrupt_names(path);
        assert!(
            moved.iter().any(|n| n == &format!("{id}.meta")),
            "{moved:?}"
        );
        assert_eq!(counter(&snap, "spool_corrupt", None), 1);
    }

    #[test]
    fn test_open_quarantines_entry_whose_parquet_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let meta = EntryMeta {
            version: META_VERSION,
            sink_id: "a".into(),
            key: "k".into(),
            descriptor_key: None,
            parquet_bytes: 4,
            descriptor_bytes: 0,
            sha256: hex::encode(Sha256::digest(b"PAR1")),
        };
        std::fs::write(
            dir.path().join("0001-x.meta"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(assert_quarantined_on_open(dir.path(), "0001-x"));
    }

    #[tokio::test]
    async fn test_open_quarantines_entry_with_sha256_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let id = seed_entry(dir.path(), true).await;
        // same length, different bytes: only the hash can catch it
        std::fs::write(dir.path().join(format!("{id}.parquet")), b"PAR2").unwrap();
        assert_quarantined_on_open(dir.path(), &id).await;
        assert!(corrupt_names(dir.path()).contains(&format!("{id}.json")));
    }

    #[tokio::test]
    async fn test_open_quarantines_entry_with_unknown_meta_version() {
        let dir = tempfile::tempdir().unwrap();
        let id = seed_entry(dir.path(), false).await;
        let mp = dir.path().join(format!("{id}.meta"));
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
        v["version"] = serde_json::json!(99);
        std::fs::write(&mp, serde_json::to_vec(&v).unwrap()).unwrap();
        assert_quarantined_on_open(dir.path(), &id).await;
    }

    #[tokio::test]
    async fn test_open_quarantines_unparseable_meta_and_missing_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let id = seed_entry(dir.path(), true).await;
        std::fs::remove_file(dir.path().join(format!("{id}.json"))).unwrap();
        assert_quarantined_on_open(dir.path(), &id).await;

        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("0009-z.meta"), b"not json").unwrap();
        let s = Spool::open(&cfg(dir2.path(), 1 << 20)).unwrap();
        assert_eq!(s.pending_entries(), 0);
        assert_eq!(corrupt_names(dir2.path()), vec!["0009-z.meta"]);
    }

    #[tokio::test]
    async fn test_spooling_sink_spools_and_reports_spooled_with_inner_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        let (inner, uploads) = MemSink::new("s3");
        let sink = SpoolingUploadSink::new(inner, spool.clone(), "hec.s3");
        let d = Some(DescriptorPayload {
            key: "a.json".into(),
            body: b"{}".to_vec(),
        });
        let r = sink
            .upload_with_descriptor("hec/a.parquet", b"PAR1".to_vec(), d)
            .await
            .unwrap();
        assert_eq!(r, UploadDisposition::Spooled);
        assert!(
            uploads.lock().unwrap().is_empty(),
            "spooling must not upload inline"
        );
        assert_eq!(spool.pending_entries(), 1);
        assert_eq!(sink.target_label(), "s3");
        assert_eq!(sink.location_hint(), "mem://");
    }

    #[tokio::test]
    async fn test_spooling_sink_falls_through_to_direct_upload_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1)).unwrap();
        let (inner, uploads) = MemSink::new("s3");
        let sink = SpoolingUploadSink::new(inner, spool.clone(), "hec.s3");
        let r = sink
            .upload_with_descriptor("hec/a.parquet", b"PAR1".to_vec(), None)
            .await
            .unwrap();
        assert_eq!(r, UploadDisposition::Delivered);
        assert_eq!(
            uploads.lock().unwrap().as_slice(),
            &[("hec/a.parquet".to_string(), b"PAR1".to_vec())]
        );
        assert_eq!(spool.pending_entries(), 0);
        assert!(sorted_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn test_spooling_sink_falls_through_when_spool_dir_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool");
        let spool = Spool::open(&cfg(&path, 1 << 20)).unwrap();
        std::fs::remove_dir_all(&path).unwrap();
        let (inner, uploads) = MemSink::new("s3");
        let sink = SpoolingUploadSink::new(inner, spool, "s");
        let r = sink
            .upload_with_descriptor("k", b"x".to_vec(), None)
            .await
            .unwrap();
        assert_eq!(r, UploadDisposition::Delivered);
        assert_eq!(uploads.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_spooling_sink_fallthrough_error_propagates_so_writer_requeues() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1)).unwrap();
        let (inner, uploads, fail) = MemSink::with_switch("s3");
        fail.store(true, Ordering::SeqCst);
        let sink = SpoolingUploadSink::new(inner, spool.clone(), "hec.s3");
        let r = sink
            .upload_with_descriptor("hec/a.parquet", b"PAR1".to_vec(), None)
            .await;
        assert!(
            r.is_err(),
            "inner failure must surface as Err for the requeue path"
        );
        assert!(uploads.lock().unwrap().is_empty());
        assert_eq!(spool.pending_entries(), 0);
    }

    #[test]
    fn test_register_rejects_duplicate_sink_id() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        let (s3, _) = MemSink::new("s3");
        spool.register("x", s3.clone(), None).unwrap();
        assert!(spool.register("x", s3.clone(), None).is_err());
        spool.register("y", s3, None).unwrap();
    }

    #[tokio::test]
    async fn test_open_leaves_entry_in_place_on_transient_read_error() {
        use std::os::unix::fs::PermissionsExt;
        if std::process::Command::new("id")
            .arg("-u")
            .output()
            .unwrap()
            .stdout
            == b"0\n"
        {
            return; // root ignores file modes; the error cannot be provoked
        }
        let dir = tempfile::tempdir().unwrap();
        let id = seed_entry(dir.path(), false).await;
        let pq = dir.path().join(format!("{id}.parquet"));
        std::fs::set_permissions(&pq, std::fs::Permissions::from_mode(0o000)).unwrap();
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let s = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        std::fs::set_permissions(&pq, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(s.pending_entries(), 0);
        assert!(
            s.pending_bytes() >= 4,
            "unreadable entry's on-disk bytes must count toward the cap"
        );
        assert_eq!(gauge(&snap, "spool_unreadable"), 1.0);
        assert!(corrupt_names(dir.path()).is_empty());
        assert_eq!(counter(&snap, "spool_corrupt", None), 0);
        assert!(pq.exists() && dir.path().join(format!("{id}.meta")).exists());
        // next open, now readable, loads it
        let again = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        assert_eq!(again.pending_entries(), 1);
    }

    fn fast_spool(path: &Path) -> Arc<Spool> {
        Spool::open_with_backoff(
            &cfg(path, 1 << 20),
            Duration::from_millis(10),
            Duration::from_millis(40),
        )
        .unwrap()
    }

    async fn wait_for(mut f: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        f()
    }

    fn desc(key: &str) -> DescriptorPayload {
        DescriptorPayload {
            key: key.into(),
            body: b"{\"d\":1}".to_vec(),
        }
    }

    #[tokio::test]
    async fn test_uploader_uploads_parquet_then_descriptor_then_deletes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let events = Events::default();
        let s3 = Mem::build("s3", "parquet", events.clone());
        let ds = Mem::build("s3", "descriptor", events.clone());
        spool
            .register("hec.s3", s3.sink.clone(), Some(ds.sink.clone()))
            .unwrap();
        spool
            .commit("hec.s3", "hec/a.parquet", b"PAR1", Some(&desc("a.json")))
            .await
            .unwrap();
        let up = spool.spawn_uploader();
        assert!(wait_for(|| spool.pending_entries() == 0).await);
        up.shutdown().await;
        assert_eq!(
            *events.lock().unwrap(),
            vec!["parquet:hec/a.parquet", "descriptor:a.json"]
        );
        assert!(sorted_names(dir.path()).is_empty());
        assert_eq!(spool.pending_bytes(), 0);
    }

    #[tokio::test]
    async fn test_uploader_keeps_entry_when_descriptor_upload_fails_then_retries_both_with_same_keys()
     {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let events = Events::default();
        let s3 = Mem::build("s3", "parquet", events.clone());
        let ds = Mem::build("s3", "descriptor", events.clone());
        ds.fail_next.store(1, Ordering::SeqCst);
        spool
            .register("hec.s3", s3.sink.clone(), Some(ds.sink.clone()))
            .unwrap();
        spool
            .commit("hec.s3", "hec/a.parquet", b"PAR1", Some(&desc("a.json")))
            .await
            .unwrap();
        let up = spool.spawn_uploader();
        assert!(wait_for(|| spool.pending_entries() == 0).await);
        up.shutdown().await;
        let s3_calls: Vec<String> = s3
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.1.clone())
            .collect();
        let ds_calls: Vec<String> = ds
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.1.clone())
            .collect();
        assert_eq!(s3_calls, vec!["hec/a.parquet", "hec/a.parquet"]);
        assert_eq!(ds_calls, vec!["a.json", "a.json"]);
        let ups = s3.uploads.lock().unwrap();
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0], ups[1], "same key and identical bytes on the retry");
        assert_eq!(
            ds.keys(),
            vec!["a.json"],
            "descriptor delivered exactly once"
        );
        assert!(sorted_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn test_uploader_backs_off_exponentially_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let s3 = Mem::build("s3", "p", Events::default());
        s3.fail_next.store(5, Ordering::SeqCst);
        spool.register("s", s3.sink.clone(), None).unwrap();
        spool.commit("s", "k", b"x", None).await.unwrap();
        let up = spool.spawn_uploader();
        assert!(wait_for(|| spool.pending_entries() == 0).await);
        up.shutdown().await;
        let times: Vec<Instant> = s3.calls.lock().unwrap().iter().map(|c| c.0).collect();
        assert_eq!(times.len(), 6, "5 failures then 1 success");
        let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
        let slack = Duration::from_millis(150);
        assert!(gaps[0] < Duration::from_millis(35), "{gaps:?}");
        assert!(gaps[3] >= Duration::from_millis(35), "{gaps:?}");
        for w in gaps.windows(2) {
            assert!(
                w[1] + Duration::from_millis(15) >= w[0],
                "not non-decreasing: {gaps:?}"
            );
        }
        for g in &gaps {
            assert!(
                *g <= Duration::from_millis(40) + slack,
                "exceeds cap: {gaps:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_entry_for_unregistered_sink_is_left_on_disk_and_not_busy_looped() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open_with_backoff(
            &cfg(dir.path(), 1 << 20),
            Duration::from_millis(10),
            Duration::from_millis(100),
        )
        .unwrap();
        spool.commit("ghost.s3", "k", b"x", None).await.unwrap();
        let up = spool.spawn_uploader();
        tokio::time::sleep(Duration::from_millis(300)).await;
        up.shutdown().await;
        assert_eq!(spool.pending_entries(), 1);
        assert_eq!(sorted_names(dir.path()).len(), 2);
        let n = spool.unknown_sink_attempts.load(Ordering::SeqCst);
        assert!((1..=10).contains(&n), "wake-ups: {n}");
    }

    #[tokio::test]
    async fn test_corrupt_parquet_is_quarantined_not_uploaded() {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let s3 = Mem::build("s3", "p", Events::default());
        spool.register("s", s3.sink.clone(), None).unwrap();
        spool.commit("s", "k", b"PAR1", None).await.unwrap();
        let pq = sorted_names(dir.path())
            .into_iter()
            .find(|n| n.ends_with(".parquet"))
            .unwrap();
        std::fs::write(dir.path().join(&pq), b"PAR2").unwrap();
        let up = spool.spawn_uploader();
        assert!(wait_for(|| spool.pending_entries() == 0).await);
        up.shutdown().await;
        assert!(
            s3.calls.lock().unwrap().is_empty(),
            "nothing may be uploaded"
        );
        assert!(corrupt_names(dir.path()).contains(&pq));
        assert!(sorted_names(dir.path()).is_empty());
        assert_eq!(spool.pending_bytes(), 0);
    }

    #[tokio::test]
    async fn test_drain_attempts_every_entry_once_ignoring_backoff_and_respects_budget() {
        let dir = tempfile::tempdir().unwrap();
        // Long backoff: only `drain` ignoring it can attempt twice in this test.
        let spool = Spool::open_with_backoff(
            &cfg(dir.path(), 1 << 20),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        let s3 = Mem::build("s3", "p", Events::default());
        s3.fail.store(true, Ordering::SeqCst);
        spool.register("s", s3.sink.clone(), None).unwrap();
        spool.commit("s", "k1", b"1", None).await.unwrap();
        spool.commit("s", "k2", b"2", None).await.unwrap();
        let started = Instant::now();
        assert_eq!(spool.drain(Duration::from_millis(200)).await, 2);
        assert_eq!(spool.drain(Duration::from_millis(200)).await, 2);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            s3.calls.lock().unwrap().len(),
            4,
            "one attempt per entry per drain"
        );
        s3.fail.store(false, Ordering::SeqCst);
        assert_eq!(spool.drain(Duration::from_secs(5)).await, 0);
        assert_eq!(s3.keys(), vec!["k1", "k2"]);
        assert!(sorted_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn test_drain_with_zero_budget_attempts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let s3 = Mem::build("s3", "p", Events::default());
        spool.register("s", s3.sink.clone(), None).unwrap();
        spool.commit("s", "k", b"x", None).await.unwrap();
        assert_eq!(spool.drain(Duration::ZERO).await, 1);
        assert!(s3.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_shutdown_cancels_in_flight_attempt_promptly_and_keeps_entry() {
        struct Hang;
        #[async_trait]
        impl UploadSink for Hang {
            async fn upload(&self, _: &str, _: Vec<u8>) -> anyhow::Result<()> {
                std::future::pending().await
            }
            fn target_label(&self) -> &'static str {
                "s3"
            }
            fn location_hint(&self) -> String {
                String::new()
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        spool.register("s", Arc::new(Hang), None).unwrap();
        spool.commit("s", "k", b"x", None).await.unwrap();
        let up = spool.spawn_uploader();
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::time::timeout(Duration::from_secs(2), up.shutdown())
            .await
            .expect("shutdown must not wait for the hung upload");
        assert_eq!(spool.pending_entries(), 1);
        assert_eq!(sorted_names(dir.path()).len(), 2);
    }

    #[tokio::test]
    async fn test_cancelled_commit_still_records_entry_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        // Zero timeout: the commit future is polled once (starting the blocking write) and
        // then dropped while the write is in flight.
        let r = tokio::time::timeout(Duration::ZERO, spool.commit("s", "k", b"abcd", None)).await;
        drop(r);
        assert!(wait_for(|| spool.pending_entries() == 1).await);
        assert_eq!(spool.pending_bytes(), 4);
        assert_eq!(sorted_names(dir.path()).len(), 2);
    }

    #[tokio::test]
    async fn test_cancelled_commit_rolls_back_reservation_when_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool");
        let spool = Spool::open(&cfg(&path, 1 << 20)).unwrap();
        std::fs::remove_dir_all(&path).unwrap();
        let r = tokio::time::timeout(Duration::ZERO, spool.commit("s", "k", b"abcd", None)).await;
        drop(r);
        assert!(wait_for(|| spool.pending_bytes() == 0).await);
        assert_eq!(spool.pending_entries(), 0);
    }

    #[tokio::test]
    async fn test_upload_failure_and_success_emit_spool_metrics() {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let s3 = Mem::build("s3", "p", Events::default());
        s3.fail_next.store(1, Ordering::SeqCst);
        spool.register("hec.s3", s3.sink.clone(), None).unwrap();
        spool.commit("hec.s3", "k", b"x", None).await.unwrap();
        assert_eq!(spool.drain(Duration::from_secs(5)).await, 1);
        assert_eq!(counter(&snap, "spool_upload_errors", Some("hec.s3")), 1);
        assert_eq!(counter(&snap, "spool_uploaded", None), 0);
        assert_eq!(spool.drain(Duration::from_secs(5)).await, 0);
        assert_eq!(counter(&snap, "spool_uploaded", Some("hec.s3")), 1);
        assert_eq!(counter(&snap, "spool_upload_errors", None), 1);
    }

    #[tokio::test]
    async fn test_wrap_for_writer_returns_input_unchanged_without_global_or_for_local_targets() {
        let dir = tempfile::tempdir().unwrap();
        let spool = fast_spool(dir.path());
        let (s3, _) = MemSink::new("s3");
        let (local, _) = MemSink::new("local");

        let same = wrap_with(None, s3.clone(), None, "hec");
        assert!(Arc::ptr_eq(&same, &s3), "no spool: unchanged");

        let same = wrap_with(Some(spool.clone()), local.clone(), None, "hec");
        assert!(Arc::ptr_eq(&same, &local), "local target: unchanged");

        let wrapped = wrap_with(Some(spool.clone()), s3.clone(), None, "hec");
        assert!(!Arc::ptr_eq(&wrapped, &s3), "s3 target is wrapped");
        assert_eq!(wrapped.target_label(), "s3");
        // already registered id: falls back to the input
        let again = wrap_with(Some(spool), s3.clone(), None, "hec");
        assert!(Arc::ptr_eq(&again, &s3));
    }
}
