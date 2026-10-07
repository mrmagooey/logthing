//! Durable local spool for S3 uploads (`[spool]`). Core: entry format, accounting, replay
//! scan, and the [`SpoolingUploadSink`] decorator. The background uploader is added in a
//! later step.
//!
//! Entry = `<id>.parquet` + optional `<id>.json` (descriptor) + `<id>.meta` (commit marker).
//! `<id>` = `{unix_micros:020}-{uuid}` so lexical order is age order. Every file is written
//! as `<name>.tmp`, fsynced, renamed; the directory is fsynced after the data renames and
//! again after the `.meta` rename. An entry is complete iff its `.meta` exists, and the
//! `.meta` is removed first on delete, so a crash never leaves a committed entry whose
//! data is missing.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use async_trait::async_trait;
use metrics::{counter, gauge};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tracing::{error, warn};

use crate::config::SpoolConfig;
use crate::forwarding::buffered_writer::{DescriptorPayload, UploadDisposition, UploadSink};

const META_VERSION: u32 = 1;
const CORRUPT_DIR: &str = "corrupt";

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

// The retry fields and `Dest`/backoff below are consumed by the background uploader (Task 6).
#[allow(dead_code)]
struct Pending {
    meta: EntryMeta,
    attempts: u32,
    next_attempt: Instant,
}

#[allow(dead_code)]
struct Dest {
    s3: Arc<dyn UploadSink>,
    descriptor: Option<Arc<dyn UploadSink>>,
}

/// The spool. Cheap to share via `Arc`.
#[allow(dead_code)]
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    bytes: AtomicU64,
    pending: Mutex<BTreeMap<String, Pending>>,
    dests: RwLock<HashMap<String, Dest>>,
    notify: Notify,
    backoff_base: Duration,
    backoff_cap: Duration,
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

/// Remove every file of entry `id`: `.meta` FIRST (un-commits it), then data and tmp files.
/// Best effort; missing files are fine.
fn remove_entry_files(dir: &Path, id: &str) {
    for ext in [
        "meta",
        "meta.tmp",
        "parquet",
        "parquet.tmp",
        "json",
        "json.tmp",
    ] {
        let _ = std::fs::remove_file(dir.join(format!("{id}.{ext}")));
    }
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
                    error!(entry = %id, %reason, "spool entry unreadable; left in place, retried on next open");
                }
            }
        }
        let _ = fsync_dir(&dir);

        gauge!("spool_bytes").set(total as f64);
        gauge!("spool_entries").set(pending.len() as f64);
        Ok(Arc::new(Spool {
            dir,
            max_bytes: cfg.max_bytes,
            bytes: AtomicU64::new(total),
            pending: Mutex::new(pending),
            dests: RwLock::new(HashMap::new()),
            notify: Notify::new(),
            backoff_base: Duration::from_secs(1),
            backoff_cap: Duration::from_secs(60),
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
        let prev = self.bytes.fetch_add(total, Ordering::SeqCst);
        if prev.saturating_add(total) > self.max_bytes {
            self.bytes.fetch_sub(total, Ordering::SeqCst);
            counter!("spool_rejected", "reason" => "full").increment(1);
            return Err(SpoolReject::Full);
        }

        let id = new_entry_id();
        let dir = self.dir.clone();
        let (id2, sink_id, key) = (id.clone(), sink_id.to_owned(), key.to_owned());
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
            write_entry_blocking(&dir, &id2, &meta, &body, desc).map(|()| meta)
        })
        .await;
        let (meta, err) = match res {
            Ok(Ok(meta)) => (Some(meta), None),
            Ok(Err(e)) => (None, Some(e.to_string())),
            Err(e) => (None, Some(format!("spool write task failed: {e}"))),
        };
        let Some(meta) = meta else {
            let msg = err.unwrap_or_default();
            self.bytes.fetch_sub(total, Ordering::SeqCst);
            counter!("spool_rejected", "reason" => "io").increment(1);
            return Err(SpoolReject::Io(msg));
        };

        let entries = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
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
        gauge!("spool_bytes").set(self.bytes.load(Ordering::SeqCst) as f64);
        gauge!("spool_entries").set(entries as f64);
        self.notify.notify_one();
        Ok(())
    }

    /// Number of complete entries awaiting upload.
    pub fn pending_entries(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Bytes (Parquet + descriptors) held by complete entries.
    pub fn pending_bytes(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn pending_keys_oldest_first(&self) -> Vec<String> {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.values().map(|p| p.meta.key.clone()).collect()
    }
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
    use std::sync::atomic::AtomicBool;

    type Uploads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    struct MemSink {
        uploads: Uploads,
        fail: Arc<AtomicBool>,
    }

    impl MemSink {
        #[allow(clippy::new_ret_no_self)]
        fn new() -> (Arc<dyn UploadSink>, Uploads) {
            let (sink, uploads, _) = Self::with_switch();
            (sink, uploads)
        }

        fn with_switch() -> (Arc<dyn UploadSink>, Uploads, Arc<AtomicBool>) {
            let uploads: Uploads = Arc::default();
            let fail = Arc::new(AtomicBool::new(false));
            let sink = Arc::new(MemSink {
                uploads: uploads.clone(),
                fail: fail.clone(),
            });
            (sink, uploads, fail)
        }
    }

    #[async_trait]
    impl UploadSink for MemSink {
        async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
            if self.fail.load(Ordering::SeqCst) {
                anyhow::bail!("injected failure");
            }
            self.uploads.lock().unwrap().push((key.to_string(), body));
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "mem"
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
        let (inner, uploads) = MemSink::new();
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
        assert_eq!(sink.target_label(), "mem");
        assert_eq!(sink.location_hint(), "mem://");
    }

    #[tokio::test]
    async fn test_spooling_sink_falls_through_to_direct_upload_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(&cfg(dir.path(), 1)).unwrap();
        let (inner, uploads) = MemSink::new();
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
        let (inner, uploads) = MemSink::new();
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
        let (inner, uploads, fail) = MemSink::with_switch();
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
        let (s3, _) = MemSink::new();
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
        assert!(corrupt_names(dir.path()).is_empty());
        assert_eq!(counter(&snap, "spool_corrupt", None), 0);
        assert!(pq.exists() && dir.path().join(format!("{id}.meta")).exists());
        // next open, now readable, loads it
        let again = Spool::open(&cfg(dir.path(), 1 << 20)).unwrap();
        assert_eq!(again.pending_entries(), 1);
    }
}
