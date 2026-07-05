//! Local-disk Parquet persistence target.
//!
//! `LocalDiskSink` implements `UploadSink` by writing to a configured root
//! directory using the same relative key layout as S3
//! (`{prefix}/{partition}/year=/month=/day=/{uuid}.parquet`, produced by
//! `buffered_writer::build_key`). Writes are atomic: bytes land in a
//! same-directory temp file first, then are renamed into place, so a
//! concurrent reader scanning the directory never observes a partial file.

use crate::forwarding::buffered_writer::UploadSink;
use std::path::{Component, Path, PathBuf};

/// Writes Parquet objects under a root directory on local disk.
pub struct LocalDiskSink {
    root: PathBuf,
}

impl LocalDiskSink {
    /// Creates `root` (and any missing parent directories) and canonicalizes
    /// it. Fails fast on construction — mirrors `S3Sink::from_connection`'s
    /// fallibility, so callers apply the same "log and fall back" pattern
    /// already used for S3 construction failures.
    pub async fn new(root: PathBuf) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(&root).await?;
        let root = tokio::fs::canonicalize(&root).await?;
        Ok(Self { root })
    }
}

#[async_trait::async_trait]
impl UploadSink for LocalDiskSink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        // Lexical safety check, purely on the string/components of `key` —
        // runs BEFORE any filesystem side effect (in particular before
        // `create_dir_all`). Only "plain" path components are allowed, so a
        // key can never lexically climb out of `self.root` (no "..", no
        // absolute-path root, no Windows drive prefix). This is what
        // actually closes the ordering gap: without it, `create_dir_all`
        // would happily follow a malicious ".." segment (or a symlink one
        // component deeper — see the second check below) and create
        // directories outside `root` before we ever verified anything.
        if key.is_empty()
            || !Path::new(key)
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
        {
            anyhow::bail!("LocalDiskSink: rejected unsafe key: {key:?}");
        }
        let dest = self.root.join(key);
        let parent = dest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("LocalDiskSink: key has no parent: {key:?}"))?;

        // Defense-in-depth against a symlink already present under `root`
        // (planted by something other than this key) that points outside the
        // tree — a case the lexical check above cannot see, since it never
        // touches the filesystem. We must verify this BEFORE creating any
        // directory: if we called `create_dir_all(parent)` first and only
        // checked afterward, a symlink one or more components into `parent`
        // would already have been followed by the OS's normal path
        // resolution, creating directories outside `root` before we ever got
        // to the check.
        //
        // To close that ordering gap we walk up from `parent` to the deepest
        // ancestor that already exists on disk (this walk always terminates
        // at or before `self.root`, since `new()` guarantees `root` itself
        // exists) and canonicalize *that* — nothing below it has been
        // created yet, so canonicalizing it fully resolves any symlink in
        // the existing part of the path without our own mkdir calls having
        // altered what's there. Only once that ancestor is confirmed to
        // resolve inside `self.root` do we create the remaining directories.
        let mut existing_ancestor = parent;
        while !tokio::fs::try_exists(existing_ancestor).await? {
            match existing_ancestor.parent() {
                Some(p) => existing_ancestor = p,
                None => break,
            }
        }
        let canonical_ancestor = tokio::fs::canonicalize(existing_ancestor).await?;
        if !canonical_ancestor.starts_with(&self.root) {
            anyhow::bail!("LocalDiskSink: resolved path escapes root: {key:?}");
        }

        tokio::fs::create_dir_all(parent).await?;

        // Second layer, after creation: re-check `parent` itself now that it
        // exists. This is belt-and-suspenders coverage for the case where a
        // symlink escape was introduced by an ancestor that got created by
        // *this* call between the check above and now (e.g. a TOCTOU race
        // from a concurrent process), and it's what
        // `rejects_key_escaping_root_via_symlink` exercises directly.
        let canonical_parent = tokio::fs::canonicalize(parent).await?;
        if !canonical_parent.starts_with(&self.root) {
            anyhow::bail!("LocalDiskSink: resolved path escapes root: {key:?}");
        }

        let file_name = dest
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("LocalDiskSink: key has no file name: {key:?}"))?
            .to_string_lossy()
            .into_owned();
        let tmp_path = parent.join(format!(".{}.tmp-{file_name}", uuid::Uuid::new_v4()));

        tokio::fs::write(&tmp_path, &body).await?;
        tokio::fs::rename(&tmp_path, &dest).await?;
        Ok(())
    }

    fn target_label(&self) -> &'static str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_file_at_expected_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        sink.upload("zeek/conn/year=2026/month=07/day=04/abc.parquet", b"hello".to_vec())
            .await
            .unwrap();

        let written = dir
            .path()
            .join("zeek/conn/year=2026/month=07/day=04/abc.parquet");
        assert!(written.exists(), "expected file at {written:?}");
        assert_eq!(tokio::fs::read(&written).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn creates_missing_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        sink.upload("a/b/c/d.parquet", b"x".to_vec()).await.unwrap();

        assert!(dir.path().join("a/b/c/d.parquet").exists());
    }

    #[tokio::test]
    async fn no_temp_file_left_behind_after_successful_write() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        sink.upload("f.parquet", b"data".to_vec()).await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["f.parquet".to_string()], "no stray .tmp file: {entries:?}");
    }

    #[tokio::test]
    async fn rejects_path_traversal_key() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        let result = sink.upload("../../etc/passwd.parquet", b"x".to_vec()).await;
        assert!(result.is_err(), "must reject a key containing '..'");
    }

    #[tokio::test]
    async fn rejects_absolute_path_key() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        let result = sink.upload("/etc/passwd", b"x".to_vec()).await;
        assert!(result.is_err(), "must reject a key with a leading '/'");
    }

    #[tokio::test]
    async fn target_label_is_local() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();
        assert_eq!(sink.target_label(), "local");
    }

    #[tokio::test]
    async fn rejects_key_escaping_root_via_symlink() {
        // Proves the post-hoc canonicalize+starts_with check is real and
        // independently load-bearing: this key contains no ".." and no
        // leading '/', so it sails through the lexical component check.
        // Only the second, filesystem-aware check can catch it.
        let root_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(root_dir.path().to_path_buf()).await.unwrap();

        // `root/escape` is a symlink pointing outside `root` entirely.
        std::os::unix::fs::symlink(outside_dir.path(), root_dir.path().join("escape")).unwrap();

        let result = sink
            .upload("escape/sub/leak.parquet", b"x".to_vec())
            .await;
        assert!(
            result.is_err(),
            "must reject a key whose parent resolves outside root via a symlink"
        );
        assert!(
            !outside_dir.path().join("sub/leak.parquet").exists(),
            "must not have written the file outside root"
        );
    }

    #[tokio::test]
    async fn symlink_escape_creates_no_directories_outside_root() {
        // Proves the ancestor-walk closes the *pre-mkdir* gap, not just the
        // final write: the key implies several directory levels
        // (`sub/deep/`) that do not yet exist under the symlink target, so
        // if `create_dir_all` ran before the ancestor-walk check, it would
        // have created `sub` and `sub/deep` outside root before any check
        // could fire. Asserting those directories were never created (not
        // just that the file wasn't written) demonstrates the escape is
        // caught before any filesystem mutation happens outside root.
        let root_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(root_dir.path().to_path_buf()).await.unwrap();

        // `root/escape` is a symlink pointing outside `root`; the deeper
        // `sub/deep` path the key implies does not exist under it yet.
        std::os::unix::fs::symlink(outside_dir.path(), root_dir.path().join("escape")).unwrap();

        let result = sink
            .upload("escape/sub/deep/leak.parquet", b"x".to_vec())
            .await;
        assert!(
            result.is_err(),
            "must reject a key whose parent resolves outside root via a symlink"
        );
        assert!(
            !outside_dir.path().join("sub").exists(),
            "must not have created any directory outside root, not even the first level"
        );
    }

    #[tokio::test]
    async fn new_creates_missing_root_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing_root = dir.path().join("does/not/exist/yet");
        let sink = LocalDiskSink::new(missing_root.clone()).await.unwrap();
        assert!(missing_root.exists());
        sink.upload("f.parquet", b"x".to_vec()).await.unwrap();
        assert!(missing_root.join("f.parquet").exists());
    }
}
