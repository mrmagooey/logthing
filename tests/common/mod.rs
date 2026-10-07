//! Shared helpers for tests that read the Parquet a local sink wrote.
#![allow(dead_code)]

use arrow::array::StringArray;
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Every `*.parquet` file under `dir`, sorted.
pub fn parquet_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "parquet") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// All record batches of all Parquet files under `dir`.
pub fn read_all(dir: &Path) -> Vec<RecordBatch> {
    let mut batches = Vec::new();
    for p in parquet_files(dir) {
        let bytes = Bytes::from(std::fs::read(&p).expect("read parquet"));
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .expect("parquet footer")
            .build()
            .expect("parquet reader");
        batches.extend(reader.map(|b| b.expect("batch")));
    }
    batches
}

/// Poll until at least `min_rows` rows are readable under `dir`, or panic after `timeout`.
pub async fn wait_for_rows(dir: &Path, min_rows: usize, timeout: Duration) -> Vec<RecordBatch> {
    let deadline = Instant::now() + timeout;
    loop {
        // A file may be mid-write; a failed read just means "try again".
        let batches = std::panic::catch_unwind(|| read_all(dir)).unwrap_or_default();
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        if rows >= min_rows {
            return batches;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {min_rows} rows under {} (have {rows})",
            dir.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Downcast a column to `StringArray`.
pub fn str_col<'a>(batch: &'a RecordBatch, name: &str) -> &'a StringArray {
    batch
        .column_by_name(name)
        .unwrap_or_else(|| panic!("missing column {name}"))
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap_or_else(|| panic!("column {name} is not Utf8"))
}
