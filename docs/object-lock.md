# S3 Object Lock (write-once retention)

S3 Object Lock makes uploaded objects write-once-read-many (WORM): for the retention period
nobody can overwrite or delete a given object version. It is the integrity guarantee for the
log archive, and supports retention requirements such as the ACSC Essential Eight and similar
log-retention controls.

## Configuration

Add two keys to any `[<source>.s3]` table (they are shared by every S3 sink):

```toml
[hec.s3]
endpoint = "https://s3.ap-southeast-2.amazonaws.com"
bucket = "logs-locked"
region = "ap-southeast-2"
access_key = "..."
secret_key = "..."
object_lock_mode = "GOVERNANCE"   # or "COMPLIANCE"
object_lock_retain_days = 365     # 1..=36500
```

- Both keys must be set together; one without the other fails startup, as does a mode other
  than `GOVERNANCE` / `COMPLIANCE` or a retention outside 1-36500 days.
- Both keys can also be set from the environment, e.g.
  `LOGTHING__HEC__S3__OBJECT_LOCK_MODE=COMPLIANCE` and
  `LOGTHING__HEC__S3__OBJECT_LOCK_RETAIN_DAYS=45` (a non-numeric retention fails startup).

## The bucket must have Object Lock enabled

Create the bucket with Object Lock enabled (this also enables versioning).
Startup does **not** probe the bucket. If it is not lock-enabled (or the endpoint does not
support Object Lock) uploads fail with an error naming Object Lock, and the writer's normal failure
path applies: nothing is dropped.

**Garage does not support Object Lock. AWS S3 and MinIO do.**

## Checksum

S3 requires an integrity checksum on Object Lock puts, so with a lock configured logthing sends
`checksum_algorithm = SHA256` on every PutObject. Without a lock, logthing sets no checksum
parameter.

## GOVERNANCE vs COMPLIANCE

- `GOVERNANCE`: principals with `s3:BypassGovernanceRetention` can still remove or shorten
  retention. Use while rolling out.
- `COMPLIANCE`: nobody, including the account root, can shorten or remove retention until it
  expires. Data uploaded under COMPLIANCE cannot be erased early, which conflicts with
  delete-by-subject (see [redaction.md](redaction.md)): choose the period accordingly.

Retention applies per object version. If the spool replays an upload, the re-upload creates a
new locked version under the same key, each with its own retain-until date.

## Do not lock the descriptor bucket or prefix

Enable Object Lock on the data bucket only. The Iceberg committer moves descriptors by
copy-then-delete, so a locked descriptor bucket or prefix makes the delete fail and the
descriptor is never finalised.

## Replays and restarts

Within a running process the spool does not re-PUT a Parquet file whose PUT already
succeeded: if only the descriptor PUT fails, retries upload the descriptor alone, so a
descriptor outage does not create a locked Parquet version per retry. This is in memory only:
a restart in the middle of such retries may PUT the Parquet once more (one extra locked
version).

## Integrity: Object Lock, not the descriptor checksum

Iceberg descriptors carry a `sha256` of the Parquet bytes (see [iceberg.md](iceberg.md)). It is
a corruption / consistency check only. It is **not** tamper evidence, because it is stored next
to the data it describes and anyone able to alter one can alter the other. Object Lock is the
integrity guarantee.

## Verifying an object

```bash
aws s3api head-object --bucket logs-locked --key hec/.../file.parquet --checksum-mode ENABLED
# shows ObjectLockMode, ObjectLockRetainUntilDate and ChecksumSHA256 (base64)
# compare with the descriptor sha256 (hex):
aws s3 cp s3://logs-locked/hec/.../file.parquet - | sha256sum
```
