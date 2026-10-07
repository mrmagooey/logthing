# Redaction (PII removal, pseudonymisation and masking)

logthing can drop, pseudonymise (HMAC-hash) or mask values in HEC and OTLP records before
they are stored. Redaction is configured per surface in `[hec.redaction]` and
`[otlp.redaction]`, is off by default, and costs nothing when no rule is configured.

## What it does and where it runs

Redaction covers the HEC family (`/services/collector/event`, `/services/collector/raw`,
`/ingest`) and OTLP (`/v1/logs`) only. Other sources (WEF, syslog, IPFIX, sFlow, Zeek,
Suricata) have fixed schemas and are out of scope; to cover one, add a `Redactor` call in that
source's handler.

The step runs after the request is parsed (HEC) or mapped (OTLP) and BEFORE the record gets its
`event_uuid` and before it is enqueued. Unredacted values therefore never reach the writer
channel, the on-disk spool or any Parquet file, and the `event_uuid` never depends on them.

## Configuration

```toml
[hec.redaction]
drop_fields   = ["password", "headers.authorization"]
hash_fields   = ["user.email"]
hash_key_env  = "LOGTHING_HASH_KEY"        # NAME of an environment variable, not the key
mask_patterns = ['\d{3}-\d{2}-\d{4}', 'secret=\w+']

[otlp.redaction]
drop_fields   = ["user.email", "@peer_addr"]
hash_fields   = ["@host_name", "enduser.id"]
hash_key_env  = "LOGTHING_HASH_KEY"
mask_patterns = ['\b\d{16}\b']
```

| Key | Meaning |
|---|---|
| `drop_fields` | Paths removed from the record (typed OTLP columns are set to NULL). |
| `hash_fields` | Paths replaced by the lowercase-hex HMAC-SHA256 of the value (64 characters). |
| `hash_key_env` | Name of the environment variable holding the HMAC key. Required when `hash_fields` is non-empty; at least 16 bytes. |
| `mask_patterns` | Regexes; every match inside a string value becomes `[REDACTED]`. |

Rules are validated at startup, only for enabled sections (`[hec] enabled = true`,
`[otlp] enabled = true`). Startup fails with a message naming the offending rule for: an
invalid regex or one over the size cap, a regex that can match the empty string (`x*`, `^`,
`\b`, ...), an empty path or empty path segment, a duplicate `hash_fields` path, `hash_fields`
without `hash_key_env`, a `hash_key_env` that is not a valid variable name (the value is never
echoed back), an unset variable or a key shorter than 16 bytes, and `@`-paths in
`[hec.redaction]` or unknown ones such as `@service_name`. Like all configuration, a change
needs a restart.

## Rule semantics

- **Paths** are dot-separated keys into JSON objects (`user.email`). A key may itself contain
  dots, which matters for OTLP attribute names: `user.email` matches both a nested
  `{"user":{"email":..}}` and a literal key `"user.email"`. Arrays are traversed
  transparently: the path is applied to every element.
- **HEC** rules apply to `fields` (the event, or `{"raw": "<body>"}` for `/services/collector/raw`)
  and to the envelope's indexed fields (the HEC `fields` object). Other envelope columns
  (`host`, `source`, `sourcetype`, `index`, time) are not redacted.
- **OTLP** unprefixed paths apply to BOTH `attributes` (log and scope attributes) and
  `resource_attributes`. Resource attributes are stored losslessly, so promoted keys such as
  `host.name` and `service.name` appear in `resource_attributes` as well as in their typed
  columns: to protect `host.name` you need `@host_name` (typed column) AND, if the raw value
  must not be stored, an unprefixed `host.name` rule for the repeated copy.
- **Typed OTLP columns** are addressed with `@body`, `@host_name` and `@peer_addr` (drop sets
  NULL, hash replaces the text). `@body.<path>` reaches into a body that is JSON text. Other
  typed columns (`service_name`, severity, trace and span ids, timestamps, ...) cannot be
  redacted: they drive partitioning and statistics or are not free text. Masks do not touch
  typed columns other than `body`.
- **Fail closed:** if an `@body.<path>` drop or hash rule is configured and the body looks like
  JSON (starts with `{` or `[`) but does not parse (too deeply nested, trailing comma, NaN, ...),
  logthing cannot locate the value, so it replaces the WHOLE body with `[REDACTED]` and counts
  `redactions_applied{rule="body_unparseable"}`. A plain-text body is left alone by
  `@body.<path>` rules. Watch the counter: a sudden rise means a producer is sending
  malformed JSON bodies that are being over-redacted.
- **Hash input:** a string value is hashed as its raw UTF-8 bytes (so the pseudonym of
  `alice@example.com` is `HMAC-SHA256(key, "alice@example.com")`). Any other JSON value
  (number, bool, object, array) is hashed as its canonical JSON text: compact, object keys
  sorted. JSON null is left as null. A whole array or object found at the final path key is
  hashed as one canonical JSON text (one pseudonym); arrays are only walked element by element
  while the path is still being traversed (e.g. `items.sku` over an array of objects hashes each
  object's `sku`).
- **Parse-error logs:** HEC / NDJSON / OTLP parse and decode failures are logged with the error
  category and line/column only. Logs never include record contents (they would bypass
  redaction).
- **Order:** drop, then hash, then mask. Masks therefore see hash output; a pattern broad
  enough to match 64 hex characters would mask a pseudonym.
- **Mask scope:** masks apply to string values only. Object keys and non-string leaves
  (numbers, booleans) are never masked. A JSON `@body` is masked leaf by leaf and re-serialised
  (compact, sorted keys) only if a rule actually changed it; an untouched body stays
  byte-identical. A plain-text body is masked as one string. Replacement text is literal
  (`$1` is not expanded).
- **Cost:** the regex engine is Rust's `regex` crate, which runs in time linear in the input,
  so a hostile payload cannot cause catastrophic backtracking.

## Pseudonym key management

Generate a key and supply it only through the environment:

```bash
export LOGTHING_HASH_KEY="$(openssl rand -hex 32)"
```

Pseudonyms are keyed hashes, so the same subject always maps to the same pseudonym under the
same key and joins on a pseudonymised column keep working.

**Rotation changes every pseudonym.** After a rotation, new records for `alice@example.com`
carry a different value than old ones, and joins across the rotation boundary break. Keep the
old key together with its rotation date so that you can still derive the old pseudonym of a
subject:

```bash
echo -n 'alice@example.com' | openssl dgst -sha256 -hmac "$OLD_KEY"
```

Losing the key makes pseudonyms irreversible by design, but it also makes delete-by-subject
impossible for the data written under that key, because you can no longer compute the value to
search for. Back the key up in your secrets manager and never commit it.

## Delete-by-subject (erasure requests)

logthing documents the procedure; it ships no deletion tool. To erase one subject:

1. Compute the subject's pseudonym under every key that was in use (see above).
2. Delete the rows. HEC `fields` and OTLP `attributes` are JSON text columns, so match with
   `json_extract_scalar`:

   ```sql
   DELETE FROM logs.hec  WHERE json_extract_scalar(fields, '$.user.email') = '<hmac>';
   -- dotted literal key in OTLP attributes:
   DELETE FROM logs.otlp WHERE json_extract_scalar(attributes, '$."user.email"') = '<hmac>';
   -- hashed typed column:
   DELETE FROM logs.otlp WHERE host_name = '<hmac>';
   ```

3. Rewrite the data files so the deleted rows leave them, then expire the old snapshots:

   ```sql
   ALTER TABLE logs.hec EXECUTE optimize;
   ALTER TABLE logs.hec EXECUTE expire_snapshots(retention_threshold => '7d');
   ```

Iceberg v2 deletes are merge-on-read: Trino writes position-delete files, so the rows are
logically gone at once, but the original Parquet files (with the PII, or its pseudonym) stay in
object storage until `optimize` has rewritten them AND the snapshots that reference the old
files have expired past the retention window. PII persists in those old files until that
expiry. The shortest retention Trino accepts is set by `iceberg.expire-snapshots.min-retention`
(default 7d); expiry cannot be forced earlier without lowering it.

Do not run `remove_orphan_files` against logthing's data location: it can delete files that
were written but not yet committed (see [iceberg.md](iceberg.md)). Expiring snapshots is
sufficient to physically remove the superseded files.

If the bucket uses S3 Object Lock, locked objects cannot be deleted until their retention ends,
so a locked bucket conflicts with erasure for as long as the lock lasts. Choose the lock
period with that in mind. See [object-lock.md](object-lock.md).

## Metrics

`redactions_applied{source,rule}` counts values changed, labelled `source` (`hec` or `otlp`) and
`rule` (`drop`, `hash`, `mask`, or `body_unparseable` for a fail-closed body replacement).
Only non-zero outcomes are emitted. See [metrics.md](metrics.md).
