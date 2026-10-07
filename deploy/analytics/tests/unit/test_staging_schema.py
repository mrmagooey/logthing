"""Staging models must only reference columns the Rust Parquet writers really produce.

logthing's schemas live in Rust (read-only here). The committer infers each Iceberg table's schema
from the Parquet file via pyiceberg, which maps every integer of <= 32 bits to Iceberg `int`
(Trino `integer`), 64-bit integers to `long` (`bigint`), Float64 -> `double`, Utf8 -> `varchar` and
a UTC microsecond timestamp -> `timestamp(6) with time zone`. A staging cast may widen
(integer -> bigint) but never narrow or change kind.
"""
import re

import pytest

from conftest import ANALYTICS

ROOT = ANALYTICS.parents[1]
STAGING_DIR = ANALYTICS / "dbt" / "models" / "staging"

# source table -> (Rust file, schema identifier the table's Parquet files are written with)
RUST_SCHEMAS = {
    "wef": ("src/forwarding/parquet_s3.rs", "WEF_SCHEMA"),
    "zeek_conn": ("src/zeek/schema.rs", "conn_schema"),
    "zeek_dns": ("src/zeek/schema.rs", "dns_schema"),
    "ipfix": ("src/forwarding/ipfix_s3.rs", "FLOW_RECORD_SCHEMA"),
    "sflow_flow": ("src/forwarding/sflow_s3.rs", "FLOW_SCHEMA"),
    "sflow_counter": ("src/forwarding/sflow_s3.rs", "COUNTER_SCHEMA"),
    "suricata": ("src/suricata/schema.rs", "envelope_schema"),
    "syslog": ("src/forwarding/syslog_s3.rs", "SYSLOG_SCHEMA"),
    "structured_syslog": ("src/forwarding/structured_syslog_s3.rs", "STRUCTURED_SYSLOG_SCHEMA"),
    "otlp": ("src/forwarding/otlp_s3.rs", "otlp_schema"),
    "hec": ("src/forwarding/generic_s3.rs", "generic_schema"),
}
WIDTH_RANK = {"integer": 1, "bigint": 2}
TS = "timestamp(6) with time zone"


def _balanced(text, start):
    """Index just past the bracket group opening at text[start]."""
    pairs = {"(": ")", "[": "]"}
    stack = []
    for i in range(start, len(text)):
        c = text[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]":
            assert stack.pop() == c
            if not stack:
                return i + 1
    raise AssertionError("unbalanced brackets")


def _split_args(args):
    out, depth, cur = [], 0, ""
    for c in args:
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def trino_type(arrow):
    arrow = re.sub(r"\s+", " ", arrow)
    if arrow == "ts_type()":
        return TS
    if arrow == "DataType::Utf8":
        return "varchar"
    if arrow == "DataType::Float64":
        return "double"
    if re.fullmatch(r"DataType::U?Int(8|16|32)", arrow):
        return "integer"
    if re.fullmatch(r"DataType::U?Int64", arrow):
        return "bigint"
    if arrow.startswith("DataType::Timestamp(TimeUnit::Microsecond, Some(\"UTC\""):
        return TS
    raise AssertionError(f"unmapped Arrow type {arrow}")


def rust_columns(table):
    """name -> (trino type, nullable) of the schema identified by RUST_SCHEMAS[table]."""
    rel, ident = RUST_SCHEMAS[table]
    text = (ROOT / rel).read_text()
    m = re.search(rf"(?:fn|static)\s+{ident}\b", text)
    assert m, f"{ident} not found in {rel}"
    s = text.index("Schema::new(", m.end())
    v = text.index("vec![", s)
    block = text[v + 4:_balanced(text, v + 4)]
    cols = {}
    # One pass over both forms so declaration order is preserved: `Field::new(...)` and the
    # otlp schema's `utf8("name", nullable)` closure helper.
    for fm in re.finditer(r'Field::new\(|\butf8\(\s*"(\w+)"\s*,\s*(true|false)\s*\)', block):
        if fm.group(1):
            cols[fm.group(1)] = ("varchar", fm.group(2) == "true")
            continue
        end = _balanced(block, fm.end() - 1)
        name, dtype, nullable = _split_args(block[fm.end():end - 1])
        cols[name.strip('"')] = (trino_type(dtype), nullable == "true")
    return cols


def staging_columns():
    """table -> {column: declared Trino type} from every source_or_empty(...) call."""
    found = {}
    for path in sorted(STAGING_DIR.glob("*.sql")):
        text = path.read_text()
        m = re.search(r"source_or_empty\('logthing', '(\w+)', \{(.*?)\}\)", text, re.S)
        if not m:
            continue
        found[m.group(1)] = dict(re.findall(r"'(\w+)':\s*'([^']+)'", m.group(2)))
    return found


def compatible(declared, actual):
    if declared == actual:
        return True
    return WIDTH_RANK.get(declared, 0) >= WIDTH_RANK.get(actual, 99)


@pytest.mark.parametrize("table", sorted(RUST_SCHEMAS))
def test_rust_schema_is_parsed(table):
    cols = rust_columns(table)
    assert len(cols) >= 5
    assert cols["partition_time"] == (TS, False)


def test_every_staging_column_exists_in_the_rust_schema_with_a_compatible_type():
    staging = staging_columns()
    assert set(staging) == {"wef", "zeek_conn", "zeek_dns", "ipfix", "sflow_flow", "suricata", "otlp",
                            "hec"}
    problems = []
    for table, cols in staging.items():
        actual = rust_columns(table)
        for name, declared in cols.items():
            if name not in actual:
                problems.append(f"{table}.{name}: not written by logthing")
            elif not compatible(declared, actual[name][0]):
                problems.append(f"{table}.{name}: declared {declared}, written as "
                                f"{actual[name][0]}")
    assert not problems, "\n".join(problems)


def test_compatibility_rule_allows_widening_only():
    assert compatible("bigint", "integer") and compatible("integer", "integer")
    assert not compatible("integer", "bigint")
    assert not compatible("varchar", "integer") and not compatible("bigint", "double")


def test_otlp_and_hec_schemas_have_the_documented_column_counts_and_nullability():
    otlp, hec = rust_columns("otlp"), rust_columns("hec")
    assert len(otlp) == 21 and otlp["event_uuid"] == ("varchar", False)
    assert otlp["severity_number"] == ("integer", True) and otlp["flags"][0] == "integer"
    assert list(otlp) == [
        "event_uuid", "time", "observed_time", "received_at", "severity_number",
        "severity_text", "body", "service_name", "service_namespace", "service_instance_id",
        "host_name", "peer_addr", "trace_id", "span_id", "flags", "event_name", "scope_name",
        "scope_version", "resource_attributes", "attributes", "partition_time"]
    assert len(hec) == 10 and hec["event_uuid"] == ("varchar", True)  # null on pre-0.22 rows
    assert list(hec)[:6] == ["sourcetype", "host", "time", "received_at", "fields",
                             "partition_time"]


def test_dedup_models_list_exactly_the_typed_models_columns_in_order():
    for table in ("otlp", "hec"):
        typed = re.search(r"source_or_empty\('logthing', '%s', \{(.*?)\}\)" % table,
                          (STAGING_DIR / f"stg_{table}_typed.sql").read_text(), re.S)
        typed_cols = re.findall(r"'(\w+)':", typed.group(1))
        dedup = (STAGING_DIR / f"stg_{table}.sql").read_text()
        dedup_cols = re.findall(r"'(\w+)'", re.search(r"\[(.*?)\]", dedup, re.S).group(1))
        assert dedup_cols == typed_cols and "ref('stg_%s_typed')" % table in dedup
        assert typed_cols == list(rust_columns(table))
