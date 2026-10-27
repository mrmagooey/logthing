#!/usr/bin/env python3
"""Render performance results as GitHub-flavoured markdown on stdout.

Usage:
  scripts/perf-summary.py --ingest DIR
      One table row per DIR/<fmt>/summary.json (written by scripts/profile-ingest.sh), in that
      script's format order; unknown extra directories follow, sorted.
  scripts/perf-summary.py --criterion DIR [--baseline NAME]
      One row per benchmark: DIR/<bench path>/NAME/estimates.json (NAME defaults to "new"),
      median and its 95% CI. `cargo bench -- --save-baseline X` writes both new/ and X/.
  Either or both of --ingest/--criterion may be given; each emits its own "###" section.
  A missing DIR prints a "no results" section and still exits 0, so a summary step can never be
  what fails a CI run. Unknown arguments: usage on stderr, exit 2.

Used by .github/workflows/performance.yml (appended to $GITHUB_STEP_SUMMARY). stdlib only.
"""
import json
import math
import os
import sys

FORMATS = ["syslog", "zeek", "suricata", "ipfix", "sflow", "hec", "generic", "otlp", "wef"]


def usage():
    sys.stderr.write(
        "usage: perf-summary.py [--ingest DIR] [--criterion DIR [--baseline NAME]]\n"
    )
    sys.exit(2)


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def num(v, spec="{:,.0f}"):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return "-"
    return spec.format(v)


def ingest_row(fmt, path):
    try:
        with open(path) as fh:
            s = json.load(fh)
        if not isinstance(s, dict):
            raise ValueError("summary.json is not a JSON object")
        rss = s.get("peak_rss_kb")
        rss_mb = num(rss / 1024 if num(rss) != "-" else None, "{:.1f}")
        written, sent = s.get("records_written"), s.get("loadgen_sent_records")
        ws = f"{num(written)}/{num(sent)}" if written is not None or sent is not None else "-"
        reasons = s.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [reasons]
        notes = "; ".join(str(r) for r in reasons)
        row = [
            fmt,
            str(s.get("verdict", "-")),
            num(s.get("offered_rate")),
            num(s.get("achieved_rate")),
            ws,
            rss_mb,
            num(s.get("cpu_us_per_record"), "{:.2f}"),
            notes or "-",
        ]
        return row, s
    except Exception as e:  # malformed summary must not crash the run summary
        return [fmt, "ERROR", "-", "-", "-", "-", "-", f"unreadable summary.json: {e}"], None


def ingest_section(d):
    out = ["### Ingest formats", ""]
    if not os.path.isdir(d):
        return out + [f"No results found in `{d}`.", ""]
    found = {}
    for name in os.listdir(d):
        p = os.path.join(d, name, "summary.json")
        if os.path.isfile(p):
            found[name] = p
    if not found:
        return out + [f"No results found in `{d}`.", ""]
    order = [f for f in FORMATS if f in found] + sorted(set(found) - set(FORMATS))
    rows = [ingest_row(f, found[f]) for f in order]
    passed = sum(1 for r, _ in rows if r[1] == "PASS")
    first = next((s for _, s in rows if s), {})
    host = " / ".join(str(x) for x in (first.get("host"), first.get("cpu")) if x)
    out.append(f"{passed}/{len(rows)} formats passed" + (f" ({host})" if host else ""))
    out.append("")
    out.append(
        "| format | verdict | offered/s | achieved/s | written/sent | peak RSS (MB) "
        "| CPU \u00b5s/record | notes |"
    )
    out.append("|---|---|--:|--:|--:|--:|--:|---|")
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r, _ in rows]
    out.append("")
    return out


def sig3(v):
    """Round v > 0 to 3 significant figures."""
    return round(v, 2 - int(math.floor(math.log10(v)))) if v > 0 else v


def fmt_ns(ns):
    if not isinstance(ns, (int, float)) or isinstance(ns, bool) or ns < 0 or math.isnan(ns):
        return "-"
    ns = sig3(ns)  # round first so 999.96 ns becomes 1.00 us, not "1000 ns"
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("\u00b5s", 1e3), ("ns", 1.0)):
        if ns >= scale or unit == "ns":
            v = ns / scale
            decimals = 0 if v <= 0 else max(0, 2 - int(math.floor(math.log10(v))))
            return f"{v:.{decimals}f} {unit}"
    return "-"


def criterion_section(d, baseline):
    out = [f"### Criterion benchmarks (baseline `{baseline}`)", ""]
    if not os.path.isdir(d):
        return out + [f"No results found in `{d}`.", ""]
    rows = []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x != "report"]
        if os.path.basename(root) != baseline or "estimates.json" not in files:
            continue
        bench = os.path.relpath(os.path.dirname(root), d)
        try:
            with open(os.path.join(root, "estimates.json")) as fh:
                med = json.load(fh)["median"]
            ci = med["confidence_interval"]
            rows.append((bench, fmt_ns(med["point_estimate"]),
                         f"{fmt_ns(ci['lower_bound'])} - {fmt_ns(ci['upper_bound'])}"))
        except Exception as e:
            rows.append((bench, "ERROR", f"unreadable estimates.json: {e}"))
    if not rows:
        return out + [f"No results found in `{d}`.", ""]
    out += ["| benchmark | median | 95% CI |", "|---|--:|--:|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in sorted(rows)]
    out.append("")
    return out


def main(argv):
    ingest = criterion = None
    baseline = "new"
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--ingest", "--criterion", "--baseline") and i + 1 < len(argv):
            if a == "--ingest":
                ingest = argv[i + 1]
            elif a == "--criterion":
                criterion = argv[i + 1]
            else:
                baseline = argv[i + 1]
            i += 2
        else:
            usage()
    if ingest is None and criterion is None:
        usage()
    lines = []
    sections = []
    if ingest is not None:
        sections.append(("Ingest formats", lambda: ingest_section(ingest)))
    if criterion is not None:
        sections.append(
            ("Criterion benchmarks", lambda: criterion_section(criterion, baseline)))
    for title, render in sections:
        try:
            lines += render()
        except Exception as e:  # a summary must never be what fails a run
            lines += [f"### {title}", "", f"unreadable results: {e}", ""]
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
