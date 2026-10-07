#!/usr/bin/env python3
"""Assert no internal port is published to the host, from `docker compose ps --format json`.

Reads stdin: NDJSON (one object per line, older compose) or a single JSON array (newer compose).
Fails if there are no rows at all (an empty listing would make the check vacuous).
Lakekeeper and Postgres must publish nothing; no service may publish 3901, 3903, 5432, 8181
or 8080.
"""
import json
import sys

INTERNAL_PORTS = (3901, 3903, 5432, 8181, 8080)
INTERNAL_SERVICES = ("lakekeeper", "postgres")


def parse(text):
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def violations(rows):
    bad = []
    for r in rows:
        for p in r.get("Publishers") or []:
            if p.get("PublishedPort") and (
                    r["Service"] in INTERNAL_SERVICES or p.get("TargetPort") in INTERNAL_PORTS):
                bad.append((r["Service"], p.get("TargetPort"), p["PublishedPort"]))
    return bad


def main(text):
    rows = parse(text)
    if not rows:
        return "no services listed by `docker compose ps`: refusing a vacuous isolation check"
    bad = violations(rows)
    return f"published internal ports: {bad}" if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.stdin.read()))
