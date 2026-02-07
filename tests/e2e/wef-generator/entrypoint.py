import json
import os
import time
from pathlib import Path

import requests

WEF_ENDPOINT = os.environ.get("WEF_ENDPOINT", "http://wef-server:5985")
STATS_ENDPOINT = os.environ.get("WEF_STATS_ENDPOINT", f"{WEF_ENDPOINT}/stats/throughput")
EVENTS_FIXTURE = Path(os.environ.get("EVENTS_FIXTURE", "/app/fixtures/wef/events_batch.xml"))
EXPECTED_EVENT_IDS = [event.strip() for event in os.environ.get("EXPECTED_EVENT_IDS", "").split(",") if event.strip()]
TIMEOUT = int(os.environ.get("WEF_TIMEOUT_SECS", "60"))


def wait_for_health():
    deadline = time.time() + TIMEOUT
    url = f"{WEF_ENDPOINT}/health"
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                print("WEF server healthy")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise SystemExit("WEF server did not become healthy in time")


def send_events():
    if not EVENTS_FIXTURE.exists():
        raise SystemExit(f"Missing fixture: {EVENTS_FIXTURE}")
    body = EVENTS_FIXTURE.read_text()
    url = f"{WEF_ENDPOINT}/wsman/events"
    headers = {"Content-Type": "application/soap+xml"}
    resp = requests.post(url, data=body.encode("utf-8"), headers=headers, timeout=10)
    resp.raise_for_status()
    print("Sent WEF events fixture", resp.text)


def wait_for_stats():
    if not EXPECTED_EVENT_IDS:
        return
    deadline = time.time() + TIMEOUT
    expected_types = {f"Microsoft-Windows-Security-Auditing:{eid}" for eid in EXPECTED_EVENT_IDS}
    while time.time() < deadline:
        try:
            resp = requests.get(STATS_ENDPOINT, timeout=5)
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, json.JSONDecodeError):
            time.sleep(2)
            continue
        counts = {row["event_type"]: row.get("total_events", 0) for row in payload}
        if all(counts.get(event_type, 0) >= 1 for event_type in expected_types):
            print("Throughput stats show expected event types")
            return
        time.sleep(2)
    raise SystemExit("Throughput stats did not reflect expected events")


def main():
    wait_for_health()
    send_events()
    wait_for_stats()
    print("WEF generator completed successfully")


if __name__ == "__main__":
    main()
