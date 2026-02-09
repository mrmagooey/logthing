import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

WEF_ENDPOINT = os.environ.get("WEF_ENDPOINT", "http://logthing:5985")
STATS_ENDPOINT = os.environ.get(
    "WEF_STATS_ENDPOINT", f"{WEF_ENDPOINT}/stats/throughput"
)
EVENTS_FIXTURE = Path(
    os.environ.get("EVENTS_FIXTURE", "/app/fixtures/wef/events_batch.xml")
)
PARSER_DIR = Path(os.environ.get("PARSER_DIR", ""))
ENV_EXPECTED_EVENT_IDS = [
    event.strip()
    for event in os.environ.get("EXPECTED_EVENT_IDS", "").split(",")
    if event.strip()
]
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


def build_events_payload():
    if PARSER_DIR and PARSER_DIR.exists():
        return build_from_parsers(PARSER_DIR)
    if EVENTS_FIXTURE.exists():
        return EVENTS_FIXTURE.read_text(), []
    raise SystemExit("No parser directory or fixture available for generating events")


def build_from_parsers(directory: Path):
    files = sorted(directory.glob("*.y*ml"))
    if not files:
        raise SystemExit(f"No parser definitions found in {directory}")

    events_xml = []
    event_ids = []
    for path in files:
        data = yaml.safe_load(path.read_text())
        event_id = data.get("event_id")
        if event_id is None:
            continue
        fields = data.get("fields", [])
        field_values = []
        for field in fields:
            field_values.append(
                (
                    field.get("name", "Field"),
                    sample_value(
                        event_id,
                        field.get("name", "Field"),
                        field.get("type", "string"),
                    ),
                )
            )
        events_xml.append(build_event_xml(event_id, field_values))
        event_ids.append(str(event_id))

    body = wrap_events(events_xml)
    return body, event_ids


def sample_value(event_id: int, field_name: str, field_type: str) -> str:
    name = field_name.lower()
    if "username" in name:
        return f"user{event_id}"
    if "domain" in name:
        return "CONTOSO"
    if "groupname" in name:
        return f"group{event_id}"
    if "computername" in name:
        return f"COMPUTER{event_id}"
    if "membername" in name:
        return f"member{event_id}"
    if "member" in name and "sid" in name:
        return f"S-1-5-21-1000000000-1000000000-1000000000-{event_id}"
    if "sid" in name:
        return f"S-1-5-21-2000000000-2000000000-2000000000-{event_id}"
    if "ipaddress" in name or "ip" in name:
        return f"192.0.2.{(event_id % 200) + 1}"
    if "port" in name:
        return str(40000 + event_id)
    if "logontype" in name:
        return "3"
    if "logonid" in name:
        return "0x3e7"
    if "status" in name or "substatus" in name:
        return "0x0"
    if "ticketoptions" in name:
        return "0x40810010"
    if "failurecode" in name:
        return "0x0"
    if "accessmask" in name:
        return "0x1f3"
    if "processname" in name:
        return f"C:\\Windows\\System32\\proc{event_id}.exe"
    if "parentprocessname" in name:
        return f"C:\\Windows\\System32\\parent{event_id}.exe"
    if "processcommandline" in name:
        return f"cmd /c echo {event_id}"
    if "imagename" in name or "imagepath" in name:
        return f"C:\\Program Files\\Service{event_id}\\service.exe"
    if "taskname" in name:
        return f"\\Microsoft\\Windows\\Task{event_id}"
    if "author" in name:
        return "Administrator"
    if "enabled" in name:
        return "true"
    if "auditpolicychanges" in name:
        return "Success,Failure"
    if "subcategoryguid" in name:
        return "{0cce922b-69ae-11d9-bed3-505054503030}"
    if "privilege" in name:
        return "SeDebugPrivilege"
    if "reason" in name:
        return "Administrative"
    if "newvalue" in name or "oldvalue" in name:
        return f"value_{event_id}"
    if "operationtype" in name:
        return "Write"
    if "objectname" in name:
        return f"C:\\Data\\object{event_id}.txt"
    if "objecttype" in name:
        return "File"
    if "service" in name and "name" in name:
        return f"Service{event_id}"
    if "taskcontent" in name:
        return f"<Task>Event{event_id}</Task>"
    if "category" in name:
        return "Logon/Logoff"
    if "displayname" in name:
        return f"User {event_id}"
    if "userprincipalname" in name:
        return f"user{event_id}@contoso.com"
    if "computer" in name and "attribute" in name:
        return "description"
    if field_type.lower() == "integer":
        return str(event_id)
    if field_type.lower() == "boolean":
        return "true"
    return f"value_{field_name.lower()}_{event_id}"


def build_event_xml(event_id: int, data_pairs):
    timestamp = datetime.now(timezone.utc).isoformat()
    event_data = "\n".join(
        f'        <Data Name="{name}">{value}</Data>' for name, value in data_pairs
    )
    return f"""
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <Provider Name=\"Microsoft-Windows-Security-Auditing\">Microsoft-Windows-Security-Auditing</Provider>
        <EventID>{event_id}</EventID>
        <Level>0</Level>
        <Task>12544</Task>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime=\"{timestamp}\">{timestamp}</TimeCreated>
        <EventRecordID>{event_id}</EventRecordID>
        <Channel>Security</Channel>
        <Computer>TEST-HOST</Computer>
      </System>
      <EventData>
{event_data}
      </EventData>
    </Event>
    """.strip()


def wrap_events(events_xml):
    inner = "\n".join(events_xml)
    return f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<Envelope>
  <Body>
    <Events>
{inner}
    </Events>
  </Body>
</Envelope>
"""


def send_events():
    body, auto_event_ids = build_events_payload()
    url = f"{WEF_ENDPOINT}/wsman/events"
    headers = {"Content-Type": "application/soap+xml"}
    resp = requests.post(url, data=body.encode("utf-8"), headers=headers, timeout=30)
    resp.raise_for_status()
    print("Sent generated WEF events", resp.text)
    return auto_event_ids


def wait_for_stats(expected_ids):
    if not expected_ids:
        return
    deadline = time.time() + TIMEOUT
    expected_types = {
        f"Microsoft-Windows-Security-Auditing:{eid}" for eid in expected_ids
    }
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
    auto_ids = send_events()
    expected_ids = ENV_EXPECTED_EVENT_IDS or auto_ids
    wait_for_stats(expected_ids)
    print("WEF generator completed successfully")


if __name__ == "__main__":
    main()
