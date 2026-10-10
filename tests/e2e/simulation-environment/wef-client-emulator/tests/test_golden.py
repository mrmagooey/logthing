"""Golden-file tests: every golden XML must be reproduced by the builders (same element set,
and, since the builders mirror the golden layout, the same text) and be understood by the
parsers."""
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from wefemu import envelope as E

GOLDEN = Path(__file__).resolve().parents[4] / "fixtures" / "wef" / "golden"
NAMES = ["enumerate", "heartbeat", "events", "end", "subscription_end"]


def golden(name: str) -> str:
    return (GOLDEN / f"{name}.xml").read_text(encoding="utf-8").rstrip("\n")


def element_set(xml: str) -> set[str]:
    return {el.tag for el in ET.fromstring(xml).iter() if isinstance(el.tag, str)}


def attr_set(xml: str) -> set[tuple[str, str]]:
    return {(el.tag, k) for el in ET.fromstring(xml).iter() for k in el.attrib}


SUB_URL = "http://logthing.example.com:5985/wsman/subscriptions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0/1"
SUB_ID = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"
MACHINE = "win10.example.com"
BM = '<BookmarkList><Bookmark Channel="Security" RecordId="1042" IsCurrent="true"/></BookmarkList>'


def events_from_golden() -> list[str]:
    return E.parse_message(golden("events")).events


def rebuilt(name: str) -> str:
    ids = dict(
        message_id={
            "enumerate": "uuid:6F2C1A8E-3B4D-4E5F-8A9B-0C1D2E3F4A5B",
            "heartbeat": "uuid:1C2D3E4F-5061-4728-8394-A5B6C7D8E9F0",
            "events": "uuid:1C2D3E4F-5061-4728-8394-A5B6C7D8E9F0",
            "end": "uuid:9E0F1A2B-3C4D-4E5F-8061-728394A5B6C7",
            "subscription_end": "uuid:5A6B7C8D-9E0F-4A1B-8C2D-3E4F50617283",
        }[name],
        operation_id={
            "enumerate": "uuid:8A1B2C3D-4E5F-4607-8192-A3B4C5D6E7F8",
            "heartbeat": "uuid:3E4F5061-7283-4940-A5B6-C7D8E9F0A1B2",
            "events": "uuid:3E4F5061-7283-4940-A5B6-C7D8E9F0A1B2",
            "end": "uuid:A1B2C3D4-E5F6-4708-9192-A3B4C5D6E7F8",
            "subscription_end": "uuid:7C8D9E0F-1A2B-4C3D-9E4F-506172839405",
        }[name],
    )
    if name == "enumerate":
        return E.build_enumerate(
            "http://logthing.example.com:5985/wsman/SubscriptionManager/WEC", MACHINE,
            session_id="uuid:2B7D9C41-5E6F-4A80-9B1C-3D4E5F607182", **ids)
    if name == "heartbeat":
        return E.build_heartbeat(SUB_URL, MACHINE, SUB_ID, **ids)
    if name == "events":
        return E.build_events(SUB_URL, MACHINE, SUB_ID, events_from_golden(), BM, **ids)
    if name == "end":
        return E.build_end(SUB_URL, MACHINE, **ids)
    return E.build_subscription_end(SUB_URL, MACHINE, SUB_ID, **ids)


@pytest.mark.parametrize("name", NAMES)
def test_builder_emits_every_golden_element_and_attribute(name):
    got, want = rebuilt(name), golden(name)
    assert element_set(got) == element_set(want)
    assert attr_set(got) == attr_set(want)


@pytest.mark.parametrize("name", NAMES)
def test_builder_text_equals_golden(name):
    assert rebuilt(name) == golden(name)


@pytest.mark.parametrize("name", NAMES)
def test_golden_roundtrips_through_parser_and_builder(name):
    msg = E.parse_message(golden(name))
    assert msg.machine_id == MACHINE
    assert msg.message_id.startswith("uuid:")
    assert rebuilt(name) == golden(name)


def test_golden_events_content():
    msg = E.parse_message(golden("events"))
    assert msg.action == E.ACTION_EVENTS
    assert len(msg.events) == 2
    assert msg.bookmark == BM
    assert msg.identifier == SUB_ID
    assert all("=\"" not in e for e in msg.events)  # single-quoted attrs inside events


def test_golden_messages_encode_to_utf16_bom_and_back():
    for name in NAMES:
        raw = E.encode_message(golden(name))
        assert raw[:2] == b"\xff\xfe"
        assert E.decode_message(raw) == golden(name)
