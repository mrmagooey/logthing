import pytest

from stubwec import enumerate_response_xml
from wefemu import envelope as E

MID = "uuid:6F2C1A8E-3B4D-4E5F-8A9B-0C1D2E3F4A5B"
NEW_MID = "uuid:12AAFC00-5BB5-42B5-BE85-077D7C02B8E9"


def ack(relates=MID, mid=NEW_MID, action=E.ACTION_ACK, body="", bom=True, decl=False):
    xml = (
        '<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
        f"<s:Header><a:Action>{action}</a:Action><a:MessageID>{mid}</a:MessageID>"
        f"<a:RelatesTo>{relates}</a:RelatesTo></s:Header><s:Body>{body}</s:Body></s:Envelope>"
    )
    if decl:
        xml = '<?xml version="1.0" encoding="UTF-16"?>' + xml
    raw = xml.encode("utf-16-le")
    return (b"\xff\xfe" if bom else b"") + raw


def test_encode_decode_message_bom():
    raw = E.encode_message("<a/>")
    assert raw[:2] == b"\xff\xfe"
    assert E.decode_message(raw) == "<a/>"


def test_decode_rejects_missing_bom_decl_and_odd_length():
    for bad in (b"<\x00a\x00/\x00>\x00", b"\xff\xfe" + "<?xml version='1.0'?><a/>".encode("utf-16-le"),
                b"\xff\xfe<\x00a"):
        with pytest.raises(E.ValidationError):
            E.decode_message(bad)


def test_validate_ack_ok():
    E.validate_ack(E.decode_message(ack()), MID)


@pytest.mark.parametrize(
    "kw",
    [
        dict(relates=MID.lower()),
        dict(relates=MID + " "),
        dict(mid="uuid:12aafc00-5bb5-42b5-be85-077d7c02b8e9"),
        dict(mid="12AAFC00-5BB5-42B5-BE85-077D7C02B8E9"),
        dict(mid="UUID:12AAFC00-5BB5-42B5-BE85-077D7C02B8E9"),
        dict(action="http://schemas.dmtf.org/wbem/wsman/1/wsman/ack"),
        dict(action=E.ACTION_ENUMERATE_RESPONSE),
        dict(body="<w:Events/>"),
        dict(body=" "),
    ],
)
def test_validate_ack_rejects(kw):
    with pytest.raises(E.ValidationError):
        E.validate_ack(E.decode_message(ack(**kw)), MID)


def test_validate_ack_requires_single_relates_and_messageid():
    xml = E.decode_message(ack()).replace("</s:Header>", f"<a:RelatesTo>{MID}</a:RelatesTo></s:Header>")
    with pytest.raises(E.ValidationError):
        E.validate_ack(xml, MID)


def test_message_id_generator_uppercase_uuid():
    import re

    for _ in range(20):
        assert re.fullmatch(r"uuid:[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}", E.new_message_id())


def test_events_builder_cdata_and_single_quotes_and_split_terminator():
    ev = '<Event xmlns="urn:x"><A b="c">t]]>u</A></Event>'
    xml = E.build_events("http://h/wsman/subscriptions/G/1", "m", "G", [ev], None)
    msg = E.parse_message(xml)
    assert msg.events == ["<Event xmlns='urn:x'><A b='c'>t]]>u</A></Event>"]
    assert "<![CDATA[" in xml


def test_events_builder_bookmark_header():
    bm = '<BookmarkList><Bookmark Channel="Security" RecordId="5" IsCurrent="true"/></BookmarkList>'
    xml = E.build_events("http://h/x", "m", "G", ["<Event/>"], bm)
    assert f"<w:Bookmark>{bm}</w:Bookmark>" in xml
    assert E.parse_message(xml).bookmark == bm


def test_parse_message_trims_whitespace_fields():
    xml = E.build_heartbeat("http://h/x", "win10.example.com", "ID1")
    msg = E.parse_message(xml)
    assert msg.machine_id == "win10.example.com"
    assert msg.identifier == "ID1"
    assert msg.action == E.ACTION_HEARTBEAT
    assert msg.ack_requested


def test_parse_enumerate_response_fields():
    xml = enumerate_response_xml(MID, bookmark='<BookmarkList><Bookmark Channel="Security" RecordId="7" IsCurrent="true"/></BookmarkList>')
    E.validate_enumerate_response(xml, MID)
    [sub] = E.parse_enumerate_response(xml)
    assert sub.version == "uuid:219C5353-0000-4000-8000-000000000001"
    assert sub.name == "Security-Events"
    assert sub.notify_to.endswith("/wsman/subscriptions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0/1")
    assert sub.heartbeat == "PT3600.000S" and sub.heartbeat_seconds == 3600.0
    assert sub.content_format == "RenderedText"
    assert sub.policy_profile.endswith("spnego-kerberos")
    assert sub.issuer_thumbprints == []
    assert sub.compression == "SLDC" and sub.cdata
    assert sub.identifier == "219C5353-0000-4000-8000-000000000001"
    assert sub.bookmark_entries() == [("Security", "7")]


def test_parse_enumerate_response_mtls_thumbprints():
    xml = enumerate_response_xml(MID, mtls=True)
    [sub] = E.parse_enumerate_response(xml)
    assert sub.policy_profile.endswith("secprofile/https/mutual")
    assert sub.issuer_thumbprints == ["A" * 40]


@pytest.mark.parametrize("fault", ["no_eos", "bad_action", "bad_relates", "lower_mid"])
def test_validate_enumerate_response_rejects(fault):
    xml = enumerate_response_xml(MID, fault=fault)
    with pytest.raises(E.ValidationError):
        E.validate_enumerate_response(xml, MID)
