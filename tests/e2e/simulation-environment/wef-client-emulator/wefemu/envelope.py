"""SOAP/WS-Management message builders, parsers and strict response validators.

Builders reproduce the shapes of tests/fixtures/wef/golden/*.xml (a hand-written transcription
of a real Windows 10 capture), including the whitespace Windows puts around MachineID and
Identifier. Validators are deliberately strict: they are the acceptance test for the server.
"""
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_A = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
NS_N = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
NS_W = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_P = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
NS_B = "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
NS_E = "http://schemas.xmlsoap.org/ws/2004/08/eventing"
NS_M_SUB = "http://schemas.microsoft.com/wbem/wsman/1/subscription"
NS_AUTH = "http://schemas.microsoft.com/wbem/wsman/1/authentication"
NS_POLICY = "http://schemas.xmlsoap.org/ws/2002/12/policy"

ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
ACTION_HEARTBEAT = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat"
ACTION_EVENTS = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Events"
ACTION_ACK = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack"
ACTION_SUBSCRIPTION_END = "http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd"
ACTION_END = "http://schemas.microsoft.com/wbem/wsman/1/wsman/End"
ACTION_EVENT = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Event"
ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
PROFILE_KERBEROS = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/http/spnego-kerberos"
PROFILE_MUTUAL = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

_ROOT_NS = (
    f'xmlns:s="{NS_S}" xmlns:a="{NS_A}" xmlns:n="{NS_N}" xmlns:w="{NS_W}" xmlns:p="{NS_P}" '
    f'xmlns:b="{NS_B}"'
)
_MESSAGE_ID_RE = re.compile(r"uuid:[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}")


class ValidationError(AssertionError):
    """A server response (or a message) violated the protocol."""


def new_message_id() -> str:
    return "uuid:" + str(uuid.uuid4()).upper()


def encode_message(xml: str) -> bytes:
    """UTF-16LE with BOM, no XML declaration (as Windows sends)."""
    return b"\xff\xfe" + xml.encode("utf-16-le")


def decode_message(raw: bytes) -> str:
    """Strictly decode a response/request body: BOM FF FE, UTF-16LE, no <?xml?> declaration."""
    if raw[:2] != b"\xff\xfe":
        raise ValidationError(f"message does not start with UTF-16LE BOM FF FE (starts {raw[:4].hex()})")
    if len(raw) % 2:
        raise ValidationError("UTF-16 message has odd length")
    try:
        text = raw[2:].decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"invalid UTF-16LE: {exc}") from exc
    if text.startswith("﻿"):
        raise ValidationError("duplicate BOM")
    if text.lstrip().startswith("<?xml"):
        raise ValidationError("message carries an <?xml?> declaration (Windows sends none)")
    if not text.startswith("<"):
        raise ValidationError("message does not start with '<'")
    return text


# --------------------------------------------------------------------------- builders
def _machine(machine_id: str) -> list[str]:
    return [
        '    <m:MachineID xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" '
        's:mustUnderstand="false">',
        f"      {escape(machine_id)}",
        "    </m:MachineID>",
    ]


_REPLY_TO = [
    "    <a:ReplyTo>",
    f'      <a:Address s:mustUnderstand="true">{ANONYMOUS}</a:Address>',
    "    </a:ReplyTo>",
]


def _identifier(identifier: str) -> list[str]:
    return [
        f'    <e:Identifier xmlns:e="{NS_E}" s:mustUnderstand="true">',
        f"      {escape(identifier)}",
        "    </e:Identifier>",
    ]


def _envelope(header: list[str], body: list[str], extra_ns: str = "") -> str:
    ns = _ROOT_NS + (f" {extra_ns}" if extra_ns else "")
    return "\n".join([f"<s:Envelope {ns}>", "  <s:Header>", *header, "  </s:Header>", *body,
                      "</s:Envelope>"])


def build_enumerate(to, machine_id, message_id=None, session_id=None, operation_id=None) -> str:
    message_id = message_id or new_message_id()
    session_id = session_id or new_message_id()
    operation_id = operation_id or new_message_id()
    header = [
        f"    <a:To>{escape(to)}</a:To>",
        '    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/'
        "SubscriptionManager/Subscription</w:ResourceURI>",
        *_machine(machine_id),
        *_REPLY_TO,
        f'    <a:Action s:mustUnderstand="true">{ACTION_ENUMERATE}</a:Action>',
        '    <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>',
        f"    <a:MessageID>{message_id}</a:MessageID>",
        '    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>',
        '    <p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>',
        f'    <p:SessionId s:mustUnderstand="false">{session_id}</p:SessionId>',
        f'    <p:OperationID s:mustUnderstand="false">{operation_id}</p:OperationID>',
        '    <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>',
        "    <w:OperationTimeout>PT60.000S</w:OperationTimeout>",
    ]
    body = ["  <s:Body>", "    <n:Enumerate>", "      <w:OptimizeEnumeration/>",
            "      <w:MaxElements>32000</w:MaxElements>", "    </n:Enumerate>", "  </s:Body>"]
    return _envelope(header, body)


def _delivery_header(to, machine_id, action, identifier, message_id, operation_id, bookmark):
    return [
        f"    <a:To>{escape(to)}</a:To>",
        *_machine(machine_id),
        *_REPLY_TO,
        f'    <a:Action s:mustUnderstand="true">{action}</a:Action>',
        f"    <a:MessageID>{message_id or new_message_id()}</a:MessageID>",
        f'    <p:OperationID s:mustUnderstand="false">{operation_id or new_message_id()}</p:OperationID>',
        '    <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>',
        "    <w:OperationTimeout>PT60.000S</w:OperationTimeout>",
        *_identifier(identifier),
        *([f"    <w:Bookmark>{bookmark}</w:Bookmark>"] if bookmark else []),
        "    <w:AckRequested/>",
    ]


def build_heartbeat(to, machine_id, identifier, message_id=None, operation_id=None) -> str:
    header = _delivery_header(to, machine_id, ACTION_HEARTBEAT, identifier, message_id, operation_id, None)
    return _envelope(header, ["  <s:Body>", "    <w:Events></w:Events>", "  </s:Body>"])


_TAG_RE = re.compile(r"<[^<>]*>")
_DQ_ATTR_RE = re.compile(r"""(\s[\w:.-]+)="([^"']*)\"""")


def single_quote_attrs(event_xml: str) -> str:
    """Windows serialises attributes inside event XML with single quotes."""
    return _TAG_RE.sub(lambda m: _DQ_ATTR_RE.sub(r"\1='\2'", m.group(0)), event_xml)


def build_events(to, machine_id, identifier, events, bookmark, message_id=None, operation_id=None) -> str:
    header = _delivery_header(to, machine_id, ACTION_EVENTS, identifier, message_id, operation_id, bookmark)
    body = ["  <s:Body>", "    <w:Events>"]
    for ev in events:
        cdata = single_quote_attrs(ev).replace("]]>", "]]]]><![CDATA[>")
        body.append(f'      <w:Event Action="{ACTION_EVENT}"><![CDATA[{cdata}]]></w:Event>')
    body += ["    </w:Events>", "  </s:Body>"]
    return _envelope(header, body)


def build_end(to, machine_id, message_id=None, operation_id=None) -> str:
    header = [
        f"    <a:To>{escape(to)}</a:To>",
        '    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/'
        "wsman/FullDuplex</w:ResourceURI>",
        *_machine(machine_id),
        *_REPLY_TO,
        f'    <a:Action s:mustUnderstand="true">{ACTION_END}</a:Action>',
        f"    <a:MessageID>{message_id or new_message_id()}</a:MessageID>",
        f'    <p:OperationID s:mustUnderstand="false">{operation_id or new_message_id()}</p:OperationID>',
        '    <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>',
    ]
    return _envelope(header, ["  <s:Body/>"])


def build_subscription_end(subscription_url, machine_id, identifier, message_id=None,
                           operation_id=None) -> str:
    header = [
        f"    <a:To>{ANONYMOUS}</a:To>",
        *_machine(machine_id),
        f'    <a:Action s:mustUnderstand="true">{ACTION_SUBSCRIPTION_END}</a:Action>',
        f"    <a:MessageID>{message_id or new_message_id()}</a:MessageID>",
        f'    <p:OperationID s:mustUnderstand="false">{operation_id or new_message_id()}</p:OperationID>',
        '    <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>',
    ]
    fault = (
        '<f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="1717" '
        f'Machine="{escape(machine_id)}"><f:Message>The interface is unknown.</f:Message></f:WSManFault>'
    )
    body = [
        "  <s:Body>",
        "    <e:SubscriptionEnd>",
        "      <e:SubscriptionManager>",
        f"        <a:Address>{escape(subscription_url)}</a:Address>",
        "        <a:ReferenceParameters>",
        f"          <e:Identifier>{escape(identifier)}</e:Identifier>",
        "        </a:ReferenceParameters>",
        "      </e:SubscriptionManager>",
        "      <e:Status>http://schemas.xmlsoap.org/ws/2004/08/eventing/SourceCancelling</e:Status>",
        f'      <e:Reason xml:lang="en-US">The subscription was cancelled. {fault}</e:Reason>',
        "    </e:SubscriptionEnd>",
        "  </s:Body>",
    ]
    return _envelope(header, body, extra_ns=f'xmlns:e="{NS_E}"')


# --------------------------------------------------------------------------- parsing
def _q(ns: str, local: str) -> str:
    return f"{{{ns}}}{local}"


def _parse(xml: str) -> ET.Element:
    try:
        return ET.fromstring(xml)
    except (ET.ParseError, ValueError) as exc:
        raise ValidationError(f"not well-formed XML: {exc}") from exc


def _bookmark_raw(xml: str, el: ET.Element) -> str | None:
    """Inner XML of the first <w:Bookmark> verbatim (falls back to a re-serialisation)."""
    m = re.search(r"<(?:\w+):Bookmark\b[^>]*>(.*?)</\w+:Bookmark>", xml, re.S)
    if m:
        return m.group(1).strip()
    kids = list(el)
    return ET.tostring(kids[0], encoding="unicode").strip() if kids else None


def bookmark_entries(inner: str | None) -> list[tuple[str, str]]:
    if not inner:
        return []
    root = ET.fromstring(inner)
    return [(b.get("Channel", ""), b.get("RecordId", "")) for b in root.iter("Bookmark")]


@dataclass
class Message:
    action: str | None = None
    message_id: str | None = None
    to: str | None = None
    machine_id: str | None = None
    identifier: str | None = None
    operation_id: str | None = None
    bookmark: str | None = None
    ack_requested: bool = False
    events: list[str] = field(default_factory=list)
    relates_to: list[str] = field(default_factory=list)


def parse_message(xml: str) -> Message:
    """Parse a client->server request (whitespace-trimmed fields)."""
    root = _parse(xml)
    hdr = root.find(_q(NS_S, "Header"))
    body = root.find(_q(NS_S, "Body"))
    if hdr is None or body is None:
        raise ValidationError("missing s:Header or s:Body")

    def text(ns, local):
        el = hdr.find(_q(ns, local))
        return el.text.strip() if el is not None and el.text else None

    msg = Message(
        action=text(NS_A, "Action"), message_id=text(NS_A, "MessageID"), to=text(NS_A, "To"),
        operation_id=text(NS_P, "OperationID"), identifier=text(NS_E, "Identifier"),
        ack_requested=hdr.find(_q(NS_W, "AckRequested")) is not None,
        relates_to=[e.text or "" for e in hdr.findall(_q(NS_A, "RelatesTo"))],
    )
    mid = hdr.find("{http://schemas.microsoft.com/wbem/wsman/1/machineid}MachineID")
    msg.machine_id = mid.text.strip() if mid is not None and mid.text else None
    bm = hdr.find(_q(NS_W, "Bookmark"))
    if bm is not None:
        msg.bookmark = _bookmark_raw(xml, bm)
    events = body.find(_q(NS_W, "Events"))
    if events is not None:
        msg.events = [(e.text or "") for e in events.findall(_q(NS_W, "Event"))]
    return msg


def parse_duration_seconds(text: str) -> float:
    m = re.fullmatch(r"PT(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?", text or "")
    if not m or not any(m.groups()):
        raise ValidationError(f"bad xs:duration {text!r}")
    h, mi, s = (float(g) if g else 0.0 for g in m.groups())
    return h * 3600 + mi * 60 + s


@dataclass
class Subscription:
    version: str
    name: str | None
    notify_to: str
    heartbeat: str
    heartbeat_seconds: float
    content_format: str | None
    policy_profile: str | None
    issuer_thumbprints: list[str]
    bookmark: str | None
    compression: str | None
    cdata: bool
    identifier: str | None

    def bookmark_entries(self) -> list[tuple[str, str]]:
        return bookmark_entries(self.bookmark)


def parse_enumerate_response(xml: str) -> list[Subscription]:
    root = _parse(xml)
    items = root.find(f"{_q(NS_S, 'Body')}/{_q(NS_N, 'EnumerateResponse')}/{_q(NS_W, 'Items')}")
    if items is None:
        raise ValidationError("EnumerateResponse has no w:Items")
    out = []
    for sub in items.findall(_q(NS_M_SUB, "Subscription")):
        ver = sub.find(_q(NS_M_SUB, "Version"))
        env = sub.find(_q(NS_S, "Envelope"))
        if ver is None or not (ver.text or "").strip() or env is None:
            raise ValidationError("m:Subscription lacks m:Version or an embedded s:Envelope")
        options = {}
        for o in env.iterfind(f".//{_q(NS_W, 'OptionSet')}/{_q(NS_W, 'Option')}"):
            options[o.get("Name")] = o
        subscribe = env.find(f"{_q(NS_S, 'Body')}/{_q(NS_E, 'Subscribe')}")
        if subscribe is None:
            raise ValidationError("embedded envelope has no e:Subscribe")
        delivery = subscribe.find(_q(NS_E, "Delivery"))
        notify = delivery.find(_q(NS_E, "NotifyTo")) if delivery is not None else None
        addr = notify.find(_q(NS_A, "Address")) if notify is not None else None
        if addr is None or not (addr.text or "").strip():
            raise ValidationError("subscription has no NotifyTo address")
        hb = delivery.find(_q(NS_W, "Heartbeats"))
        hb_text = (hb.text or "").strip() if hb is not None else ""
        ident = None
        for refs in ("ReferenceProperties", "ReferenceParameters"):
            el = notify.find(f"{_q(NS_A, refs)}/{_q(NS_E, 'Identifier')}")
            if el is not None:
                ident = (el.text or "").strip()
        auth = notify.find(f".//{_q(NS_AUTH, 'Authentication')}")
        thumbs = [t.text.strip() for t in notify.iter(_q(NS_AUTH, "Thumbprint"))
                  if t.get("Role") == "issuer" and t.text]
        bm_el = subscribe.find(_q(NS_W, "Bookmark"))
        opt = lambda n: (options[n].text or "").strip() if n in options else None  # noqa: E731
        out.append(Subscription(
            version=ver.text.strip(), name=opt("SubscriptionName"), notify_to=addr.text.strip(),
            heartbeat=hb_text, heartbeat_seconds=parse_duration_seconds(hb_text),
            content_format=opt("ContentFormat"),
            policy_profile=auth.get("Profile") if auth is not None else None,
            issuer_thumbprints=thumbs,
            bookmark=_bookmark_raw(xml, bm_el) if bm_el is not None else None,
            compression=opt("Compression"), cdata="CDATA" in options, identifier=ident,
        ))
    return out


# --------------------------------------------------------------------------- validation
def _validate_response_header(xml: str, request_message_id: str, action: str) -> ET.Element:
    root = _parse(xml)
    if root.tag != _q(NS_S, "Envelope"):
        raise ValidationError(f"root element is {root.tag}, expected soap-envelope Envelope")
    hdr = root.find(_q(NS_S, "Header"))
    body = root.find(_q(NS_S, "Body"))
    if hdr is None or body is None:
        raise ValidationError("response lacks s:Header or s:Body")

    def only(ns, local):
        els = hdr.findall(_q(ns, local))
        if len(els) != 1:
            raise ValidationError(f"expected exactly one {local} header, found {len(els)}")
        return els[0].text or ""

    got = only(NS_A, "Action")
    if got != action:
        raise ValidationError(f"Action is {got!r}, expected {action!r}")
    mid = only(NS_A, "MessageID")
    if not _MESSAGE_ID_RE.fullmatch(mid):
        raise ValidationError(f"response MessageID {mid!r} is not 'uuid:' + uppercase GUID")
    rel = only(NS_A, "RelatesTo")
    if rel != request_message_id:
        raise ValidationError(f"RelatesTo {rel!r} != request MessageID {request_message_id!r}")
    return body


def validate_ack(xml: str, request_message_id: str) -> None:
    body = _validate_response_header(xml, request_message_id, ACTION_ACK)
    if len(body) or (body.text or ""):
        raise ValidationError("Ack s:Body is not empty")


def validate_enumerate_response(xml: str, request_message_id: str) -> list[Subscription]:
    body = _validate_response_header(xml, request_message_id, ACTION_ENUMERATE_RESPONSE)
    resp = body.find(_q(NS_N, "EnumerateResponse"))
    if resp is None:
        raise ValidationError("s:Body lacks n:EnumerateResponse")
    if resp.find(_q(NS_W, "EndOfSequence")) is None:
        raise ValidationError("EnumerateResponse lacks w:EndOfSequence")
    return parse_enumerate_response(xml)
