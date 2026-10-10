"""Offline stand-in for a WEC server, for client-flow tests.

Not a reference implementation of the real server: it speaks just enough of the protocol to
exercise the emulator, can inject response faults, and uses a fake GSS context (reversible
byte transform) so no Kerberos libraries are needed.
"""
import base64
import datetime
import http.server
import ipaddress
import socketserver
import ssl
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit

from wefemu import envelope as E
from wefemu import multipart, sldc

SUB_GUID = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"
SUB_VERSION = "uuid:219C5353-0000-4000-8000-000000000001"
AP_REQ = b"FAKE-AP-REQ"
AP_REP = b"FAKE-AP-REP"
FAKE_HEADER = b"FAKEGSS!" * 7 + b"abcd"  # 60 bytes, like a CFX sealed token header


class FakeContext:
    """Mimics the pyspnego context surface the client uses."""

    def __init__(self):
        self.steps = []
        self.complete = False

    def step(self, in_token=None):
        self.steps.append(in_token)
        if in_token is None:
            return AP_REQ
        assert in_token == AP_REP, in_token
        self.complete = True
        return None

    def wrap_winrm(self, data: bytes):
        return SimpleNamespace(header=FAKE_HEADER, data=bytes(b ^ 0x5A for b in data), padding_length=0)

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes:
        assert header == FAKE_HEADER, header
        return bytes(b ^ 0x5A for b in data)


def enumerate_response_xml(request_mid, bookmark=None, mtls=False, fault=None, notify=None,
                           version=SUB_VERSION):
    notify = notify or f"HTTP://logthing.example.com:5985/wsman/subscriptions/{SUB_GUID}/1"
    if mtls:
        policy = (
            '<auth:Authentication Profile="http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual">'
            '<auth:ClientCertificate><auth:Thumbprint Role="issuer">' + "A" * 40 + "</auth:Thumbprint>"
            "</auth:ClientCertificate></auth:Authentication>"
        )
    else:
        policy = (
            '<auth:Authentication Profile="http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/http/spnego-kerberos">'
            "</auth:Authentication>"
        )
    bm = f"<w:Bookmark>{bookmark}</w:Bookmark>" if bookmark else ""
    action = E.ACTION_ENUMERATE_RESPONSE
    relates = request_mid
    mid = E.new_message_id()
    if fault == "bad_action":
        action = E.ACTION_ACK
    if fault == "bad_relates":
        relates = request_mid.lower()
    if fault == "lower_mid":
        mid = mid.lower()
    eos = "" if fault == "no_eos" else "<w:EndOfSequence/>"
    ident = version.removeprefix("uuid:")
    return (
        '<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
        'xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" '
        'xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration">'
        f"<s:Header><a:Action>{action}</a:Action><a:MessageID>{mid}</a:MessageID>"
        '<p:OperationID s:mustUnderstand="false">uuid:EA2EE566-0000-4000-8000-000000000000</p:OperationID>'
        "<p:SequenceId>1</p:SequenceId>"
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        f"<a:RelatesTo>{relates}</a:RelatesTo></s:Header>"
        "<s:Body><n:EnumerateResponse><n:EnumerationContext></n:EnumerationContext><w:Items>"
        f'<m:Subscription xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/subscription">'
        f"<m:Version>{version}</m:Version>"
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
        'xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header>'
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        '<a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe</a:Action>'
        '<w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<w:Option Name="SubscriptionName">Security-Events</w:Option>'
        '<w:Option Name="Compression">SLDC</w:Option>'
        '<w:Option Name="CDATA" xsi:nil="true"/>'
        '<w:Option Name="ContentFormat">RenderedText</w:Option>'
        '<w:Option Name="IgnoreChannelError" xsi:nil="true"/>'
        "</w:OptionSet></s:Header><s:Body><e:Subscribe>"
        f"<e:EndTo><a:Address>{notify}</a:Address>"
        f"<a:ReferenceProperties><e:Identifier>{ident}</e:Identifier></a:ReferenceProperties></e:EndTo>"
        '<e:Delivery Mode="http://schemas.dmtf.org/wbem/wsman/1/wsman/Events">'
        "<w:Heartbeats>PT3600.000S</w:Heartbeats><e:NotifyTo>"
        f"<a:Address>{notify}</a:Address>"
        f"<a:ReferenceProperties><e:Identifier>{ident}</e:Identifier></a:ReferenceProperties>"
        '<c:Policy xmlns:c="http://schemas.xmlsoap.org/ws/2002/12/policy" '
        'xmlns:auth="http://schemas.microsoft.com/wbem/wsman/1/authentication">'
        f"<c:ExactlyOne><c:All>{policy}</c:All></c:ExactlyOne></c:Policy></e:NotifyTo>"
        '<w:ConnectionRetry Total="5">PT60.0S</w:ConnectionRetry><w:MaxTime>PT30.000S</w:MaxTime>'
        '<w:MaxEnvelopeSize Policy="Notify">512000</w:MaxEnvelopeSize>'
        "<w:ContentEncoding>UTF-16</w:ContentEncoding></e:Delivery>"
        '<w:Filter Dialect="http://schemas.microsoft.com/win/2004/08/events/eventquery">'
        '<QueryList><Query Id="0"><Select Path="Security">*</Select></Query></QueryList></w:Filter>'
        f"{bm}<w:SendBookmarks/></e:Subscribe></s:Body></s:Envelope>"
        f"</m:Subscription></w:Items>{eos}</n:EnumerateResponse></s:Body></s:Envelope>"
    )


def ack_xml(request_mid, fault=None):
    action, relates, mid, body = E.ACTION_ACK, request_mid, E.new_message_id(), ""
    if fault == "ack_bad_action":
        action = E.ACTION_HEARTBEAT
    if fault == "ack_bad_relates":
        relates = request_mid.lower()
    if fault == "ack_lower_mid":
        mid = mid.lower()
    if fault == "ack_body":
        body = "<w:Events/>"
    xml = (
        '<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
        'xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header>'
        f"<a:Action>{action}</a:Action><a:MessageID>{mid}</a:MessageID>"
        "<p:SequenceId>1</p:SequenceId>"
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        f"<a:RelatesTo>{relates}</a:RelatesTo></s:Header><s:Body>{body}</s:Body></s:Envelope>"
    )
    if fault == "ack_decl":
        xml = '<?xml version="1.0" encoding="UTF-16"?>' + xml
    return xml


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class StubWec:
    def __init__(self, mode="kerberos", faults=(), tls=None, notify_scheme="HTTP"):
        self.mode, self.faults, self.tls = mode, set(faults), tls
        self.notify_scheme = notify_scheme
        self.log: list[dict] = []
        self.bookmark: str | None = None
        self.version = SUB_VERSION
        self.lock = threading.Lock()
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            wbufsize = 65536  # header+body in one segment (avoids Nagle/delayed-ACK stalls)

            def setup(self):
                super().setup()
                self.authed = False

            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", headers=()):
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()

            def do_GET(self):
                self._send(200, b"ok") if self.path == "/health" else self._send(404)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                stub._post(self, body)

        self.httpd = _Server(("127.0.0.1", 0), Handler)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls["server_cert"], tls["server_key"])
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(tls["ca"])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        host = "localhost" if tls else "127.0.0.1"
        self.origin = f"{'https' if tls else 'http'}://{host}:{self.port}"
        self.url = self.origin + "/wsman/SubscriptionManager/WEC"
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ----------------------------------------------------------------------------------
    def _post(self, h, body):
        f = self.faults
        rec = {"path": h.path, "conn": id(h), "auth": h.headers.get("Authorization"),
               "ctype": h.headers.get("Content-Type"), "cenc": h.headers.get("Content-Encoding"),
               "raw_len": len(body), "action": None}
        with self.lock:
            self.log.append(rec)
        if self.mode == "kerberos":
            if rec["auth"]:
                scheme, _, tok = rec["auth"].partition(" ")
                if scheme != "Kerberos" or base64.b64decode(tok) != AP_REQ:
                    return h._send(401, headers=[("WWW-Authenticate", "Kerberos"), ("WWW-Authenticate", "Negotiate")])
                h.authed = True
                rec["action"] = "AUTH"
                if "auth_401" in f:
                    return h._send(401)
                hdrs = [] if "auth_no_www" in f else [("WWW-Authenticate", "Kerberos " + base64.b64encode(AP_REP).decode())]
                return h._send(200, b"x" if "auth_body" in f else b"", hdrs)
            if not h.authed:
                return h._send(401, headers=[("WWW-Authenticate", "Kerberos"), ("WWW-Authenticate", "Negotiate")])
            if rec["ctype"] != multipart.CONTENT_TYPE:
                return h._send(400)
            protocol, n, hdr, data = multipart.parse(body)
            assert protocol == multipart.PROTOCOL
            plain = FakeContext().unwrap_winrm(hdr, data)
            assert len(plain) == n, (len(plain), n)
        else:
            if self.tls:
                assert h.request.getpeercert(), "client certificate required"
            if rec["ctype"] != "application/soap+xml;charset=UTF-16":
                return h._send(400)
            plain = body
        rec["compressed"] = False
        if rec["cenc"] == "SLDC":
            try:
                plain2 = sldc.decompress(plain)
                rec["compressed"] = plain2 != plain
                plain = plain2
            except sldc.SldcError:
                pass
        xml = E.decode_message(plain)
        msg = E.parse_message(xml)
        rec["action"], rec["msg"], rec["xml"] = msg.action, msg, xml
        if msg.action == E.ACTION_ENUMERATE:
            origin = urlsplit(self.url).netloc
            notify = f"{self.notify_scheme}://{origin}/wsman/subscriptions/{SUB_GUID}/1"
            if self.mode == "https-mtls" and self.notify_scheme == "HTTP":
                notify = f"HTTPS://{origin}/wsman/subscriptions/{SUB_GUID}/1"
            fault = next((x for x in ("bad_action", "bad_relates", "lower_mid", "no_eos") if x in f), None)
            out = enumerate_response_xml(msg.message_id, self.bookmark, self.mode == "https-mtls", fault,
                                         notify, self.version)
            return self._reply(h, out)
        if msg.action in (E.ACTION_HEARTBEAT, E.ACTION_EVENTS):
            if msg.action == E.ACTION_EVENTS and msg.bookmark:
                self.bookmark = msg.bookmark
            fault = next((x for x in f if x.startswith("ack_")), None)
            return self._reply(h, ack_xml(msg.message_id, fault), bom="ack_no_bom" not in f)
        if msg.action in (E.ACTION_END, E.ACTION_SUBSCRIPTION_END):
            if "end_204" in f:
                return h._send(204)
            return h._send(200, b"junk" if "end_body" in f else b"")
        return h._send(400)

    def _reply(self, h, xml, bom=True):
        raw = xml.encode("utf-16-le")
        raw = (b"\xff\xfe" + raw) if bom else raw
        if self.mode == "kerberos":
            w = FakeContext().wrap_winrm(raw)
            length = len(raw) + (1 if "mp_length" in self.faults else 0)
            proto = multipart.PROTOCOL
            body = multipart.build(proto, length, w.header, w.data)
            if "mp_tab" in self.faults:
                body = body.replace(b"\r\nOriginalContent", b"\r\n\tOriginalContent", 1)
            if "mp_charset" in self.faults:
                body = body.replace(b"charset=UTF-16", b"charset=UTF-8", 1)
            ctype = multipart.CONTENT_TYPE
            if "ct_spnego" in self.faults:
                ctype = ctype.replace("Kerberos", "SPNEGO")
        else:
            body, ctype = raw, "application/soap+xml;charset=UTF-16"
            if "ct_utf8" in self.faults:
                ctype = "application/soap+xml;charset=UTF-8"
        h._send(200, body, [("Content-Type", ctype)])


def make_pki(d):
    """Create CA + server (localhost/127.0.0.1) + client certs under directory d."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def save_key(key, path):
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))

    def issue(cn, issuer_name, issuer_key, key, ca=False, eku=None, san=None):
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                            critical=False))
        if ca:
            b = b.add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = issue("Test CA", name("Test CA"), ca_key, ca_key, ca=True)
    out = {}
    for label, cn, eku, san in (
        ("server", "localhost", ExtendedKeyUsageOID.SERVER_AUTH,
         [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
        ("client", "win10.example.com", ExtendedKeyUsageOID.CLIENT_AUTH, None),
    ):
        k = ec.generate_private_key(ec.SECP256R1())
        c = issue(cn, ca.subject, ca_key, k, eku=eku, san=san)
        (d / f"{label}.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
        save_key(k, d / f"{label}.key")
        out[f"{label}_cert"], out[f"{label}_key"] = str(d / f"{label}.pem"), str(d / f"{label}.key")
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    out["ca"] = str(d / "ca.pem")
    return out


def fake_factory(hostname=None):
    """Target of the CLI's --context-factory option in subprocess tests."""
    return FakeContext()
