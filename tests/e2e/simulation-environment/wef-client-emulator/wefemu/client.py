"""Windows-style WEF client: transports, message flow and strict response validation."""
import base64
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests

from . import envelope as E
from . import multipart, sldc
from .envelope import ValidationError

HTTPS_CONTENT_TYPE = "application/soap+xml;charset=UTF-16"
MODES = ("kerberos-http", "https-mtls")
USER_AGENT = "Microsoft WinRM Client"


def default_context_factory(hostname: str):
    """pyspnego Kerberos initiator for the WEF client: raw Kerberos GSS token (not SPNEGO)."""
    import spnego  # guarded: needs the Kerberos backend (libkrb5) at call time only

    return spnego.client(username=None, password=None, hostname=hostname, service="HTTP",
                         protocol="kerberos", options=spnego.NegotiateOptions.wrapping_winrm)


def load_events(events_dir) -> list[str]:
    """Event XML strings from a directory. Each *.xml file is either a bare <Event> or a WEF
    Events envelope (golden style) whose w:Event children are extracted."""
    events: list[str] = []
    for path in sorted(Path(events_dir).glob("*.xml")):
        text = path.read_text(encoding="utf-8").strip()
        root = ET.fromstring(text)
        if root.tag.endswith("}Envelope"):
            events += [(e.text or "").strip() for e in root.iter(E._q(E.NS_W, "Event"))]
        else:
            events.append(text)
    events = [e for e in events if e]
    if not events:
        raise ValueError(f"no events found in {events_dir}")
    return events


class _Conn:
    """One TCP connection (a requests.Session) plus, for Kerberos, its GSS context."""

    def __init__(self, session, ctx=None):
        self.session, self.ctx = session, ctx

    def close(self):
        self.session.close()


class WefClient:
    def __init__(self, mode, server_url, machine_id, ca=None, cert=None, key=None, compress=True,
                 context_factory=None, timeout=30, notify_host=None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.mode, self.server_url, self.machine_id = mode, server_url, machine_id
        self.ca, self.cert, self.key = ca, cert, key
        self.compress = compress
        self.context_factory = context_factory or default_context_factory
        self.timeout = timeout
        self.notify_host = notify_host
        self.validations = 0

    # ------------------------------------------------------------------ connections
    def _check(self, cond, msg):
        if not cond:
            raise ValidationError(msg)
        self.validations += 1

    def _open(self, url: str) -> _Conn:
        s = requests.Session()
        s.headers["User-Agent"] = USER_AGENT
        if self.mode == "https-mtls":
            if self.cert:
                s.cert = (self.cert, self.key) if self.key else self.cert
            if self.ca:
                s.verify = self.ca
            return _Conn(s)
        conn = _Conn(s, self.context_factory(urlsplit(url).hostname))
        self._authenticate(conn, url)
        return conn

    def _authenticate(self, conn: _Conn, url: str) -> None:
        token = conn.ctx.step()
        headers = {
            "Authorization": "Kerberos " + base64.b64encode(token).decode("ascii"),
            "Content-Type": HTTPS_CONTENT_TYPE,
        }
        if self.compress:
            headers["Content-Encoding"] = "SLDC"
        r = conn.session.post(url, data=b"", headers=headers, timeout=self.timeout,
                              allow_redirects=False)
        self._check(r.status_code == 200, f"auth leg: HTTP {r.status_code}, expected 200")
        self._check(r.content == b"", "auth leg: response body must be empty")
        www = r.raw.headers.getlist("WWW-Authenticate")
        self._check(len(www) == 1 and www[0].startswith("Kerberos "),
                    f"auth leg: expected one 'WWW-Authenticate: Kerberos <token>', got {www}")
        try:
            tok = base64.b64decode(www[0][len("Kerberos "):], validate=True)
        except ValueError as exc:
            raise ValidationError(f"auth leg: AP-REP is not base64: {exc}") from exc
        conn.ctx.step(tok)
        complete = getattr(conn.ctx, "complete", True)
        self._check(complete, "auth leg: GSS context not complete after AP-REP")

    # ------------------------------------------------------------------ messaging
    def _post(self, conn: _Conn, url: str, xml: str, expect_body: bool) -> str | None:
        plain = E.encode_message(xml)
        if self.compress:
            comp = sldc.compress(plain)
            if len(comp) < len(plain):
                plain = comp
        headers = {}
        if self.compress:
            headers["Content-Encoding"] = "SLDC"
        if self.mode == "kerberos-http":
            w = conn.ctx.wrap_winrm(plain)
            body = multipart.build(multipart.PROTOCOL, len(plain), w.header, w.data)
            headers["Content-Type"] = multipart.CONTENT_TYPE
        else:
            body, headers["Content-Type"] = plain, HTTPS_CONTENT_TYPE
        r = conn.session.post(url, data=body, headers=headers, timeout=self.timeout,
                              allow_redirects=False)
        self._check(r.status_code == 200, f"HTTP {r.status_code} (expected 200) from {url}: {r.content[:80]!r}")
        self._check("SLDC" not in r.headers.get("Content-Encoding", ""), "server compressed its response")
        if not expect_body:
            self._check(r.content == b"", f"expected empty 200 body, got {len(r.content)} bytes")
            return None
        return self._decode_response(conn, r)

    def _decode_response(self, conn: _Conn, r) -> str:
        ctype = r.headers.get("Content-Type", "")
        if self.mode == "kerberos-http":
            self._check(ctype == multipart.CONTENT_TYPE, f"response Content-Type {ctype!r}")
            try:
                protocol, length, header, data = multipart.parse(r.content)
                self._check(protocol == multipart.PROTOCOL, f"multipart protocol {protocol!r}")
                plain = conn.ctx.unwrap_winrm(header, data)
                multipart.check_length(length, plain)
            except multipart.MultipartError as exc:
                raise ValidationError(f"response multipart: {exc}") from exc
        else:
            self._check(ctype == HTTPS_CONTENT_TYPE, f"response Content-Type {ctype!r}")
            plain = r.content
        self._check(len(plain) > 0, "empty decrypted response")
        return E.decode_message(plain)

    # ------------------------------------------------------------------ operations
    def _enumerate(self, conn, url) -> list[E.Subscription]:
        req = E.build_enumerate(url, self.machine_id)
        mid = E.parse_message(req).message_id
        resp = self._post(conn, url, req, expect_body=True)
        subs = E.validate_enumerate_response(resp, mid)
        self.validations += 1
        return subs

    def _end(self, conn, url):
        self._post(conn, url, E.build_end(url, self.machine_id), expect_body=False)

    def _ack_post(self, conn, url, xml) -> None:
        mid = E.parse_message(xml).message_id
        E.validate_ack(self._post(conn, url, xml, expect_body=True), mid)
        self.validations += 1
        self.acks += 1

    def _normalise_notify(self, sub: E.Subscription) -> str:
        parts = urlsplit(sub.notify_to)
        scheme = parts.scheme.lower()
        if self.mode == "https-mtls":
            self._check(scheme == "https", f"NotifyTo scheme {parts.scheme!r}: https-mtls needs https")
        else:
            self._check(scheme in ("http", "https"), f"NotifyTo scheme {parts.scheme!r}")
        netloc = self.notify_host or parts.netloc
        return urlunsplit((scheme, netloc, parts.path, parts.query, ""))

    def _check_subscription(self, sub: E.Subscription) -> None:
        if self.mode == "kerberos-http":
            self._check(sub.policy_profile == E.PROFILE_KERBEROS, f"auth profile {sub.policy_profile!r}")
        else:
            self._check(sub.policy_profile == E.PROFILE_MUTUAL, f"auth profile {sub.policy_profile!r}")
            self._check(bool(sub.issuer_thumbprints) and all(
                re.fullmatch(r"[0-9A-Fa-f]{40}", t) for t in sub.issuer_thumbprints),
                f"issuer thumbprints {sub.issuer_thumbprints}")
        self._check(sub.content_format in (None, "Raw", "RenderedText"), f"ContentFormat {sub.content_format!r}")
        self._check(sub.compression in (None, "SLDC"), f"Compression {sub.compression!r}")

    def run_flow(self, events_dir, batches=3, batch_size=5, start_record_id=1000) -> dict:
        events = load_events(events_dir)
        self.acks = 0
        sent = 0
        enum_url = self.server_url

        # 1. enumeration connection
        conn = self._open(enum_url)
        subs = self._enumerate(conn, enum_url)
        self._check(len(subs) >= 1, "EnumerateResponse carries no subscription")
        sub = subs[0]
        self._check_subscription(sub)
        self._end(conn, enum_url)
        conn.close()

        # 2. delivery connection (new TCP connection / GSS context)
        notify = self._normalise_notify(sub)
        ident = sub.identifier or sub.version.removeprefix("uuid:")
        dconn = self._open(notify)
        try:
            self._ack_post(dconn, notify, E.build_heartbeat(sub.notify_to, self.machine_id, ident))
            last_bookmark = None
            for b in range(batches):
                batch = [events[(b * batch_size + i) % len(events)] for i in range(batch_size)]
                sent += len(batch)
                channel = (re.findall(r"<Channel>([^<]*)</Channel>", batch[-1]) or ["Security"])[-1]
                last_bookmark = (channel, str(start_record_id + sent))
                bm = (f'<BookmarkList><Bookmark Channel="{channel}" RecordId="{last_bookmark[1]}" '
                      'IsCurrent="true"/></BookmarkList>')
                self._ack_post(dconn, notify,
                               E.build_events(sub.notify_to, self.machine_id, ident, batch, bm))

            # 3. next refresh: a fresh enumeration connection must replay the bookmark
            conn2 = self._open(enum_url)
            subs2 = self._enumerate(conn2, enum_url)
            same = [s for s in subs2 if s.version == sub.version or s.name == sub.name]
            self._check(len(same) == 1, "subscription missing from second Enumerate")
            sub2 = same[0]
            self._check(sub2.version == sub.version,
                        f"subscription Version changed {sub.version} -> {sub2.version} without any change")
            if last_bookmark:
                self._check(sub2.bookmark_entries() == [last_bookmark],
                            f"bookmark not replayed: sent {last_bookmark}, got {sub2.bookmark_entries()}")
            self._end(conn2, enum_url)
            conn2.close()

            # 4. tear down the delivery connection
            self._post(dconn, notify, E.build_subscription_end(sub.notify_to, self.machine_id, ident),
                       expect_body=False)
            self._end(dconn, notify)
        finally:
            dconn.close()
        return {
            "ok": True, "mode": self.mode, "events_sent": sent, "acks": self.acks, "batches": batches,
            "subscription_version": sub.version, "subscription_name": sub.name,
            "validations": self.validations,
        }


# ---------------------------------------------------------------------- negative / positive checks
def _challenges(resp) -> set[str]:
    out = set()
    for v in resp.raw.headers.getlist("WWW-Authenticate"):
        out.add(v.split()[0] if v.split() else "")
    return out


def run_checks(server, kerberos=False, positive=True, context_factory=None, timeout=15) -> dict:
    """Ported kerberos-test checks. `server` may be a bare origin or any URL on the server."""
    p = urlsplit(server)
    origin = f"{p.scheme}://{p.netloc}"
    results = []

    def record(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    def attempt(name, fn):
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 - a failed check, not a crash
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        record(name, ok, detail)

    soap = {"Content-Type": "application/soap+xml"}

    def health():
        r = requests.get(origin + "/health", timeout=timeout)
        return r.status_code == 200, f"HTTP {r.status_code}"

    attempt("health", health)
    if kerberos:
        def wsman_unauth():
            r = requests.post(origin + "/wsman", data=b"<x/>", headers=soap, timeout=timeout)
            ch = _challenges(r)
            return r.status_code == 401 and {"Kerberos", "Negotiate"} <= ch, f"HTTP {r.status_code} {sorted(ch)}"

        def syslog_unauth():
            r = requests.post(origin + "/syslog", data=b'{"message":"x"}',
                              headers={"Content-Type": "application/json"}, timeout=timeout)
            return r.status_code == 401, f"HTTP {r.status_code}"

        def bogus():
            r = requests.post(origin + "/wsman", data=b"<x/>", timeout=timeout,
                              headers={**soap, "Authorization": "Negotiate dGVzdA=="})
            return r.status_code == 401, f"HTTP {r.status_code}"

        attempt("wsman-no-auth-401-both-challenges", wsman_unauth)
        attempt("syslog-no-auth-401", syslog_unauth)
        attempt("wsman-bogus-token-401", bogus)
        if positive:
            attempt("syslog-negotiate-2xx", lambda: _positive_negotiate(origin, context_factory, timeout))
    return {"ok": all(r["ok"] for r in results), "checks": results}


def _positive_negotiate(origin, context_factory, timeout):
    host = urlsplit(origin).hostname
    if context_factory:
        ctx = context_factory(host)
    else:
        import spnego

        ctx = spnego.client(username=os.environ.get("WEFEMU_PRINCIPAL"),
                            password=os.environ.get("WEFEMU_PASSWORD"), hostname=host,
                            service="HTTP", protocol="negotiate")
    in_token = None
    for _ in range(4):
        out = ctx.step(in_token)
        headers = {"Content-Type": "application/json"}
        if out:
            headers["Authorization"] = "Negotiate " + base64.b64encode(out).decode("ascii")
        r = requests.post(origin + "/syslog", data=json.dumps({"message": "kerberos check"}),
                          headers=headers, timeout=timeout)
        if 200 <= r.status_code < 300:
            return True, f"HTTP {r.status_code}"
        www = r.headers.get("WWW-Authenticate", "")
        m = re.search(r"Negotiate\s+([A-Za-z0-9+/=]+)", www)
        if r.status_code == 401 and m:
            in_token = base64.b64decode(m.group(1))
            continue
        return False, f"HTTP {r.status_code}"
    return False, "SPNEGO did not complete"
