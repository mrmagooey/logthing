import importlib.util
import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

ANALYTICS = pathlib.Path(__file__).resolve().parents[1]
CHART = ANALYTICS / "helm" / "logthing-analytics"
BOOTSTRAP = CHART / "files" / "bootstrap.py"


def _load_bootstrap():
    spec = importlib.util.spec_from_file_location("bootstrap", BOOTSTRAP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def bootstrap():
    return _load_bootstrap()


class FakeServer:
    """In-process HTTP server. `routes` maps (METHOD, path) -> callable(query, body) -> (status, obj)."""

    def __init__(self):
        self.routes = {}
        self.calls = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _handle(self):
                url = urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None
                outer.calls.append((self.command, url.path, body, self.headers.get("Authorization")))
                fn = outer.routes.get((self.command, url.path))
                status, obj = fn(parse_qs(url.query), body) if fn else (404, {"code": "NotFound"})
                data = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = FakeServer()
    yield s
    s.close()
