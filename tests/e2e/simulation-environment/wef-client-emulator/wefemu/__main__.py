"""CLI: python -m wefemu flow|checks ... ; prints one JSON summary line, exit 0 iff all OK."""
import argparse
import importlib
import json
import sys

from .client import WefClient, run_checks


def _factory(spec):
    if not spec:
        return None
    mod, _, attr = spec.partition(":")
    return getattr(importlib.import_module(mod), attr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wefemu")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("flow", help="full Windows-style WEF client flow")
    f.add_argument("--mode", required=True, choices=["kerberos-http", "https-mtls"])
    f.add_argument("--server", required=True, help="Enumerate URL (the Subscription Manager URL)")
    f.add_argument("--machine-id", required=True)
    f.add_argument("--events-dir", required=True)
    f.add_argument("--batches", type=int, default=3)
    f.add_argument("--batch-size", type=int, default=5)
    f.add_argument("--ca")
    f.add_argument("--cert")
    f.add_argument("--key")
    f.add_argument("--no-compress", action="store_true")
    f.add_argument("--notify-host", help="override host:port of the NotifyTo address")
    f.add_argument("--context-factory", help=argparse.SUPPRESS)
    c = sub.add_parser("checks", help="auth negative/positive checks")
    c.add_argument("--server", required=True)
    c.add_argument("--kerberos", action="store_true")
    c.add_argument("--no-positive", action="store_true")
    c.add_argument("--context-factory", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "flow":
            client = WefClient(a.mode, a.server, a.machine_id, ca=a.ca, cert=a.cert, key=a.key,
                               compress=not a.no_compress, context_factory=_factory(a.context_factory),
                               notify_host=a.notify_host)
            out = client.run_flow(a.events_dir, batches=a.batches, batch_size=a.batch_size)
        else:
            out = run_checks(a.server, kerberos=a.kerberos, positive=not a.no_positive,
                             context_factory=_factory(a.context_factory))
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
