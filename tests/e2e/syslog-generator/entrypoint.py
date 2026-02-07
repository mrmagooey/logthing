import os
import socket
import time

import requests

SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "wef-server")
UDP_PORT = int(os.environ.get("SYSLOG_UDP_PORT", "5514"))
TCP_PORT = int(os.environ.get("SYSLOG_TCP_PORT", "5601"))
HTTP_ENDPOINT = os.environ.get("SYSLOG_HTTP_ENDPOINT", "http://wef-server:5985/syslog")
TIMEOUT = int(os.environ.get("SYSLOG_WAIT_SECS", "60"))

MESSAGE = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)"


def wait_for_http():
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            resp = requests.get(HTTP_ENDPOINT.replace("/syslog", "/health"), timeout=5)
            if resp.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise SystemExit("Syslog target never became ready")


def send_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(MESSAGE.encode("utf-8"), (SYSLOG_HOST, UDP_PORT))
    sock.close()
    print("Sent UDP syslog message")


def send_tcp():
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            with socket.create_connection((SYSLOG_HOST, TCP_PORT), timeout=5) as conn:
                conn.sendall(MESSAGE.encode("utf-8") + b"\n")
                print("Sent TCP syslog message")
                return
        except OSError:
            time.sleep(2)
    raise SystemExit("TCP syslog port never became reachable")


def send_http():
    resp = requests.post(HTTP_ENDPOINT, data=MESSAGE.encode("utf-8"), timeout=5)
    resp.raise_for_status()
    print("HTTP syslog endpoint accepted payload")


def main():
    wait_for_http()
    send_udp()
    send_tcp()
    send_http()
    print("Syslog generator completed")


if __name__ == "__main__":
    main()
