# WEF client emulator

An independent Python emulator of a Windows source-initiated WEF client, used to test the
logthing WEF collector. It was written from the protocol reference, the golden fixtures
(`tests/fixtures/wef/golden/`), ECMA-321 and public pyspnego/requests documentation, without
reference to the server implementation. Its validators are strict on purpose: they are the
acceptance test for the server.

## Run

```
python3 -m venv .venv && .venv/bin/pip install -e .[test] && .venv/bin/pytest tests   # offline
python -m wefemu flow --mode kerberos-http --server http://wec:5985/wsman/SubscriptionManager/WEC \
    --machine-id win10.example.com --events-dir DIR [--batches 3 --batch-size 5] [--no-compress]
python -m wefemu flow --mode https-mtls --server https://wec:5986/wsman/SubscriptionManager/WEC \
    --machine-id win10.example.com --events-dir DIR --ca ca.pem --cert client.pem --key client.key
python -m wefemu checks --server http://wec:5985 --kerberos     # auth negative/positive checks
```

Both commands print one JSON summary line and exit 0 only if every validation passed.
`flow` reads `*.xml` from `--events-dir`: bare `<Event>` documents, or WEF Events envelopes
(e.g. `golden/events.xml`) whose `w:Event` CDATA payloads are used.

Real Kerberos runs in the Docker image (`docker build -t wef-client-emulator .`; the entrypoint
runs `kinit -k -t $KRB5_CLIENT_KEYTAB 'WIN10$@EXAMPLE.COM'` when `KRB5_CLIENT_KEYTAB` is set).
`checks --kerberos` positive check uses `WEFEMU_PRINCIPAL`/`WEFEMU_PASSWORD` (or the default ccache,
e.g. alice via `kinit`). Offline tests use a fake GSS context and a stub HTTP(S) server
(`tests/stubwec.py`), so no libkrb5 is needed on the host; `import spnego` happens lazily.

## What it checks

* Kerberos mode uses scheme `Kerberos` and multipart protocol
  `application/HTTP-Kerberos-session-encrypted` (not pywinrm's `Negotiate`/SPNEGO strings);
  empty preemptive auth POST (`Content-Length: 0`, `Content-Encoding: SLDC`) must give 200 + one
  `WWW-Authenticate: Kerberos <AP-REP>` and no body; enumeration and delivery use separate
  connections (one `requests.Session` and GSS context each).
* Bodies: UTF-16LE + BOM, no XML declaration, SLDC when it shrinks the message (header sent
  whenever compression is enabled), then `wrap_winrm`, then the multipart layout of
  `golden/multipart_layout.txt`.
* Responses: UTF-16LE BOM `FF FE`, no `<?xml?>`; Ack/EnumerateResponse Action exact;
  `RelatesTo` equal to the request MessageID byte for byte; response MessageID `uuid:` +
  uppercase GUID; Ack body empty; `w:EndOfSequence` present; End/SubscriptionEnd and the auth leg
  are 200 with no body; encrypted responses use the exact multipart layout (no tabs,
  `charset=UTF-16`, `Length=` equals the decrypted length, exact Content-Type header);
  HTTPS responses use `application/soap+xml;charset=UTF-16`; responses are never SLDC-compressed.
* Flow: auth -> Enumerate -> End -> new connection -> Heartbeat -> Events batches (Bookmark header
  with increasing RecordId) -> second Enumerate on a new connection must replay the last
  bookmark and keep the subscription Version -> SubscriptionEnd -> End.

## SLDC (`wefemu/sldc.py`), ECMA-321 1st ed. (June 2001)

Clauses used: 1 (1024-byte buffer); 7.1/7.2 (schemes 1 and 2); 7.3 and 8.2 (History Buffer: the
Displacement Field is an absolute location 0..1023 in the circular buffer, matches may wrap and
may overlap the string being written, the location being written is excluded so distance is
1..1023); 8.3 (MSB-first packing); 8.4.1 Literal 1; 8.4.2 Copy Pointer and Table 1 (Match Count
Field, lengths 2..271); 8.4.3 Literal 2 (0xFF followed by ZERO); 8.5 Table 1 (control symbols
Flush 0000, Scheme1 0001, Scheme2 0010, FileMark 0011, EOR 0100, Reset1 0101, Reset2 0110, End
Marker 1111, all behind nine ONEs) and 8.6 (Pad). The encoder emits scheme 1 greedy longest
matches then EOR + Flush + zero pad to 32 bits (no leading Reset 1). `tests/test_sldc.py` holds
vectors assembled by hand from those tables, independent of the encoder.

## Protocol ambiguities decided here

See the task report; in short: EOR is followed directly by Flush (the standard's table lists a
Pad after EOR; the decoder accepts both forms), HTTP 200 (not 204) is required for End, the
NotifyTo scheme is normalised to lower case (Windows capture shows `HTTP://`), and the
`e:Identifier` header carries the NotifyTo ReferenceProperties/Parameters identifier.
