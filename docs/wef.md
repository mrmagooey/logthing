# Windows Event Forwarding (WEF)

## Kerberos Client Authentication

Require inbound clients (e.g., Windows Event Forwarding collectors) to authenticate with SPNEGO/Negotiate.

```toml
[security.kerberos]
enabled = true
spn = "HTTP/wef.contoso.com@CONTOSO.COM"
keytab = "/etc/logthing/krb5.keytab"
```

- Build the binary or container with `--features kerberos-auth` so the Kerberos middleware is compiled in. (Without the feature the server will log a warning and continue without enforcing Negotiate.)
- When `enabled = true`, the main server's protected routes (`/wsman/**`, `/syslog`) enforce Kerberos authentication before any route logic runs. `/health` and `/stats/throughput` stay public. The **admin API is a separate server on its own port and is NOT covered by Kerberos** — it has its own Basic-auth/trusted-header authentication and its own IP allowlist.
- `spn` must match the service principal registered in Active Directory (format `HTTP/hostname@REALM`).
- `keytab` (optional) points to the keytab that contains the service principal’s keys. If provided, logthing sets `KRB5_KTNAME` automatically so `libgssapi` can decrypt tickets.
- The middleware logs the authenticated client principal at `debug` level; there is no extractor exposing it to handlers.
- `/wsman/**` uses its own per-connection Kerberos handling with message encryption (see "Kerberos details" below); this paragraph's two-pass SPNEGO applies to the other protected routes. Only two-pass SPNEGO is supported there: the client is expected to already hold a Kerberos ticket and send a single, complete `Negotiate` token, as real Kerberos-over-HTTP normally works. Multi-leg negotiation (as an NTLM fallback would need) is not implemented — a token that comes back "continue needed" is rejected with `401` rather than tracked across requests.

### Active Directory Setup (Kerberos clients → logthing)

1. **Create a service account** that represents the logthing server itself, e.g., `CONTOSO\logthing-appliance`.
2. **Register the HTTP SPN** so KDCs know which account owns the hostname clients connect to:
   ```powershell
   setspn -S HTTP/wef.contoso.com CONTOSO\logthing-appliance
   ```
3. **Generate a keytab** for that account (Domain Admin privilege required):
   ```powershell
   ktpass /princ HTTP/wef.contoso.com@CONTOSO.COM ^
          /mapuser CONTOSO\logthing-appliance ^
          /pass * ^
          /ptype KRB5_NT_PRINCIPAL ^
          /crypto AES256-SHA1 ^
          /out C:\temp\logthing.keytab
   ```
   Copy the resulting keytab to the Linux host/container that runs logthing and guard it (`chmod 600`).
4. **Configure `/etc/krb5.conf`** with your AD realm and KDCs.
5. **Sanity check Kerberos locally** before enabling the server:
   ```bash
   export KRB5_KTNAME=/etc/logthing/krb5.keytab
   kinit -k -t "$KRB5_KTNAME" HTTP/wef.contoso.com@CONTOSO.COM
   curl --negotiate -u : https://wef.contoso.com/wsman -d '' -k
   ```
   (The curl call should not return `401`; anything else shows the ticket exchange works.)
6. **Update `logthing.toml`** as shown above, restart the service, and ensure the keytab is mounted into any containers. Clients will now need valid Kerberos tickets to reach the API.

## Windows Client Configuration (source-initiated)

logthing is a **source-initiated** collector: Windows machines are pointed at it with a group
policy and fetch their subscriptions from it. Nothing is created on the Windows side with
`wecutil` (that tool configures a Windows *collector*, which logthing is not).

### 1. Define the subscriptions on logthing

```toml
[wef]
collector_url = "http://logthing.example.com:5985"   # what clients will use; no trailing path

[[wef.subscriptions]]
name = "security"
uuid = "0b0e3a7c-52f4-4b8a-9c53-7e2f1a6d9b10"       # any unique GUID
channels = ["Security", "System"]                     # or query = "<QueryList>...</QueryList>"
content_format = "Raw"                                # or "RenderedText"
heartbeat_interval_secs = 3600
max_latency_secs = 30
read_existing_events = false
```

`[[wef.subscriptions]]` keys:

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique, 1 to 128 characters of `A-Z a-z 0-9 _ . -` |
| `uuid` | required | Unique subscription identifier |
| `channels` | `[]` | Event log channels to forward (all events). Exclusive with `query` |
| `query` | none | A full `<QueryList>` XML document. Exclusive with `channels` |
| `content_format` | `Raw` | `Raw` or `RenderedText` (adds the localized message text) |
| `heartbeat_interval_secs` | `3600` | Client heartbeat interval |
| `max_latency_secs` | `30` | Maximum time the client batches events |
| `max_envelope_size` | `512000` | Maximum SOAP envelope bytes, minimum `8192` |
| `read_existing_events` | `false` | Also send events already in the log when a client first subscribes |
| `enabled` | `true` | Disabled subscriptions are not offered to clients |

Other `[wef]` keys:

| Key | Default | Meaning |
|---|---|---|
| `collector_url` | none | Public base URL clients use. Required when any subscription is configured; must be `http://` without TLS and `https://` with TLS |
| `allow_unauthenticated` | `false` | Accept clients with no authentication (plain HTTP, no Kerberos). Anyone who can reach the port can then submit events; `security.allowed_ips` is the only remaining control |
| `bookmark_capacity` | `10000` | Maximum number of per-(machine, subscription) bookmarks held in memory |

Changing any client-visible parameter changes the subscription's version, so clients pick up
the change at their next refresh. Settings are read at startup.

### 2. Choose a topology

Exactly one of these applies to a logthing instance. Mixing them is not supported.

**(a) Kerberos over HTTP.** TLS disabled, `[security.kerberos]` enabled (build with
`--features kerberos-auth`), `collector_url` starting `http://`. Clients authenticate with
Kerberos and logthing encrypts the SOAP messages (see below).

**(b) HTTPS with client certificates.** `[tls] enabled = true`, `require_client_cert = true`,
`ca_file` set to the CA that issued the clients' certificates, `collector_url` starting
`https://`.

There is also a third, explicit opt-in and **unsafe** mode: `wef.allow_unauthenticated = true`
accepts clients over plain HTTP with no authentication at all. Startup logs a warning, and
`security.allowed_ips` is the only control left. Use it only on a trusted, isolated network.

Startup fails with one of these messages when the configuration does not fit:

- `wef.collector_url is required when [[wef.subscriptions]] are configured`
- `wef.collector_url must use https:// when TLS is enabled`
- `wef.collector_url must use http:// when TLS is disabled`
- `WEF subscriptions over TLS require tls.require_client_cert = true (Windows HTTPS delivery uses client certificates); for Kerberos, disable TLS and use the plain HTTP listener`
- `WEF subscriptions over TLS require tls.ca_file (client CA certificates)`
- `WEF subscriptions require authentication: enable [security.kerberos] (built with --features kerberos-auth) or TLS with require_client_cert, or set wef.allow_unauthenticated = true`

### 3. Point Windows at logthing (group policy)

In a GPO linked to the machines that should forward events, set
`Computer Configuration > Administrative Templates > Windows Components > Event Forwarding >
Configure target Subscription Manager` to Enabled and add one entry:

```
Server=http://logthing.example.com:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

For HTTPS (topology b), give the SHA-1 thumbprint of the CA that issued logthing's server
certificate (hex, no spaces):

```
Server=https://logthing.example.com:5986/wsman/SubscriptionManager/WEC,Refresh=60,IssuerCA=<SHA-1 thumbprint of the CA, hex, no spaces>
```

`Refresh` is how often, in seconds, the client re-reads its subscriptions. The client also
needs the Windows Remote Management service running (`winrm quickconfig -q`) and, for HTTPS,
a client certificate issued by the CA in `tls.ca_file` in the machine's certificate store.

**Standard Windows WEF prerequisite (not specific to logthing):** the forwarding service runs
as NETWORK SERVICE and needs read access to the logs it forwards. For the Security log, either
add NETWORK SERVICE to the local `Event Log Readers` group or grant it access with
`wevtutil sl security /ca:<SDDL including (A;;0x1;;;NS)>`.

### Kerberos details

- Each TCP connection authenticates once. logthing accepts both `Authorization: Kerberos` (what
  Windows sends) and `Authorization: Negotiate`, and answers an unauthenticated request with a
  `401` offering both schemes. A new `Authorization` header on a connection always starts a
  fresh authentication.
- After authentication, Windows sends each SOAP message encrypted
  (`multipart/encrypted`); logthing decrypts it and encrypts its responses. Contexts that do not
  provide confidentiality, integrity and mutual authentication are refused. Encrypted bodies are
  refused on HTTP/2 connections (`400`); Windows uses HTTP/1.1.
- The service principal must be `HTTP/<fqdn>` for the name in `collector_url` (see the Active
  Directory setup above). Windows Server 2025 clients may request `host/<fqdn>` instead; that is
  not supported yet.
- NTLM is not supported.

### Endpoints

All are `POST`, under the same listener: `/wsman/SubscriptionManager/WEC` (subscription
manager: Enumerate and End) and `/wsman/subscriptions/<subscription uuid>` (event and heartbeat
delivery, which logthing acknowledges). Unknown paths or subscriptions return `404`; an
unsupported `Content-Encoding` returns `415`; an unparseable body returns `400`. Event batches
compressed with SLDC and UTF-8 or UTF-16 bodies are accepted. Bodies that are a bare `<Events>`
element with no SOAP envelope are rejected with `400`. A request body larger than 4 MiB is
rejected with `413` in every topology (Windows' default `MaxEnvelopeSize` is 512000 bytes, so
normal clients stay far below this).

### Known limits

- **Acknowledged events can still be lost.** logthing answers a delivery with an Ack even when
  an event is dropped because the sink buffer is full. Windows then advances its bookmark and
  does not resend it. Watch `parquet_s3_dropped{source="wef"}` and size
  `channel_capacity`/`max_buffer_rows` accordingly.
- **Bookmarks are held in memory.** After a logthing restart (or when `bookmark_capacity` is
  exceeded) clients have no bookmark and resume from now (or from the earliest event if
  `read_existing_events = true`), which can duplicate or skip events.
- **Any client certificate issued by the configured CA can read every subscription** and submit
  events for any of them. Use a dedicated CA for event forwarding clients.
- **Bookmarks are not bound to the authenticated client.** The MachineID in Heartbeat/Events
  bookmarks is not tied to the authenticated Kerberos principal or client certificate, so an
  authenticated client can overwrite another machine's stored bookmark, causing that machine to
  resend or skip events after a reconnect. Each bookmark is capped at 8 KiB, so memory is bounded
  by `bookmark_capacity` x 8 KiB. Binding the principal to the MachineID is a planned follow-up.
- Windows Server 2025 clients requesting `host/<fqdn>` and NTLM are not supported.
- Topologies (a) and (b) cannot be combined on one instance.

## WEF (Windows Event) S3 Persistence

Store Windows events in S3-compatible storage (AWS S3, MinIO, etc.) as ZSTD-compressed Parquet files:

```toml
[wef.s3]
endpoint              = "http://localhost:9000"   # S3-compatible endpoint
bucket                = "wef-events"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
# prefix defaults to "" (empty) — preserves event_type=.../year=... layout at root
flush_threshold_bytes = 104857600        # flush when buffer reaches 100 MiB (default)
flush_interval_secs   = 900             # flush every N seconds regardless of size (default 900)
channel_capacity      = 22755           # bounded channel depth
                                        # (default: 100 MiB budget / 4608 B per record)
max_buffer_rows       = 100000          # hard-cap rows before oldest are dropped (default 100 000)
```

The `[wef.s3]` block is optional; when absent, WEF events are not persisted to S3.

**Features**:
- **Event Type Partitioning**: Each Windows Event ID gets its own Parquet file series
- **Time-Based Partitioning**: Files organized by `event_type/year/month/day/`
- **Compression**: ZSTD compression for efficient storage
- **Backpressure**: Bounded channel; drops are counted by `parquet_s3_dropped{source="wef"}`
- **Drop-log throttling**: The human-facing "channel full/closed" log line for a dropped record
  is capped at one line per 30 seconds per (call site, drop reason) pair; its `dropped_total`
  field is cumulative since process start, not a per-window count — `parquet_s3_dropped` remains
  the authoritative per-drop metric

**S3 Path Structure**:
```
s3://bucket-name/
  event_type=4624/
    year=2024/
      month=01/
        day=15/
          <uuid>.parquet
  event_type=4668/
    year=2024/
      month=01/
        day=15/
          <uuid>.parquet
```

## Generic Event Parser Configuration

Add per-event parser definitions under `config/event_parsers/`. Each file contains a single event definition so you can mix and match without touching the others. For example, `config/event_parsers/4624_successful_logon.yaml`:

```yaml
event_id: 4624
name: "Successful Logon"
description: "An account was successfully logged on"
fields:
  - name: "TargetUserName"
    source: EventData
    xpath: "Data[@Name='TargetUserName']"
    required: true
    type: string
  - name: "LogonType"
    source: EventData
    xpath: "Data[@Name='LogonType']"
    required: true
    type: integer
enrichments:
  - field: "LogonType"
    lookup_table:
      "2": "Interactive"
      "3": "Network"
      "10": "RemoteInteractive"
output_format: |
  User {TargetUserName} logged on via {LogonType_Name}
```

> **Note:** The legacy aggregated `config/event_parsers.yaml` file format is still supported for backward compatibility, but the directory layout makes it easier to version and swap individual event definitions.

The parser supports:
- **Field Extraction**: Extract specific fields from EventData, System, RenderingInfo, or UserData sections
- **Type Conversion**: Convert fields to string, integer, boolean, IP address, or GUID
- **Enrichments**: Add lookup tables to enrich raw values (e.g., logon type codes to names)
- **Message Formatting**: Generate custom output messages using field placeholders

## Event Parser Coverage

The repository ships example parsers for 50 high-value Windows Security events. Each file in `config/event_parsers/` matches one of the entries below:

| Event ID | Description |
| --- | --- |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |
| 4647 | User Initiated Logoff |
| 4648 | Logon Using Explicit Credentials |
| 4649 | Replay Attack Detected |
| 4656 | Handle Requested |
| 4657 | Registry Value Changed |
| 4658 | Handle Closed |
| 4660 | Object Deleted |
| 4661 | Handle Requested for Object |
| 4662 | Operation Performed on Object |
| 4663 | Attempted Object Access |
| 4670 | Permissions on Object Changed |
| 4672 | Admin Logon |
| 4673 | Privileged Service Called |
| 4674 | Privileged Service Operation |
| 4688 | Process Created |
| 4689 | Process Terminated |
| 4697 | Service Installed |
| 4698 | Scheduled Task Created |
| 4699 | Scheduled Task Deleted |
| 4700 | Scheduled Task Enabled |
| 4702 | Scheduled Task Updated |
| 4719 | System Audit Policy Changed |
| 4720 | User Account Created |
| 4722 | User Account Enabled |
| 4723 | Password Change Attempt |
| 4724 | Password Reset Attempt |
| 4725 | User Account Disabled |
| 4726 | User Account Deleted |
| 4727 | Global Group Created |
| 4728 | Member Added to Global Group |
| 4729 | Member Removed from Global Group |
| 4730 | Global Group Deleted |
| 4731 | Local Group Created |
| 4732 | Member Added to Local Group |
| 4733 | Member Removed from Local Group |
| 4735 | Local Group Changed |
| 4737 | Global Group Changed |
| 4740 | Account Locked |
| 4741 | Computer Account Created |
| 4742 | Computer Account Changed |
| 4743 | Computer Account Deleted |
| 4756 | Member Added to Universal Group |
| 4757 | Member Removed from Universal Group |
| 4767 | Account Unlocked |
| 4768 | Kerberos TGT Requested |
| 4769 | Kerberos Service Ticket Requested |
| 4770 | Kerberos Service Ticket Renewed |
