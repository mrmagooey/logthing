# logthing dbt project

dbt-trino models over the Iceberg tables logthing writes (namespace `logs`): typed staging views,
four flattened OCSF 1.3 views and three example detections.

## Setup and running

```bash
deploy/analytics/.venv/bin/pip install -r deploy/analytics/tests/requirements.txt   # pins dbt-core 1.11.15, dbt-trino 1.10.6
cd deploy/analytics/dbt
# compose: extract the generated CA once
docker compose -f ../docker-compose.yml exec -T trino cat /etc/trino/tls/ca.pem > trino-ca.pem
export TRINO_HOST=localhost TRINO_PORT=8443 TRINO_USER=admin
export TRINO_PASSWORD=<TRINO_ADMIN_PASSWORD from .env> TRINO_CA_CERT=$PWD/trino-ca.pem
dbt build            # views, schema tests and dbt unit tests
dbt compile          # compiles analyses/ to target/compiled/logthing_analytics/analyses/
```
Helm: `kubectl port-forward svc/<release>-logthing-analytics-trino 8443` and read the CA with
`kubectl get secret <release>-logthing-analytics-trino-tls -o jsonpath='{.data.ca\.pem}' | base64 -d`.

**Tables appear only after data arrives.** The committer creates `zeek_conn`, `wef`, `suricata`, ...
on first data. `stg_*` views use the `source_or_empty` macro, so `dbt build` works on an empty lake
(empty views), but a view built while its table was missing stays empty: run `dbt run` again once
the table exists.

## Models

| Model | Source table | Notes |
|-------|--------------|-------|
| `stg_wef`, `stg_zeek_conn`, `stg_zeek_dns`, `stg_ipfix`, `stg_sflow_flow`, `stg_suricata` | `wef`, `zeek_conn`, `zeek_dns`, `ipfix`, `sflow_flow`, `suricata` | typed passthrough |
| `ocsf_network_activity` (4001) | zeek_conn, ipfix, sflow_flow | activity 6 Traffic; protocol number from the Zeek protocol name (tcp 6, udp 17, icmp 1, icmp6 58) |
| `ocsf_dns_activity` (4003) | zeek_dns | Query (1) without rcode, Response (2) with |
| `ocsf_authentication` (3002) | wef 4624, 4625, 4634, 4648 | Logon (1) / Logoff (2); 4625 = status Failure, severity Low |
| `ocsf_detection_finding` (2004) | suricata `event_type = 'alert'` | Suricata severity 1/2/3 -> OCSF 4/3/2; timestamps keep microseconds |

OCSF dotted attributes are flattened with underscores (`src_endpoint.ip` -> `src_endpoint_ip`,
`metadata.product.name` -> `metadata_product_name`). Required columns carry `not_null` tests.
**Syslog has no OCSF model** (no natural OCSF class); `syslog`, `structured_syslog`, `sflow_counter`
and `hec` are declared as sources only. `stg_otlp` and `stg_hec` arrive with the OTLP/HEC work.

**WEF fields come from `raw_xml`.** The `wef.event_data` column is the serialized event JSON; its
`parsed.data` is always null, so TargetUserName, IpAddress, LogonType... are read from the XML in
`raw_xml` with a regexp (`macros/wef_field.sql`). Absent, empty and `-` values become NULL, and
malformed JSON/XML yields NULLs (the row's `time` falls back to the receipt time).

## Detections (`analyses/`)

| Analysis | Fires when | Variable |
|----------|-----------|----------|
| `detect_auth_bruteforce` | >= N failed logons (4625) from one source IP in a 10-minute window, last day | `bruteforce_threshold` (10) |
| `detect_suricata_high_severity` | Suricata alerts with OCSF severity >= 4, grouped by destination, last day | `suricata_min_severity_id` (4) |
| `detect_rare_outbound_port` | destination port unseen in the previous 7 days and < N connections in the last day | `rare_port_max_connections` (5) |

"Last day" is relative to the wall clock by default. Set `detection_as_of` (ISO 8601, e.g.
`--vars '{detection_as_of: "2026-10-05T12:00:00Z"}'`) to pin the reference time, for replaying
history or reproducible tests.

dbt compiles analyses but never runs them. Schedule them yourself: compile, then run the SQL with
any Trino client over HTTPS with the CA, e.g. cron every 10 minutes:

```bash
cd /opt/logthing/deploy/analytics/dbt && dbt compile -q --vars '{bruteforce_threshold: 20}' && \
for f in target/compiled/logthing_analytics/analyses/detect_*.sql; do
  trino --server https://trino.example:8443 --truststore-path /etc/ssl/trino-ca.pem --user admin \
        --password --execute "$(cat "$f")"
done
```
or the same two commands in a Kubernetes `CronJob` whose image contains dbt (`pip install -r
requirements.txt`) and the Trino CLI, with `TRINO_*` taken from the credentials Secret and the CA
mounted (illustrative: this stack ships no such image). Alert routing is up to you; logthing is a
SIEM feeder, not an alerting engine.

**Sigma:** there is no pySigma backend for Trino (verified 2026-10-06 against the pySigma plugin
directory: none for Trino, Presto, Athena or generic SQL), so Sigma rules are not converted
automatically. The future route is a custom pySigma `TextQueryBackend` emitting Trino SQL over these
OCSF views; that is not shipped.
