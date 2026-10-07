# logthing analytics stack

A ready-to-run stack that turns logthing's Parquet output into queryable Iceberg tables,
as docker compose or a Helm chart.

```
syslog / IPFIX / sFlow / Zeek ──▶ logthing ──Parquet + descriptors──▶ Garage (S3)
                                                                         │
  Trino (HTTPS) ──▶ Lakekeeper (Iceberg REST) ◀── committer ◀─────┘
```

| Component | Role | Default image |
|-----------|------|---------------|
| logthing | ingest, writes Parquet + descriptors to S3 | `ghcr.io/mrmagooey/logthing:0.21.0` |
| Garage | S3-compatible object store (bucket `logthing-data`) | `dxflrs/garage:v2.4.1` |
| committer | registers descriptors as Iceberg tables | `ghcr.io/mrmagooey/logthing-committer:0.21.0` |
| Lakekeeper | Iceberg REST catalog (warehouse `logthing`) | `quay.io/lakekeeper/catalog:v0.13.6` |
| Postgres | Lakekeeper metadata | `postgres:17` |
| Trino | SQL engine over HTTPS 8443 with password auth, catalog `iceberg`, schema `logs` | `trinodb/trino:483` |

**Hardware:** Trino 480+ needs an x86-64-v3 / AVX2 CPU. On older CPUs override the image at
your own risk: `TRINO_IMAGE` (compose) or `trino.image` (Helm); `trinodb/trino:470` is known to
start without AVX2.

**Security**

- **Credentials are generated, never defaulted.** Compose refuses to start without `.env`; Helm generates random secrets (see Credentials).
- **Trino is HTTPS + password only** (users `admin` and `metabase`, private CA generated at first start). Lakekeeper has no authentication: keep it on a private network (it is published on loopback by default; it will stop being published in a later change).
- Garage S3, Lakekeeper and Trino bind to `${ANALYTICS_BIND_ADDR:-127.0.0.1}` in compose
  (loopback by default; `ANALYTICS_BIND_ADDR=0.0.0.0` exposes them).
- logthing ingest ports (514/udp, 601/tcp, 4739/udp, 6343/udp, 47760/tcp) and 5985/tcp listen
  on **all interfaces**.
- Port 5985 is logthing's HTTP endpoint. Besides `/health`, it accepts unauthenticated plaintext HTTP requests and is published on all interfaces like the other ingest ports; firewall it if the host is reachable from untrusted networks.

## Credentials

There are no default secrets.

- **compose:** `deploy/analytics/scripts/gen-analytics-env.sh` writes `.env` (mode 600) with random
  values; `docker compose up` fails with a message naming any variable that is missing or empty.
  Regenerating (`--force`) or editing credentials after the first start needs
  `docker compose down -v` (it **deletes all data**) because Postgres roles and the Garage key are
  created from them on first start.
- **Helm:** leave `credentials.*` empty and the chart generates random values on first install and
  keeps them on `helm upgrade` (read back from the live Secret with `lookup`). Set a value to pin
  it, or `credentials.existingSecret` for your own Secret. `helm template` cannot see the live
  Secret and renders fresh values each time: pin credentials (or use `existingSecret`) when
  applying with GitOps tools. Reinstalling after `helm uninstall` needs the PVCs deleted
  (`kubectl delete pvc -n <ns> -l app.kubernetes.io/instance=<release>`, deletes all data) unless
  you supply `existingSecret` with the original values.

Passwords must be URL-safe (`[A-Za-z0-9._~-]`, they are spliced into Postgres URLs); the chart
fails the render otherwise. The Garage key id must be `GK` + 24 hex characters and its secret
64 hex characters.

## Docker compose

All commands run from `deploy/analytics`.

```bash
cd deploy/analytics
scripts/gen-analytics-env.sh   # writes .env with random secrets
docker compose up -d
docker compose ps        # wait: init services (garage-init, lakekeeper-migrate,
                         # lakekeeper-init) "Exited (0)", the rest running/healthy
```

| Service | Host port |
|---------|-----------|
| logthing syslog | 514/udp, 601/tcp |
| logthing IPFIX / sFlow | 4739/udp, 6343/udp |
| logthing Zeek / health | 47760/tcp, 5985/tcp |
| Garage S3 / Lakekeeper | 3900 / 8181 |
| Trino (HTTPS) | 8443 |

Every host port can be changed with a variable listed in `.env.example`. Long-running
services use `restart: unless-stopped`.

1. Send a test message:
   `logger -n 127.0.0.1 -P 514 -d "hello"` or
   `echo '<134>test hello' | nc -u -w1 127.0.0.1 514`.
2. Wait 1-2 minutes: logthing flushes every 60 s (`LOGTHING_FLUSH_INTERVAL_SECS`) and the
   committer runs every 60 s (`COMMIT_INTERVAL_SECS`).
3. Check the tables (see "Querying Trino" below):
   `docker compose exec trino trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem --user admin --password --execute 'SHOW TABLES FROM iceberg.logs'`.
   Empty output or "schema does not exist" means no committer run has found descriptors yet:
   wait another minute and check `docker compose logs committer`.
4. Query: `docker compose exec trino trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem --user admin --password --execute 'SELECT count(*) FROM iceberg.logs.syslog'`.

### Querying Trino (HTTPS + password)

Trino listens on https://localhost:8443 with a private CA generated into the `trino-tls` volume.
The admin password is `TRINO_ADMIN_PASSWORD` in `.env`. Trino's plain-HTTP port 8080 is used only
for its own internal traffic inside the container and is never published.

```bash
# Inside the container (the CLI reads TRINO_PASSWORD, which compose sets to the admin password):
docker compose exec trino trino --server https://localhost:8443 \
  --truststore-path /etc/trino/tls/ca.pem --user admin --password \
  --execute 'SELECT count(*) FROM iceberg.logs.syslog'
# From the host: extract the CA once, then trust it explicitly
docker compose exec -T trino cat /etc/trino/tls/ca.pem > trino-ca.pem
curl --cacert trino-ca.pem -u admin:"$TRINO_ADMIN_PASSWORD" -X POST -H 'X-Trino-User: admin' \
  -d 'select 1' https://localhost:8443/v1/statement
```

The certificate is valid for `trino`, `localhost` and `127.0.0.1` and is kept while it has more than
30 days left. To rotate it delete the volume (`docker compose down` then `docker volume rm
<project>_trino-tls`) and start again; clients must re-read `ca.pem`. To use your own certificate,
write `ca.pem` and `server.pem` (certificate + PKCS#8 key, readable by uid 1000) into that volume.
Any other container that needs the CA must mount only `ca.pem`, never `server.pem` (it holds the
private key). Both Trino users have the same rights: there is no Trino authorization policy.

## Helm

Examples assume release `lt` in namespace `analytics`; Services are named
`<release>-logthing-analytics-<component>`.

```bash
helm install lt deploy/analytics/helm/logthing-analytics -n analytics --create-namespace \
  -f my-values.yaml
kubectl get jobs,cronjob -n analytics     # init Jobs Complete; committer CronJob present
kubectl get pods -n analytics             # wait until Ready
kubectl exec -n analytics deploy/lt-logthing-analytics-trino -- \
  trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem --user admin --password --execute 'SHOW TABLES FROM iceberg.logs'
```

As with compose, tables appear 1-2 minutes after data arrives (the committer is a CronJob).

- **Credentials:** set `credentials.*` in values, or `credentials.existingSecret` naming a
  Secret with these keys:
  - `garage-rpc-secret`
  - `garage-admin-token`
  - `s3-access-key`
  - `s3-secret-key`
  - `postgres-password`
  - `lakekeeper-db-password`
  - `lakekeeper-encryption-key`
  - `trino-admin-password`
  - `trino-metabase-password`
  - `trino-shared-secret`
- **Trino TLS:** the chart generates a private CA and certificate into Secret `<fullname>-trino-tls` (kept across upgrades; delete it and upgrade to rotate, then restart Trino). Provide your own with `trino.tls.existingSecret` (keys `ca.pem` and `server.pem`). The Service exposes only HTTPS 8443.
- **logthing Services:** two are created, `<fullname>-logthing-udp` (514, 4739, 6343) and
  `<fullname>-logthing-tcp` (601, 47760, 5985), because mixed-protocol LoadBalancers are
  poorly supported. Set `logthing.udpService.type` / `logthing.tcpService.type` (default
  `ClusterIP`) to expose them.
- **Committer** is a CronJob (`committer.schedule`, default every minute).
- **Init Jobs** are named per release revision and re-run idempotently on every `helm upgrade`.
- Uninstalling leaves the PVCs behind; see Credentials.
- All other settings (images, resources, storage sizes): see
  [values.yaml](helm/logthing-analytics/values.yaml).

## Tables and maintenance

- Table naming (`syslog`, `zeek_<stream>`, `sflow_<partition>`, ...): see
  [committer/README.md](../../committer/README.md#table-naming).
- Compaction and snapshot expiry (`optimize`, `expire_snapshots`) are periodic jobs you run;
  never run `remove_orphan_files`. See [docs/iceberg.md](../../docs/iceberg.md#table-maintenance).

## Development

Test commands (unit, integration, e2e) are listed in the root [AGENTS.md](../../AGENTS.md).

- The e2e scripts refuse to run on a non-AVX2 CPU unless `TRINO_IMAGE` is overridden. `compose.sh` uses non-default host ports; run one at a time.
- `helm-minikube.sh` uses its own minikube profile `lt-analytics-e2e` and a private
  `KUBECONFIG` (it never touches `~/.kube/config`). `KEEP_CLUSTER=1` keeps the cluster; a cold
  run can take over 15 minutes.
