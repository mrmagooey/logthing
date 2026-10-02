# logthing analytics stack

A ready-to-run stack that turns logthing's Parquet output into queryable Iceberg tables,
as docker compose or a Helm chart.

```
syslog / IPFIX / sFlow / Zeek ──▶ logthing ──Parquet + descriptors──▶ Garage (S3)
                                                                         │
        Hue ──▶ Trino ──▶ Lakekeeper (Iceberg REST) ◀── committer ◀─────┘
```

| Component | Role | Default image |
|-----------|------|---------------|
| logthing | ingest, writes Parquet + descriptors to S3 | `ghcr.io/mrmagooey/logthing:0.21.0` |
| Garage | S3-compatible object store (bucket `logthing-data`) | `dxflrs/garage:v2.4.1` |
| committer | registers descriptors as Iceberg tables | `ghcr.io/mrmagooey/logthing-committer:0.21.0` |
| Lakekeeper | Iceberg REST catalog (warehouse `logthing`) | `quay.io/lakekeeper/catalog:v0.13.6` |
| Postgres | Lakekeeper and Hue metadata | `postgres:17` |
| Trino | SQL engine, catalog `iceberg`, schema `logs` | `trinodb/trino:483` |
| Hue | SQL web UI | `gethue/hue:20260611-140101` |

**Hardware:** Trino 480+ and the stock Hue image need an x86-64-v3 / AVX2 CPU. On older CPUs
override the images at your own risk: `TRINO_IMAGE` / `HUE_IMAGE` (compose) or
`trino.image` / `hue.image` (Helm).

## Credentials (read first)

All credentials default to **demo values**. Change them in `.env` (compose) or `values.yaml`
(Helm) **before the first start**: Postgres roles (lakekeeper/hue passwords) and Garage keys
are created on first start and persist in volumes/PVCs. Changing them later requires wiping
that state, which **deletes all data**:

- compose: `docker compose down -v`
- Helm: `kubectl delete pvc -l app.kubernetes.io/instance=<release> -n <ns>`

Passwords must be URL-safe (they are spliced into Postgres connection URLs). Lakekeeper and
Trino run **without authentication**; keep them on a private network.

## Docker compose

```bash
cd deploy/analytics
cp .env.example .env     # edit credentials first
docker compose up -d
```

| Service | Host port | Bound to |
|---------|-----------|----------|
| logthing syslog | 514/udp, 601/tcp | all interfaces |
| logthing IPFIX / sFlow | 4739/udp, 6343/udp | all interfaces |
| logthing Zeek / health | 47760/tcp, 5985/tcp | all interfaces |
| Garage S3 | 3900 | `${ANALYTICS_BIND_ADDR:-127.0.0.1}` |
| Lakekeeper | 8181 | `${ANALYTICS_BIND_ADDR:-127.0.0.1}` |
| Trino | 8080 | `${ANALYTICS_BIND_ADDR:-127.0.0.1}` |
| Hue | 8888 | `${ANALYTICS_BIND_ADDR:-127.0.0.1}` |

Set `ANALYTICS_BIND_ADDR=0.0.0.0` to expose the last four (mind the no-auth warning above).
Every host port can be changed with a variable listed in `.env.example`. Long-running
services use `restart: unless-stopped`.

1. Send a test message: `logger -n 127.0.0.1 -P 514 -d "hello"` (or any UDP syslog sender).
2. Wait 1-2 minutes. logthing flushes every 60 s (`LOGTHING_FLUSH_INTERVAL_SECS`) and the
   committer loop runs every 60 s (`COMMIT_INTERVAL_SECS`); tables appear in `iceberg.logs`
   only after a committer run finds descriptors.
3. Query: `docker compose exec trino trino --execute "SELECT * FROM iceberg.logs.syslog"`,
   or open Hue at <http://localhost:8888>. The first login creates the admin account
   (whoever logs in first becomes admin).

## Helm

```bash
helm install lt deploy/analytics/helm/logthing-analytics -n analytics --create-namespace \
  -f my-values.yaml
kubectl port-forward -n analytics svc/lt-logthing-analytics-hue 8888
kubectl port-forward -n analytics svc/lt-logthing-analytics-trino 8080
```

(Service names are `<release>-logthing-analytics-<component>`; `helm install` prints them.)

- **Credentials:** set `credentials.*` in values, or `credentials.existingSecret` naming a
  Secret with the 9 keys `garage-rpc-secret`, `garage-admin-token`, `s3-access-key`,
  `s3-secret-key`, `postgres-password`, `lakekeeper-db-password`,
  `lakekeeper-encryption-key`, `hue-db-password`, `hue-secret-key`.
- **GitOps:** nothing is generated at render time, so `helm template` output is complete.
- **logthing Services:** two are created, `<fullname>-logthing-udp` (514, 4739, 6343) and
  `<fullname>-logthing-tcp` (601, 47760, 5985), because mixed-protocol LoadBalancers are
  poorly supported. Set `logthing.udpService.type` / `logthing.tcpService.type` (default
  `ClusterIP`) to expose them.
- **Committer** runs as a CronJob (`committer.schedule`, default `*/1 * * * *`);
  logthing flush interval is `logthing.flushIntervalSecs` (60).
- **Init Jobs** (Garage, Lakekeeper) are named per release revision and re-run idempotently
  on every `helm upgrade`.
- Other values: `*.image`, `*.resources`, `garage.dataStorage`, `postgres.storage`,
  `storageClassName`; see `helm/logthing-analytics/values.yaml`.
- Uninstalling leaves the PVCs behind (see Credentials).

## Tables and maintenance

- Table naming (`syslog`, `zeek_<stream>`, `sflow_<partition>`, ...): see
  [committer/README.md](../../committer/README.md#table-naming).
- Compaction and snapshot expiry (`optimize`, `expire_snapshots`) are periodic jobs you run;
  never run `remove_orphan_files`. See [docs/iceberg.md](../../docs/iceberg.md#table-maintenance).

## Tests

```bash
python3 -m venv deploy/analytics/.venv
deploy/analytics/.venv/bin/pip install -r deploy/analytics/tests/requirements.txt

# unit
deploy/analytics/.venv/bin/pytest -c deploy/analytics/tests/pytest.ini deploy/analytics/tests/unit
# integration (Docker)
deploy/analytics/.venv/bin/pytest -c deploy/analytics/tests/pytest.ini deploy/analytics/tests/integration -m integration
# end-to-end
deploy/analytics/tests/e2e/compose.sh         # Docker
deploy/analytics/tests/e2e/helm-minikube.sh   # minikube, helm, kubectl
```

- The e2e scripts refuse to run on a non-AVX2 CPU unless both `TRINO_IMAGE` and `HUE_IMAGE`
  are overridden.
- `compose.sh` uses non-default host ports and its own compose project; run one at a time.
- `helm-minikube.sh` uses its own minikube profile `lt-analytics-e2e` and a private
  `KUBECONFIG` (it never touches `~/.kube/config`). `KEEP_CLUSTER=1` keeps the cluster after
  the run. A cold run can take over 15 minutes.
