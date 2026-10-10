# Test-only Samba Active Directory DC for the nightly wef-interop --samba variant.
#   docker build -t logthing-test-samba-ad:latest tests/e2e/simulation-environment/samba-ad
# Mount a volume at /keytabs; provisioning runs on first start (idempotent).
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends samba samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind ldb-tools \
        krb5-user procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY provision.sh /provision.sh
RUN chmod +x /provision.sh && mkdir -p /keytabs
VOLUME /keytabs
EXPOSE 88/tcp 88/udp
# Healthy once provisioning finished (marker) and the samba DC process is running.
HEALTHCHECK --interval=2s --timeout=3s --start-period=20s --retries=60 \
    CMD test -f /keytabs/.provisioned && test -f /keytabs/logthing.keytab \
        && test -f /keytabs/clients.keytab && test -f /keytabs/other.keytab \
        && pgrep -x samba >/dev/null \
        && bash -c 'exec 3<>/dev/tcp/127.0.0.1/88'
ENTRYPOINT ["/provision.sh"]
