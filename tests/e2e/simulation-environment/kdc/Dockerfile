# Test-only MIT Kerberos KDC for the WEF emulator / real-Kerberos tests.
#   docker build -t logthing-test-kdc:latest tests/e2e/simulation-environment/kdc
# Mount a volume at /keytabs; provisioning runs on first start (idempotent).
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server procps \
    && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY provision.sh /provision.sh
RUN chmod +x /provision.sh && mkdir -p /keytabs
VOLUME /keytabs
EXPOSE 88/tcp 88/udp
# Healthy once provisioning finished (marker) and krb5kdc is running.
HEALTHCHECK --interval=2s --timeout=3s --start-period=10s --retries=30 \
    CMD test -f /keytabs/.provisioned && test -f /keytabs/logthing.keytab \
        && test -f /keytabs/clients.keytab && test -f /keytabs/other.keytab \
        && pgrep -x krb5kdc >/dev/null
ENTRYPOINT ["/provision.sh"]
