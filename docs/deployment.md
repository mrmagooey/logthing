# Host tuning for UDP ingest

The UDP listeners (syslog, IPFIX, sFlow) request a **4 MiB socket receive
buffer** by default via `SO_RCVBUF`. Linux silently clamps that request to
`net.core.rmem_max`, whose default on most distributions is **212992 bytes
(208 KiB)** — roughly 20x smaller than requested. Under sustained load the
kernel then discards datagrams before logthing ever sees them.

logthing detects the clamp and warns at startup:

```
WARN syslog_udp: SO_RCVBUF requested 4194304 bytes, kernel granted only
     425984 bytes (clamped by net.core.rmem_max)
```

(The granted figure is double `rmem_max` because the kernel doubles the value
for its own bookkeeping.)

**If you see that warning and care about UDP throughput, raise the limit:**

```bash
# Immediate, until reboot
sudo sysctl -w net.core.rmem_max=16777216

# Persistent
echo 'net.core.rmem_max=16777216' | sudo tee /etc/sysctl.d/60-logthing.conf
```

Measured impact: at 40,000 syslog messages/s on a host with the stock 208 KiB
limit, ~16.8% of datagrams were lost in the kernel socket — with zero drops
recorded inside logthing, because those messages never arrived. This loss is
invisible to `parquet_s3_dropped`; watch `syslog_udp_socket_drops` and
`syslog_udp_socket_rx_queue_bytes` instead, which are read per-socket from
`/proc/net/udp`.

To decline the larger buffer entirely and keep the OS default, set
`receive_buffer_bytes = 0`:

```toml
[syslog]
receive_buffer_bytes = 0   # 0 = leave SO_RCVBUF alone; omit for the 4 MiB default
```

TCP syslog is unaffected — `SO_RCVBUF` here applies only to the UDP arm.

## Security Considerations

1. **Use TLS**: Always enable TLS in production
2. **IP Whitelisting**: Restrict to known source IP ranges (`security.allowed_ips`)
3. **Client Certificates**: Configure mTLS for additional security
4. **Firewall**: Open only the listener ports you actually use between hosts.
   Defaults: `5985` (HTTP/WEF), `5986` (HTTPS/TLS), `9090` (Prometheus
   metrics), `514`/`601` (syslog UDP/TCP), `4739` (IPFIX UDP), `47760` (Zeek
   TCP), `47761` (Suricata TCP), `6343` (sFlow UDP), and `8080` (admin
   interface, see [admin.md](admin.md) — normally kept off the public
   network entirely rather than firewalled).
5. **Least Privilege**: Run server with minimal permissions
