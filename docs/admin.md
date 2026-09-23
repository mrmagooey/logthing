# Admin Interface Security Hardening

This document describes the security hardening improvements implemented in the Logthing admin interface.

## Security Features

### 1. Configurable Admin Port

The admin interface bind address is now configurable via environment variable:

```bash
# Default: 0.0.0.0:8080
LOGTHING_ADMIN_BIND=0.0.0.0:8443
```

### 2. HTTPS/TLS Support

The admin interface now supports TLS for encrypted connections:

```bash
LOGTHING_ADMIN_TLS_CERT=/path/to/cert.pem
LOGTHING_ADMIN_TLS_KEY=/path/to/key.pem
```

When TLS is enabled, the admin interface runs on HTTPS and all traffic is encrypted.

### 3. IP Whitelist

Access to the admin interface can be restricted by IP address or CIDR range:

```bash
# Comma-separated list of allowed IPs/CIDRs
LOGTHING_ADMIN_ALLOWED_IPS=127.0.0.1,192.168.1.0/24,10.0.0.0/8
```

If not set, all IPs are allowed (warning logged on startup).

### 4. Password Hashing

Passwords are now hashed using Argon2 for secure storage:

```bash
# Option 1: Plain password (automatically hashed at runtime)
LOGTHING_ADMIN_USER=admin
LOGTHING_ADMIN_PASS=securepassword

# Option 2: Pre-hashed password (recommended for production)
LOGTHING_ADMIN_USER=admin
LOGTHING_ADMIN_PASS_HASH=$argon2id$v=19$m=19456,t=2,p=1$...
```

To generate a hashed password, use the Argon2 CLI tool or a compatible library.

### 5. Audit Logging

All admin interface actions are logged with timestamps and user information:

- Configuration reads (`CONFIG_READ`)
- Failed authentication attempts (`AUTH_FAILED`)
- Admin page access (`ADMIN_PAGE_ACCESS`)
- Statistics page access (`STATS_PAGE_ACCESS`)
- Statistics JSON read (`STATS_JSON_READ`)
- Metrics page access (`METRICS_PAGE_ACCESS`)
- Audit log reads (`AUDIT_LOG_READ`)

Audit logs are available:
- In the application logs (standard logging)
- Via the `/audit-log` API endpoint
- In the admin UI, rendered automatically under "Recent Audit Log" on the
  admin page (`GET /`) — there is no separate button

### 6. Rate Limiting

Requests to the admin interface are rate-limited to prevent brute force attacks:

```bash
# Enable/disable rate limiting (default: true)
LOGTHING_ADMIN_ENABLE_RATE_LIMIT=true
```

Default: 30 requests per minute per IP address. Returns `429 Too Many Requests` when exceeded.

### 7. Trusted Reverse-Proxy Header Auth (Authentik)

The admin interface can trust identity headers injected by a reverse-proxy
forward-auth setup (e.g. an Authentik outpost), as an alternative to typing
Basic Auth credentials. This is opt-in and additive — Basic Auth keeps
working unchanged as a fallback.

```bash
LOGTHING_ADMIN_TRUST_PROXY_HEADERS=true
LOGTHING_ADMIN_TRUSTED_HEADER=X-authentik-username           # default shown
LOGTHING_ADMIN_TRUSTED_GROUPS_HEADER=X-authentik-groups       # default shown
LOGTHING_ADMIN_TRUSTED_SECRET_HEADER=X-Admin-Proxy-Secret     # default shown
LOGTHING_ADMIN_TRUSTED_HEADER_SECRET=<a long random value only the proxy and this server know>
LOGTHING_ADMIN_TRUSTED_GROUPS=admins,ops                      # comma-separated allowlist
```

**Both `LOGTHING_ADMIN_TRUSTED_HEADER_SECRET` and `LOGTHING_ADMIN_TRUSTED_GROUPS` are
required whenever `LOGTHING_ADMIN_TRUST_PROXY_HEADERS=true`** — the admin server
refuses to start otherwise, regardless of bind address. Presence of the
identity headers alone is never trusted: Authentik does not itself guarantee
that a reverse-proxy config strips client-forged copies of these headers —
that's the proxy's job. **The proxy must overwrite (not merely pass through)
any client-supplied copy of these headers**, and the shared secret must never
be reachable by anything other than the proxy and this server.

**Caveat — verify before relying on this in production**: Authentik's exact
delimiter for `X-authentik-groups` was not confirmed against live Authentik
documentation at the time this was implemented. This implementation accepts
both `,` and `|` as a best-effort default. Confirm the actual format against
your deployed Authentik version before relying on group-based access control.

JWT verification of Authentik's signed `X-authentik-jwt` header is not
implemented — the shared-secret + loopback-bind + group-check combination is
the current trust model.

**`X-Forwarded-For` is trusted for audit logging, rate limiting, and the IP
allowlist — but only on requests where the shared secret verified.** When
trust mode is enabled, every request is checked against the same shared
secret used for identity headers; only if that check passes does the server
read `X-Forwarded-For` (its leftmost hop) to resolve the real end-user IP for
`AuditEntry.client_ip`, the rate limiter's bucket key, and
`LOGTHING_ADMIN_ALLOWED_IPS` matching. If the secret is missing or wrong, the
header is never even inspected and the raw TCP peer address (i.e. the
proxy's own IP) is used instead — this is what stops a client who lacks the
secret from spoofing their logged/rate-limited/allowlisted IP by simply
setting the header themselves. Exactly like the identity headers, **the
proxy must strip or overwrite any client-supplied `X-Forwarded-For` before
appending its own hop.** If it does not, a request that also happens to
guess or obtain a valid shared secret could still forge its logged and
rate-limited IP — the shared secret is what makes `X-Forwarded-For`
trustworthy at all, but only if the proxy guarantees the header it forwards
is proxy-authored, not attacker-authored.

## Read-only interface

The admin interface no longer writes configuration. Every surviving route is
a `GET`. `GET /` renders a server-rendered, read-only console showing the
redacted effective config as TOML, the list of `LOGTHING__*` environment
variable **names** currently set (never their values), the audit log, and a
link to `/stats`.

`PUT`/`PATCH /config` and `POST /config/{validate,diff,export,import,reload}`
have been **removed** — they return `405`/`404` now. Configuration is
changed by editing `logthing.toml` (or an `/etc/logthing/config` drop-in) or
setting `LOGTHING__*` environment variables, layered over the file, with
environment variables winning; both require a restart to take effect.
`security.allowed_ips` and `aggregate.rules` have **no environment-variable
equivalent** and remain file-only — the first is a list and the loader sets
no list separator, the second is a list of tables. Setting
`LOGTHING__SECURITY__ALLOWED_IPS` does nothing.

Because there are no state-changing routes left, there is nothing left to
protect against a forged form submission, so the token-based protection for
that threat and its associated environment variable have been removed (see
the CHANGELOG).

**Every field is now restart-only.** `hec.token`, `syslog.http_token`,
`otlp.bearer_token`, `security.allowed_ips`, and every sink's
`flush_interval_secs` used to be read live from the shared, admin-writable
config, so an update via `PUT /config`/`/config/reload`/`/config/import` took
effect on the next request with no restart. Those write endpoints are gone
and nothing else ever mutates the running config after startup, so every one
of those fields now behaves like the rest: a change requires a restart to
take effect. See the CHANGELOG for the breaking-change details.

## API Endpoints

- `GET /` - Admin web interface (requires authentication)
- `GET /health` - Health check endpoint (no authentication required)
- `GET /config` - Get current (redacted) configuration (requires authentication)
- `GET /stats` - Ingestion statistics page (requires authentication)
- `GET /stats.json` - Ingestion statistics as JSON (requires authentication)
- `GET /metrics` - Live in-process metric values and cardinality-watch status (requires authentication)
- `GET /audit-log` - Get audit log entries (requires authentication)

## Environment Variables Summary

| Variable | Description | Default |
|----------|-------------|---------|
| `LOGTHING_ADMIN_BIND` | Bind address for admin interface | `0.0.0.0:8080` |
| `LOGTHING_ADMIN_USER` | Admin username | `admin` |
| `LOGTHING_ADMIN_PASS` | Admin password (plain text) | `admin` |
| `LOGTHING_ADMIN_PASS_HASH` | Admin password (Argon2 hash) | - |
| `LOGTHING_ADMIN_ALLOWED_IPS` | Comma-separated allowed IPs/CIDRs | - |
| `LOGTHING_ADMIN_TLS_CERT` | TLS certificate file path | - |
| `LOGTHING_ADMIN_TLS_KEY` | TLS private key file path | - |
| `LOGTHING_ADMIN_ENABLE_RATE_LIMIT` | Enable rate limiting | `true` |
| `LOGTHING_ADMIN_TRUST_PROXY_HEADERS` | Enable trusted reverse-proxy header auth | `false` |
| `LOGTHING_ADMIN_TRUSTED_HEADER` | Header carrying the trusted username | `X-authentik-username` |
| `LOGTHING_ADMIN_TRUSTED_GROUPS_HEADER` | Header carrying the trusted group list | `X-authentik-groups` |
| `LOGTHING_ADMIN_TRUSTED_SECRET_HEADER` | Header carrying the shared secret | `X-Admin-Proxy-Secret` |
| `LOGTHING_ADMIN_TRUSTED_HEADER_SECRET` | Shared secret the proxy must send; required when trust mode is enabled | - |
| `LOGTHING_ADMIN_TRUSTED_GROUPS` | Comma-separated allowed group names; required when trust mode is enabled | - |

## Security Recommendations

1. **Always use TLS in production** - Set `LOGTHING_ADMIN_TLS_CERT` and `LOGTHING_ADMIN_TLS_KEY`
2. **Configure IP whitelist** - Restrict access to known admin IPs with `LOGTHING_ADMIN_ALLOWED_IPS`
3. **Use hashed passwords** - Generate a pre-hashed password with Argon2 for production
4. **Change default credentials** - Never use the default `admin/admin` credentials
5. **Monitor audit logs** - Regularly review the audit log for suspicious activity
6. **Use a non-default port** - Consider using a non-standard port to reduce automated scans

## Generating Password Hashes

To generate an Argon2 password hash for `LOGTHING_ADMIN_PASS_HASH`:

```bash
# Using argon2 CLI (if installed)
echo -n "yourpassword" | argon2 somesalt -e

# Using Python
import argon2
ph = argon2.PasswordHasher()
hash = ph.hash("yourpassword")
print(hash)
```
