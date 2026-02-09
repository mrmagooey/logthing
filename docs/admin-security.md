# Admin Interface Security Hardening

This document describes the security hardening improvements implemented in the Logthing admin interface.

## Security Features

### 1. Configurable Admin Port

The admin interface bind address is now configurable via environment variable:

```bash
# Default: 0.0.0.0:8080
WEF_ADMIN_BIND=0.0.0.0:8443
```

### 2. HTTPS/TLS Support

The admin interface now supports TLS for encrypted connections:

```bash
WEF_ADMIN_TLS_CERT=/path/to/cert.pem
WEF_ADMIN_TLS_KEY=/path/to/key.pem
WEF_ADMIN_TLS_CA=/path/to/ca.pem              # Optional
WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT=true        # Require client certificates
```

When TLS is enabled, the admin interface runs on HTTPS and all traffic is encrypted.

### 3. IP Whitelist

Access to the admin interface can be restricted by IP address or CIDR range:

```bash
# Comma-separated list of allowed IPs/CIDRs
WEF_ADMIN_ALLOWED_IPS=127.0.0.1,192.168.1.0/24,10.0.0.0/8
```

If not set, all IPs are allowed (warning logged on startup).

### 4. Password Hashing

Passwords are now hashed using Argon2 for secure storage:

```bash
# Option 1: Plain password (automatically hashed at runtime)
WEF_ADMIN_USER=admin
WEF_ADMIN_PASS=securepassword

# Option 2: Pre-hashed password (recommended for production)
WEF_ADMIN_USER=admin
WEF_ADMIN_PASS_HASH=$argon2id$v=19$m=19456,t=2,p=1$...
```

To generate a hashed password, use the Argon2 CLI tool or a compatible library.

### 5. Audit Logging

All admin interface actions are logged with timestamps and user information:

- Configuration reads (`CONFIG_READ`)
- Configuration updates (`CONFIG_UPDATED`, `CONFIG_UPDATE_FAILED`)
- Failed authentication attempts (`AUTH_FAILED`)
- Admin page access (`ADMIN_PAGE_ACCESS`)
- Audit log reads (`AUDIT_LOG_READ`)

Audit logs are available:
- In the application logs (standard logging)
- Via the `/audit-log` API endpoint
- In the admin UI (View Audit Log button)

### 6. Rate Limiting

Requests to the admin interface are rate-limited to prevent brute force attacks:

```bash
# Enable/disable rate limiting (default: true)
WEF_ADMIN_ENABLE_RATE_LIMIT=true
```

Default: 30 requests per minute per IP address. Returns `429 Too Many Requests` when exceeded.

### 7. CSRF Protection

Cross-Site Request Forgery tokens are generated for form submissions:

```bash
# Enable/disable CSRF protection (default: true)
WEF_ADMIN_ENABLE_CSRF=true
```

The CSRF token is embedded in the admin page and validated on form submissions.

## API Endpoints

- `GET /` - Admin web interface (requires authentication)
- `GET /health` - Health check endpoint (no authentication required)
- `GET /config` - Get current configuration (requires authentication)
- `PUT /config` - Update configuration (requires authentication)
- `GET /audit-log` - Get audit log entries (requires authentication)

## Environment Variables Summary

| Variable | Description | Default |
|----------|-------------|---------|
| `WEF_ADMIN_BIND` | Bind address for admin interface | `0.0.0.0:8080` |
| `WEF_ADMIN_USER` | Admin username | `admin` |
| `WEF_ADMIN_PASS` | Admin password (plain text) | `admin` |
| `WEF_ADMIN_PASS_HASH` | Admin password (Argon2 hash) | - |
| `WEF_ADMIN_ALLOWED_IPS` | Comma-separated allowed IPs/CIDRs | - |
| `WEF_ADMIN_TLS_CERT` | TLS certificate file path | - |
| `WEF_ADMIN_TLS_KEY` | TLS private key file path | - |
| `WEF_ADMIN_TLS_CA` | TLS CA certificate file path | - |
| `WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT` | Require client certificates | `false` |
| `WEF_ADMIN_ENABLE_CSRF` | Enable CSRF protection | `true` |
| `WEF_ADMIN_ENABLE_RATE_LIMIT` | Enable rate limiting | `true` |

## Security Recommendations

1. **Always use TLS in production** - Set `WEF_ADMIN_TLS_CERT` and `WEF_ADMIN_TLS_KEY`
2. **Configure IP whitelist** - Restrict access to known admin IPs with `WEF_ADMIN_ALLOWED_IPS`
3. **Use hashed passwords** - Generate a pre-hashed password with Argon2 for production
4. **Change default credentials** - Never use the default `admin/admin` credentials
5. **Monitor audit logs** - Regularly review the audit log for suspicious activity
6. **Use a non-default port** - Consider using a non-standard port to reduce automated scans

## Generating Password Hashes

To generate an Argon2 password hash for `WEF_ADMIN_PASS_HASH`:

```bash
# Using argon2 CLI (if installed)
echo -n "yourpassword" | argon2 somesalt -e

# Using Python
import argon2
ph = argon2.PasswordHasher()
hash = ph.hash("yourpassword")
print(hash)
```
