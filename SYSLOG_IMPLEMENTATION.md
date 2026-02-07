# Syslog Parser and Listener - Implementation Summary

## Overview

Added comprehensive syslog parsing and listening capabilities to the WEF Server, including support for RFC 3164 (BSD syslog), RFC 5424 (modern syslog), and automatic DNS query log parsing.

## Features Implemented

### 1. Syslog Parser (`src/syslog/mod.rs`)

**Supported Protocols:**
- **RFC 3164** (BSD Syslog): `<priority>timestamp hostname tag[pid]: message`
- **RFC 5424**: `<priority>version timestamp hostname app-name procid msgid [structured-data] message`

**Parsed Fields:**
- Priority, Severity, Facility
- Timestamp (with timezone support)
- Hostname
- Application name (tag)
- Process ID
- Message ID (RFC 5424)
- Structured data (RFC 5424)
- Message content

**Severity Levels:**
- Emergency (0), Alert (1), Critical (2), Error (3), Warning (4), Notice (5), Informational (6), Debug (7)

**Facilities:**
- Kernel, User, Mail, System, Security, Syslog, LinePrinter, News, Uucp, Clock, Authpriv, Ftp, Ntp, Audit, Alert, Clock2, Local0-7

### 2. DNS Query Log Parser (`src/syslog/mod.rs` - `dns` submodule)

**Supported DNS Server Formats:**

1. **BIND/named**:
   ```
   client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)
   ```

2. **Unbound**:
   ```
   info: 192.168.1.100 example.com. A IN
   ```

3. **PowerDNS**:
   ```
   Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512
   ```

**Parsed DNS Fields:**
- Client IP address
- Query name (domain)
- Query type (A, AAAA, MX, TXT, etc.)
- Response code
- Response IPs (when available)

### 3. Syslog Listener (`src/syslog/listener.rs`)

**Transport Support:**
- **UDP**: Standard syslog port 514 (configurable)
- **TCP**: RFC 6587 port 601 (configurable)
- **HTTP**: POST to `/syslog` endpoint

**Features:**
- Async UDP socket listener
- TCP connection handling with newline framing
- Auto-detection of syslog format
- DNS log parsing (configurable)
- Structured data extraction

### 4. HTTP Endpoints

**New Routes:**
- `POST /syslog` - Receive syslog messages via HTTP
- `GET /syslog/udp` - Get UDP/TCP listener configuration
- `GET /syslog/examples` - Get example DNS syslog records

### 5. Configuration

**Config File** (`wef-server.toml`):
```toml
[syslog]
enabled = true
udp_port = 514      # Standard syslog UDP port
tcp_port = 601      # Standard syslog TCP port (RFC 6587)
parse_dns = true    # Enable DNS log parsing
```

## Example DNS Syslog Records

### BIND/named Examples (10 records)
1. Standard A record query
2. AAAA record query (IPv6)
3. MX record query
4. NXDOMAIN response
5. CNAME chain
6. TXT record (SPF)
7. PTR record (reverse DNS)
8. NS record query
9. SOA record query
10. DNSSEC related query

### Unbound Examples (3 records)
- Basic query format examples

### PowerDNS Examples (3 records)
- Query format with buffer size info

### RFC 5424 Examples (2 records)
- Modern syslog with structured data

**Access examples via:** `GET /syslog/examples`

## Usage Examples

### Send Syslog via UDP
```bash
echo "<34>Oct 11 22:14:15 mymachine su: 'su root' failed" | nc -u localhost 514
```

### Send Syslog via TCP
```bash
echo "<34>Oct 11 22:14:15 mymachine su: 'su root' failed" | nc localhost 601
```

### Send Syslog via HTTP
```bash
curl -X POST http://localhost:5985/syslog \
  -d "<34>Oct 11 22:14:15 mymachine su: 'su root' failed"
```

### Send DNS Query Log
```bash
echo "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)" | nc -u localhost 514
```

### Get Examples
```bash
curl http://localhost:5985/syslog/examples
```

## Testing

**Test Coverage:**
- RFC 3164 parsing (legacy BSD syslog)
- RFC 5424 parsing (modern syslog)
- Structured data parsing
- DNS log format parsing (BIND, Unbound, PowerDNS)
- Full syslog to DNS parsing pipeline
- UDP listener functionality

**All Tests Pass:** 13 tests including 8 new syslog tests

## Dependencies Added

- `regex` - Pattern matching for log parsing
- `async-trait` - Async trait support

## Files Created/Modified

1. **New Files:**
   - `src/syslog/mod.rs` - Core syslog parser (593 lines)
   - `src/syslog/listener.rs` - UDP/TCP listener (330 lines)

2. **Modified Files:**
   - `src/main.rs` - Added syslog module, started listener
   - `src/server/mod.rs` - Added syslog HTTP endpoints
   - `src/config/mod.rs` - Added SyslogConfig struct
   - `Cargo.toml` - Added regex and async-trait dependencies
   - `wef-server.toml` - Added syslog configuration section
   - `README.md` - Updated documentation

## Architecture Integration

```
Syslog Sources (UDP/TCP/HTTP)
         ↓
Syslog Parser (RFC 3164/5424)
         ↓
DNS Log Parser (if enabled)
         ↓
Event Processing → Forwarders
```

## Future Enhancements

Potential improvements:
- TLS-encrypted syslog (RFC 5425)
- Structured data filtering
- Additional DNS server formats
- Syslog forwarding to other destinations
- Log correlation between WEF and syslog events