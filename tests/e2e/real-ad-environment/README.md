# WEF Server Real AD Environment Testing

This directory contains the infrastructure-as-code and test automation for running WEF Server integration tests against a real Active Directory environment using [Ludus](https://ludus.cloud).

## Overview

This testing framework deploys a complete Microsoft Active Directory environment with:

- **Domain Controller** (Windows Server 2022)
- **WEF Server** (Debian 12 with WEF application)
- **MinIO S3 Storage** (for Parquet file storage)
- **Windows Workstations** (Windows 10/11)
- **Windows Server** (Windows Server 2022)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Ludus Virtual Range                       │
│                    Network: 10.10.10.0/24                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐     ┌──────────────────┐                 │
│  │    DC01      │────▶│   WEF-SRV-01     │                 │
│  │  10.10.10.10 │     │   10.10.10.20    │                 │
│  │   AD + DNS   │     │   Application    │                 │
│  └──────────────┘     │   Under Test     │                 │
│                       └────────┬─────────┘                 │
│                                │                            │
│                       ┌────────▼─────────┐                 │
│                       │   MinIO S3       │                 │
│                       │   10.10.10.30    │                 │
│                       └──────────────────┘                 │
│                                ▲                            │
│        ┌──────────┬───────────┴───────────┬──────────┐     │
│        │          │                       │          │     │
│  ┌─────▼──┐ ┌────▼────┐ ┌──────────┐ ┌──▼─────┐    │     │
│  │  WS01  │ │  WS02   │ │   WS03   │ │ SRV01  │    │     │
│  │Win11   │ │Win11    │ │ Win10    │ │Win2022 │    │     │
│  │10.10.  │ │10.10.   │ │10.10.    │ │10.10.  │    │     │
│  │10.100  │ │10.101   │ │10.102    │ │10.103  │    │     │
│  └────────┘ └─────────┘ └──────────┘ └────────┘    │     │
│                                                    │     │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Hardware Requirements

- **CPU**: 8+ cores (16+ recommended)
- **RAM**: 32GB minimum (64GB recommended)
- **Storage**: 200GB+ SSD
- **Network**: 2+ NICs for VLAN isolation
- **Virtualization**: VT-x/AMD-V support required

### Software Requirements

- Debian 12 host for Ludus
- Ludus installed and configured
- SSH access to Ludus host
- Git (for cloning this repository)

## Quick Start

### 1. Install Ludus

```bash
# On your Debian 12 host
curl https://raw.githubusercontent.com/ludus-cloud/ludus/main/install.sh | sudo bash
ludus range config
```

### 2. Deploy the Test Environment

```bash
# Copy the configuration
cp ludus-range-config.yml ~/ludus-range-config.yml

# Deploy the range
ludus range deploy -f ~/ludus-range-config.yml

# Wait for deployment to complete (this may take 30-60 minutes)
ludus range wait
```

### 3. Configure the WEF Server

After deployment completes, configure the WEF server:

```bash
# Connect to the WEF server
ssh root@wef-srv-01.wef.lab

# Run Ansible configuration
cd /opt/wef-server/tests/e2e/real-ad-environment
ansible-playbook ansible/configure-wef-server.yml

# Or configure from your local machine:
ansible-playbook -i inventory.yml ansible/configure-wef-server.yml
```

### 4. Configure Windows Clients

Configure WEF subscriptions on Windows clients:

```bash
# Run from Ludus host or management station
ansible-playbook -i inventory.yml ansible/configure-wef-client.yml
```

### 5. Run Tests

```bash
# Run all test phases
./run-real-ad-tests.py

# Run specific phase
./run-real-ad-tests.py --phase 1
./run-real-ad-tests.py --phase 2
./run-real-ad-tests.py --phase 3

# Run with custom duration/rate for Phase 3
./run-real-ad-tests.py --phase 3 --duration 10 --rate 500
```

## Test Phases

### Phase 1: Basic Connectivity & Protocol Validation

Tests basic connectivity and protocol support:

- ✅ HTTP connectivity (port 5985)
- ✅ HTTPS connectivity (port 5986)
- ✅ Kerberos/SPNEGO authentication
- ✅ Windows client connectivity
- ✅ Metrics endpoint (port 9090)
- ✅ Subscription registration

**Run**: `./run-real-ad-tests.py --phase 1`

### Phase 2: Event Types & Parsing Validation

Tests event reception, parsing, and forwarding:

- ✅ Event reception from Windows clients
- ✅ Event forwarding to destinations
- ✅ Event type coverage (50+ event parsers)
- ✅ S3 storage validation
- ✅ Parquet format verification
- ✅ Parser accuracy
- ✅ Syslog integration

**Run**: `./run-real-ad-tests.py --phase 2`

### Phase 3: Load & Performance Testing

Tests performance under load:

- ✅ Concurrent connection handling (4+ clients)
- ✅ Processing latency measurement
- ✅ Resource usage monitoring (CPU, memory)
- ✅ Batching performance
- ✅ High-volume event processing (configurable rate)

**Run**: `./run-real-ad-tests.py --phase 3 --duration 5 --rate 100`

## Directory Structure

```
real-ad-environment/
├── README.md                          # This file
├── ludus-range-config.yml             # Ludus range configuration
├── run-real-ad-tests.py              # Master test runner
│
├── ansible/                           # Ansible playbooks
│   ├── configure-wef-server.yml      # WEF server setup
│   ├── configure-wef-client.yml      # Windows client setup
│   ├── configure-dc.yml              # Domain Controller setup
│   └── configure-minio.yml           # MinIO S3 setup
│
├── scripts/                           # Test scripts
│   ├── test_phase1_connectivity.py   # Phase 1 tests
│   ├── test_phase2_events.py         # Phase 2 tests
│   ├── test_phase3_performance.py    # Phase 3 tests
│   └── validate_metrics.py           # Monitoring script
│
├── configs/                           # Configuration templates
│   ├── wef-server.toml.j2            # WEF server config
│   ├── subscription.xml.j2           # WEF subscription config
│   ├── krb5.conf.j2                  # Kerberos config
│   └── wef-server.service.j2         # Systemd service
│
└── tests/                            # Additional test resources
    ├── fixtures/                     # Test event data
    └── expected/                     # Expected results
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WEF_SERVER` | WEF server hostname | `wef-srv-01.wef.lab` |
| `S3_ENDPOINT` | S3/MinIO endpoint | `http://minio-srv.wef.lab:9000` |
| `TEST_DURATION` | Phase 3 duration (minutes) | `5` |
| `TEST_RATE` | Phase 3 event rate/min | `100` |

### Test Configuration

Edit the test scripts to customize thresholds:

- **Phase 1**: Edit `scripts/test_phase1_connectivity.py`
- **Phase 2**: Edit `scripts/test_phase2_events.py`
- **Phase 3**: Edit `scripts/test_phase3_performance.py`

## Monitoring

Run the monitoring script to watch metrics in real-time:

```bash
# Monitor for 10 minutes with 30-second intervals
python3 scripts/validate_metrics.py --duration 10 --interval 30

# Monitor indefinitely
python3 scripts/validate_metrics.py --duration 0
```

## Troubleshooting

### Ludus Deployment Issues

```bash
# Check deployment status
ludus range status

# View VM logs
ludus vm logs <vm-name>

# Restart a VM
ludus vm restart <vm-name>

# Access VM console
ludus vm console <vm-name>
```

### WEF Server Issues

```bash
# Check service status
systemctl status wef-server

# View logs
journalctl -u wef-server -f

# Test connectivity
curl http://wef-srv-01.wef.lab:5985/health
curl http://wef-srv-01.wef.lab:9090/metrics
```

### Windows Client Issues

```bash
# Check subscription status (on Windows client)
wecutil gs SecurityEvents-RealAD-Test

# Test connectivity to WEF server
Test-NetConnection -ComputerName wef-srv-01.wef.lab -Port 5985

# View forwarded events
Get-WinEvent -LogName ForwardedEvents -MaxEvents 10
```

### Kerberos Issues

```bash
# Test Kerberos ticket
klist

# Test authentication
curl --negotiate -u : http://wef-srv-01.wef.lab:5985/wsman

# Check keytab
klist -k /etc/wef-server/keytabs/wef.keytab
```

## Advanced Usage

### Scaling the Test

To add more Windows clients, edit `ludus-range-config.yml`:

```yaml
vms:
  - hostname: ws04
    template: win11-22h2-x64
    ip: 10.10.10.104
    domain_join: wef.lab
    ansible:
      - playbook: ansible/configure-wef-client.yml
```

Then redeploy:

```bash
ludus range deploy -f ludus-range-config.yml
```

### Custom Event Types

Add custom event parsers in `/etc/wef-server/event_parsers/`:

```yaml
# /etc/wef-server/event_parsers/1234_custom.yaml
event_id: 1234
name: "Custom Event"
fields:
  - name: "FieldName"
    source: EventData
    xpath: "Data[@Name='FieldName']"
    type: string
```

### HTTPS-Only Testing

Update the subscription XML to use HTTPS:

```xml
<TransportName>HTTPS</TransportName>
```

And ensure certificates are deployed on the WEF server.

## Cleanup

To destroy the test environment:

```bash
ludus range destroy
```

To keep VMs but shut them down:

```bash
ludus range stop
```

To snapshot before major changes:

```bash
ludus vm snapshot create wef-srv-01 pre-change
ludus vm snapshot restore wef-srv-01 pre-change
```

## Test Results

Test results are saved to:

- `/var/log/wef-tests/phase1-results.json`
- `/var/log/wef-tests/phase2-results.json`
- `/var/log/wef-tests/phase3-results.json`
- `/var/log/wef-tests/master-results.json`

View results:

```bash
cat /var/log/wef-tests/master-results.json | jq
```

## Contributing

When adding new tests:

1. Create test function in appropriate phase script
2. Add to test list in `run_tests()` function
3. Update this README with new test description
4. Run `./run-real-ad-tests.py` to verify

## License

This testing framework is part of the WEF Server project and follows the same license (MIT).

## Support

For issues with:

- **Ludus**: https://docs.ludus.cloud or GitLab issues
- **WEF Server**: See main project README
- **These tests**: Create an issue in this repository
