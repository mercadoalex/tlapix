# Tlapix Demo Environment

This directory contains everything needed to demonstrate Tlapix's autonomous certificate guardian capabilities using short-lived certificates and simulated traffic.

## Prerequisites

- Docker and Docker Compose
- Linux host with kernel 5.15+ (or a Linux VM)
- `openssl` CLI tool

## Quick Start

```bash
# 1. Generate the demo CA and certificates
./setup-ca.sh

# 2. Issue certificates for each scenario
./issue-certs.sh

# 3. Start the demo environment
docker compose up -d

# 4. Run individual scenarios
./scenarios/01-discovery.sh
./scenarios/02-near-expiry.sh
./scenarios/03-expired.sh
./scenarios/04-weak-key.sh
./scenarios/05-shadow-cert.sh
```

## Scenarios

| # | Scenario | What Happens | Expected Tlapix Response |
|---|----------|-------------|--------------------------|
| 01 | Discovery | Normal TLS traffic with valid cert | Certificate appears in inventory, no alerts |
| 02 | Near Expiry | Cert expires in 2 minutes | Renewal prediction → "renew" directive |
| 03 | Expired | Already-expired cert in traffic | Critical alert → operator notification |
| 04 | Weak Key | RSA 1024-bit certificate | WeakCryptography anomaly → critical alert |
| 05 | Shadow Cert | Cert not in inventory file | Shadow classification → escalating alerts |
| 06 | Isolation | Compromised cert fingerprint added to isolate map | Connections dropped at kernel speed |

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker Network (demo-net)            │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ TLS Srv  │  │ TLS Srv  │  │ TLS Srv  │      │
│  │ (good)   │  │(expiring)│  │ (weak)   │      │
│  │ :4431    │  │ :4432    │  │ :4433    │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │              │              │            │
│       └──────────────┼──────────────┘            │
│                      │                           │
│              ┌───────┴───────┐                   │
│              │    Tlapix     │                   │
│              │  (monitors    │                   │
│              │   all traffic)│                   │
│              └───────┬───────┘                   │
│                      │                           │
│              ┌───────┴───────┐                   │
│              │   Traffic     │                   │
│              │  Generator    │                   │
│              └───────────────┘                   │
└─────────────────────────────────────────────────┘
```

## Time Compression

For demo purposes, Tlapix uses compressed time thresholds:
- Renewal prediction re-evaluation: every 10 seconds (instead of 24 hours)
- Near-expiry threshold: 5 minutes (instead of 30 days)
- Critical escalation: 2 minutes (instead of 14 days)
- Shadow escalation: 1 minute (instead of 24 hours)

This lets you see the full lifecycle in under 5 minutes.
