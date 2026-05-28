# Veth Interfaces & Demo Setup Guide

## What is a veth Interface?

A **veth** (virtual Ethernet) is a Linux kernel construct that creates a pair of virtual network interfaces connected like a pipe. Whatever goes in one end comes out the other.

```
┌──────────────┐          ┌──────────────┐
│   veth0      │◄────────►│   veth1      │
│ (namespace A)│  kernel   │ (namespace B)│
└──────────────┘  pipe     └──────────────┘
```

### Key Properties

- **Always created in pairs** — you can't have one end without the other
- **Bidirectional** — packets sent into `veth0` appear on `veth1` and vice versa
- **Namespace-aware** — each end can live in a different network namespace (this is how Docker containers get networking)
- **Kernel-level** — traffic passes through the kernel's network stack, which means eBPF programs attached to TC hooks can observe it

### Why Tlapix Uses veth

When Tlapix attaches its eBPF Collector to a network interface via TC (traffic control) hooks, it observes all packets flowing through that interface. A veth pair gives us:

1. **Controlled traffic** — we send exactly what we want through one end
2. **Full kernel path** — packets traverse the real network stack (unlike loopback shortcuts)
3. **eBPF visibility** — TC hooks fire on veth interfaces just like physical NICs
4. **Isolation** — demo traffic doesn't leak to the real network

### How Docker Uses veth

When Docker creates a container, it:
1. Creates a veth pair
2. Puts one end (`eth0`) inside the container's network namespace
3. Puts the other end (`vethXXXX`) on the host, attached to a bridge (`docker0` or a custom network)

This is why Tlapix can observe container traffic by attaching to the bridge or veth interfaces on the host side.

```
┌─────────────────────────────────────────────────────┐
│                    HOST                               │
│                                                      │
│  ┌─────────┐     ┌──────────┐     ┌─────────┐      │
│  │Container│     │  docker0  │     │Container│      │
│  │  eth0   │◄───►│  bridge   │◄───►│  eth0   │      │
│  │(veth-a) │     │           │     │(veth-b) │      │
│  └─────────┘     └─────┬────┘     └─────────┘      │
│                         │                            │
│                    ┌────┴────┐                       │
│                    │  Tlapix │                       │
│                    │  (eBPF  │                       │
│                    │  on br) │                       │
│                    └─────────┘                       │
└─────────────────────────────────────────────────────┘
```

### Manual veth Setup (for testing without Docker)

```bash
# Create a veth pair
sudo ip link add veth-tlapix0 type veth peer name veth-tlapix1

# Bring both ends up
sudo ip link set veth-tlapix0 up
sudo ip link set veth-tlapix1 up

# Assign IPs
sudo ip addr add 10.99.0.1/24 dev veth-tlapix0
sudo ip addr add 10.99.0.2/24 dev veth-tlapix1

# Now Tlapix can attach to veth-tlapix0 and observe traffic on veth-tlapix1
# Start a TLS server on 10.99.0.2:443
# Traffic from 10.99.0.1 → 10.99.0.2 passes through the veth pair
# Tlapix's eBPF program on veth-tlapix0 sees the TLS handshakes

# Cleanup
sudo ip link del veth-tlapix0  # deleting one end removes both
```

---

## Demo Setup Documentation

### Overview

The demo environment simulates a production scenario where multiple services use TLS certificates with various properties. Tlapix monitors all traffic and demonstrates its autonomous capabilities.

### Components

| Component | Role | Port |
|-----------|------|------|
| `tlapix` | The guardian daemon | 8080 (UI), 9090 (Prometheus) |
| `tls-server-good` | Valid cert, strong key | 443 |
| `tls-server-expiring` | Cert about to expire | 443 |
| `tls-server-weak` | RSA 1024-bit key | 443 |
| `tls-server-shadow` | Self-signed, unknown CA | 443 |
| `traffic-generator` | Continuous TLS requests | — |
| `pebble` | Local ACME server | 14000 |

### Network Topology

All containers are on the `demo-net` Docker bridge network. Tlapix attaches its eBPF programs to the bridge interface (`eth0` inside its container) and observes all inter-container TLS traffic.

```
traffic-generator
    │
    ├──► tls-server-good     (valid, in inventory)
    ├──► tls-server-expiring (valid, expires soon, in inventory)
    ├──► tls-server-weak     (RSA 1024, NOT in inventory)
    └──► tls-server-shadow   (self-signed, NOT in inventory)
         │
         ▼
    Tlapix observes ALL of the above via eBPF on the bridge
```

### Certificate Inventory

The `inventory.json` file contains only the "known" certificates:
- `good.tlapix-demo.local` — known, no alerts
- `expiring.tlapix-demo.local` — known, but triggers renewal prediction

Certificates NOT in inventory:
- `weak.tlapix-demo.local` — triggers WeakCryptography anomaly
- `shadow.unknown-ca.local` — triggers Shadow classification

### Time Compression

The demo config (`config/tlapix-demo.toml`) uses compressed thresholds:

| Parameter | Demo Value | Production Value | Effect |
|-----------|-----------|-----------------|--------|
| `prediction_reevaluation_hours` | 0 (every cycle) | 24 | Predictions update immediately |
| `renewal_threshold_probability` | 0.5 | 0.7 | Triggers renewal sooner |
| `inventory_poll_interval_secs` | 30 | 300 | Faster inventory refresh |
| `directive_expiry_hours` | 1 | 72 | Directives expire faster |
| `otlp_export_interval_secs` | 10 | 60 | Metrics visible sooner |

### Step-by-Step Demo Flow

#### Setup (one-time)

```bash
cd demo

# 1. Create the Certificate Authority
./setup-ca.sh
# Creates: demo/certs/ca/ca.key, demo/certs/ca/ca.crt

# 2. Issue all demo certificates
./issue-certs.sh
# Creates: demo/certs/{good,expiring,weak,shadow}/server.{key,crt}
# Creates: demo/inventory.json (only good + expiring)
```

#### Running the Demo

```bash
# 3. Start all containers
docker compose up -d

# 4. Verify everything is running
docker compose ps

# 5. Open the Web UI
open http://localhost:8080

# 6. Check Prometheus metrics
curl -s http://localhost:9090/metrics | grep tlapix
```

#### Running Scenarios

```bash
# Run scenarios one at a time (each takes ~30 seconds)
./scenarios/01-discovery.sh      # See cert appear in UI
./scenarios/02-near-expiry.sh    # See prediction + renew directive
./scenarios/03-expired.sh        # See critical alert
./scenarios/04-weak-key.sh       # See anomaly detection
./scenarios/05-shadow-cert.sh    # See shadow classification + escalation
```

#### Observing Results

| What to Check | Where |
|---------------|-------|
| Discovered certificates | http://localhost:8080/certificates |
| Active anomalies | http://localhost:8080/anomalies |
| Action directives | http://localhost:8080/actions |
| Renewal predictions | http://localhost:8080/predictions |
| Raw metrics | http://localhost:9090/metrics |
| Container logs | `docker compose logs -f tlapix` |

#### Cleanup

```bash
docker compose down
rm -rf certs/  # Remove generated certificates
```

### Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| "Operation not permitted" | Missing capabilities | Ensure `cap_add: [NET_ADMIN, BPF, SYS_ADMIN]` |
| No certificates discovered | eBPF not loading | Check kernel version: `uname -r` (need 5.15+) |
| Pebble connection refused | Container not ready | Wait 10s after `docker compose up` |
| Web UI empty | No traffic yet | Run a scenario script or wait for traffic-generator |

### Extending the Demo

To add a new scenario:

1. Create a new cert in `issue-certs.sh` with the desired properties
2. Add an nginx config in `nginx/`
3. Add a service in `docker-compose.yml`
4. Create a scenario script in `scenarios/`
5. Decide if the cert should be in `inventory.json` (known) or not (shadow)
