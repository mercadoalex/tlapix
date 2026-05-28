# 🦎 Tlapix — Autonomous Certificate Guardian

> *From Náhuatl "tlapixqui" — the guardian, the one who watches while everyone sleeps.*

Tlapix is an autonomous certificate lifecycle management system that uses **eBPF** for zero-overhead TLS certificate discovery, **AI** for anomaly detection and renewal prediction, and **BPF maps** for kernel-speed autonomous action execution.

![Tlapix](./Tlapix07.png)

**One binary. Three layers. Zero expired certificates.**

---

## Why Tlapix Exists

### The $11.1 Million Problem

Certificate expiry is entirely predictable, yet it remains one of the most common causes of major service outages. The average cost: **$11.1 million per incident**.

| Incident | Impact |
|----------|--------|
| Microsoft Teams (2020) | Multi-hour outage, users locked out |
| Spotify/Megaphone (2022) | 8-hour platform outage |
| SpaceX Starlink (2024) | Global multi-hour outage — "inexcusable" |
| Ericsson/O2 (2018) | 32 million users without service |
| Bank of England | £6 trillion RTGS system crashed |
| Tailscale (2024) | 90-minute outage |

**88%** of security leaders report being impacted by CA revocations. **31%** experienced a certificate-related outage.

### The Coming Storm: 47-Day Certificates

In April 2025, the CA/Browser Forum voted to reduce TLS certificate maximum validity to **47 days by March 2029**:

- 200 days max → March 2026
- 100 days max → March 2027
- **47 days max → March 2029**

This represents **8x more certificate lifecycle work** than organizations handle today. Manual management becomes impossible.

### Why Current Tools Fail

Existing certificate management tools are **reactive** — they alert after expiry or near-expiry. None combine:

1. **Passive traffic observation** (discover ALL certificates, including shadow certs)
2. **AI-driven prediction** (predict failures before they happen)
3. **Autonomous action** (renew, protect, or isolate without human intervention)

Tlapix is the first system to combine all three at kernel speed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL SPACE                              │
│                                                                  │
│  Network ──► TC Hook ──► eBPF Collector ──► Ring Buffer         │
│                              │                                   │
│              BPF Action Maps ◄── eBPF Executor (protect/isolate)│
└─────────────────────────────────────────────────────────────────┘
                              │                    ▲
                              ▼                    │
┌─────────────────────────────────────────────────────────────────┐
│                       USERSPACE                                   │
│                                                                  │
│  Ring Buffer Reader ──► Dedup Engine ──► AI Analyzer             │
│                                              │                   │
│                                    ┌─────────┼─────────┐        │
│                                    ▼         ▼         ▼        │
│                              Anomaly    Renewal    Shadow        │
│                              Detector   Predictor  Detector      │
│                                    │         │         │        │
│                                    └─────────┼─────────┘        │
│                                              ▼                   │
│                                    BPF Map Writer ──────────────►│
│                                              │                   │
│                              ┌───────────────┼───────────┐      │
│                              ▼               ▼           ▼      │
│                          ACME Client    Webhooks    Observability│
│                         (auto-renew)   (PagerDuty)  (OTLP/Prom) │
└─────────────────────────────────────────────────────────────────┘
```

### The Three Layers

| Layer | Role | Speed |
|-------|------|-------|
| **Collector** (eBPF) | Passively observes ALL TLS handshakes in real traffic | <1% CPU at 10K handshakes/sec |
| **Analyzer** (AI + Rules) | Detects anomalies, predicts renewal failures, identifies shadow certs | <30 seconds per certificate |
| **Executor** (BPF Maps) | Autonomous actions: alert, renew, protect, isolate | <100ms enforcement |

### Key Design Principle

> The kernel **never** executes dynamically generated code. Only pre-verified BPF programs that read action maps. This is the sweet spot between autonomous action and kernel stability.

---

## Features

### 🔍 Certificate Discovery
- Discovers ALL TLS certificates in live network traffic via eBPF
- Zero application modification required
- Supports TLS 1.2 and 1.3 on any TCP port
- Deduplication with LRU cache (100K certificates)
- Certificate chain extraction and issuer tracking

### 🧠 AI-Powered Analysis
- **Anomaly Detection**: Weak keys, policy violations, SNI mismatches, expired certs
- **Renewal Prediction**: Predicts failures 30 days in advance with probability scoring
- **Shadow Certificate Detection**: Identifies unmanaged certificates in traffic
- **Graceful Degradation**: Falls back to rule-based detection if AI model unavailable

### ⚡ Autonomous Actions
- **Alert**: Notify operators via webhooks (PagerDuty, OpsGenie, Slack)
- **Renew**: Trigger ACME renewal workflow automatically
- **Protect**: Enforce certificate pinning at kernel speed
- **Isolate**: Block connections with compromised certificates in <100ms

### 📊 Observability
- **OpenTelemetry** (OTLP) → Datadog, Dynatrace, Splunk, Grafana
- **Prometheus** exposition endpoint for scraping
- **StatsD** for legacy monitoring infrastructure
- **Webhooks** with retry and exponential backoff
- **Audit Trail** with correlation IDs for end-to-end tracing
- **Built-in Web UI** (optional, for standalone deployments)

### 🛡️ Safety Guarantees
- No dynamic eBPF code generation at runtime
- SHA-256 checksum validation of all eBPF programs at startup
- Bounded BPF map memory (64 MB cap, 10K entries per map)
- Audit logging halt-on-failure (no actions without audit trail)
- 90-day data retention with automatic cleanup

---

## Quick Start

### Prerequisites

- Linux kernel 5.15+ (for BPF ring buffer and CO-RE support)
- Rust nightly (for eBPF compilation)
- `bpf-linker` installed

### Build

```bash
# Build userspace daemon
cargo build --release

# Build eBPF programs (requires nightly + bpf-linker)
cargo xtask build-ebpf --release
```

### Configure

```bash
cp config/tlapix.toml /etc/tlapix/tlapix.toml
# Edit to set your interfaces, inventory source, and webhook endpoints
```

### Run

```bash
sudo ./target/release/tlapix --config /etc/tlapix/tlapix.toml
```

### Verify

```bash
# Check Prometheus metrics
curl http://localhost:9090/metrics

# Check Web UI
open http://localhost:8080
```

---

## Configuration

```toml
[collector]
interfaces = ["eth0"]           # Network interfaces to monitor
ring_buffer_size_mb = 16        # eBPF ring buffer size
local_buffer_capacity = 10000   # Buffer when Analyzer unavailable
metadata_retention_days = 90    # Certificate data retention

[analyzer]
ai_model_path = "/opt/tlapix/models/anomaly.onnx"
ai_timeout_secs = 5            # Fallback to rules on timeout
inventory_poll_interval_secs = 300
renewal_threshold_probability = 0.7

[analyzer.inventory_source]
type = "file"                   # or "api"
path = "/etc/tlapix/inventory.json"

[executor]
max_map_entries = 10000
directive_expiry_hours = 72
webhooks = []

[observability]
otlp_endpoint = "http://localhost:4317"
prometheus_bind = "0.0.0.0:9090"
audit_retention_days = 90

[web_ui]
bind = "0.0.0.0:8080"
```

---

## Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| eBPF Programs | **Rust + Aya** | Pure Rust eBPF, no libbpf/BCC, CO-RE portable binaries |
| Daemon | **Rust + Tokio** | Memory safety, async, single binary deployment |
| AI/ML | **ONNX Runtime** | Local inference, no cloud dependency |
| ACME | **instant-acme** | Pure Rust, async, RFC 8555 compliant |
| Storage | **SQLite** | Embedded, zero-config, sufficient for single-node |
| Observability | **OpenTelemetry** | Vendor-neutral, OTLP export to any backend |
| Web UI | **axum + htmx** | Lightweight, server-rendered, minimal JS |

**Single language. Single binary. Lean team friendly.**

---

## Project Structure

```
tlapix/
├── crates/
│   ├── tlapix-common/       # Shared types, storage, audit logging
│   ├── tlapix-ebpf/         # eBPF programs (kernel space, no_std)
│   ├── tlapix-collector/    # Userspace collector (ring buffer, dedup, buffer)
│   ├── tlapix-analyzer/     # AI analysis (anomaly, renewal, shadow, inventory)
│   ├── tlapix-executor/     # Action execution (BPF maps, ACME, integrity)
│   └── tlapix-daemon/       # Binary (wiring, observability, web UI)
├── xtask/                   # Build automation (eBPF compilation)
├── config/                  # Sample configuration
└── .kiro/specs/             # Design specification
```

---

## How It Compares

| Feature | Tlapix | cert-manager | Venafi | Keyfactor |
|---------|--------|-------------|--------|-----------|
| Passive traffic discovery | ✅ eBPF | ❌ | ❌ | ❌ |
| Shadow cert detection | ✅ Real-time | ❌ | Partial | Partial |
| AI prediction | ✅ Local ONNX | ❌ | ❌ | ❌ |
| Autonomous action | ✅ Kernel speed | ❌ | Partial | Partial |
| Zero overhead | ✅ <1% CPU | N/A | Agent-based | Agent-based |
| Small team viable | ✅ | ✅ | ❌ | ❌ |
| 47-day mandate ready | ✅ | Partial | ✅ | ✅ |
| Open source | ✅ | ✅ | ❌ | ❌ |

---

## The Philosophy

Tlapix is **not** a dashboard product. It's an autonomous engine that:

1. **Discovers** what you don't know you have (shadow certs in traffic)
2. **Predicts** what will fail before it fails (AI-driven renewal prediction)
3. **Acts** at kernel speed without waiting for humans (BPF map execution)
4. **Feeds** your existing observability stack (Datadog, Grafana, Splunk — whatever you already use)

The 47-day certificate mandate makes this approach not optional but essential. When certificates rotate every 47 days, you need a guardian that never sleeps.

**Tlapix watches while everyone sleeps.**

---

## Development

```bash
# Run all tests (344+ tests including 22 property-based)
cargo test --workspace

# Check eBPF programs compile (requires nightly)
cargo +nightly check --target=bpfel-unknown-none -Z build-std=core -p tlapix-ebpf

# Run with debug logging
RUST_LOG=debug cargo run --bin tlapix -- --config config/tlapix.toml
```

### Minimum Kernel Version

**Linux 5.15+** (LTS) — required for BPF ring buffer, CO-RE, and modern map types. Develop on 6.1+ for best tooling. Ubuntu 22.04 LTS ships with 5.15.

---

## Roadmap

- [x] Core three-layer architecture (eBPF → AI → BPF Maps)
- [x] Rule-based anomaly detection with AI fallback
- [x] Renewal prediction with probability scoring
- [x] Shadow certificate detection and escalation
- [x] ACME auto-renewal workflow
- [x] Multi-target observability (OTLP, Prometheus, StatsD, Webhooks)
- [x] Lightweight web UI (axum + htmx)
- [x] 344+ tests including 22 property-based correctness proofs
- [ ] Train production anomaly detection ONNX model
- [ ] IPv6 support in eBPF collector
- [ ] Kubernetes operator for multi-node deployment
- [ ] Certificate transparency log integration
- [ ] ACME DNS-01 challenge solver

---

## License

MIT

---

## Acknowledgments

- **Aya** — Pure Rust eBPF framework that makes kernel programming accessible
- **OpenTelemetry** — Vendor-neutral observability standard
- **proptest** — Property-based testing for Rust
- The certificate outages that inspired this project — may they be the last
