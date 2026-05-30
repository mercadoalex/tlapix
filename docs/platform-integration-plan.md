# Platform Integration Plan: Nahual AiOps Modules

## Vision

We don't compete with observability platforms. We add autonomous capabilities that plug into whatever stack people already use. The more integrations, the better.

**Position:** "Autonomous AiOps modules for Kubernetes — install via Helm, feeds into your existing Grafana/Prometheus/Datadog/Splunk."

---

## The Portfolio

| Module | Domain | What It Does | Tech |
|--------|--------|-------------|------|
| **Earthworm** | Health | K8s cluster heartbeat monitoring via eBPF | Go + TypeScript + C |
| **Tlapix** | Security/Compliance | Autonomous TLS certificate lifecycle guardian | Rust + Aya |
| **eBeeControl** | Threat Detection | Autonomous deception engine (honeytokens) | TypeScript + Gemini |
| **Quack** | Performance | AI-powered container CPU scheduling | Go + sched_ext |

All four share the same architecture pattern:

```
eBPF (kernel observation) → AI (analysis/decision) → Autonomous Action
```

---

## Integration Strategy

We are NOT building:
- A metrics database (use VictoriaMetrics/Prometheus)
- A log aggregator (use Loki/Elastic)
- A tracing backend (use Tempo/Jaeger)
- A dashboard engine (use Grafana)
- An alerting system (use Alertmanager/PagerDuty)

We ARE building:
- Autonomous eBPF-powered capabilities that generate insights
- AI that makes decisions without humans
- Actions that execute at kernel speed
- A correlation layer that connects signals no single tool can see

---

## Target Integrations

| Backend | How We Integrate | Status |
|---------|-----------------|--------|
| Prometheus / VictoriaMetrics | `/metrics` endpoint (Prometheus exposition format) | Tlapix ✅, Earthworm ✅, eBeeControl ❌, Quack ❌ |
| Grafana | Pre-built dashboard JSON + optional plugin | Planned |
| Grafana Cloud | Remote write | Planned |
| Datadog | OTLP export | Tlapix ✅ |
| Splunk | HEC export | Quack ✅ |
| Dynatrace | API push | eBeeControl ✅ |
| PagerDuty / OpsGenie | Webhook alerts | Tlapix ✅ |
| Slack / Teams | Webhook alerts | Tlapix ✅ |
| Elastic / OpenSearch | OTLP or Filebeat | Planned |
| OpenTelemetry Collector | OTLP native | Tlapix ✅ |

---

## Phase 1: Make Each Module Independently Installable (2-3 weeks)

**Goal:** Anyone can `helm install` one module and get value in 5 minutes.

| Task | What | Why |
|------|------|-----|
| 1.1 | Each project has a working Helm chart | One command install |
| 1.2 | Each project exports Prometheus metrics at `/metrics` | Works with any stack |
| 1.3 | Each project ships a Grafana dashboard JSON | Instant visibility |
| 1.4 | Each project has a 3-minute demo video | People don't read, they watch |
| 1.5 | Each project has a `values.yaml` that works with zero config | Reduce friction to zero |

### Current Status

| Module | Helm Chart | Prometheus | Grafana Dashboard | Demo Video |
|--------|-----------|-----------|-------------------|-----------|
| Tlapix | ✅ | ✅ | ❌ | ❌ |
| Earthworm | ✅ (deploy/helm) | ✅ | ❌ | ❌ |
| eBeeControl | ✅ | ❌ (Dynatrace only) | ❌ | ❌ |
| Quack | ❌ (K8s manifests) | ❌ (Splunk HEC only) | ❌ | ❌ |

### Priority Fixes

1. **eBeeControl**: Add Prometheus metrics exporter alongside Dynatrace
2. **Quack**: Add Prometheus metrics exporter alongside Splunk HEC
3. **Quack**: Create proper Helm chart (currently raw manifests)
4. **All**: Create Grafana dashboard JSON files

---

## Phase 2: Unified Helm Chart + Shared Identity (1-2 weeks)

**Goal:** One chart installs all four modules (each toggleable).

```bash
helm install nahual nahual/nahual \
  --set tlapix.enabled=true \
  --set earthworm.enabled=true \
  --set ebeecontrol.enabled=false \
  --set quack.enabled=false
```

| Task | What |
|------|------|
| 2.1 | Create umbrella Helm chart that depends on the four sub-charts |
| 2.2 | Shared ServiceAccount + RBAC (one ClusterRole for all modules) |
| 2.3 | Shared ConfigMap for common settings (cluster name, OTLP endpoint) |
| 2.4 | One DaemonSet that loads all eBPF programs (instead of four) |
| 2.5 | Landing page / documentation site |

### Umbrella Chart Structure

```
helm/nahual/
├── Chart.yaml                    # Umbrella chart
├── values.yaml                   # Global + per-module config
├── charts/
│   ├── tlapix/                   # Sub-chart (from tlapix repo)
│   ├── earthworm/                # Sub-chart (from earthworm repo)
│   ├── ebeecontrol/              # Sub-chart (from ebeecontrol repo)
│   └── quack/                    # Sub-chart (from quack repo)
└── templates/
    ├── shared-rbac.yaml          # Unified RBAC
    ├── shared-configmap.yaml     # Common config
    └── correlation-service.yaml  # Phase 5 component
```

---

## Phase 3: Grafana Dashboard Pack (1 week)

**Goal:** Import or install dashboards that show all modules.

| Dashboard | Key Panels |
|-----------|-----------|
| **Overview** | Module health, events/sec, active alerts, AI decisions |
| **Certificates (Tlapix)** | Cert inventory, expiry timeline, shadow certs, anomalies |
| **Heartbeat (Earthworm)** | Node cardiogram, anomaly heatmap, prediction timeline |
| **Deception (eBeeControl)** | Honeytoken map, access events, threat classification |
| **Scheduling (Quack)** | Priority decisions, latency impact, model confidence |
| **Correlation** | Cross-module events on shared timeline |

### Distribution Options

1. Grafana dashboard JSON files in each repo's `grafana/` directory
2. Grafana plugin (more polished, discoverable in marketplace)
3. Published to Grafana.com dashboard library (free, searchable)

---

## Phase 4: Integration Adapters (2-3 weeks)

**Goal:** Work with whatever backend the customer already has.

Each module gets a unified export configuration:

```yaml
# In Helm values.yaml
export:
  prometheus:
    enabled: true
    port: 9090
  otlp:
    enabled: false
    endpoint: ""
  splunk:
    enabled: false
    hecUrl: ""
    hecToken: ""
  dynatrace:
    enabled: false
    apiUrl: ""
    apiToken: ""
  webhooks:
    - endpoint: "https://hooks.slack.com/..."
      events: ["critical", "high"]
```

The key: every module supports every backend. Customer picks what they have.

---

## Phase 5: Correlation Engine (3-4 weeks)

**Goal:** Connect signals across modules automatically. This is the paid differentiator.

### How It Works

```
Earthworm: "Node X heartbeat degraded"         (t=0)
Tlapix:    "Shadow cert appeared on Node X"     (t=+30s)
eBeeControl: "Honeytoken accessed from pod Y"   (t=+45s)
Quack:     "Pod Y consuming 95% CPU"            (t=+60s)

Correlation Engine:
  → Match by node_name="X" within 2-minute window
  → Generate: "Possible crypto-miner on Node X (confidence: 92%)"
  → Auto-action: Isolate pod Y, alert operator, forensic report
```

### Components

| Component | What |
|-----------|------|
| Shared event schema | All modules emit events with `node`, `pod`, `namespace`, `timestamp`, `severity`, `module` |
| Event bus | Lightweight in-cluster gRPC service or shared NATS/Redis stream |
| Correlation rules | "If A + B + C within N minutes → correlated incident" |
| AI layer | Model trained on correlated incidents to predict attack chains |
| Output | Correlated alerts with full narrative, sent to configured backends |

### Why This Is the Moat

No single observability tool can do this because:
- Datadog doesn't have eBPF-based deception
- Grafana doesn't have autonomous certificate renewal
- Splunk doesn't have kernel-level scheduling
- VictoriaMetrics doesn't have AI-driven action execution

The correlation of signals across these domains is unique. That's what you charge for.

---

## Phase 6: Go-to-Market

| Channel | Action | Timeline |
|---------|--------|----------|
| GitHub | All repos public, good READMEs, stars campaign | Now |
| Artifact Hub | Publish Helm charts (K8s community discovers them) | Phase 2 |
| Grafana Marketplace | Publish dashboard pack | Phase 3 |
| Blog posts | One per module + one platform overview | Phase 3-4 |
| Conference CFPs | KubeCon, eBPF Summit, GrafanaCon, Splunk .conf | Phase 4 |
| YouTube | 3-min demo per module + 10-min platform overview | Phase 3 |
| Hacker News | 47-day certificate mandate angle (Tlapix) | Phase 1 |
| CNCF Landscape | Apply for listing under Observability → AIOps | Phase 4 |
| Product Hunt | Launch the unified platform | Phase 5 |

---

## Business Model

| Tier | What | Price |
|------|------|-------|
| **Open Source** | All four modules, Helm charts, Grafana dashboards | Free |
| **Pro** | Correlation engine, managed AI models, priority support | $X/node/month |
| **Enterprise** | Custom integrations, SLA, dedicated support, training | Contact |

The open source modules drive adoption. The correlation engine drives revenue.

---

## Timeline Summary

| Phase | Duration | Outcome |
|-------|----------|---------|
| 1. Individual modules ready | 2-3 weeks | Each module installable and demo-able |
| 2. Unified chart | 1-2 weeks | One `helm install` for everything |
| 3. Grafana dashboards | 1 week | Visual proof of value |
| 4. Integration adapters | 2-3 weeks | Works with any backend |
| 5. Correlation engine | 3-4 weeks | The paid differentiator |
| 6. Go-to-market | Ongoing | Visibility and adoption |

**Total to MVP platform: ~10 weeks.**

---

## Architecture Decision: Keep Projects Separate

The four projects use different languages (Rust, Go, TypeScript). Don't rewrite them. Connect them via:

1. **Shared event schema** (protobuf or JSON with common fields)
2. **OTLP as the universal transport** (all modules emit, any backend consumes)
3. **Umbrella Helm chart** (installs sub-charts as dependencies)
4. **Correlation service** (new, small, reads from all four)

Each project continues to evolve independently. The platform is the orchestration layer on top.

---

## Key Principle

> "We don't replace your observability stack. We give it superpowers."

The customer keeps Grafana, keeps Prometheus, keeps their alerts. They add our modules and suddenly their cluster has autonomous certificate management, deception-based threat detection, AI scheduling, and heartbeat monitoring — all feeding into the tools they already trust.
