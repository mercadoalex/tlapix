# Deployment Strategy

## Overview

Tlapix has a unique deployment constraint: it requires **kernel-level access** (eBPF) on every node where it monitors TLS traffic. This shapes how we ship and deploy it across different environments.

The system runs as two logical components:
- **Collector + Executor** (per-node): Needs privileged kernel access for eBPF
- **Analyzer + Web UI + Storage** (central): Standard unprivileged workload

---

## Shipping Formats

| Format | Target | Registry/Location |
|--------|--------|-------------------|
| OCI container image | All container environments | `ghcr.io/mercadoalex/tlapix` |
| Helm chart | Kubernetes production | `ghcr.io/mercadoalex/tlapix/charts` |
| Static binary | VMs, bare metal, quick testing | GitHub Releases |
| Terraform module | AWS EC2 demo/staging | `terraform/` directory |

---

## Kubernetes Deployment (Primary)

### Why Kubernetes is the Primary Target

Kubernetes is where most certificate complexity lives:
- **cert-manager** issues and rotates hundreds of certificates
- **Istio/Linkerd** mTLS means every pod has a short-lived certificate
- **Ingress controllers** terminate TLS for external traffic
- **Operators and webhooks** bring their own CAs
- The 47-day mandate will hit K8s clusters hardest (highest cert density)

### Architecture in K8s

```
┌─────────────────────────────────────────────────────────────┐
│                      K8s Cluster                             │
│                                                              │
│  Node 1                 Node 2                 Node 3        │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────┐ │
│  │ Tlapix Agent  │     │ Tlapix Agent  │     │  Tlapix   │ │
│  │ (DaemonSet)   │     │ (DaemonSet)   │     │  Agent    │ │
│  │               │     │               │     │           │ │
│  │ • eBPF Coll.  │     │ • eBPF Coll.  │     │ • eBPF    │ │
│  │ • BPF Executor│     │ • BPF Executor│     │ • Executor│ │
│  │ • Ring Buffer │     │ • Ring Buffer │     │ • Ring Buf│ │
│  └───────┬───────┘     └───────┬───────┘     └─────┬─────┘ │
│          │                      │                    │       │
│          └──────────────────────┼────────────────────┘       │
│                                 │                            │
│                        ┌────────┴────────┐                   │
│                        │ Tlapix Central  │                   │
│                        │ (Deployment)    │                   │
│                        │                 │                   │
│                        │ • AI Analyzer   │                   │
│                        │ • Renewal Pred. │                   │
│                        │ • Shadow Detect.│                   │
│                        │ • Inventory Mgr │                   │
│                        │ • Web UI        │                   │
│                        │ • SQLite Store  │                   │
│                        │ • OTLP Export   │                   │
│                        └─────────────────┘                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Component Separation

| Component | K8s Resource | Privileges | Replicas |
|-----------|-------------|-----------|----------|
| **Tlapix Agent** | DaemonSet | Privileged (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN) | 1 per node |
| **Tlapix Central** | Deployment | Unprivileged | 1 (or HA with 2-3) |
| **Configuration** | ConfigMap | — | — |
| **Secrets** | Secret | — | — |
| **Metrics** | ServiceMonitor | — | — |

### Why DaemonSet for the Agent

eBPF programs attach to **network interfaces on the host**. They observe traffic at the kernel level, not at the pod level. This means:
- One Tlapix agent per node is sufficient to see ALL traffic on that node
- The agent must run with host networking or at minimum access to the host's network namespace
- It cannot run as a sidecar (that would only see one pod's traffic)

A DaemonSet guarantees exactly one agent pod per node, automatically scaling with the cluster.

### Required Capabilities

The agent pod needs these Linux capabilities (not full `privileged: true`):

```yaml
securityContext:
  capabilities:
    add:
      - BPF           # Load and manage eBPF programs
      - NET_ADMIN     # Attach TC hooks to network interfaces
      - SYS_ADMIN     # Access BPF maps, read kernel BTF
      - PERFMON       # Access perf events (some eBPF features)
```

The central component runs as a standard unprivileged pod.

### RBAC Requirements

Tlapix Central needs to read TLS secrets for inventory comparison:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tlapix-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
    # Filtered to type=kubernetes.io/tls in the controller
  - apiGroups: ["cert-manager.io"]
    resources: ["certificates", "certificaterequests"]
    verbs: ["get", "list", "watch"]
```

---

## Helm Chart Structure

```
helm/tlapix/
├── Chart.yaml                  # Chart metadata, version, dependencies
├── values.yaml                 # Default configuration values
├── templates/
│   ├── _helpers.tpl            # Template helpers (labels, names)
│   ├── namespace.yaml          # Optional dedicated namespace
│   ├── serviceaccount.yaml     # ServiceAccount for RBAC
│   ├── clusterrole.yaml        # Permission to read TLS secrets
│   ├── clusterrolebinding.yaml # Bind role to service account
│   ├── configmap.yaml          # tlapix.toml configuration
│   ├── secret.yaml             # ACME credentials, webhook tokens
│   ├── daemonset.yaml          # Per-node eBPF agent
│   ├── deployment.yaml         # Central analyzer + web UI
│   ├── service.yaml            # ClusterIP for agent, LoadBalancer for UI
│   ├── ingress.yaml            # Optional ingress for Web UI
│   ├── pdb.yaml                # PodDisruptionBudget
│   ├── servicemonitor.yaml     # Prometheus Operator integration
│   └── hpa.yaml                # HorizontalPodAutoscaler for central
└── README.md                   # Chart documentation
```

### Key values.yaml Sections

```yaml
# Agent (DaemonSet) configuration
agent:
  image:
    repository: ghcr.io/mercadoalex/tlapix
    tag: latest
  interfaces: ["eth0"]          # Host interfaces to monitor
  ringBufferSizeMb: 16
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

# Central (Deployment) configuration
central:
  replicas: 1
  image:
    repository: ghcr.io/mercadoalex/tlapix
    tag: latest
  webUi:
    enabled: true
    port: 8080
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi

# Analyzer configuration
analyzer:
  aiModelPath: /opt/tlapix/models/anomaly.onnx
  aiTimeoutSecs: 5
  inventorySource:
    type: kubernetes       # Read TLS secrets directly from K8s API
  renewalThreshold: 0.7

# Observability
observability:
  otlp:
    enabled: false
    endpoint: ""
  prometheus:
    enabled: true
    port: 9090
    serviceMonitor: true   # Create ServiceMonitor for Prometheus Operator
  webhooks: []

# ACME auto-renewal
acme:
  enabled: false
  directoryUrl: "https://acme-v02.api.letsencrypt.org/directory"
  contactEmail: ""
```

### Installation

```bash
# Add the Tlapix Helm repository
helm repo add tlapix https://mercadoalex.github.io/tlapix/charts
helm repo update

# Install with default values
helm install tlapix tlapix/tlapix -n tlapix-system --create-namespace

# Install with custom values
helm install tlapix tlapix/tlapix \
  -n tlapix-system --create-namespace \
  -f my-values.yaml

# Upgrade
helm upgrade tlapix tlapix/tlapix -n tlapix-system -f my-values.yaml

# Uninstall
helm uninstall tlapix -n tlapix-system
```

---

## Bare Metal / VM Deployment

For non-Kubernetes environments (the Terraform EC2 scenario, on-prem servers):

### Static Binary

```bash
# Download the latest release
curl -L https://github.com/mercadoalex/tlapix/releases/latest/download/tlapix-linux-amd64 \
  -o /usr/local/bin/tlapix
chmod +x /usr/local/bin/tlapix

# Create configuration
mkdir -p /etc/tlapix
cp tlapix.toml /etc/tlapix/

# Create systemd service
cat > /etc/systemd/system/tlapix.service <<EOF
[Unit]
Description=Tlapix Certificate Guardian
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tlapix --config /etc/tlapix/tlapix.toml
Restart=always
RestartSec=5
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable --now tlapix

# Check status
systemctl status tlapix
journalctl -u tlapix -f
```

### Key systemd Configuration

| Setting | Purpose |
|---------|---------|
| `LimitMEMLOCK=infinity` | eBPF maps require locked memory |
| `AmbientCapabilities` | Grant eBPF capabilities without running as root |
| `Restart=always` | Auto-restart on crash |
| `After=network.target` | Wait for network before starting |

---

## Container Image

### Multi-Architecture Build

```dockerfile
# Build for both amd64 and arm64
FROM --platform=$BUILDPLATFORM rust:1.79-bookworm AS builder
# ... (see demo/Dockerfile.tlapix for full build)

FROM debian:bookworm-slim
# Minimal runtime with eBPF support
```

### Image Registry

Published to GitHub Container Registry:
```
ghcr.io/mercadoalex/tlapix:latest
ghcr.io/mercadoalex/tlapix:0.1.0
ghcr.io/mercadoalex/tlapix:0.1.0-arm64
```

### Running with Docker (non-K8s)

```bash
docker run -d \
  --name tlapix \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --cap-add=PERFMON \
  --network=host \
  -v /etc/tlapix:/etc/tlapix:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  ghcr.io/mercadoalex/tlapix:latest
```

Note: `--network=host` is required so the eBPF programs can attach to the host's network interfaces.

---

## Upgrade Strategy

### Rolling Updates (DaemonSet)

The DaemonSet uses `RollingUpdate` strategy:
- One node at a time gets the new agent
- Old eBPF programs are detached, new ones loaded
- Brief gap (~2-3 seconds) during transition where traffic is not observed
- No traffic is dropped (eBPF programs are observation-only by default)

```yaml
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1    # One node at a time
```

### Canary Deployments

For the central component, use standard Deployment rollout:
```bash
helm upgrade tlapix tlapix/tlapix \
  --set central.image.tag=0.2.0-rc1 \
  --set central.replicas=2
```

### Rollback

```bash
# Helm rollback
helm rollback tlapix 1

# Or kubectl rollback for DaemonSet
kubectl rollout undo daemonset/tlapix-agent -n tlapix-system
```

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Privileged agent pods | Use specific capabilities, not `privileged: true` |
| eBPF program integrity | SHA-256 checksum validation at startup |
| Secret access (RBAC) | Read-only, filtered to TLS type secrets only |
| Network exposure | Web UI behind ingress with auth, not exposed directly |
| Supply chain | Signed container images, SBOM published with releases |
| Data at rest | SQLite on encrypted volumes (EBS encryption, LUKS) |

---

## Monitoring the Monitor

Tlapix monitors certificates — but who monitors Tlapix?

| Signal | How |
|--------|-----|
| Agent health | DaemonSet pod status + liveness probe |
| Central health | Deployment readiness probe + `/healthz` endpoint |
| eBPF programs loaded | Metric: `tlapix_ebpf_programs_loaded` |
| Certificates discovered | Metric: `tlapix_certificates_discovered` (should be > 0) |
| Audit logging healthy | Metric: `tlapix_audit_healthy` (1 = ok, 0 = halted) |
| Analyzer mode | Metric: `tlapix_analyzer_mode` (ai_powered vs rule_based) |

Set alerts on:
- `tlapix_certificates_discovered == 0` for > 5 minutes (agent not observing)
- `tlapix_audit_healthy == 0` (directive processing halted)
- DaemonSet pods not running on all nodes

---

## Summary

| Environment | Ship As | Deploy With |
|-------------|---------|-------------|
| Kubernetes | OCI image + Helm chart | `helm install` |
| AWS EC2 / VMs | Static binary | systemd + Terraform |
| Docker (non-K8s) | OCI image | `docker run --cap-add` |
| Development | Source | `cargo run` |

The Helm chart is the primary distribution mechanism for production. The static binary and Docker image serve simpler environments and quick testing.
