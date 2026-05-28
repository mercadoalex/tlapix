# AI/ML Inference Strategy: ONNX Runtime

## Decision Summary

Tlapix uses **ONNX Runtime** (via the `ort` Rust crate) for local AI inference. The model runs on the same machine as the daemon — no cloud APIs, no network round-trips, no per-request billing.

This document explains why, how it works, what alternatives exist, what it costs, and what to watch out for.

---

## Why Local Inference?

### The Problem with Cloud AI for Security Infrastructure

Tlapix is a security-critical system that:
- Processes certificate metadata from live production traffic
- Must respond within 30 seconds of observation (Requirement 3.1)
- Runs 24/7 without human intervention
- Handles sensitive data (internal hostnames, IP addresses, certificate subjects)

Sending this data to a cloud API (OpenAI, AWS Bedrock, Google Vertex) introduces:

| Risk | Impact |
|------|--------|
| **Latency** | 200-2000ms per API call vs 1-5ms local inference |
| **Availability** | Cloud outage = blind spot in certificate monitoring |
| **Data exfiltration** | Internal hostnames and IPs sent to third parties |
| **Cost at scale** | 10K certs × 24 evaluations/day × $0.01/call = $2,400/day |
| **Rate limits** | API throttling during incident response (worst time) |
| **Vendor lock-in** | Tied to one provider's model format and pricing |

### Why ONNX Specifically

ONNX (Open Neural Network Exchange) is a vendor-neutral model format supported by every major ML framework:

- **Train anywhere**: PyTorch, TensorFlow, scikit-learn, XGBoost — all export to ONNX
- **Run anywhere**: CPU, GPU, ARM, x86 — ONNX Runtime handles hardware abstraction
- **No Python dependency**: The `ort` Rust crate links directly to the C++ runtime
- **Deterministic**: Same input always produces same output (no temperature/sampling)
- **Offline**: Works in air-gapped environments, submarines, satellites — anywhere

---

## How It Works in Tlapix

### Architecture

```
┌─────────────────────────────────────────────────┐
│                 Tlapix Daemon                     │
│                                                  │
│  CertificateMetadata ──► Feature Extraction      │
│                              │                   │
│                              ▼                   │
│                    ┌─────────────────┐           │
│                    │  ONNX Runtime   │           │
│                    │  (ort crate)    │           │
│                    │                 │           │
│                    │  anomaly.onnx   │           │
│                    │  (loaded once)  │           │
│                    └────────┬────────┘           │
│                             │                    │
│                             ▼                    │
│                    Anomaly Scores                 │
│                    (0.0 - 1.0 per category)      │
│                             │                    │
│                             ▼                    │
│              ┌──────────────────────────┐        │
│              │  Rule Engine (fallback)  │        │
│              │  Combines AI + Rules     │        │
│              └──────────────────────────┘        │
└─────────────────────────────────────────────────┘
```

### Inference Flow

1. **Model loaded once at startup** — the ONNX file is memory-mapped, session created
2. **Feature extraction** — `CertificateMetadata` is converted to a numeric tensor:
   - Key size (normalized)
   - Validity period (days)
   - Days until expiry
   - Is self-signed (0/1)
   - SAN count
   - Chain depth
   - Connection frequency
   - Time since first seen
   - Algorithm type (one-hot encoded)
3. **Inference** — single forward pass through the model (~1-5ms on CPU)
4. **Output** — anomaly probability scores per category
5. **Decision** — scores above threshold generate `ActionDirective`

### Fallback Mechanism

If the ONNX model is unavailable (file missing, load error, inference timeout):
- The system falls back to **rule-based detection** immediately
- Rules cover all critical cases (weak keys, expired certs, SNI mismatches)
- The AI layer adds nuance (unusual patterns, behavioral anomalies) but is not required
- Degraded state is logged and exposed as a metric

```rust
// From ai_backend.rs
match self.ai_backend.evaluate(metadata).await {
    Ok(ai_anomalies) => {
        // Combine AI + rule-based results
        let mut combined = rule_anomalies;
        combined.extend(ai_anomalies);
        combined
    }
    Err(_) => {
        // AI unavailable — rule-based only
        rule_anomalies
    }
}
```

---

## Model Types for Certificate Anomaly Detection

### Recommended: Isolation Forest

Best fit for Tlapix because:
- **Unsupervised** — doesn't need labeled "anomalous" certificates (hard to get)
- **Fast inference** — tree-based, O(log n) per sample
- **Small model size** — typically 1-10 MB as ONNX
- **Interpretable** — anomaly score directly maps to "how unusual is this cert"

```python
# Training example (scikit-learn → ONNX)
from sklearn.ensemble import IsolationForest
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Train on "normal" certificate features
model = IsolationForest(n_estimators=100, contamination=0.05)
model.fit(normal_cert_features)

# Export to ONNX
onnx_model = convert_sklearn(
    model,
    "tlapix_anomaly_detector",
    [("features", FloatTensorType([None, 12]))],  # 12 features
)
with open("anomaly.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
```

### Alternative: Autoencoder

Good for detecting certificates that "don't look like" normal ones:
- Train on normal certificate features
- High reconstruction error = anomaly
- Better at catching novel attack patterns
- Slightly larger model (5-50 MB)

### Alternative: XGBoost/LightGBM

If you have labeled data (known-good vs known-bad certificates):
- Supervised classification
- Extremely fast inference
- Excellent for known anomaly patterns
- Exports cleanly to ONNX via `onnxmltools`

### What NOT to Use

| Approach | Why Not |
|----------|---------|
| LLMs (GPT, Claude) | Overkill, slow, expensive, non-deterministic, data privacy |
| Deep neural networks | Unnecessary complexity for tabular certificate data |
| Online learning | Risk of model drift from adversarial inputs |
| Cloud AutoML | Vendor lock-in, latency, cost |

---

## Alternatives to ONNX Runtime

### Comparison Table

| Runtime | Language | GPU Support | Model Formats | Rust Crate | Maturity |
|---------|----------|-------------|---------------|------------|----------|
| **ONNX Runtime** | C++ | ✅ CUDA, TensorRT, DirectML | ONNX | `ort` | Production (Microsoft) |
| **Tract** | Pure Rust | ❌ CPU only | ONNX, TF | `tract` | Stable, no C++ deps |
| **Candle** | Rust | ✅ CUDA, Metal | Custom | `candle` | Newer (Hugging Face) |
| **TensorFlow Lite** | C | ✅ GPU delegate | TFLite | `tflite` | Production (Google) |
| **PyTorch (libtorch)** | C++ | ✅ CUDA | TorchScript | `tch-rs` | Heavy dependency |
| **WASI-NN** | Wasm | Varies | Multiple | — | Experimental |

### Why Not Tract (Pure Rust)?

Tract is appealing (no C++ dependency, pure Rust) but:
- Slower inference for larger models
- Less operator coverage (some ONNX ops unsupported)
- No GPU acceleration path
- Good choice if you want zero native dependencies and CPU-only is fine

**Verdict**: Consider Tract if deployment simplicity matters more than performance. For Tlapix, ONNX Runtime's maturity and performance win.

### Why Not Candle?

Candle (by Hugging Face) is Rust-native with GPU support but:
- Designed for transformer/LLM workloads, not tabular ML
- Younger ecosystem, fewer examples for anomaly detection
- No direct ONNX import (need to rewrite model in Candle)

**Verdict**: Better for NLP/vision tasks. Overkill for certificate anomaly detection.

### Why Not a Cloud API with Caching?

You could call OpenAI/Bedrock and cache results:
- Cache hit = fast (local lookup)
- Cache miss = 200-2000ms API call
- Still has data privacy concerns
- Cache invalidation is complex for evolving certificate landscapes
- Cold start problem after restart

**Verdict**: Adds complexity without clear benefit over local inference for this use case.

---

## Cost Analysis

### ONNX Runtime (Local) — What Tlapix Uses

| Item | Cost |
|------|------|
| Hardware | $0 additional (runs on existing server) |
| Inference | $0 per request (CPU cycles only) |
| Model training | One-time, on your laptop |
| Model storage | 1-10 MB on disk |
| Monthly operational | $0 |

**Total: $0/month** (beyond the server Tlapix already runs on)

### Cloud API Alternative — Cost Projection

Assuming 10,000 certificates monitored, evaluated every 24 hours:

| Provider | Per-Request Cost | Daily Cost | Monthly Cost |
|----------|-----------------|-----------|--------------|
| OpenAI GPT-4o-mini | ~$0.001 | $10 | $300 |
| AWS Bedrock (Claude) | ~$0.003 | $30 | $900 |
| Google Vertex AI | ~$0.002 | $20 | $600 |
| Azure OpenAI | ~$0.002 | $20 | $600 |

And that's just for anomaly detection. Add renewal prediction (every cert, every 24h) and shadow detection (every new cert), and costs multiply 3-5x.

**At scale (100K certs): $3,000-$9,000/month** just for AI inference.

### Hybrid Approach (Future Option)

For complex cases that local models can't handle:
- Local ONNX handles 99% of evaluations (fast, free)
- Cloud API called only for edge cases flagged by local model
- Budget: ~$50-100/month for the 1% that needs deeper analysis

---

## Hardware Considerations

### Minimum Requirements (CPU-Only)

| Resource | Requirement | Notes |
|----------|-------------|-------|
| CPU | Any x86_64 or ARM64 | ONNX Runtime supports both |
| RAM | +50-100 MB | Model loaded in memory |
| Disk | +10 MB | ONNX model file |
| Inference time | 1-5 ms/cert | On modern CPU (2020+) |

**Tlapix adds negligible overhead** — the eBPF programs and SQLite are heavier than the AI inference.

### GPU Acceleration (Optional)

Not needed for certificate anomaly detection (tabular data, small models), but if you want it:

| GPU | ONNX Runtime Provider | Use Case |
|-----|----------------------|----------|
| NVIDIA | CUDA / TensorRT | If processing >100K certs/sec |
| AMD | ROCm | Linux only |
| Apple Silicon | CoreML | macOS development |
| Intel | OpenVINO | Edge deployments |

**Recommendation**: Don't bother with GPU for this workload. A $5/month VPS CPU handles it fine.

### Memory-Mapped Model Loading

ONNX Runtime supports memory-mapping the model file:
- Model stays on disk, pages loaded on demand
- Startup time: ~10ms (vs 100ms+ for full load)
- Memory pressure: OS can evict unused model pages
- Good for resource-constrained environments

---

## Considerations and Pitfalls

### 1. Model Drift

Certificate landscapes change over time:
- New CAs emerge
- Key algorithms evolve (post-quantum coming)
- Validity periods shrink (47-day mandate)
- Your infrastructure grows

**Mitigation**: Retrain the model quarterly using recent certificate observations from Tlapix's own SQLite database. The data is already there.

### 2. Adversarial Inputs

An attacker who knows you use anomaly detection might craft certificates that look "normal" to the model but are malicious.

**Mitigation**: The rule-based engine runs in parallel. Even if the AI is fooled, rules catch:
- Weak keys (hard to fake — the key IS weak)
- Expired certs (timestamp is objective)
- Self-signed certs (issuer == subject is binary)

### 3. Cold Start

On first deployment, there's no trained model. The system runs rule-based only.

**Mitigation**: 
- Rule-based detection covers all critical cases from day one
- After 1-2 weeks of observation, you have enough data to train
- Ship a pre-trained "generic" model for common patterns

### 4. Model Size vs Accuracy

| Model Size | Accuracy | Inference Time | Use Case |
|-----------|----------|----------------|----------|
| <1 MB | Good (85-90%) | <1 ms | Edge, IoT |
| 1-10 MB | Very good (90-95%) | 1-5 ms | **Tlapix default** |
| 10-100 MB | Excellent (95-99%) | 5-50 ms | High-security environments |
| >100 MB | Diminishing returns | >50 ms | Probably overkill |

### 5. Feature Engineering Matters More Than Model Choice

For certificate anomaly detection, the features you extract matter more than whether you use Isolation Forest vs Autoencoder:

**High-value features:**
- Validity period relative to issuer's typical range
- Key size relative to algorithm best practices
- SAN count (unusually high = suspicious)
- Time-of-day patterns (certs appearing at 3 AM)
- Issuer reputation (new/unknown vs established CA)
- Certificate transparency log presence

**Low-value features:**
- Raw subject string (too variable)
- Exact expiry date (already handled by rules)
- Serial number format (issuer-specific)

### 6. Explainability

ONNX models (especially tree-based) can provide feature importance:
- "This cert was flagged because: validity_period contributed 0.4, key_size contributed 0.3"
- Important for audit trails (Requirement 8.1 — reasoning summary)
- Isolation Forest naturally provides anomaly scores per feature

### 7. Licensing

| Component | License | Commercial Use |
|-----------|---------|----------------|
| ONNX Runtime | MIT | ✅ Free |
| `ort` crate | MIT/Apache-2.0 | ✅ Free |
| ONNX format | Apache-2.0 | ✅ Free |
| scikit-learn | BSD-3 | ✅ Free |
| Your trained model | Yours | You own it |

No licensing costs. No usage fees. No vendor agreements.

---

## Training Pipeline (Future Work)

```
┌─────────────────────────────────────────────────────┐
│                Training Pipeline                     │
│                                                      │
│  Tlapix SQLite ──► Export Features ──► Train Model   │
│  (90 days of       (Python script)    (scikit-learn) │
│   cert metadata)                           │         │
│                                            ▼         │
│                                     Export to ONNX   │
│                                            │         │
│                                            ▼         │
│                                   anomaly.onnx       │
│                                            │         │
│                                            ▼         │
│                              Deploy to /opt/tlapix/  │
│                              (hot-reload on next     │
│                               evaluation cycle)      │
└─────────────────────────────────────────────────────┘
```

The training pipeline is intentionally separate from the runtime:
- Train offline (laptop, CI, wherever)
- Deploy the `.onnx` file to the server
- Tlapix picks it up on next startup (or via config reload)
- No Python in production. No Jupyter notebooks on the server.

---

## Summary

| Question | Answer |
|----------|--------|
| Why local? | Privacy, latency, cost, availability |
| Why ONNX? | Vendor-neutral, train anywhere, run anywhere |
| What model? | Isolation Forest (unsupervised, fast, small) |
| Hardware needed? | None extra — runs on existing CPU |
| Monthly cost? | $0 |
| What if model fails? | Rule-based fallback (always active) |
| When to retrain? | Quarterly, using Tlapix's own observation data |
| GPU needed? | No |
