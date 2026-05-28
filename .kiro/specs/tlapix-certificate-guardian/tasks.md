# Implementation Plan: Tlapix Certificate Guardian

## Overview

This plan implements the three-layer autonomous certificate lifecycle management system in Rust. Tasks are ordered for incremental, testable progress: shared types and storage first, then the Collector layer, Analyzer layer, Executor layer, Observability, and finally the Web UI. Each task builds on previous work and ends with integration wiring.

## Tasks

- [x] 1. Project structure, shared types, and storage layer
  - [x] 1.1 Initialize Cargo workspace and crate structure
    - Create workspace with crates: `tlapix-common` (shared types), `tlapix-ebpf` (eBPF programs), `tlapix-collector` (userspace collector), `tlapix-analyzer`, `tlapix-executor`, `tlapix-daemon` (binary)
    - Add workspace-level dependencies: `tokio`, `aya`, `aya-ebpf`, `rusqlite`, `x509-parser`, `ort`, `instant-acme`, `opentelemetry`, `axum`, `proptest`, `serde`, `uuid`, `chrono`
    - Set up `xtask` or build script for eBPF compilation
    - _Requirements: All (project foundation)_

  - [x] 1.2 Define shared data types in `tlapix-common`
    - Implement `TlsCertEvent` (repr(C) struct for ring buffer)
    - Implement `CertificateMetadata`, `ActionDirective`, `ActionType`, `Severity`, `AnomalyType`, `RiskLevel`, `ShadowClassification`, `RenewalPrediction`, `BpfActionEntry`
    - Implement `TlapixConfig` and all sub-configs (`CollectorConfig`, `AnalyzerConfig`, `ExecutorConfig`, `ObservabilityConfig`, `WebhookConfig`)
    - Add serde Serialize/Deserialize derives where appropriate
    - _Requirements: 2.1, 6.2, 3.2–3.5, 5.3_

  - [x] 1.3 Implement SQLite storage layer
    - Create database initialization with all schemas: `certificates`, `action_directives`, `shadow_certificates`, `renewal_predictions`, `audit_log`, `certificate_inventory`, `inventory_refresh_log`
    - Implement CRUD operations for each table as async-compatible functions (using `tokio::task::spawn_blocking` with rusqlite)
    - Implement data retention cleanup (90-day policy for certificates and audit logs)
    - _Requirements: 2.6, 8.5_

  - [x]* 1.4 Write property tests for data retention policy
    - **Property 20: Data Retention Policy**
    - Test that records with last_seen > 90 days are eligible for deletion and records < 90 days are preserved
    - **Validates: Requirements 2.6, 8.5**

- [x] 2. eBPF Collector programs (kernel space)
  - [x] 2.1 Implement TLS handshake parser eBPF program
    - Create TC ingress/egress eBPF programs using `aya-ebpf`
    - Parse TCP packets to identify TLS record layer (content type 0x16)
    - Extract certificate from ServerHello/Certificate messages (TLS 1.2)
    - Handle TLS 1.3 unencrypted portions
    - Compute SHA-256 fingerprint of leaf certificate DER
    - Push `TlsCertEvent` to BPF ring buffer
    - _Requirements: 1.1, 1.2, 2.1_

  - [x] 2.2 Implement BPF maps for Collector
    - Create `seen_certs` hash map (fingerprint → first_seen_ts, 100K entries)
    - Create `cert_stats` per-CPU hash map (fingerprint → connection_count, 100K entries)
    - Create `drop_counter` per-CPU array (index → count, 4 entries)
    - Create `events` ring buffer (16 MB configurable)
    - Implement `is_new` check against `seen_certs` map before pushing to ring buffer
    - _Requirements: 1.4, 1.6, 2.3_

  - [x] 2.3 Implement certificate chain extraction in eBPF
    - Extract chain depth from Certificate message
    - Compute issuer fingerprint (SHA-256 of immediate CA cert)
    - Store chain_depth and issuer_fingerprint in `TlsCertEvent`
    - _Requirements: 2.7_

  - [x]* 2.4 Write property test for TLS handshake parsing round-trip
    - **Property 1: TLS Handshake Parsing Round-Trip**
    - Generate valid DER-encoded X.509 certificates, wrap in TLS handshake bytes, verify extracted fingerprint and fields match
    - **Validates: Requirements 1.1, 1.2, 2.1**

  - [x]* 2.5 Write property test for malformed input resilience
    - **Property 2: Malformed Input Resilience**
    - Generate arbitrary byte sequences, verify parser returns error without panic and system continues
    - **Validates: Requirements 1.5**

  - [x]* 2.6 Write property test for certificate chain extraction
    - **Property 22: Certificate Chain Extraction**
    - Generate handshakes with chains of depth D ≥ 1, verify chain_depth and issuer_fingerprint are correct
    - **Validates: Requirements 2.7**

- [ ] 3. Userspace Collector service
  - [x] 3.1 Implement ring buffer reader and event processing
    - Read events from BPF ring buffer asynchronously via `aya::maps::RingBuf`
    - Parse DER certificate data into `CertificateMetadata` using `x509-parser`
    - Handle partial/truncated certificates (set completeness_flags bitmask)
    - Log malformed handshakes with context (timestamp, IPs, port, bytes)
    - _Requirements: 1.1, 1.5, 2.1, 2.4_

  - [x] 3.2 Implement deduplication engine with LRU cache
    - Deduplicate by SHA-256 fingerprint using local LRU cache
    - Forward only unique certificate metadata to Analyzer
    - Update last_seen timestamp and increment connection_ckedin
    ount for duplicates
    - Persist metadata to SQLite
    - _Requirements: 2.2, 2.3_

  - [x] 3.3 Implement local buffer and retry logic
    - Buffer up to 10,000 pending metadata records when Analyzer is unavailable
    - Implement FIFO eviction when buffer is full
    - Retry forwarding with exponential backoff (30s intervals, up to 1 hour)
    - _Requirements: 1.7, 2.5_

  - [x] 3.4 Implement fingerprint persistence and reload
    - Persist seen-certificate fingerprint set to SQLite
    - Reload fingerprint set from persistent storage on restart
    - Ensure previously-seen certificates are not re-reported as new
    - _Requirements: 1.8_

  - [x]* 3.5 Write property test for deduplication and observation counting
    - **Property 3: Deduplication and Observation Counting**
    - Generate N events with K unique fingerprints, verify exactly K forwarded and connection_counts correct
    - **Validates: Requirements 2.2, 2.3**

  - [x]* 3.6 Write property test for buffer capacity invariant
    - **Property 4: Buffer Capacity Invariant**
    - Generate sequences exceeding 10,000 records, verify buffer never exceeds limit and oldest discarded first
    - **Validates: Requirements 1.7**

  - [x]* 3.7 Write property test for fingerprint persistence round-trip
    - **Property 5: Fingerprint Persistence Round-Trip**
    - Persist fingerprint sets, reload, verify equality
    - **Validates: Requirements 1.8**

  - [x]* 3.8 Write property test for partial metadata completeness flags
    - **Property 6: Partial Metadata Completeness Flags**
    - Generate certificates with subsets of fields, verify bitmask correctness
    - **Validates: Requirements 2.4, 3.7**

- [x] 4. Checkpoint - Collector layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Analyzer service — Anomaly Detection
  - [x] 5.1 Implement rule-based anomaly detector
    - Detect validity > 398 days → PolicyViolation/medium
    - Detect RSA < 2048 or ECDSA < 256 → WeakCryptography/critical
    - Detect SNI not matching any SAN → SniMismatch/high
    - Detect expired certificates
    - Detect near-expiry (configurable threshold)
    - Generate one `ActionDirective` per anomaly detected
    - Handle partial metadata (evaluate only applicable patterns)
    - _Requirements: 3.1–3.7_

  - [x] 5.2 Implement SNI-to-SAN wildcard matching
    - Exact case-insensitive match
    - Wildcard SAN (starting with "*.") matches single-level subdomain of base domain
    - _Requirements: 3.4_

  - [x] 5.3 Implement AI model integration with fallback
    - Load ONNX model via `ort` crate
    - Implement 5-second timeout for AI backend
    - Fall back to rule-based detection on timeout/failure
    - Log degraded state when in fallback mode
    - _Requirements: 3.6_

  - [x]* 5.4 Write property test for anomaly detection rule correctness
    - **Property 7: Anomaly Detection Rule Correctness**
    - Generate certificates with known attributes, verify anomalies detected if and only if rules violated
    - **Validates: Requirements 3.2, 3.3, 3.4, 3.5**

  - [x]* 5.5 Write property test for SNI-to-SAN wildcard matching
    - **Property 8: SNI-to-SAN Wildcard Matching**
    - Generate SNI/SAN pairs, verify match logic (exact, wildcard single-level)
    - **Validates: Requirements 3.4**

- [ ] 6. Analyzer service — Renewal Prediction
  - [x] 6.1 Implement renewal predictor
    - Generate `RenewalPrediction` for certificates ≤ 30 days from expiry
    - Assign baseline failure_probability ≥ 0.5 when no historical data
    - Escalate to critical when < 14 days and no renewal activity detected
    - Generate "renew" `ActionDirective` when failure_probability ≥ 0.7
    - Generate "alert" at critical severity when certificate expires without renewal
    - _Requirements: 4.1–4.6_

  - [x] 6.2 Implement periodic re-evaluation (24h cycle)
    - Re-evaluate all active predictions every 24 hours
    - Incorporate historical renewal patterns and current state
    - Use `tokio::time::interval` for scheduling
    - _Requirements: 4.4_

  - [x]* 6.3 Write property test for renewal prediction correctness
    - **Property 9: Renewal Prediction Correctness**
    - Generate certificates with various days_until_expiry and renewal states, verify prediction logic
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.5**

- [ ] 7. Analyzer service — Shadow Certificate Detection
  - [x] 7.1 Implement inventory manager
    - Support file-based and API-based inventory import
    - Poll at configurable interval (≤ 5 minutes)
    - Handle unreachable source (30s timeout, continue with last known)
    - Log staleness warning at 60 minutes
    - Skip malformed entries, log each, continue with valid
    - _Requirements: 9.1, 9.2, 9.4, 9.5, 9.7_

  - [x] 7.2 Implement shadow certificate classifier
    - Compare fingerprint against inventory
    - Classify as Shadow with risk level: critical (self-signed/weak key), high (untrusted issuer/long validity), medium (< 30 days remaining), low (otherwise)
    - Generate "alert" `ActionDirective` with origin context
    - Defer classification when inventory unreachable
    - _Requirements: 5.1–5.4, 5.6_

  - [x] 7.3 Implement shadow certificate escalation
    - Escalate risk level by one tier every 24 hours for unresolved shadows
    - Generate new critical-severity directive when escalated to critical
    - Replace prior lower-severity directives
    - _Requirements: 5.5, 5.7_

  - [x] 7.4 Implement inventory reconciliation
    - Reclassify shadow → known when certificate appears in updated inventory
    - Cancel pending directives and write removal to BPF map
    - Reclassify known → shadow when certificate absent from full refresh but still in traffic
    - _Requirements: 9.3, 9.6_

  - [x]* 7.5 Write property test for shadow certificate classification
    - **Property 10: Shadow Certificate Classification**
    - Generate certificates not in inventory, verify risk level assignment and alert generation
    - **Validates: Requirements 5.2, 5.3, 5.4**

  - [x]* 7.6 Write property test for shadow certificate escalation
    - **Property 11: Shadow Certificate Escalation**
    - Generate shadow certs with time progression, verify escalation tiers and directive replacement
    - **Validates: Requirements 5.5, 5.7**

  - [x]* 7.7 Write property test for inventory reconciliation
    - **Property 12: Inventory Reconciliation**
    - Generate shadow certs that appear/disappear from inventory, verify reclassification
    - **Validates: Requirements 9.3, 9.6**

  - [x]* 7.8 Write property test for inventory import robustness
    - **Property 13: Inventory Import Robustness**
    - Generate inventory data with valid/invalid mix, verify valid accepted and invalid skipped
    - **Validates: Requirements 9.5**

- [x] 8. Checkpoint - Analyzer layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Executor service
  - [x] 9.1 Implement BPF map writer
    - Write `ActionDirective` to appropriate BPF map (`action_alert`, `action_protect`, `action_isolate`)
    - Enforce 10,000 entry max per map and 64 MB total memory cap
    - Implement retry logic (3 attempts, exponential backoff 100ms base)
    - Notify Analyzer on map full or permanent failure
    - _Requirements: 6.1, 7.3, 7.4, 7.5, 7.8_

  - [x] 9.2 Implement executor eBPF programs (protect and isolate)
    - `protect_program`: TC-attached, reads protect map, rejects non-pinned certs within 100ms
    - `isolate_program`: TC-attached, reads isolate map, drops matching connections within 100ms
    - Both programs read-only from pre-defined BPF maps (no dynamic code)
    - _Requirements: 6.2, 6.3, 6.4, 6.8, 7.1, 7.2_

  - [x] 9.3 Implement ACME renewal workflow
    - Invoke `instant-acme` for "renew" action directives within 30 seconds
    - Handle ACME failures with retry and escalation
    - _Requirements: 6.6_

  - [x] 9.4 Implement directive expiry and conflict resolution
    - Expire directives for certificates not seen in 72 hours
    - Remove expired directives from BPF maps
    - Resolve conflicts: apply highest severity, discard lower
    - _Requirements: 6.5, 6.9_

  - [x] 9.5 Implement retry exhaustion and failure handling
    - Mark directive as failed after 3 attempts
    - Log failure reason
    - Generate alert notification to operators
    - _Requirements: 6.7_

  - [x] 9.6 Implement program integrity validation at startup
    - Validate all pre-loaded eBPF programs against expected SHA-256 checksums
    - Abort startup on any mismatch, log expected vs actual
    - Activate Collector only after validation passes
    - _Requirements: 7.6, 7.7_

  - [x]* 9.7 Write property test for directive expiry
    - **Property 14: Directive Expiry**
    - Generate directives with various last_seen timestamps, verify 72h expiry logic
    - **Validates: Requirements 6.5**

  - [x]* 9.8 Write property test for directive conflict resolution
    - **Property 15: Directive Conflict Resolution**
    - Generate pairs of directives for same fingerprint, verify highest severity wins
    - **Validates: Requirements 6.9**

  - [x]* 9.9 Write property test for BPF map capacity enforcement
    - **Property 16: BPF Map Capacity Enforcement**
    - Generate sequences of writes exceeding 10,000, verify rejection and notification
    - **Validates: Requirements 7.3, 7.8**

  - [x]* 9.10 Write property test for program integrity validation
    - **Property 17: Program Integrity Validation**
    - Generate program binaries with correct/incorrect checksums, verify pass/abort behavior
    - **Validates: Requirements 7.6, 7.7**

  - [x]* 9.11 Write property test for retry exhaustion state transition
    - **Property 18: Retry Exhaustion State Transition**
    - Generate directives that fail 3 times, verify failed state and alert generation
    - **Validates: Requirements 6.7**

- [x] 10. Checkpoint - Executor layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Observability and audit trail
  - [x] 11.1 Implement audit logging with correlation IDs
    - Assign unique correlation_id to each certificate observation event
    - Propagate correlation_id through Analyzer and Executor stages
    - Log observation → analysis → action decision chain for high-impact actions
    - Halt directive processing if audit logging fails
    - _Requirements: 8.1, 8.2, 8.4, 8.6, 8.7_

  - [x] 11.2 Implement OpenTelemetry metrics export
    - Initialize `opentelemetry-rust` SDK with OTLP exporter
    - Export metrics: certificates_discovered, anomalies_detected, predictions_generated, actions_executed, actions_failed
    - Update metrics within 60 seconds of underlying event
    - Support configurable OTLP endpoint and auth token
    - _Requirements: 8.3, 10.1, 10.2_

  - [x] 11.3 Implement Prometheus exposition endpoint
    - Expose metrics in Prometheus text format on configurable HTTP endpoint
    - Include all system metrics with appropriate labels
    - _Requirements: 10.3_

  - [x] 11.4 Implement StatsD exporter
    - Export metrics via StatsD protocol to configurable endpoint
    - _Requirements: 10.4_

  - [x] 11.5 Implement webhook dispatcher
    - Deliver HTTP POST with JSON payload to configured endpoints within 10 seconds
    - Include correlation_id, cert_fingerprint, action_type, severity, timestamp in payload
    - Retry up to 3 times with exponential backoff (1s base)
    - Log failure and increment webhook-failure metric after exhaustion
    - Support PagerDuty, OpsGenie, Slack integrations
    - _Requirements: 10.5, 10.6, 10.7, 10.9_

  - [x] 11.6 Implement independent multi-target export
    - Configure multiple simultaneous export targets (OTLP, Prometheus, StatsD, webhooks)
    - Ensure failure of one channel does not affect others
    - _Requirements: 10.10_

  - [x]* 11.7 Write property test for audit trail completeness
    - **Property 19: Audit Trail Completeness**
    - Generate observation events, verify correlation_id propagation and decision chain completeness
    - **Validates: Requirements 8.1, 8.2, 8.4, 8.7**

  - [x]* 11.8 Write property test for export format compliance
    - **Property 21: Export Format Compliance**
    - Generate metric events and actions, verify all payloads contain required fields and channels are independent
    - **Validates: Requirements 10.3, 10.4, 10.9, 10.10**

- [x] 12. Checkpoint - Observability layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Web UI and daemon wiring
  - [x] 13.1 Implement lightweight web UI (axum + htmx)
    - Certificate inventory status page
    - Active anomalies view
    - Recent actions log
    - Current predictions dashboard
    - Server-rendered with htmx for interactivity
    - _Requirements: 10.8_

  - [x] 13.2 Wire all components into the daemon binary
    - Initialize configuration loading (TOML/YAML)
    - Start Collector, Analyzer, Executor, Observability services with `CancellationToken`
    - Implement graceful shutdown (SIGTERM/SIGINT handling)
    - Ensure startup order: validate checksums → load eBPF → start collector → start analyzer → start executor → start observability → start web UI
    - _Requirements: All (integration)_

  - [x] 13.3 Implement end-to-end integration tests
    - Synthetic TLS traffic via veth pairs → observation → analysis → action
    - Verify full pipeline with mock AI backend, ACME CA, webhook endpoints
    - Test graceful degradation (AI timeout → rule fallback, inventory unreachable → last known)
    - _Requirements: 1.1, 3.1, 6.1_

- [x] 14. Final checkpoint - All layers integrated
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after each layer
- Property tests validate universal correctness properties from the design document using `proptest`
- Unit tests validate specific examples and edge cases
- The eBPF programs require Linux 5.15+ kernel for ring buffer and modern map types
- Integration tests use `veth` pairs with synthetic TLS traffic
- AI model, ACME CA, webhook endpoints, and inventory sources should be mocked in tests

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["1.3"] },
    { "id": 3, "tasks": ["1.4", "2.1", "2.2"] },
    { "id": 4, "tasks": ["2.3", "2.4", "2.5"] },
    { "id": 5, "tasks": ["2.6", "3.1"] },
    { "id": 6, "tasks": ["3.2", "3.3", "3.4"] },
    { "id": 7, "tasks": ["3.5", "3.6", "3.7", "3.8"] },
    { "id": 8, "tasks": ["5.1", "5.2"] },
    { "id": 9, "tasks": ["5.3", "5.4", "5.5"] },
    { "id": 10, "tasks": ["6.1"] },
    { "id": 11, "tasks": ["6.2", "6.3"] },
    { "id": 12, "tasks": ["7.1"] },
    { "id": 13, "tasks": ["7.2", "7.3"] },
    { "id": 14, "tasks": ["7.4", "7.5", "7.6"] },
    { "id": 15, "tasks": ["7.7", "7.8"] },
    { "id": 16, "tasks": ["9.1", "9.2"] },
    { "id": 17, "tasks": ["9.3", "9.4", "9.5", "9.6"] },
    { "id": 18, "tasks": ["9.7", "9.8", "9.9", "9.10", "9.11"] },
    { "id": 19, "tasks": ["11.1"] },
    { "id": 20, "tasks": ["11.2", "11.3", "11.4", "11.5"] },
    { "id": 21, "tasks": ["11.6", "11.7", "11.8"] },
    { "id": 22, "tasks": ["13.1", "13.2"] },
    { "id": 23, "tasks": ["13.3"] }
  ]
}
```
