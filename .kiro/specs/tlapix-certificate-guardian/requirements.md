# Requirements Document

## Introduction

Tlapix Certificate Guardian is an autonomous certificate lifecycle management system that leverages eBPF for zero-overhead TLS certificate discovery and observation, AI-driven anomaly detection and prediction, and BPF map-based autonomous action execution. The system operates as a three-layer architecture: the Collector (eBPF programs that passively observe TLS handshakes in real traffic), the External Analyzer (AI engine that detects anomalies, predicts renewal failures, and identifies shadow certificates), and the Minimalist Executor (BPF maps that trigger pre-verified actions at kernel speed). The design prioritizes safety by ensuring the kernel never executes dynamically generated code — only pre-verified BPF programs that read action maps.

## Problem Statement

Certificate expiry is entirely predictable, yet it remains one of the most common causes of major service outages across the industry. The average cost of a single certificate-related outage is estimated at $11.1 million per incident ([source](https://axonshield.com/business/certificate-outage-costs/)). Research indicates that 88% of security leaders report their organization has been impacted by Certificate Authority revocations, 45% had to deploy extra resources to locate, revoke, and replace certificates, 38% suffered a security incident tied to certificates, and 31% experienced a certificate-related outage.

### Notable Real-World Incidents

The following incidents illustrate how predictable certificate expiry continues to cause severe disruptions:

- **Microsoft Teams (February 2020):** A multi-hour outage caused by an expired authentication certificate prevented users from logging in.
- **Spotify/Megaphone (May 2022):** An expired SSL certificate triggered an 8-hour platform outage affecting podcast publishers and listeners ([source](https://www.npr.org/2022/05/31/1102320291/a-spotify-publisher-was-down-monday-night-the-culprit-a-lapsed-security-certific)).
- **LinkedIn (2023):** A certificate-related outage disrupted service availability.
- **Microsoft Teams (2023):** Another certificate-related incident impacted the platform.
- **SpaceX Starlink (April 2024):** A multi-hour global outage caused by an expired ground station certificate — described by Elon Musk as an "inexcusable" single point of failure.
- **Tailscale (March 2024):** A 90-minute outage caused by an expired TLS certificate ([source](https://tailscale.com/blog/tls-outage-20240307)).
- **Ericsson/O2 (2018):** An expired certificate caused downtime for 32 million cellular users in the UK and millions more across Asia ([source](https://www.bbc.co.uk/news/business-46499366)).
- **Bank of England:** An expired certificate crashed their £6 trillion Real-Time Gross Settlement system ([source](https://www.sectigo.com/resource-library/expired-certificate-crashed-6-trillion-bank-of-england-system)).
- **GitHub (2014):** An SSL provider's certificate expired, affecting both GitHub and BitBucket.

### The Coming Storm: 47-Day Certificate Mandate

In April 2025, the CA/Browser Forum voted (Ballot SC-081v3) to progressively reduce TLS certificate maximum validity from 398 days down to 47 days by March 2029 ([source](https://www.theregister.com/2025/04/14/ssl_tls_certificates/)). The timeline is as follows: 200-day maximum by March 2026, 100-day maximum by March 2027, and 47-day maximum by March 2029. Domain validation reuse will drop to just 10 days. Apple, Google, Mozilla, and Microsoft all supported this change ([source](https://www.hashicorp.com/en/blog/47-day-certificates-lifespan-mandate-how-we-can-help)).

This represents approximately 8x more certificate lifecycle work than organizations handle today. Manual certificate management becomes impossible at this scale.

### Why Tlapix Exists

Current certificate management tools are reactive — they alert after expiry or near-expiry — rather than proactive in predicting and preventing failures. No existing solution combines passive traffic observation via eBPF, AI-driven prediction, and autonomous action execution through BPF maps. The 47-day mandate makes autonomous certificate lifecycle management not merely desirable but essential. Tlapix demonstrates that a small, focused team armed with eBPF, AI, and BPF maps can build what previously required enterprise-scale organizations and budgets.

## Glossary

- **Collector**: The eBPF-based data gathering layer that attaches to kernel hooks to passively observe TLS handshakes and extract certificate metadata from live network traffic with zero application overhead.
- **Analyzer**: The AI-powered external analysis engine (runs in userspace) that processes certificate metadata to detect anomalies, predict renewal failures, and identify shadow certificates.
- **Executor**: The BPF map-based action execution layer that reads pre-populated action maps to perform autonomous responses (alert, renew, protect, isolate) without generating or loading new eBPF code at runtime.
- **BPF_Map**: A kernel-resident key-value data structure shared between eBPF programs and userspace, used to communicate action directives from the Analyzer to the Executor.
- **Shadow_Certificate**: A TLS certificate present in live traffic that is not registered in any known certificate inventory or management system.
- **Certificate_Metadata**: Extracted information from observed TLS handshakes including subject, issuer, serial number, validity period, SANs, key type, and fingerprint.
- **Action_Directive**: A structured entry written to a BPF map by the Analyzer that instructs the Executor to perform a specific action (alert, renew, protect, or isolate) on a target certificate or connection.
- **Renewal_Prediction**: An AI-generated assessment of the likelihood that an upcoming certificate renewal will fail, based on historical patterns and current system state.
- **Certificate_Inventory**: The authoritative registry of all known and managed certificates within the monitored infrastructure.
- **TLS_Handshake**: The protocol negotiation at the start of a TLS connection where certificates are exchanged and can be observed by the Collector.

## Requirements

### Requirement 1: TLS Certificate Discovery via eBPF

**User Story:** As a platform operator, I want the system to automatically discover all TLS certificates in live network traffic, so that I have complete visibility into my certificate landscape without modifying applications.

#### Acceptance Criteria

1. WHEN a TLS_Handshake occurs on a monitored network interface, THE Collector SHALL extract Certificate_Metadata from the handshake and forward it to the Analyzer within 5 seconds of observation.
2. THE Collector SHALL capture certificates from all TLS versions (1.2 and 1.3) observed on monitored interfaces, including handshakes on any TCP port where a valid TLS ClientHello is detected.
3. WHILE the Collector is active and processing up to 10,000 TLS handshakes per second, THE Collector SHALL maintain less than 1% CPU overhead on the monitored host as measured by the difference in CPU utilization with and without the Collector attached.
4. WHEN a previously unseen certificate is observed (identified by a SHA-256 fingerprint not present in the Collector's local observation store), THE Collector SHALL record the first-seen timestamp, source IP, destination IP, and SNI hostname (if available in the ClientHello) alongside the Certificate_Metadata.
5. IF the Collector encounters a malformed TLS handshake, THEN THE Collector SHALL log the event with the timestamp, source IP, destination IP, destination port, and the TLS record bytes available, and continue processing subsequent handshakes without interruption.
6. WHILE the Collector is active and traffic volume exceeds the processing capacity, THE Collector SHALL drop no more than 0.1% of observed TLS handshakes and SHALL increment a dropped-handshake counter accessible to the observability layer.
7. IF the Collector cannot forward extracted Certificate_Metadata to the Analyzer (due to queue full, Analyzer unavailable, or storage failure), THEN THE Collector SHALL buffer up to 10,000 pending metadata records locally and retry forwarding with exponential backoff, discarding the oldest records when the buffer is full.
8. WHEN the Collector is restarted, THE Collector SHALL reload its previously-seen certificate fingerprint set from persistent storage so that previously discovered certificates are not re-reported as newly seen.

### Requirement 2: Certificate Metadata Extraction and Storage

**User Story:** As a platform operator, I want comprehensive certificate metadata extracted and stored, so that the Analyzer has sufficient data to detect anomalies and predict failures.

#### Acceptance Criteria

1. WHEN Certificate_Metadata is extracted, THE Collector SHALL record the following fields for the leaf certificate: subject (up to 2048 characters), issuer (up to 2048 characters), serial number, not-before date, not-after date, Subject Alternative Names (up to 100 entries), key algorithm, key size, and SHA-256 fingerprint.
2. THE Collector SHALL deduplicate observed certificates by SHA-256 fingerprint and forward only unique certificate metadata to the Analyzer within 10 seconds of extraction.
3. WHEN a certificate is observed again after initial discovery, THE Collector SHALL update the last-seen timestamp (UTC, millisecond precision) and increment the connection count for that certificate.
4. IF the Collector cannot extract complete Certificate_Metadata from a handshake, THEN THE Collector SHALL store partial metadata with a per-field presence indicator identifying which of the required fields are missing.
5. IF the Analyzer is unreachable when the Collector attempts to forward Certificate_Metadata, THEN THE Collector SHALL buffer the metadata locally for up to 1 hour and retry forwarding at 30-second intervals until successful delivery or buffer expiration.
6. THE Collector SHALL retain stored Certificate_Metadata for a minimum of 90 days from the last-seen timestamp before eligible for deletion.
7. WHEN a TLS_Handshake presents a certificate chain, THE Collector SHALL extract and store Certificate_Metadata for the leaf certificate and record the chain depth and issuer fingerprint of the immediate issuing CA.

### Requirement 3: AI-Driven Anomaly Detection

**User Story:** As a platform operator, I want the system to automatically detect certificate anomalies, so that I am alerted to potential security issues before they cause incidents.

#### Acceptance Criteria

1. WHEN new Certificate_Metadata is received, THE Analyzer SHALL evaluate the certificate against known anomaly patterns within 30 seconds of receipt.
2. THE Analyzer SHALL detect certificates with validity periods exceeding 398 days as a policy anomaly with severity "medium".
3. THE Analyzer SHALL detect certificates using key sizes below 2048 bits (RSA) or 256 bits (ECDSA) as a security anomaly with severity "critical".
4. THE Analyzer SHALL detect a configuration anomaly with severity "high" WHEN the observed SNI hostname does not match any Subject Alternative Name in the certificate, where matching is defined as either an exact case-insensitive match or a valid wildcard match (a SAN beginning with "*." matches any single-level subdomain of the base domain).
5. WHEN one or more anomalies are detected on a single certificate, THE Analyzer SHALL generate one Action_Directive per anomaly and assign the severity level corresponding to that anomaly type.
6. IF the Analyzer cannot establish a connection to its AI model backend within 5 seconds, THEN THE Analyzer SHALL fall back to rule-based anomaly detection and log the degraded state.
7. IF Certificate_Metadata is received with a completeness flag indicating missing fields, THEN THE Analyzer SHALL evaluate only the anomaly patterns applicable to the available fields and include a partial-analysis indicator in the generated Action_Directive.

### Requirement 4: Certificate Renewal Failure Prediction

**User Story:** As a platform operator, I want the system to predict certificate renewal failures before they happen, so that I can prevent outages caused by expired certificates.

#### Acceptance Criteria

1. THE Analyzer SHALL generate a Renewal_Prediction for each certificate currently observed in traffic at least 30 days before its expiration date, including a failure probability score between 0.0 and 1.0.
2. WHEN a certificate has fewer than 14 days until expiration and no renewal activity is detected (where renewal activity is defined as observation of a new certificate with the same subject or SAN set, or receipt of an external renewal confirmation via the Certificate_Inventory), THE Analyzer SHALL escalate the Renewal_Prediction severity to critical.
3. IF a certificate has no historical renewal data available, THEN THE Analyzer SHALL generate a Renewal_Prediction using issuer-default response times and assign a baseline failure probability of no less than 0.5.
4. THE Analyzer SHALL re-evaluate each active Renewal_Prediction at least once every 24 hours, incorporating historical renewal patterns (previous renewal timing, issuer response times, past failures) and current system state.
5. WHEN a Renewal_Prediction failure probability score equals or exceeds 0.7, THE Analyzer SHALL generate an Action_Directive with action type "renew".
6. IF a certificate expires without renewal, THEN THE Analyzer SHALL generate an Action_Directive with action type "alert" at critical severity.

### Requirement 5: Shadow Certificate Identification

**User Story:** As a security engineer, I want the system to identify shadow certificates that are not in our inventory, so that I can eliminate unmanaged certificates that pose security risks.

#### Acceptance Criteria

1. WHEN a certificate is observed in traffic, THE Analyzer SHALL compare its SHA-256 fingerprint against the Certificate_Inventory within 30 seconds of receiving the Certificate_Metadata.
2. WHEN a certificate is not found in the Certificate_Inventory, THE Analyzer SHALL classify it as a Shadow_Certificate.
3. THE Analyzer SHALL categorize each Shadow_Certificate into one of four risk levels (critical, high, medium, low) using the following criteria: critical if the certificate is self-signed or uses a key size below 2048 bits (RSA) or 256 bits (ECDSA); high if the issuer is not in the organization's trusted issuer list or the validity period exceeds 398 days; medium if the certificate has fewer than 30 days remaining validity; low if the certificate has a trusted issuer, adequate key strength, and a validity period within 398 days.
4. WHEN a Shadow_Certificate is identified, THE Analyzer SHALL generate an Action_Directive with action type "alert" and include the certificate origin context (source IP, destination, first-seen timestamp).
5. WHILE a Shadow_Certificate has been observed in at least one connection within the preceding 24-hour window and remains unregistered in the Certificate_Inventory, THE Analyzer SHALL escalate its risk level by one tier every 24 hours, up to a maximum of critical.
6. IF the Certificate_Inventory is unreachable during a shadow certificate comparison, THEN THE Analyzer SHALL defer classification until the inventory becomes available and log the deferred comparison event.
7. WHEN a Shadow_Certificate risk level is escalated to critical, THE Analyzer SHALL generate a new Action_Directive with action type "alert" at critical severity, replacing any prior lower-severity directive for that certificate.

### Requirement 6: Autonomous Action Execution via BPF Maps

**User Story:** As a platform operator, I want the system to autonomously execute protective actions at kernel speed, so that threats are mitigated immediately without human intervention.

#### Acceptance Criteria

1. WHEN the Analyzer generates an Action_Directive, THE Analyzer SHALL write the directive to the BPF_Map designated for that action type within 5 seconds.
2. THE Executor SHALL support four action types: alert (deliver a notification to the configured operator channel within 10 seconds), renew (trigger certificate renewal workflow), protect (reject new TLS handshakes that do not present the pinned certificate for the targeted hostname within 100 milliseconds), and isolate (drop new connections presenting the targeted certificate within 100 milliseconds).
3. WHEN an Action_Directive with type "isolate" is written to the BPF_Map, THE Executor SHALL drop new connections presenting the targeted certificate within 100 milliseconds.
4. THE Executor SHALL only read Action_Directives from pre-defined BPF_Maps and SHALL NOT load or generate new eBPF programs at runtime.
5. IF an Action_Directive references a certificate no longer observed in traffic for more than 72 hours, THEN THE Executor SHALL expire the directive and remove it from the BPF_Map.
6. WHEN an Action_Directive with type "renew" is written to the BPF_Map, THE Executor SHALL invoke the configured certificate renewal workflow (ACME or custom webhook) within 30 seconds.
7. IF the Executor fails to execute an Action_Directive after 3 attempts, THEN THE Executor SHALL mark the directive as failed in the BPF_Map, log the failure reason, and generate an alert notification to operators.
8. WHEN an Action_Directive with type "protect" is written to the BPF_Map, THE Executor SHALL reject new TLS handshakes that do not present the pinned certificate for the targeted hostname within 100 milliseconds.
9. IF conflicting Action_Directives exist for the same certificate (identified by SHA-256 fingerprint), THEN THE Executor SHALL apply the directive with the highest severity and discard the lower-severity directive.

### Requirement 7: Safety and Stability Guarantees

**User Story:** As a platform operator, I want the system to guarantee kernel stability, so that autonomous actions never compromise system availability.

#### Acceptance Criteria

1. THE Executor SHALL only execute eBPF programs that have passed the kernel verifier at load time.
2. THE Executor SHALL NOT generate, compile, or load new eBPF bytecode during runtime operation.
3. WHILE the Executor is active, THE Executor SHALL enforce a maximum of 10,000 entries per BPF_Map and a total BPF_Map memory allocation not exceeding 64 MB across all maps to prevent unbounded kernel memory consumption.
4. IF a BPF_Map write operation fails, THEN THE Executor SHALL log the failure, notify the Analyzer, and retry the write up to 3 times with exponential backoff starting at 100 milliseconds and doubling each attempt.
5. IF all 3 retry attempts for a BPF_Map write operation are exhausted, THEN THE Executor SHALL log the permanent failure, notify the Analyzer with the failed Action_Directive details, and discard the write operation without further retries.
6. WHEN the system starts, THE Executor SHALL validate all pre-loaded eBPF programs against their expected SHA-256 checksums before activating the Collector.
7. IF any pre-loaded eBPF program fails checksum validation at startup, THEN THE Executor SHALL abort system startup, log the mismatched program identity and expected versus actual checksum, and report the failure to the operator.
8. IF a BPF_Map reaches its maximum entry capacity, THEN THE Executor SHALL reject new write operations for that map, log the capacity event, and notify the Analyzer that the map is full.
9. THE Collector SHALL operate within the eBPF instruction limit enforced by the kernel verifier for each attached program.

### Requirement 8: Observability and Audit Trail

**User Story:** As a platform operator, I want complete visibility into the system's decisions and actions, so that I can audit autonomous behavior and troubleshoot issues.

#### Acceptance Criteria

1. WHEN the Analyzer generates an Action_Directive, THE Analyzer SHALL log the directive with context including the triggering certificate fingerprint, anomaly type, confidence score, recommended action type, and a reasoning summary of no more than 500 characters.
2. WHEN the Executor processes an Action_Directive, THE Executor SHALL log the action outcome (success, failure, expired) with a timestamp, affected certificate fingerprint, and the correlation identifier linking back to the originating Analyzer directive.
3. THE system SHALL expose metrics for: certificates discovered, anomalies detected, predictions generated, actions executed, and actions failed, updated within 60 seconds of the underlying event.
4. WHEN any Action_Directive with type "isolate", "protect", or "renew" is executed, THE system SHALL generate an audit event containing the decision chain from observation (certificate fingerprint, first-seen timestamp) through analysis (anomaly type, confidence score) to action (action type, outcome, execution timestamp), linked by a correlation identifier.
5. THE system SHALL retain audit logs for a minimum of 90 days.
6. IF the system is unable to persist an audit log entry, THEN THE system SHALL halt processing of new Action_Directives until audit logging is restored and SHALL expose a metric indicating audit logging failure.
7. THE system SHALL assign a unique correlation identifier to each certificate observation event and propagate it through the Analyzer and Executor stages to enable end-to-end tracing of the decision chain.

### Requirement 9: Certificate Inventory Integration

**User Story:** As a platform operator, I want the system to integrate with my existing certificate inventory, so that shadow certificate detection is accurate and actionable.

#### Acceptance Criteria

1. THE Analyzer SHALL support importing Certificate_Inventory data from at least one external source (file-based or API-based), where each inventory entry contains at minimum a SHA-256 fingerprint and a certificate subject.
2. WHEN the Certificate_Inventory is updated externally, THE Analyzer SHALL detect the change and refresh its local copy within 5 minutes by polling the source at a configurable interval not exceeding 5 minutes.
3. WHEN a previously classified Shadow_Certificate appears in an updated Certificate_Inventory, THE Analyzer SHALL reclassify it as a known certificate, cancel any pending Action_Directives for it in the Analyzer queue, and write a removal directive to the BPF_Map to expire any active directives targeting that certificate.
4. IF the Certificate_Inventory source is unreachable after a connection timeout of 30 seconds, THEN THE Analyzer SHALL continue operating with the last known inventory, log the connectivity failure, and retry on the next polling cycle.
5. IF the Certificate_Inventory import contains entries that are malformed or missing required fields (SHA-256 fingerprint or subject), THEN THE Analyzer SHALL skip the invalid entries, log each skipped entry, and proceed with importing the remaining valid entries.
6. WHEN a certificate previously present in the Certificate_Inventory is absent from a subsequent full inventory refresh, THE Analyzer SHALL reclassify it as a Shadow_Certificate if it is still observed in live traffic.
7. IF the Certificate_Inventory has not been successfully refreshed for more than 60 minutes, THEN THE Analyzer SHALL log a staleness warning and include the inventory age in any Shadow_Certificate classifications produced during this period.

### Requirement 10: Observability Dashboard Integration

**User Story:** As a platform operator, I want the system to integrate with my existing observability platforms, so that I can monitor certificate health within the tools I already use rather than managing a separate dashboard.

#### Acceptance Criteria

1. THE system SHALL export all metrics (certificates discovered, anomalies detected, predictions generated, actions executed, actions failed) via OpenTelemetry Protocol (OTLP) as the primary integration mechanism.
2. THE system SHALL support integration with Datadog, Dynatrace, Splunk, and Grafana through OTLP-compatible metric export endpoints configurable via connection parameters (endpoint URL, authentication token, export interval).
3. THE system SHALL expose metrics in Prometheus exposition format on a configurable HTTP endpoint to support custom dashboards and Prometheus-compatible scraping tools.
4. THE system SHALL support StatsD protocol for metric export to enable integration with legacy monitoring infrastructure.
5. WHEN an Action_Directive with type "alert", "isolate", "protect", or "renew" is executed, THE system SHALL deliver a webhook notification (HTTP POST with JSON payload) to each configured webhook endpoint within 10 seconds, supporting integration with PagerDuty, OpsGenie, and Slack.
6. IF a webhook delivery fails (non-2xx response or connection timeout of 10 seconds), THEN THE system SHALL retry delivery up to 3 times with exponential backoff starting at 1 second and doubling each attempt.
7. IF all webhook delivery retries are exhausted, THEN THE system SHALL log the delivery failure with the target endpoint, payload summary, and failure reason, and increment a webhook-failure metric.
8. WHERE the standalone deployment mode is enabled, THE system SHALL provide a lightweight built-in web UI that displays certificate inventory status, active anomalies, recent actions, and current predictions without requiring external observability platform integration.
9. THE system SHALL include a correlation identifier, certificate fingerprint, action type, severity, and timestamp in every webhook payload and OTLP metric annotation to enable cross-referencing with the audit trail.
10. THE system SHALL allow operators to configure multiple simultaneous export targets (OTLP, Prometheus, StatsD, and webhooks) that operate independently, so that failure of one export channel does not affect delivery to other channels.
