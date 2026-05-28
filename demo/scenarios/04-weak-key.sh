#!/usr/bin/env bash
# Scenario 04: Weak Key Anomaly
#
# Demonstrates Tlapix detecting a certificate with RSA 1024-bit key.
# Expected behavior:
#   - WeakCryptography anomaly detected (Critical severity)
#   - Alert directive generated
#   - Certificate flagged in Web UI

set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Scenario 04: Weak Key Detection (RSA 1024)"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Generating traffic to the 'weak' server (RSA 1024-bit key)..."
echo ""

for i in $(seq 1 5); do
    curl -sk https://tls-server-weak:443/ -o /dev/null 2>/dev/null || true
    echo "  → Request ${i}/5 sent"
    sleep 1
done

echo ""
echo "  ✅ Check:"
echo "     http://localhost:8080/anomalies  (WeakCryptography/Critical)"
echo "     Prometheus: curl localhost:9090/metrics | grep anomalies"
echo ""
echo "═══════════════════════════════════════════════════════════════"
