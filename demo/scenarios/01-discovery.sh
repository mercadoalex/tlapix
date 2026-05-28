#!/usr/bin/env bash
# Scenario 01: Certificate Discovery
#
# Demonstrates Tlapix discovering a valid TLS certificate in live traffic.
# Expected behavior:
#   - Certificate appears in the Web UI inventory
#   - No anomalies triggered (valid cert, strong key, in inventory)
#   - Prometheus counter increments for certificates_discovered

set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Scenario 01: Certificate Discovery"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Generating TLS traffic to the 'good' server..."
echo "  Tlapix should discover the certificate without raising alerts."
echo ""

# Generate traffic to the good server
for i in $(seq 1 10); do
    curl -sk https://tls-server-good:443/ -o /dev/null 2>/dev/null || true
    echo "  → Request ${i}/10 sent"
    sleep 1
done

echo ""
echo "  ✅ Traffic generated. Check the Tlapix Web UI:"
echo "     http://localhost:8080/certificates"
echo ""
echo "  Expected:"
echo "    - 'good.tlapix-demo.local' appears in certificate list"
echo "    - No anomalies on http://localhost:8080/anomalies"
echo "    - Prometheus: curl http://localhost:9090/metrics | grep discovered"
echo ""
echo "═══════════════════════════════════════════════════════════════"
