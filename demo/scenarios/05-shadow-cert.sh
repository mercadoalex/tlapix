#!/usr/bin/env bash
# Scenario 05: Shadow Certificate Detection
#
# Demonstrates Tlapix identifying a certificate NOT in the inventory.
# Expected behavior:
#   - Certificate classified as Shadow (self-signed → Critical risk)
#   - Alert directive generated with origin context
#   - Risk escalates over time if unresolved

set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Scenario 05: Shadow Certificate Detection"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  The 'shadow' server uses a self-signed cert from an unknown CA."
echo "  It is NOT in the inventory file → classified as shadow."
echo ""

for i in $(seq 1 5); do
    curl -sk https://tls-server-shadow:443/ -o /dev/null 2>/dev/null || true
    echo "  → Request ${i}/5 sent"
    sleep 1
done

echo ""
echo "  ✅ Check:"
echo "     http://localhost:8080/anomalies  (Shadow/Critical — self-signed)"
echo ""
echo "  Wait 1 minute and check again — risk level should escalate."
echo ""
echo "═══════════════════════════════════════════════════════════════"
