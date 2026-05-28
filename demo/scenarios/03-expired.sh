#!/usr/bin/env bash
# Scenario 03: Expired Certificate Alert
#
# Demonstrates Tlapix detecting an already-expired certificate.
# Expected behavior:
#   - ExpiredCertificate anomaly detected (Critical severity)
#   - Alert directive generated immediately
#   - Webhook notification sent to operators

set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Scenario 03: Expired Certificate Detection"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Note: The 'expired' server uses a backdated certificate."
echo "  Tlapix should immediately flag it as Critical."
echo ""

for i in $(seq 1 5); do
    curl -sk https://tls-server-good:443/ -o /dev/null 2>/dev/null || true
    echo "  → Request ${i}/5 to expired server"
    sleep 1
done

echo ""
echo "  ✅ Check:"
echo "     http://localhost:8080/anomalies  (ExpiredCertificate/Critical)"
echo "     http://localhost:8080/actions    (alert directive)"
echo ""
echo "═══════════════════════════════════════════════════════════════"
