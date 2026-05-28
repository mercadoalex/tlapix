#!/usr/bin/env bash
# Scenario 02: Near-Expiry Detection
#
# Demonstrates Tlapix detecting a certificate about to expire.
# Expected behavior:
#   - Renewal prediction generated with high failure probability
#   - "renew" action directive created
#   - ACME renewal triggered (via Pebble)

set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Scenario 02: Near-Expiry Detection & Auto-Renewal"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Generating traffic to the 'expiring' server..."
echo "  Tlapix should predict renewal failure and trigger ACME."
echo ""

for i in $(seq 1 10); do
    curl -sk https://tls-server-expiring:443/ -o /dev/null 2>/dev/null || true
    echo "  → Request ${i}/10 sent"
    sleep 1
done

echo ""
echo "  ✅ Traffic generated. Check:"
echo "     http://localhost:8080/predictions  (renewal prediction)"
echo "     http://localhost:8080/actions       (renew directive)"
echo ""
echo "  Expected:"
echo "    - Prediction with failure_probability >= 0.7"
echo "    - 'renew' directive in pending state"
echo "    - ACME renewal attempt logged"
echo ""
echo "═══════════════════════════════════════════════════════════════"
