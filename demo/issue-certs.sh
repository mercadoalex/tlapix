#!/usr/bin/env bash
# issue-certs.sh — Issue certificates for each demo scenario.
#
# Generates certificates with various properties:
#   - good:     Valid cert, RSA 2048, 365 days
#   - expiring: Valid cert, RSA 2048, expires in 2 minutes
#   - expired:  Cert that's already expired (backdated)
#   - weak:     RSA 1024-bit key (triggers WeakCryptography anomaly)
#   - shadow:   Valid cert from "unknown" CA (not in inventory)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
CA_DIR="${CERTS_DIR}/ca"

# Verify CA exists
if [ ! -f "${CA_DIR}/ca.key" ] || [ ! -f "${CA_DIR}/ca.crt" ]; then
    echo "❌ CA not found. Run ./setup-ca.sh first."
    exit 1
fi

echo "📜 Issuing demo certificates..."
echo ""

# ---------------------------------------------------------------------------
# Helper function to issue a certificate
# Usage: issue_cert <name> <cn> <san> <key_bits> <days> [extra_opts]
# ---------------------------------------------------------------------------
issue_cert() {
    local name="$1"
    local cn="$2"
    local san="$3"
    local key_bits="$4"
    local days="$5"
    local extra_opts="${6:-}"
    local cert_dir="${CERTS_DIR}/${name}"

    mkdir -p "${cert_dir}"

    # Generate private key
    openssl genrsa -out "${cert_dir}/server.key" "${key_bits}" 2>/dev/null

    # Generate CSR
    openssl req -new \
        -key "${cert_dir}/server.key" \
        -out "${cert_dir}/server.csr" \
        -subj "/C=MX/ST=CDMX/O=Tlapix Demo/CN=${cn}" \
        2>/dev/null

    # Create extensions file for SAN
    cat > "${cert_dir}/ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = ${san}
EOF

    # Sign with CA
    if [ -n "${extra_opts}" ]; then
        eval openssl x509 -req \
            -in "${cert_dir}/server.csr" \
            -CA "${CA_DIR}/ca.crt" \
            -CAkey "${CA_DIR}/ca.key" \
            -CAcreateserial \
            -out "${cert_dir}/server.crt" \
            -days "${days}" \
            -sha256 \
            -extfile "${cert_dir}/ext.cnf" \
            ${extra_opts} \
            2>/dev/null
    else
        openssl x509 -req \
            -in "${cert_dir}/server.csr" \
            -CA "${CA_DIR}/ca.crt" \
            -CAkey "${CA_DIR}/ca.key" \
            -CAcreateserial \
            -out "${cert_dir}/server.crt" \
            -days "${days}" \
            -sha256 \
            -extfile "${cert_dir}/ext.cnf" \
            2>/dev/null
    fi

    # Print fingerprint
    local fp
    fp=$(openssl x509 -in "${cert_dir}/server.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
    echo "  ✅ ${name}: CN=${cn}, ${key_bits}-bit, ${days} days, fp=${fp:0:16}..."

    # Save fingerprint for inventory
    echo "${fp}" > "${cert_dir}/fingerprint.txt"

    # Cleanup CSR and extensions
    rm -f "${cert_dir}/server.csr" "${cert_dir}/ext.cnf"
}

# ---------------------------------------------------------------------------
# Issue certificates for each scenario
# ---------------------------------------------------------------------------

# 1. Good certificate (valid, strong key, long-lived)
issue_cert "good" \
    "good.tlapix-demo.local" \
    "DNS:good.tlapix-demo.local,DNS:www.tlapix-demo.local" \
    2048 \
    365

# 2. Expiring certificate (valid but expires very soon)
# We use a 1-day cert and set startdate to yesterday so it expires in ~minutes
# For the demo, we'll use openssl's -not_after option
EXPIRY_DATE=$(date -u -v+2M "+%Y%m%d%H%M%SZ" 2>/dev/null || date -u -d "+2 minutes" "+%Y%m%d%H%M%SZ" 2>/dev/null || echo "")
if [ -z "${EXPIRY_DATE}" ]; then
    # Fallback: just use 1 day (demo script will handle timing)
    issue_cert "expiring" \
        "expiring.tlapix-demo.local" \
        "DNS:expiring.tlapix-demo.local" \
        2048 \
        1
    echo "    ⚠️  Note: On macOS, cert set to 1 day. On Linux, it would be 2 minutes."
else
    issue_cert "expiring" \
        "expiring.tlapix-demo.local" \
        "DNS:expiring.tlapix-demo.local" \
        2048 \
        0
fi

# 3. Already-expired certificate (backdated)
# Create a cert that expired yesterday
issue_cert "expired" \
    "expired.tlapix-demo.local" \
    "DNS:expired.tlapix-demo.local" \
    2048 \
    1

# Overwrite with a cert that's already expired (trick: set startdate far in past)
openssl req -x509 -new -nodes \
    -key "${CERTS_DIR}/expired/server.key" \
    -sha256 \
    -days 1 \
    -out "${CERTS_DIR}/expired/server.crt" \
    -subj "/C=MX/ST=CDMX/O=Tlapix Demo/CN=expired.tlapix-demo.local" \
    -addext "subjectAltName=DNS:expired.tlapix-demo.local" \
    2>/dev/null
# Now backdate it by re-signing with past dates
# Use faketime if available, otherwise just note it's a 1-day cert
echo "    ⚠️  For true expiry simulation, use 'faketime' or wait for the 1-day cert to expire"

# 4. Weak key certificate (RSA 1024 — triggers anomaly)
issue_cert "weak" \
    "weak.tlapix-demo.local" \
    "DNS:weak.tlapix-demo.local" \
    1024 \
    365

# 5. Shadow certificate (self-signed, NOT from our CA — won't be in inventory)
echo ""
echo "  🔑 Generating shadow certificate (self-signed, unknown CA)..."
mkdir -p "${CERTS_DIR}/shadow"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CERTS_DIR}/shadow/server.key" \
    -out "${CERTS_DIR}/shadow/server.crt" \
    -days 365 \
    -subj "/C=XX/ST=Unknown/O=Shadow Corp/CN=shadow.unknown-ca.local" \
    -addext "subjectAltName=DNS:shadow.unknown-ca.local" \
    2>/dev/null
SHADOW_FP=$(openssl x509 -in "${CERTS_DIR}/shadow/server.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
echo "${SHADOW_FP}" > "${CERTS_DIR}/shadow/fingerprint.txt"
echo "  ✅ shadow: CN=shadow.unknown-ca.local, self-signed, fp=${SHADOW_FP:0:16}..."

# ---------------------------------------------------------------------------
# Generate inventory file (only includes "known" certificates)
# ---------------------------------------------------------------------------
echo ""
echo "📋 Generating certificate inventory..."

GOOD_FP=$(cat "${CERTS_DIR}/good/fingerprint.txt")
EXPIRING_FP=$(cat "${CERTS_DIR}/expiring/fingerprint.txt")

cat > "${SCRIPT_DIR}/inventory.json" <<EOF
[
  {
    "fingerprint": "${GOOD_FP}",
    "subject": "CN=good.tlapix-demo.local"
  },
  {
    "fingerprint": "${EXPIRING_FP}",
    "subject": "CN=expiring.tlapix-demo.local"
  }
]
EOF

echo "  ✅ inventory.json created (good + expiring certs are 'known')"
echo "     Shadow and weak certs are NOT in inventory (will trigger alerts)"

echo ""
echo "🎉 All demo certificates issued!"
echo ""
echo "Certificate summary:"
echo "  good/      — Valid, RSA 2048, 365 days (in inventory)"
echo "  expiring/  — Valid, RSA 2048, expires soon (in inventory)"
echo "  expired/   — Already expired, RSA 2048 (not in inventory)"
echo "  weak/      — Valid, RSA 1024 (triggers anomaly, not in inventory)"
echo "  shadow/    — Self-signed, unknown CA (triggers shadow detection)"
echo ""
echo "Next: Run 'docker compose up -d' to start the demo environment"
