#!/usr/bin/env bash
# setup-ca.sh — Create a local Certificate Authority for demo purposes.
#
# Generates:
#   demo/certs/ca/ca.key       — CA private key
#   demo/certs/ca/ca.crt       — CA certificate (self-signed, 10 years)
#   demo/certs/ca/ca.srl       — Serial number file

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
CA_DIR="${CERTS_DIR}/ca"

echo "🔐 Setting up Tlapix Demo CA..."

# Create directory structure
mkdir -p "${CA_DIR}"
mkdir -p "${CERTS_DIR}/good"
mkdir -p "${CERTS_DIR}/expiring"
mkdir -p "${CERTS_DIR}/expired"
mkdir -p "${CERTS_DIR}/weak"
mkdir -p "${CERTS_DIR}/shadow"

# Generate CA private key (4096-bit RSA)
if [ ! -f "${CA_DIR}/ca.key" ]; then
    openssl genrsa -out "${CA_DIR}/ca.key" 4096
    echo "  ✅ CA private key generated"
else
    echo "  ⏭️  CA private key already exists, skipping"
fi

# Generate self-signed CA certificate (valid for 10 years)
if [ ! -f "${CA_DIR}/ca.crt" ]; then
    openssl req -x509 -new -nodes \
        -key "${CA_DIR}/ca.key" \
        -sha256 \
        -days 3650 \
        -out "${CA_DIR}/ca.crt" \
        -subj "/C=MX/ST=CDMX/O=Tlapix Demo/CN=Tlapix Demo Root CA"
    echo "  ✅ CA certificate generated"
else
    echo "  ⏭️  CA certificate already exists, skipping"
fi

# Initialize serial number
if [ ! -f "${CA_DIR}/ca.srl" ]; then
    echo "1000" > "${CA_DIR}/ca.srl"
fi

echo ""
echo "📁 CA files created in: ${CA_DIR}"
echo "   ca.key — Private key (keep secret!)"
echo "   ca.crt — CA certificate (distribute to clients)"
echo ""
echo "Next: Run ./issue-certs.sh to generate demo certificates"
