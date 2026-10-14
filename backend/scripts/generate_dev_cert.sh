#!/usr/bin/env bash
#
# Generate a self-signed certificate for the Syslog-over-TLS listener (task 6.2).
#
# Proposal Section 3, Table 11, NFR-04 (verbatim, in part):
#   "All web application, API, and external-service traffic must be encrypted
#   using TLS 1.2 or higher. Syslog over TLS on TCP port 6514 must be used
#   where supported."
#
# WHAT THIS PRODUCES, AND WHAT IT DOES NOT
# ----------------------------------------
# A self-signed certificate: the collector proves it holds the matching
# private key, and traffic on 6514 is encrypted. It does NOT prove the
# collector's identity to a sender, because no certificate authority vouches
# for it — a sender must either trust this exact certificate explicitly or
# skip verification.
#
# That is the correct trade-off for an isolated demo network with one known
# sender, and it is what Table 11's measurement column means by "verification
# of Syslog-over-TLS configuration where enabled" rather than an SSL Labs
# rating (SSL Labs scans public hostnames and cannot reach localhost).
#
# For a real deployment the collector would carry a CA-issued certificate and
# senders would verify it. Say so in the write-up rather than implying this
# setup is production-grade.
#
# USAGE
#   ./scripts/generate_dev_cert.sh                 # defaults below
#   THREATSENSE_CERT_DAYS=90 ./scripts/generate_dev_cert.sh
#
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${THREATSENSE_CERT_DIR:-$BACKEND_DIR/certs}"
DAYS="${THREATSENSE_CERT_DAYS:-825}"
CN="${THREATSENSE_CERT_CN:-threatsense-collector}"

# Subject Alternative Names. A modern TLS client ignores CN entirely and
# matches against SAN, so every address a sender might dial must appear here.
# 192.168.64.1 is the Mac's address on the UTM bridge — the address the Kali
# sandbox connects to.
SAN="${THREATSENSE_CERT_SAN:-DNS:localhost,IP:127.0.0.1,IP:192.168.64.1}"

CRT="$CERT_DIR/threatsense.crt"
KEY="$CERT_DIR/threatsense.key"

mkdir -p "$CERT_DIR"

if [ -f "$CRT" ] && [ -f "$KEY" ] && [ "${THREATSENSE_CERT_FORCE:-0}" != "1" ]; then
  echo "Certificate already exists:"
  echo "  $CRT"
  openssl x509 -in "$CRT" -noout -subject -dates -ext subjectAltName 2>/dev/null || true
  echo
  echo "Set THREATSENSE_CERT_FORCE=1 to regenerate."
  exit 0
fi

echo "Generating a self-signed certificate for Syslog-over-TLS"
echo "  dir  : $CERT_DIR"
echo "  CN   : $CN"
echo "  SAN  : $SAN"
echo "  days : $DAYS"
echo

# -nodes leaves the key unencrypted. The listener starts unattended and cannot
# prompt for a passphrase; an encrypted key would make it fail at boot.
openssl req -x509 -newkey rsa:4096 -sha256 \
  -days "$DAYS" \
  -nodes \
  -keyout "$KEY" \
  -out "$CRT" \
  -subj "/C=AU/ST=New South Wales/L=Sydney/O=ThreatSense/CN=$CN" \
  -addext "subjectAltName=$SAN" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  2>/dev/null

# The private key must not be world-readable. The listener runs as your user,
# so 600 is correct and anything looser is a finding waiting to happen.
chmod 600 "$KEY"
chmod 644 "$CRT"

echo "Created:"
echo "  $CRT"
echo "  $KEY  (mode 600)"
echo
openssl x509 -in "$CRT" -noout -subject -dates -ext subjectAltName

cat <<'NEXT'

NEXT STEPS

  1. Start the listener — it picks the pair up from settings automatically:

       python -m app.services.ingestion.listener

     Look for:  TLS  0.0.0.0:6514   RFC 5425 syslog-over-TLS (min=TLSv1_2, ...)

  2. Copy the CERTIFICATE ONLY to the sender (never the key):

       scp backend/certs/threatsense.crt kali@192.168.64.2:~/

  3. On Kali, point rsyslog at 6514 over TLS. See docs/syslog_tls_setup.md.

  4. NEVER commit certs/ — it is gitignored. Regenerate per machine.
NEXT
