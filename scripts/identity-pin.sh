#!/usr/bin/env bash
# Print the fingerprint used by peer_pin and authorized_peers from a public cert.
set -euo pipefail

if (( $# > 1 )); then
    echo "usage: scripts/identity-pin.sh [SYNC_ROOT]" >&2
    exit 2
fi

certificate="${1:-.}/.quicsync/identity.crt"
if [[ ! -f "$certificate" ]]; then
    echo "identity certificate not found: $certificate" >&2
    exit 1
fi

fingerprint=$(
    openssl x509 -inform DER -in "$certificate" -pubkey -noout |
        openssl pkey -pubin -outform DER |
        openssl dgst -sha256 -binary |
        od -An -tx1 -v |
        tr -d '[:space:]'
)
if [[ ! $fingerprint =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "cannot derive identity fingerprint: $certificate" >&2
    exit 1
fi
printf '%s\n' "$fingerprint"
