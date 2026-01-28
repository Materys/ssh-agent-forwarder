#!/bin/bash
# Usage: ./gen_cert.sh <hostname> [certfile] [keyfile]
# Example: ./gen_cert.sh myhost.local myhost.crt myhost.key

set -e

HOSTNAME=${1:-localhost}
CERTFILE=${2:-$HOSTNAME.crt}
KEYFILE=${3:-$HOSTNAME.key}
DESTDIR=${DESTDIR:-.}

#if the HOSTNAME is an IP, set the IP SAN
if [[ $HOSTNAME =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN="IP:$HOSTNAME"
else
  SAN="DNS:$HOSTNAME"
fi

if [ -f "$CERTFILE" ] && [ -f "$KEYFILE" ]; then
  echo "Certificate and key already exist: $CERTFILE $KEYFILE"
  exit 0
fi

echo "Generating self-signed certificate for $HOSTNAME..."
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${DESTDIR}/$KEYFILE" -out "${DESTDIR}/$CERTFILE" -days 365 \
  -subj "/CN=$HOSTNAME" \
  -addext "subjectAltName=$SAN"

echo "Generated $CERTFILE and $KEYFILE for $HOSTNAME in $DESTDIR"
