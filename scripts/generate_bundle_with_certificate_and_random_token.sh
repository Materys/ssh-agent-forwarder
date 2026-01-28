#!/bin/bash

set -e
set -x

# usage: $0 <platform_url> <redis_address> [redis_password] [token] [uuid]

PLATFORM_URL=${1:-"localhost:4242"}
shift || true
REDIS_ADDRESS=${1:-"localhost:6379"}
shift || true
REDIS_PASSWORD=${1:-""}
shift || true

#if token and uuid are not provided, use random values
if [ -z "$1" ]; then
  TOKEN=$(openssl rand -hex 16)
else
  TOKEN=$1
fi
shift || true
if [ -z "$1" ]; then
  UUID=$(openssl rand -hex 16)
else
  UUID=$1
fi

PLATFORM_HOSTNAME=$(echo "$PLATFORM_URL" | cut -d':' -f1)

export DESTDIR="${PLATFORM_HOSTNAME}"
mkdir -p "${DESTDIR}"

./make.sh

./gen_cert.sh "${PLATFORM_HOSTNAME}"



cat > "${DESTDIR}/ssh-agent-endpoint.yaml" << EOF
uuid: $UUID
token: $TOKEN
cert_path: ${PLATFORM_HOSTNAME}.crt
platform_url: $PLATFORM_URL
tls_server_name: $PLATFORM_HOSTNAME
EOF

cp "${DESTDIR}/ssh-agent-endpoint.yaml" "${DESTDIR}/ssh-agent-forwarder.yaml"

cat > "${DESTDIR}/ssh-platform.yaml" << EOF
platform_url: $PLATFORM_URL
cert_path: ${PLATFORM_HOSTNAME}.crt
key_path: ${PLATFORM_HOSTNAME}.key
redis_address: $REDIS_ADDRESS
redis_password: $REDIS_PASSWORD
tls_server_name: $PLATFORM_HOSTNAME
EOF

tar cvjf "${DESTDIR}.tar.bz2" "${DESTDIR}"