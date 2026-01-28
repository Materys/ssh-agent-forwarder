#!/bin/bash

set -e
set -x

BASEDIR=..

UUID="testuuid"
TOKEN="testtoken"
ENDPOINT_UUID="$UUID"
ENDPOINT_TOKEN="$TOKEN"

PLATFORM_URL="localhost:4242"
CERT=platform.crt
KEY=platform.key

# Source common Redis setup
source ./redis_test_setup.sh

# Reset and initialize tokens for this test

docker exec $REDIS_CONTAINER redis-cli FLUSHALL

docker exec $REDIS_CONTAINER redis-cli set token:$UUID $TOKEN

docker exec $REDIS_CONTAINER redis-cli set token:$ENDPOINT_UUID $ENDPOINT_TOKEN

# Start a local ssh-agent and export its socket for the forwarder

eval $(ssh-agent -s)
export FORWARDER_SSH_AUTH_SOCK="$SSH_AUTH_SOCK"
echo "Started local ssh-agent for forwarder: $FORWARDER_SSH_AUTH_SOCK"

# Add a test key to the agent
ssh-add -D >/dev/null 2>&1
ssh-keygen -t ed25519 -N "" -f /tmp/testkey -C "testkey" <<<y >/dev/null 2>&1
ssh-add /tmp/testkey

# Start the 3 components

echo "\n=== Restarting platform, forwarder, and endpoint for end-to-end test ==="
REDIS_ADDRESS=localhost:$REDIS_PORT CERT_PATH=$CERT KEY=$KEY PLATFORM_URL=$PLATFORM_URL go run ${BASEDIR}/cmd/ssh-platform/main.go > platform_end2end.log 2>&1 &
PLATFORM_PID=$!
sleep 1
SSH_AUTH_SOCK="$FORWARDER_SSH_AUTH_SOCK" KEY_OWNER_UUID=$UUID SSH_AGENT_TOKEN=$TOKEN REDIS_ADDRESS=localhost:$REDIS_PORT CERT_PATH=$CERT KEY=$KEY PLATFORM_URL=$PLATFORM_URL go run ${BASEDIR}/cmd/ssh-agent-forwarder/main.go > forwarder_end2end.log 2>&1 &
FORWARDER_PID=$!
sleep 1
KEY_OWNER_UUID=$ENDPOINT_UUID SSH_AGENT_TOKEN=$ENDPOINT_TOKEN PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT ENDPOINT_UUID=$ENDPOINT_UUID ENDPOINT_TOKEN=$ENDPOINT_TOKEN go run ${BASEDIR}/cmd/ssh-agent-endpoint/main.go > endpoint_end2end.log 2>&1 &
ENDPOINT_PID=$!
sleep 2

cleanup() {
  kill $PLATFORM_PID || echo "kill $PLATFORM_PID failed"
  kill $FORWARDER_PID || echo "kill $FORWARDER_PID failed"
  kill $ENDPOINT_PID || echo "kill $ENDPOINT_PID failed"
  ssh-agent -k >/dev/null 2>&1
  rm -f /tmp/testkey /tmp/testkey.pub
}

trap cleanup ERR

# Now start the end-to-end agent forwarding test
echo "\n=== Testing end-to-end agent forwarding ==="

# Wait for endpoint socket to be ready
for i in {1..10}; do
  ENDPOINT_SOCK=$(find /run/user/$(id -u) -name 'agent-endpoint.sock' 2>/dev/null | head -n1)
  if [ -S "$ENDPOINT_SOCK" ]; then
    break
  fi
  sleep 1
done
if [ ! -S "$ENDPOINT_SOCK" ]; then
    echo "[FAIL] Could not find endpoint agent socket!"
    # Print all logs for debugging
    for log in platform_end2end.log forwarder_end2end.log endpoint_end2end.log; do
    echo "\n=== $log ==="
    cat $log
    echo "\n"
    done
  exit 1
fi

# Run ssh-add -l using the endpoint socket (with 5s timeout)
export SSH_AUTH_SOCK="$ENDPOINT_SOCK"
echo "Using SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
set +e
SSH_ADD_OUTPUT=$(timeout 5s ssh-add -l 2>&1)
SSH_ADD_EXIT=$?
echo "Output of ssh-add -l via endpoint socket:"
echo "$SSH_ADD_OUTPUT"
echo "Exit code: $SSH_ADD_EXIT"


# Check for the test key's fingerprint
if echo "$SSH_ADD_OUTPUT" | grep -q "testkey"; then
  echo "[SUCCESS] Agent forwarding end-to-end is working."
else
  echo "[FAIL] Agent forwarding did not work as expected."
  exit 1
fi

# Keep processes alive for a few seconds to allow manual inspection or further tests
sleep 5

# Cleanup
cleanup