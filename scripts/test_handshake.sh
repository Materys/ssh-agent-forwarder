#!/bin/bash

set -e

BASEDIR=..

# Source common Redis setup
source ./redis_test_setup.sh

REDIS_CONTAINER="agent-forwarder-redis"
REDIS_PORT=6379
REDIS_IMAGE="redis:7-alpine"
UUID="testuuid"
TOKEN="testtoken"

PLATFORM_URL="localhost:4242"
CERT=platform.crt
KEY=platform.key

# Generate self-signed cert with SAN if not present
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Generating self-signed TLS certificate with SAN..."
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost"
fi

# 1. Ensure Redis is running
if ! docker ps --format '{{.Names}}' | grep -q "^$REDIS_CONTAINER$"; then
    echo "Starting Redis container..."
    docker run --name $REDIS_CONTAINER -p $REDIS_PORT:6379 -d $REDIS_IMAGE
else
    echo "Redis container already running."
fi

# 2. Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
until docker exec $REDIS_CONTAINER redis-cli ping | grep -q PONG; do
    sleep 0.5
done

# 3. Set the token in Redis (same UUID and TOKEN for both forwarder and endpoint)
echo "Setting token in Redis for UUID $UUID (used by both forwarder and endpoint)..."
docker exec $REDIS_CONTAINER redis-cli set token:$UUID $TOKEN

# 4. Start the platform
echo "Starting platform..."
REDIS_ADDRESS=localhost:$REDIS_PORT CERT_PATH=$CERT KEY=$KEY PLATFORM_URL=$PLATFORM_URL go run ${BASEDIR}/cmd/ssh-platform/main.go > platform.log 2>&1 &
PLATFORM_PID=$!
sleep 1

# 5. Start the forwarder (using KEY_OWNER_UUID and SSH_AGENT_TOKEN)
echo "Starting forwarder..."
KEY_OWNER_UUID=$UUID SSH_AGENT_TOKEN=$TOKEN PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT go run ${BASEDIR}/cmd/ssh-agent-forwarder/main.go > forwarder.log 2>&1 &
FORWARDER_PID=$!
sleep 1

# 6. Start the endpoint (using same UUID and TOKEN)
echo "Starting endpoint..."
KEY_OWNER_UUID=$UUID SSH_AGENT_TOKEN=$TOKEN PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT go run ${BASEDIR}/cmd/ssh-agent-endpoint/main.go > endpoint.log 2>&1 &
ENDPOINT_PID=$!

# 7. Wait and show logs
sleep 2
echo "=== Platform log ==="
cat platform.log
echo "=== Forwarder log ==="
cat forwarder.log
echo "=== Endpoint log ==="
cat endpoint.log

# 8. Cleanup
kill $PLATFORM_PID $FORWARDER_PID $ENDPOINT_PID 2>/dev/null || true
# Also kill any process still using port 4242 (platform) or 4343 (forwarder) just in case
tmp_pid=$(lsof -ti udp:4242 || lsof -ti tcp:4242 || lsof -ti udp:4343 || lsof -ti tcp:4343)
if [ -n "$tmp_pid" ]; then
  kill $tmp_pid 2>/dev/null || true
fi

# Optionally stop redis container (uncomment if you want to stop it)
# docker stop $REDIS_CONTAINER

echo "Handshake test complete."

echo "\n=== Testing handshake failure with wrong token ==="
WRONG_TOKEN="wrongtoken"
echo "Setting wrong token in Redis for UUID $UUID..."
docker exec $REDIS_CONTAINER redis-cli set token:$UUID $TOKEN
# Start endpoint with wrong token
KEY_OWNER_UUID=$UUID SSH_AGENT_TOKEN=$WRONG_TOKEN PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT go run ${BASEDIR}/cmd/ssh-agent-endpoint/main.go > endpoint_wrong_token.log 2>&1 &
WRONG_ENDPOINT_PID=$!
sleep 2
echo "=== Endpoint log (wrong token) ==="
cat endpoint_wrong_token.log
kill $WRONG_ENDPOINT_PID 2>/dev/null || true

# === Start platform for concurrency test ===
echo "\n=== Starting platform for concurrency test ==="
REDIS_ADDRESS=localhost:$REDIS_PORT CERT_PATH=$CERT KEY=$KEY PLATFORM_URL=$PLATFORM_URL go run ${BASEDIR}/cmd/ssh-platform/main.go > platform_conc.log 2>&1 &
PLATFORM_CONC_PID=$!
sleep 2

echo "\n=== Testing concurrency with multiple forwarders and endpoints ==="
ACTORS=3
SUCCESS=0
FAIL=0
PIDS=()
UUIDS=()
TOKENS=()

# Generate unique UUIDs and tokens for each actor
for i in $(seq 1 $ACTORS); do
  UUIDS+=("uuid_$i")
  TOKENS+=("token_$i")
  echo "Setting token in Redis for UUID uuid_$i ..."
  docker exec $REDIS_CONTAINER redis-cli set token:uuid_$i token_$i > /dev/null
  sleep 0.1
  # Start forwarder
  echo "Starting forwarder $i ..."
  KEY_OWNER_UUID=uuid_$i SSH_AGENT_TOKEN=token_$i PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT go run ${BASEDIR}/cmd/ssh-agent-forwarder/main.go > forwarder_$i.log 2>&1 &
  PIDS+=("$!")
  # Start endpoint
  echo "Starting endpoint $i ..."
  KEY_OWNER_UUID=uuid_$i SSH_AGENT_TOKEN=token_$i PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT go run ${BASEDIR}/cmd/ssh-agent-endpoint/main.go > endpoint_$i.log 2>&1 &
  PIDS+=("$!")
done

sleep 3

# Check logs for successful handshakes
for i in $(seq 1 $ACTORS); do
  if grep -q "Handshake complete" forwarder_$i.log && grep -q "Handshake complete" endpoint_$i.log; then
    echo "[SUCCESS] Forwarder $i and Endpoint $i handshake succeeded."
    SUCCESS=$((SUCCESS+1))
  else
    echo "[FAIL] Forwarder $i or Endpoint $i handshake failed."
    FAIL=$((FAIL+1))
    echo "--- forwarder_$i.log ---"; cat forwarder_$i.log
    echo "--- endpoint_$i.log ---"; cat endpoint_$i.log
  fi
done

# Cleanup all actors
for pid in "${PIDS[@]}"; do
  kill $pid 2>/dev/null || true
done

# Test cross-authentication (wrong token for correct uuid)
echo "\n=== Testing cross-authentication (wrong token for correct uuid) ==="
WRONG=0
for i in $(seq 1 $ACTORS); do
  j=$(( (i % ACTORS) + 1 ))
  echo "Testing forwarder $i with token of $j (should fail) ..."
  KEY_OWNER_UUID=uuid_$i SSH_AGENT_TOKEN=token_$j PLATFORM_URL=$PLATFORM_URL CERT_PATH=$CERT go run ${BASEDIR}/cmd/ssh-agent-forwarder/main.go > forwarder_wrong_${i}_as_${j}.log 2>&1 &
  PIDS+=("$!")
done
sleep 2
for i in $(seq 1 $ACTORS); do
  j=$(( (i % ACTORS) + 1 ))
  if grep -q "Handshake complete" forwarder_wrong_${i}_as_${j}.log; then
    echo "[FAIL] Forwarder $i with token of $j should not succeed!"
    WRONG=$((WRONG+1))
    cat forwarder_wrong_${i}_as_${j}.log
  else
    echo "[SUCCESS] Forwarder $i with token of $j failed as expected."
  fi
done
for pid in "${PIDS[@]}"; do
  kill $pid 2>/dev/null || true
done

kill $PLATFORM_CONC_PID 2>/dev/null || true

echo "\n=== Concurrency/authentication test summary ==="
echo "Successful pairs: $SUCCESS, Failed pairs: $FAIL, Wrong-token failures: $((ACTORS-WRONG)), Wrong-token unexpected successes: $WRONG"

# End of handshake/concurrency/authentication tests
exit 0
