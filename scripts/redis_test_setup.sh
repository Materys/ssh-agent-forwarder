#!/bin/bash

# Common Redis initialization for agent-forwarder tests
# Usage: source ./redis_test_setup.sh

REDIS_CONTAINER="agent-forwarder-redis"
REDIS_PORT=6379
REDIS_IMAGE="redis:7-alpine"


# 1. Ensure Redis is running or start it if not
if ! docker ps --format '{{.Names}}' | grep -q "^$REDIS_CONTAINER$"; then
    # If container exists but is stopped, start it
    if docker ps -a --format '{{.Names}}' | grep -q "^$REDIS_CONTAINER$"; then
        echo "Starting existing Redis container..."
        docker start $REDIS_CONTAINER
    else
        echo "Starting new Redis container..."
        docker run --name $REDIS_CONTAINER -p $REDIS_PORT:6379 -d $REDIS_IMAGE
    fi
else
    echo "Redis container already running."
fi

# 2. Wait for Redis to be ready
 echo "Waiting for Redis to be ready..."
until docker exec $REDIS_CONTAINER redis-cli ping | grep -q PONG; do
    sleep 0.5
done
