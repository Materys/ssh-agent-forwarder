#!/bin/bash
set -x
set -e

DESTDIR=${DESTDIR:-.}

targets=(arm64 arm amd64)
executables=(ssh-agent-forwarder ssh-agent-endpoint ssh-platform)

for target in ${targets[@]}; do
for executable in ${executables[@]}; do
GOOS=linux GOARCH=$target go build -o "${DESTDIR}/$executable-$target" ./cmd/$executable
done
done

echo "Build complete. Executables are located in $DESTDIR"