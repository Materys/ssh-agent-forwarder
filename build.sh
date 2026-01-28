#!/bin/bash
set -x
set -e

DESTDIR=${DESTDIR:-./bin}
mkdir -p "${DESTDIR}"
executables=(ssh-agent-endpoint ssh-platform)

for executable in ${executables[@]}; do
CGO_ENABLED=0 go build -o "${DESTDIR}/$executable" ./cmd/$executable
done

targets=(${AGENT_FORWARDER_BUILD_TARGETS})

mkdir -p "${DESTDIR}/agent-forwarder"

executable=ssh-agent-forwarder

for target in ${targets[@]}; do
    echo "Building for $target"
    OS=${target%/*}
    ARCH=${target#*/}
    GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -o "${DESTDIR}/agent-forwarder/${AGENT_FORWARDER_BUILD_NAME}-v$AGENT_FORWARDER_BUILD_VERSION-$OS-$ARCH" ./cmd/$executable
done

echo "Build complete. Executables are located in $DESTDIR"
