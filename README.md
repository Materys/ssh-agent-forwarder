# Agent Forwarder

## Overview

This project implements a secure SSH agent socket forwarding system using a microservice architecture. It consists of three main Go components:

- **Platform**: Multiuser central coordination service, exposes an API and manages agent connections.
- **Forwarder**: Connects to the local SSH agent and forwards requests to the platform.
- **Endpoint**: Connects to the platform and exposes the forwarded SSH agent to remote clients.

Redis is used for token management and coordination between the service that is supposed to stay in a public server (platform), and an external managing service (not implemented here).

## Architecture

- All components communicate over QUIC and use mutual TLS for security.
- Tokens and UUIDs are used for authentication and authorization, stored in Redis or in configuration files, or environment variables.
- The system is designed for containerized and cloud-native environments (e.g., Docker, Kubernetes).

## Running the System

### Prerequisites

- Go (>=1.18)
- Docker (for Redis)
- ssh-agent socket capable of performing authentication, to be forwarded

### Quick Start (Development)

1. **Start Redis**:
   ```sh
   docker run --name agent-forwarder-redis -p 6379:6379 -d redis:7-alpine
   ```
2. **Generate self-signed certificates** (if not present):
   ```sh
   openssl req -x509 -newkey rsa:4096 -keyout platform.key -out platform.crt -days 365 -nodes -subj "/CN=localhost"
   ```
3. **Set up tokens in Redis**:
   ```sh
   docker exec agent-forwarder-redis redis-cli set token:<UUID> <TOKEN>
   ```
4. **Run the platform**:
   ```sh
   REDIS_ADDRESS=localhost:6379 CERT_PATH=platform.crt KEY=platform.key PLATFORM_URL=localhost:4242 go run ../cmd/ssh-platform/main.go
   ```
5. **Run the forwarder**:
   ```sh
   KEY_OWNER_UUID=<UUID> SSH_AGENT_TOKEN=<TOKEN> PLATFORM_URL=localhost:4242 CERT_PATH=platform.crt go run ../cmd/ssh-agent-forwarder/main.go
   ```
6. **Run the endpoint**:
   ```sh
   KEY_OWNER_UUID=<UUID> SSH_AGENT_TOKEN=<TOKEN> PLATFORM_URL=localhost:4242 CERT_PATH=platform.crt go run ../cmd/ssh-agent-endpoint/main.go
   ```

### Automated Test

You can use the provided scripts in `servers/agent-forwarder/scripts/`:

- `test_handshake.sh`: Tests handshake and basic connectivity.
- `test_agent_forwarding.sh`: Runs an end-to-end agent forwarding test.

## Notice

```
    ssh-agent-forwarder, a code to authenticate ssh connections using an agent on a different machine
    Copyright (C) 2026 Riccardo Bertossa (MATERYS SRL), Sebastiano Bisacchi (MATERYS SRL)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
