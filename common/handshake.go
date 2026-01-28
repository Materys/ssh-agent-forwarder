// ssh-agent-forwarder, a code to authenticate ssh connections using an agent on a different machine
// Copyright (C) 2026 Riccardo Bertossa (MATERYS SRL), Sebastiano Bisacchi (MATERYS SRL)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package common

import (
	"crypto/rand"
	"fmt"
	"io"
)

// DoHandshake performs the client handshake (forwarder/endpoint):
// Sends hello (with role), waits for ack, validates ack nonce. Returns ack message and nonce.
func DoHandshake(stream io.ReadWriter, uuid, role, token string, vinfo *VersionInfoData) (*ProtocolMessage, string, error) {
	nonce := randomHex(16)
	helloMsg, _ := NewHelloMessage(uuid, role, nonce, token, vinfo.Version)
	b, _ := helloMsg.Marshal(token)
	if err := WriteLPMessage(stream, b); err != nil {
		return nil, "", fmt.Errorf("failed to send hello: %w", err)
	}
	ackBuf, err := ReadLPMessage(stream, MaxAgentMessageSize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read ack: %w", err)
	}
	ackMsg, err := ValidateAckMessage(ackBuf, func(uuid string) (string, error) { return token, nil })
	if err != nil {
		return nil, "", fmt.Errorf("ack validation failed: %w", err)
	}

	// Check versions compatibility
	err = vinfo.Validate(ackMsg.Version)
	if err != nil {
		return nil, "", fmt.Errorf("ack validation failed: outdated agent-forwarder client (v%d), please update to the latest version", ackMsg.Version)
	}

	if ackMsg.Nonce != nonce {
		return nil, "", fmt.Errorf("ack nonce mismatch: got %q, want %q", ackMsg.Nonce, nonce)
	}
	return ackMsg, nonce, nil
}

// HandleHandshake performs the server handshake (platform):
// Reads hello, validates, sends ack. Returns hello message.
func HandleHandshake(stream io.ReadWriter, tokenLookup func(uuid string) (string, error), expectedRole []string, vinfo *VersionInfoData) (*ProtocolMessage, error) {
	helloBuf, err := ReadLPMessage(stream, MaxAgentMessageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read hello: %w", err)
	}
	helloMsg, err := ValidateHelloMessage(helloBuf, tokenLookup)
	if err != nil {
		return nil, fmt.Errorf("handshake validation failed: %w", err)
	}

	// Validate role
	validrole := false
	// Debug: print received role and allowed roles
	fmt.Printf("[DEBUG handshake] Received role: '%s', allowed roles: %v\n", helloMsg.Role, expectedRole)
	for _, role := range expectedRole {
		fmt.Printf("[DEBUG handshake] Comparing received role '%s' to allowed role '%s'\n", helloMsg.Role, role)
		if helloMsg.Role == role {
			// Valid role found, continue
			validrole = true
			break
		}
	}
	if len(expectedRole) == 0 {
		// If no specific roles are expected, any role is valid
		validrole = true
	}
	// If we reach here, no valid role was found
	if !validrole {
		return nil, fmt.Errorf("unexpected role: got %q, want %v", helloMsg.Role, expectedRole)
	}

	// Check version compatibility
	err = vinfo.Validate(helloMsg.Version)
	if err != nil {
		return nil, fmt.Errorf("handshake validation failed: unsupported %s version %d", helloMsg.Role, helloMsg.Version)
	}

	token, _ := tokenLookup(helloMsg.UUID)
	ackMsg, err := NewAckMessage(helloMsg.UUID, helloMsg.Nonce, token, vinfo.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create ack: %w", err)
	}
	ackBytes, err := ackMsg.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ack: %w", err)
	}
	if err := WriteLPMessage(stream, ackBytes); err != nil {
		return nil, fmt.Errorf("failed to write ack: %w", err)
	}
	return helloMsg, nil
}

// randomHex returns a random hex string of n bytes.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
