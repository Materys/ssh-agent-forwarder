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
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AgentMsgType is the SSH agent message type (1 byte)
type AgentMsgType byte

// AgentMsgParser is a function that parses a message payload and returns a human-readable string
type AgentMsgParser func([]byte) string

// SSH Agent Protocol Message Types
// Based on IETF draft-miller-ssh-agent-00 and OpenSSH implementation
// Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent
// Reference: https://raw.githubusercontent.com/openssh/openssh-portable/master/authfd.h
// Reference: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-00
//
// Note: OpenSSH uses both SSH_AGENTC_* and SSH2_AGENTC_* prefixes in their codebase.
// This implementation follows the SSH2 protocol (RFC 4252) naming convention.

// Request Messages (Client to Agent) - Standard Protocol
const (
	SSH_AGENTC_REQUEST_IDENTITIES            = 11 // List available identities
	SSH_AGENTC_SIGN_REQUEST                  = 13 // Sign authentication challenge
	SSH_AGENTC_ADD_IDENTITY                  = 17 // Add identity to agent
	SSH_AGENTC_REMOVE_IDENTITY               = 18 // Remove identity from agent
	SSH_AGENTC_REMOVE_ALL_IDENTITIES         = 19 // Remove all identities
	SSH_AGENTC_ADD_SMARTCARD_KEY             = 20 // Add smartcard key
	SSH_AGENTC_REMOVE_SMARTCARD_KEY          = 21 // Remove smartcard key
	SSH_AGENTC_LOCK                          = 22 // Lock agent
	SSH_AGENTC_UNLOCK                        = 23 // Unlock agent
	SSH_AGENTC_ADD_ID_CONSTRAINED            = 25 // Add constrained identity
	SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26 // Add constrained smartcard key
	SSH_AGENTC_EXTENSION                     = 27 // Extension mechanism
)

// Request Messages - OpenSSH Extensions
const (
	SSH_AGENTC_SESSION_BIND       = 0x1b // Session binding extension
	SSH_AGENT_CONSTRAIN_EXTENSION = 0xff // Constraint extension
)

// Response Messages (Agent to Client)
const (
	SSH_AGENT_FAILURE           = 5  // Operation failed
	SSH_AGENT_SUCCESS           = 6  // Operation succeeded
	SSH_AGENT_IDENTITIES_ANSWER = 12 // List of identities
	SSH_AGENT_SIGN_RESPONSE     = 14 // Signed response
	SSH_AGENT_EXTENSION_FAILURE = 28 // Extension failed
)

// SECURITY NOTE: The whitelist below intentionally excludes dangerous SSH agent operations.
// In a forwarding scenario, we MUST NOT allow any operations that can:
// 1. Modify the agent state (add/remove keys)
// 2. Lock/unlock the agent
// 3. Access extension mechanisms
// 4. Remove all identities (catastrophic data loss)
//
// The minimal safe set for authentication forwarding is:
// - SSH_AGENTC_REQUEST_IDENTITIES (11): List available keys for authentication
// - SSH_AGENTC_SIGN_REQUEST (13): Sign authentication challenges
//
// To enable additional operations in trusted environments, uncomment the specific
// operations needed and recompile. NEVER enable all operations without careful
// consideration of the security implications.

// Message name registry for request and response types
var (
	SshAgentResponseWhitelist = map[AgentMsgType]string{
		SSH_AGENT_FAILURE:           "SSH_AGENT_FAILURE",
		SSH_AGENT_SUCCESS:           "SSH_AGENT_SUCCESS",
		SSH_AGENT_IDENTITIES_ANSWER: "SSH_AGENT_IDENTITIES_ANSWER",
		SSH_AGENT_SIGN_RESPONSE:     "SSH_AGENT_SIGN_RESPONSE",
		SSH_AGENT_EXTENSION_FAILURE: "SSH_AGENT_EXTENSION_FAILURE",
	}

	SshAgentRequestWhitelist = map[AgentMsgType]string{
		SSH_AGENTC_REQUEST_IDENTITIES: "SSH_AGENTC_REQUEST_IDENTITIES",
		SSH_AGENTC_SIGN_REQUEST:       "SSH_AGENTC_SIGN_REQUEST",
		// DANGEROUS OPERATIONS - COMMENTED OUT FOR SECURITY
		// SSH_AGENTC_ADD_IDENTITY:           "SSH_AGENTC_ADD_IDENTITY",           // Allows adding new keys to agent
		// SSH_AGENTC_REMOVE_IDENTITY:        "SSH_AGENTC_REMOVE_IDENTITY",        // Allows removing specific keys
		// SSH_AGENTC_REMOVE_ALL_IDENTITIES:  "SSH_AGENTC_REMOVE_ALL_IDENTITIES",  // DELETES ALL KEYS FROM AGENT
		// SSH_AGENTC_ADD_SMARTCARD_KEY:      "SSH_AGENTC_ADD_SMARTCARD_KEY",      // Allows adding smartcard keys
		// SSH_AGENTC_REMOVE_SMARTCARD_KEY:   "SSH_AGENTC_REMOVE_SMARTCARD_KEY",   // Allows removing smartcard keys
		// SSH_AGENTC_LOCK:                  "SSH_AGENTC_LOCK",                  // Can lock the agent
		// SSH_AGENTC_UNLOCK:                "SSH_AGENTC_UNLOCK",                // Can unlock the agent (brute force risk)
		// SSH_AGENTC_ADD_ID_CONSTRAINED:     "SSH_AGENTC_ADD_ID_CONSTRAINED",     // Allows adding constrained keys
		// SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED", // Allows adding constrained smartcard keys
		// SSH_AGENTC_EXTENSION:             "SSH_AGENTC_EXTENSION",             // Extension mechanism (security risk)
		// OpenSSH Extensions (commented for security)
		// SSH_AGENTC_SESSION_BIND:          "SSH_AGENTC_SESSION_BIND",          // Session binding extension
		// SSH_AGENT_CONSTRAIN_EXTENSION:     "SSH_AGENT_CONSTRAIN_EXTENSION",     // Constraint extension
	}

	sshAgentMsgNames = func() map[AgentMsgType]string {
		m := make(map[AgentMsgType]string)
		for k, v := range SshAgentRequestWhitelist {
			m[k] = v
		}
		for k, v := range SshAgentResponseWhitelist {
			m[k] = v
		}
		return m
	}()
)

var PACKET_SSH_AGENT_FAILURE = []byte{0, 0, 0, 1, 5} // SSH_AGENT_FAILURE message

// Parser registry for extensibility
var (
	reqParsers  = map[AgentMsgType]AgentMsgParser{}
	respParsers = map[AgentMsgType]AgentMsgParser{}
)

// RegisterAgentRequestParser allows adding custom request parsers
func RegisterAgentRequestParser(msgType AgentMsgType, parser AgentMsgParser) {
	reqParsers[msgType] = parser
}

// RegisterAgentResponseParser allows adding custom response parsers
func RegisterAgentResponseParser(msgType AgentMsgType, parser AgentMsgParser) {
	respParsers[msgType] = parser
}

// DumpAgentMessage returns a human-readable string for an SSH agent message (generic fallback)
func DumpAgentMessage(msg []byte) string {
	if len(msg) < 5 {
		return "[malformed agent message]"
	}
	msgType := AgentMsgType(msg[4])
	msgName := GetMsgTypeName(msgType)

	if msgName == "UNKNOWN" {
		// For unknown types, match test expectation
		return fmt.Sprintf("Unknown agent message type: %d", msg[4])
	}
	// For test compatibility, return just the name for known types
	return msgName
}

// ParseAgentRequest parses and pretty-prints an SSH agent request
func ParseAgentRequest(req []byte) string {
	if len(req) < 5 {
		return "[Malformed: too short]"
	}
	msgType := AgentMsgType(req[4])
	msgName := GetMsgTypeName(msgType)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Type: 0x%02x (%s)\n", msgType, msgName))
	if parser, ok := reqParsers[msgType]; ok {
		b.WriteString(parser(req[5:]))
	} else {
		b.WriteString(defaultRequestParser(msgType, req[5:]))
	}
	return b.String()
}

// ParseAgentResponse parses and pretty-prints an SSH agent response
func ParseAgentResponse(resp []byte) string {
	if len(resp) < 5 {
		return "[Malformed: too short]"
	}
	msgType := AgentMsgType(resp[4])
	msgName := GetMsgTypeName(msgType)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Type: 0x%02x (%s)\n", msgType, msgName))
	if parser, ok := respParsers[msgType]; ok {
		b.WriteString(parser(resp[5:]))
	} else {
		b.WriteString(defaultResponseParser(msgType, resp[5:]))
	}
	return b.String()
}

func GetMsgTypeName(msgType AgentMsgType) string {
	if name, ok := sshAgentMsgNames[msgType]; ok {
		return name
	}
	return "UNKNOWN"
}

func GetMsgType(msg []byte) (AgentMsgType, error) {
	if len(msg) < 5 {
		return 0, fmt.Errorf("message too short")
	}
	return AgentMsgType(msg[4]), nil
}

func IsMsgTypeAllowed(msgType AgentMsgType, allowedTypes map[AgentMsgType]string) bool {
	_, ok := allowedTypes[msgType]
	return ok
}

// Default request parser for known types
func defaultRequestParser(msgType AgentMsgType, data []byte) string {
	switch msgType {
	case 11:
		return "Request: List all identities\n"
	case 13:
		return parseSignRequest(data)
	case 17, 20:
		return "Request: Add identity (key)\n"
	case 18:
		return "Request: Remove identity (key)\n"
	case 19:
		return "Request: Remove all identities\n"
	case 23:
		return parseLockUnlock(data, true)
	case 24:
		return parseLockUnlock(data, false)
	default:
		return fmt.Sprintf("Raw payload: %x\n", data)
	}
}

// Default response parser for known types
func defaultResponseParser(msgType AgentMsgType, data []byte) string {
	switch msgType {
	case 12:
		return parseIdentitiesAnswer(data)
	case 14:
		return parseSignResponse(data)
	case 6:
		return "Success\n"
	case 5:
		return "Failure\n"
	default:
		return fmt.Sprintf("Raw payload: %x\n", data)
	}
}

// ParseAgentRequestLength parses the SSH agent request length
func ParseAgentRequestLength(msg []byte) (int, error) {
	if len(msg) < 4 {
		return 0, fmt.Errorf("message too short")
	}
	return int(binary.BigEndian.Uint32(msg[:4])), nil
}

// ParseSSHString parses an SSH string (4-byte length + bytes)
func ParseSSHString(data []byte) (out, rest []byte, ok bool) {
	if len(data) < 4 {
		return nil, data, false
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	if len(data) < 4+n {
		return nil, data, false
	}
	return data[4 : 4+n], data[4+n:], true
}

// --- Internal helpers for default parsers ---

func parseSignRequest(data []byte) string {
	var b strings.Builder
	keyBlob, rest, ok := ParseSSHString(data)
	if !ok {
		return "Malformed sign request (key_blob)\n"
	}
	b.WriteString(fmt.Sprintf("Key blob: %x\n", keyBlob))
	sigData, rest, ok := ParseSSHString(rest)
	if !ok {
		return "Malformed sign request (data)\n"
	}
	b.WriteString(fmt.Sprintf("Data to sign: %x\n", sigData))
	if len(rest) < 4 {
		b.WriteString("Malformed sign request (flags)\n")
		return b.String()
	}
	flags := binary.BigEndian.Uint32(rest[:4])
	b.WriteString(fmt.Sprintf("Flags: 0x%x\n", flags))
	return b.String()
}

func parseLockUnlock(data []byte, isLock bool) string {
	pass, _, ok := ParseSSHString(data)
	if !ok {
		return "Malformed lock/unlock request\n"
	}
	if isLock {
		return fmt.Sprintf("Lock agent with passphrase: %q\n", string(pass))
	}
	return fmt.Sprintf("Unlock agent with passphrase: %q\n", string(pass))
}

func parseIdentitiesAnswer(data []byte) string {
	var b strings.Builder
	if len(data) < 4 {
		return "Malformed identities answer (nkeys)\n"
	}
	nkeys := int(binary.BigEndian.Uint32(data[:4]))
	b.WriteString(fmt.Sprintf("Number of identities: %d\n", nkeys))
	off := 4
	for i := 0; i < nkeys; i++ {
		key, rest, ok := ParseSSHString(data[off:])
		if !ok {
			b.WriteString("Malformed key blob\n")
			break
		}
		comment, rest2, ok := ParseSSHString(rest)
		if !ok {
			b.WriteString("Malformed comment\n")
			break
		}
		b.WriteString(fmt.Sprintf("Identity %d:\n  Key blob: %x\n  Comment: %q\n", i+1, key, comment))
		off = len(data) - len(rest2)
	}
	return b.String()
}

func parseSignResponse(data []byte) string {
	sig, _, ok := ParseSSHString(data)
	if !ok {
		return "Malformed sign response\n"
	}
	return fmt.Sprintf("Signature: %x\n", sig)
}

func fingerprintSHA256(keyBlob []byte) (string, error) {
	pub, err := ssh.ParsePublicKey(keyBlob)
	if err != nil {
		return "", err
	}

	var fp string

	if cert, ok := pub.(*ssh.Certificate); ok {
		fp = ssh.FingerprintSHA256(cert.Key)
	} else {
		fp = ssh.FingerprintSHA256(pub)
	}

	return strings.TrimPrefix(fp, "SHA256:"), nil
}

func FilterIdentitiesInAgentResponse(resp []byte, allowedIdentities []string) ([]byte, error) {
	if len(allowedIdentities) == 0 {
		return resp, nil
	}

	// Need at least packet length
	if len(resp) < 4 {
		return nil, fmt.Errorf("short agent response")
	}

	msgType := resp[4]
	if msgType != 12 { // SSH2_AGENT_IDENTITIES_ANSWER
		return resp, nil
	}

	pktLen := int(binary.BigEndian.Uint32(resp[:4]))
	if len(resp) < 4+pktLen {
		return nil, fmt.Errorf("incomplete agent packet")
	}

	payload := resp[4 : 4+pktLen]
	tail := resp[4+pktLen:]

	if len(payload) < 5 {
		return nil, fmt.Errorf("malformed agent payload")
	}

	nkeys := binary.BigEndian.Uint32(payload[1:5])
	data := payload[5:]

	// Normalize allowed fingerprints
	allowed := make(map[string]bool, len(allowedIdentities))
	for _, a := range allowedIdentities {
		a = strings.TrimSpace(strings.TrimPrefix(a, "SHA256:"))
		allowed[a] = true
	}

	var filteredEntries [][]byte

	for i := uint32(0); i < nkeys; i++ {
		keyBlob, rest, ok := ParseSSHString(data)
		if !ok {
			return nil, fmt.Errorf("malformed key blob at index %d", i)
		}

		comment, rest2, ok := ParseSSHString(rest)
		if !ok {
			return nil, fmt.Errorf("malformed comment at index %d", i)
		}

		fp, err := fingerprintSHA256(keyBlob)
		if err != nil {
			return nil, fmt.Errorf("fingerprint failed at index %d: %v", i, err)
		}

		if allowed[fp] {
			// Rebuild entry: string keyBlob || string comment
			entry := make([]byte, 4+len(keyBlob)+4+len(comment))
			binary.BigEndian.PutUint32(entry[0:4], uint32(len(keyBlob)))
			copy(entry[4:], keyBlob)
			binary.BigEndian.PutUint32(entry[4+len(keyBlob):8+len(keyBlob)], uint32(len(comment)))
			copy(entry[8+len(keyBlob):], comment)

			filteredEntries = append(filteredEntries, entry)
			fmt.Println("MATCH")
		}

		data = rest2
	}

	if len(data) != 0 {
		return nil, fmt.Errorf("identity parsing desync: %d leftover bytes", len(data))
	}

	keysSize := 0
	for _, e := range filteredEntries {
		keysSize += len(e)
	}

	newPayloadLen := 1 + 4 + keysSize
	newResp := make([]byte, 4+newPayloadLen)

	binary.BigEndian.PutUint32(newResp[0:4], uint32(newPayloadLen))
	newResp[4] = 12
	binary.BigEndian.PutUint32(newResp[5:9], uint32(len(filteredEntries)))

	// Copy entries
	off := 9
	for _, e := range filteredEntries {
		copy(newResp[off:], e)
		off += len(e)
	}

	return append(newResp, tail...), nil
}

func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}
