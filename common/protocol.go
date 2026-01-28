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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

var ERR_WRITE_LPMESSAGE_FAIL = 1
var ERR_READ_LPMESSAGE_FAIL = 2
var ERR_FORWARDER_NO_REPLY = 3

// WrapAgentPacket wraps an agent protocol payload in a ProtocolMessage (Type=3) with HMAC and a nonce, returns marshaled bytes
func WrapAgentPacket(payload []byte, uuid, nonce, token string) ([]byte, error) {
	msg := &ProtocolMessage{
		Type:      3, // agent-packet
		Timestamp: time.Now().Unix(),
		UUID:      uuid,
		Nonce:     nonce,
		Payload:   payload,
	}
	return msg.Marshal(token)
}

// UnwrapAndVerifyAgentPacket unmarshals and verifies HMAC and nonce for an agent protocol packet, returns payload and nonce if valid
// UnwrapAndVerifyAgentPacket unmarshals and verifies HMAC and optionally nonce for an agent protocol packet.
// If checkNonce is false, the nonce is not checked and always returned.
func UnwrapAndVerifyAgentPacket(msgBytes []byte, uuid, expectedNonce, token string, checkNonce bool) ([]byte, string, error) {
	msg, err := UnmarshalProtocolMessage(msgBytes, "")
	if err != nil {
		return nil, "", err
	}
	if msg.Type != 3 {
		return nil, "", fmt.Errorf("unexpected message type: %d", msg.Type)
	}
	if msg.UUID != uuid {
		return nil, "", fmt.Errorf("uuid mismatch: got %q, want %q", msg.UUID, uuid)
	}
	mac, err := msg.computeHMAC(token)
	if err != nil {
		return nil, "", err
	}
	if mac != msg.HMAC {
		return nil, "", fmt.Errorf("hmac validation failed: got %q, want %q", msg.HMAC, mac)
	}
	if checkNonce && msg.Nonce != expectedNonce {
		return nil, msg.Nonce, fmt.Errorf("nonce mismatch: got %q, want %q", msg.Nonce, expectedNonce)
	}
	return msg.Payload, msg.Nonce, nil
}

// NewAckMessage creates a signed ack message for handshake reply (type 2)
func NewAckMessage(uuid, nonce, secret string, version uint32) (*ProtocolMessage, error) {
	msg := &ProtocolMessage{
		Type:      2, // ack-message
		Timestamp: time.Now().Unix(),
		UUID:      uuid,
		Nonce:     nonce,
		Payload:   nil,
		Version:   version,
	}
	mac, err := msg.computeHMAC(secret)
	if err != nil {
		return nil, err
	}
	msg.HMAC = mac
	return msg, nil
}

// ValidateAckMessage validates a handshake ack message using a token lookup function.
// It checks HMAC, timestamp, and UUID. Returns the parsed message or error.
func ValidateAckMessage(data []byte, getToken func(uuid string) (string, error)) (*ProtocolMessage, error) {
	msg, err := UnmarshalProtocolMessage(data, "")
	if err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}
	token, err := getToken(msg.UUID)
	if err != nil {
		return nil, fmt.Errorf("token lookup failed: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("no token for uuid %q", msg.UUID)
	}
	mac, err := msg.computeHMAC(token)
	if err != nil {
		return nil, fmt.Errorf("hmac compute failed: %w", err)
	}
	if mac != msg.HMAC {
		return nil, fmt.Errorf("hmac validation failed: got %q, want %q", msg.HMAC, mac)
	}
	if !ValidateUUID(msg.UUID) {
		return nil, fmt.Errorf("invalid uuid: %q", msg.UUID)
	}
	if !ValidateTimestamp(msg.Timestamp) {
		return nil, fmt.Errorf("invalid or stale timestamp: %d", msg.Timestamp)
	}
	return msg, nil
}

type ProtocolMessage struct {
	Type      uint8
	Timestamp int64
	UUID      string
	Role      string
	Nonce     string
	Payload   []byte
	HMAC      string
	Version   uint32
}

func NewHelloMessage(uuid, role, nonce, secret string, version uint32) (*ProtocolMessage, error) {
	msg := &ProtocolMessage{
		Type:      1, // hello-message
		Timestamp: time.Now().Unix(),
		UUID:      uuid,
		Role:      role,
		Nonce:     nonce,
		Payload:   nil,
		Version:   version,
	}
	mac, err := msg.computeHMAC(secret)
	if err != nil {
		return nil, err
	}
	msg.HMAC = mac
	return msg, nil
}

func (m *ProtocolMessage) computeHMAC(secret string) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte{m.Type})
	h.Write([]byte(m.UUID))
	h.Write([]byte(m.Role))
	h.Write([]byte(m.Nonce))
	if m.Payload != nil {
		h.Write(m.Payload)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (m *ProtocolMessage) Marshal(secret string) ([]byte, error) {
	mac, err := m.computeHMAC(secret)
	if err != nil {
		return nil, err
	}
	m.HMAC = mac
	// Properly encode all fields: Type|Timestamp|UUIDLen|UUID|RoleLen|Role|NonceLen|Nonce|PayloadLen|Payload|HMACLen|HMAC
	buf := new(bytes.Buffer)
	buf.WriteByte(m.Type)
	_ = binary.Write(buf, binary.BigEndian, m.Timestamp)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(m.UUID)))
	buf.WriteString(m.UUID)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(m.Role)))
	buf.WriteString(m.Role)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(m.Nonce)))
	buf.WriteString(m.Nonce)
	if m.Payload != nil {
		_ = binary.Write(buf, binary.BigEndian, uint32(len(m.Payload)))
		buf.Write(m.Payload)
	} else {
		_ = binary.Write(buf, binary.BigEndian, uint32(0))
	}
	_ = binary.Write(buf, binary.BigEndian, uint16(len(m.HMAC)))
	buf.WriteString(m.HMAC)
	_ = binary.Write(buf, binary.BigEndian, uint32(m.Version))
	return buf.Bytes(), nil
}

func UnmarshalProtocolMessage(data []byte, secret string) (*ProtocolMessage, error) {
	buf := bytes.NewReader(data)
	msg := &ProtocolMessage{}
	// Type
	t, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	msg.Type = t
	// Timestamp
	if err := binary.Read(buf, binary.BigEndian, &msg.Timestamp); err != nil {
		return nil, err
	}
	// UUID
	var uuidLen uint16
	if err := binary.Read(buf, binary.BigEndian, &uuidLen); err != nil {
		return nil, err
	}
	uuid := make([]byte, uuidLen)
	if _, err := buf.Read(uuid); err != nil {
		return nil, err
	}
	msg.UUID = string(uuid)
	// Role
	var roleLen uint16
	if err := binary.Read(buf, binary.BigEndian, &roleLen); err != nil {
		return nil, err
	}
	role := make([]byte, roleLen)
	if _, err := buf.Read(role); err != nil {
		return nil, err
	}
	msg.Role = string(role)
	// Nonce
	var nonceLen uint16
	if err := binary.Read(buf, binary.BigEndian, &nonceLen); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := buf.Read(nonce); err != nil {
		return nil, err
	}
	msg.Nonce = string(nonce)
	// Payload
	var payloadLen uint32
	if err := binary.Read(buf, binary.BigEndian, &payloadLen); err != nil {
		return nil, err
	}
	if payloadLen > 0 {
		msg.Payload = make([]byte, payloadLen)
		if _, err := buf.Read(msg.Payload); err != nil {
			return nil, err
		}
	}
	// HMAC
	var hmacLen uint16
	if err := binary.Read(buf, binary.BigEndian, &hmacLen); err != nil {
		return nil, err
	}
	hmac := make([]byte, hmacLen)
	if _, err := buf.Read(hmac); err != nil {
		return nil, err
	}
	msg.HMAC = string(hmac)

	// Version
	if err := binary.Read(buf, binary.BigEndian, &msg.Version); err != nil {
		return nil, err
	}

	return msg, nil
}

// Exported HMAC validation for use by platform
func ComputeHMAC(msg *ProtocolMessage, secret string) (string, error) {
	return msg.computeHMAC(secret)
}

func ValidateUUID(uuid string) bool {
	return len(uuid) > 0
}

func ValidateTimestamp(ts int64) bool {
	now := time.Now().Unix()
	return ts >= now-5 && ts <= now+5
}

// ValidateHelloMessage validates a handshake hello message using a token lookup function.
// It checks HMAC, timestamp, and UUID. Returns the parsed message or error.
func ValidateHelloMessage(data []byte, getToken func(uuid string) (string, error)) (*ProtocolMessage, error) {
	// Unmarshal without HMAC validation to extract UUID
	msg, err := UnmarshalProtocolMessage(data, "")
	if err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}
	token, err := getToken(msg.UUID)
	if err != nil {
		return nil, fmt.Errorf("token lookup failed: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("no token for uuid %q", msg.UUID)
	}
	mac, err := msg.computeHMAC(token)
	if err != nil {
		return nil, fmt.Errorf("hmac compute failed: %w", err)
	}
	if mac != msg.HMAC {
		return nil, fmt.Errorf("hmac validation failed: got %q, want %q", msg.HMAC, mac)
	}
	if !ValidateUUID(msg.UUID) {
		return nil, fmt.Errorf("invalid uuid: %q", msg.UUID)
	}
	if !ValidateTimestamp(msg.Timestamp) {
		return nil, fmt.Errorf("invalid or stale timestamp: %d", msg.Timestamp)
	}
	return msg, nil
}

// ReadFull reads exactly len(buf) bytes from r into buf, or returns error.
func ReadFull(r io.Reader, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ReadLPMessage reads a length-prefixed message (4-byte big-endian length) from r, up to maxLen bytes.
func ReadLPMessage(r io.Reader, maxLen int) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if err := ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	if msgLen <= 0 || msgLen > maxLen {
		return nil, fmt.Errorf("invalid message length: %d", msgLen)
	}
	msg := make([]byte, msgLen)
	if err := ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteLPMessage writes a length-prefixed message (4-byte big-endian length) to w.
func WriteLPMessage(w io.Writer, msg []byte) error {
	msgLen := len(msg)
	if msgLen > 0x7FFFFFFF {
		return fmt.Errorf("message too large: %d", msgLen)
	}
	lenBuf := []byte{
		byte(msgLen >> 24),
		byte(msgLen >> 16),
		byte(msgLen >> 8),
		byte(msgLen),
	}
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}
