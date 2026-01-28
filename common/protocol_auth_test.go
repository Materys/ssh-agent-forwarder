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
	"strings"
	"testing"
	"time"
)

func staticTokenMap(tokens map[string]string) func(string) (string, error) {
	return func(uuid string) (string, error) {
		tok, ok := tokens[uuid]
		if !ok {
			return "", nil
		}
		return tok, nil
	}
}

func TestValidateHelloMessage_Success(t *testing.T) {
	uuid := "testuuid"
	token := "testtoken"
	nonce := "nonce"
	tokens := map[string]string{uuid: token}
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, token, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	data, err := msg.Marshal(token)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	parsed, err := ValidateHelloMessage(data, staticTokenMap(tokens))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if parsed.UUID != uuid {
		t.Errorf("uuid mismatch: got %q, want %q", parsed.UUID, uuid)
	}
}

func TestValidateHelloMessage_WrongToken(t *testing.T) {
	uuid := "testuuid"
	token := "testtoken"
	wrongToken := "wrongtoken"
	nonce := "nonce"
	tokens := map[string]string{uuid: wrongToken}
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, token, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	data, err := msg.Marshal(token)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	_, err = ValidateHelloMessage(data, staticTokenMap(tokens))
	if err == nil || err.Error() == "" || !contains(err.Error(), "hmac validation failed") {
		t.Fatalf("expected hmac validation error, got: %v", err)
	}
}

func TestValidateHelloMessage_NoToken(t *testing.T) {
	uuid := "testuuid"
	token := "testtoken"
	nonce := "nonce"
	tokens := map[string]string{}
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, token, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	data, err := msg.Marshal(token)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	_, err = ValidateHelloMessage(data, staticTokenMap(tokens))
	if err == nil || err.Error() == "" || !contains(err.Error(), "no token") {
		t.Fatalf("expected no token error, got: %v", err)
	}
}

func TestValidateHelloMessage_StaleTimestamp(t *testing.T) {
	uuid := "testuuid"
	token := "testtoken"
	nonce := "nonce"
	tokens := map[string]string{uuid: token}
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, token, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	msg.Timestamp = time.Now().Unix() - 1000 // way too old
	data, err := msg.Marshal(token)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	_, err = ValidateHelloMessage(data, staticTokenMap(tokens))
	if err == nil || err.Error() == "" || !contains(err.Error(), "timestamp") {
		t.Fatalf("expected timestamp error, got: %v", err)
	}
}

func TestValidateHelloMessage_InvalidUUID(t *testing.T) {
	uuid := ""
	token := "testtoken"
	nonce := "nonce"
	tokens := map[string]string{"": token}
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, token, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	data, err := msg.Marshal(token)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	_, err = ValidateHelloMessage(data, staticTokenMap(tokens))
	if err == nil || err.Error() == "" || !contains(err.Error(), "invalid uuid") {
		t.Fatalf("expected uuid error, got: %v", err)
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
