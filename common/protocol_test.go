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
	"testing"
)

func TestProtocolMessageHMAC_Success(t *testing.T) {
	uuid := "testuuid"
	secret := "testtoken"
	nonce := "randomnonce"
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, secret, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	data, err := msg.Marshal(secret)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	parsed, err := UnmarshalProtocolMessage(data, secret)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	mac, err := parsed.computeHMAC(secret)
	if err != nil {
		t.Fatalf("failed to compute hmac: %v", err)
	}
	if mac != parsed.HMAC {
		t.Errorf("expected valid HMAC, got %s want %s", parsed.HMAC, mac)
	}
	if msg.Version != parsed.Version {
		t.Errorf("expected version %d, got %d", msg.Version, parsed.Version)
	}
}

func TestProtocolMessageHMAC_Failure(t *testing.T) {
	uuid := "testuuid"
	secret := "testtoken"
	wrongSecret := "wrongtoken"
	nonce := "randomnonce"
	msg, err := NewHelloMessage(uuid, "forwarder", nonce, secret, 1)
	if err != nil {
		t.Fatalf("failed to create hello message: %v", err)
	}
	data, err := msg.Marshal(secret)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	parsed, err := UnmarshalProtocolMessage(data, wrongSecret)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	mac, err := parsed.computeHMAC(wrongSecret)
	if err != nil {
		t.Fatalf("failed to compute hmac: %v", err)
	}
	if mac == parsed.HMAC {
		t.Errorf("expected HMAC mismatch with wrong token, but got valid HMAC")
	}
	if msg.Version != parsed.Version {
		t.Errorf("expected version %d, got %d", msg.Version, parsed.Version)
	}
}
