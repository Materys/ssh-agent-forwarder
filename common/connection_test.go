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

import "testing"

func TestAddRemoveConnection(t *testing.T) {
	for i := 0; i < MaxConnections; i++ {
		if !AddConnection() {
			t.Fatalf("AddConnection failed at %d", i)
		}
	}
	if AddConnection() {
		t.Errorf("Should not allow more than MaxConnections")
	}
	for i := 0; i < MaxConnections; i++ {
		RemoveConnection()
	}
	if GetActiveConnections() != 0 {
		t.Errorf("Expected 0 active connections, got %d", GetActiveConnections())
	}
}
