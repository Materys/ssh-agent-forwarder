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

func TestCheckNTPDrift(t *testing.T) {
	// Use a public NTP server for test
	server := "pool.ntp.org"
	drift, err := CheckNTPDrift(server)
	if err != nil {
		t.Fatalf("NTP drift check failed: %v", err)
	}
	if drift < -60 || drift > 60 {
		t.Errorf("Unrealistic NTP drift: %f seconds", drift)
	}
}

func TestIsTimeSynchronized(t *testing.T) {
	server := "pool.ntp.org"
	ok, err := IsTimeSynchronized(server, 60)
	if err != nil {
		t.Fatalf("NTP sync check failed: %v", err)
	}
	if !ok {
		t.Errorf("System time not synchronized within 60 seconds")
	}
}
