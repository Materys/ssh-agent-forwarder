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
	"time"

	"github.com/beevik/ntp"
)

// CheckNTPDrift returns the time difference between system and NTP server (in seconds)
func CheckNTPDrift(server string) (float64, error) {
	t, err := ntp.Time(server)
	if err != nil {
		return 0, err
	}
	return t.Sub(time.Now()).Seconds(), nil
}

// IsTimeSynchronized checks if the system clock is within the allowed drift
func IsTimeSynchronized(server string, maxDrift float64) (bool, error) {
	drift, err := CheckNTPDrift(server)
	if err != nil {
		return false, err
	}
	return drift >= -maxDrift && drift <= maxDrift, nil
}
