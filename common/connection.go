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

import "sync"

const MaxConnections = 100

var (
	activeConnections int
	connectionLock    sync.Mutex
)

func AddConnection() bool {
	connectionLock.Lock()
	defer connectionLock.Unlock()
	if activeConnections >= MaxConnections {
		return false
	}
	activeConnections++
	return true
}

func RemoveConnection() {
	connectionLock.Lock()
	defer connectionLock.Unlock()
	if activeConnections > 0 {
		activeConnections--
	}
}

func GetActiveConnections() int {
	connectionLock.Lock()
	defer connectionLock.Unlock()
	return activeConnections
}
