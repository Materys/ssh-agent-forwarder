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
	"fmt"
)

type Logger interface {
	Printf(format string, v ...interface{})
}

type StdoutLogger struct{}

func (l StdoutLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

var defaultLogger Logger = StdoutLogger{}

func SetLogger(l Logger) {
	defaultLogger = l
}

func Logf(format string, v ...interface{}) {
	defaultLogger.Printf(format, v...)
}
