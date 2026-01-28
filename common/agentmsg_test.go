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

func TestDumpAgentMessage(t *testing.T) {
	cases := []struct {
		msg    []byte
		expect string
	}{
		{[]byte{0, 0, 0, 1, 11}, "SSH_AGENTC_REQUEST_IDENTITIES"},
		{[]byte{0, 0, 0, 1, 13}, "SSH_AGENTC_SIGN_REQUEST"},
		{[]byte{0, 0, 0, 1, 12}, "SSH_AGENT_IDENTITIES_ANSWER"},
		{[]byte{0, 0, 0, 1, 14}, "SSH_AGENT_SIGN_RESPONSE"},
		{[]byte{0, 0, 0, 1, 99}, "Unknown agent message type: 99"},
		{[]byte{0, 0, 0}, "[malformed agent message]"},
	}
	for _, c := range cases {
		if got := DumpAgentMessage(c.msg); got != c.expect {
			t.Errorf("DumpAgentMessage(%v) = %q, want %q", c.msg, got, c.expect)
		}
	}
}
