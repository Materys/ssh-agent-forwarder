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
	"os"
	"testing"
)

func TestLoadConfigEnv(t *testing.T) {
	os.Setenv("KEY_OWNER_UUID", "uuid-test")
	os.Setenv("SSH_AGENT_TOKEN", "token-test")
	os.Setenv("REDIS_ADDRESS", "localhost:6379")
	os.Setenv("PLATFORM_URL", "https://platform")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.UUID != "uuid-test" {
		t.Errorf("UUID mismatch: got %q", cfg.UUID)
	}
	if cfg.Token != "token-test" {
		t.Errorf("Token mismatch: got %q", cfg.Token)
	}
	if cfg.RedisAddr != "localhost:6379" {
		t.Errorf("RedisAddr mismatch: got %q", cfg.RedisAddr)
	}
	if cfg.PlatformURL != "https://platform" {
		t.Errorf("PlatformURL mismatch: got %q", cfg.PlatformURL)
	}
}
