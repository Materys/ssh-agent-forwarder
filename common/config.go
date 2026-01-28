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
	"flag"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// MaxAgentMessageSize is the maximum allowed size for a single agent protocol message (bytes)
const MaxAgentMessageSize = 4096

// PrintUnifiedUsageAndExit prints a unified usage/help message for all executables and exits.
// Pass the binary name (e.g. "ssh-platform"), the default YAML file, and any extra notes or required fields.
func PrintUnifiedUsageAndExit(binaryName, defaultYaml string, msg string, extraNotes string) {
	usage := fmt.Sprintf(`
USAGE: %[1]s [--config <file.yaml>] [--platform <url>] [--cert <path>] [--platform-host <host>] [--socket-dir <dir>] [--tls-server-name <name>] [--uuid <uuid>] [--token <token>] [--redis <addr>]

Config sources (lowest to highest priority):
  1. YAML file (default: %[2]s, override with --config)
  2. Environment variables (see below)
  3. Command-line flags (see above)

Environment variables:
  PLATFORM_URL, CERT, CERT_PATH, KEY, SOCKET_DIR, TLS_SERVER_NAME, KEY_OWNER_UUID, SSH_AGENT_TOKEN, REDIS_ADDRESS, REDIS_PASSWORD

YAML fields:
  platform_url, cert_path, cert, socket_dir, tls_server_name, uuid, token, redis_addr, redis_pass

EXAMPLE:
  KEY=platform.key ./%[1]s --config %[2]s --platform :4242
  PLATFORM_URL=0.0.0.0:4242 CERT=platform.crt KEY=platform.key ./%[1]s

%[3]s
See %[2]s.example for a template.
`, binaryName, defaultYaml, extraNotes)
	if msg != "" {
		os.Stderr.WriteString(msg + "\n")
	}
	os.Stderr.WriteString(usage)
	os.Exit(2)
}

type Config struct {
	UUID          string `yaml:"uuid"`
	Token         string `yaml:"token"`
	RedisAddr     string `yaml:"redis_addr"`
	RedisPass     string `yaml:"redis_pass"`
	RedisDb       int    `yaml:"redis_db"`
	PlatformURL   string `yaml:"platform_url"`
	Cert          string `yaml:"cert"`
	CertPath      string `yaml:"cert_path"`
	KeyPath       string `yaml:"key_path"`
	SocketDir     string `yaml:"socket_dir"`
	TLSServerName string `yaml:"tls_server_name"`
	AllowedIdentities []string `yaml:"allowed_identities"`
	config        string `yaml:"-"`
}

// LoadConfig loads config from file, env, and CLI flags (in that order)
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			_ = yaml.NewDecoder(f).Decode(cfg)
		}
	}
	// Env overrides
	if v := os.Getenv("KEY_OWNER_UUID"); v != "" {
		cfg.UUID = v
	}
	if v := os.Getenv("SSH_AGENT_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("REDIS_ADDRESS"); v != "" {
		cfg.RedisAddr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.RedisPass = v
	}
	if v := os.Getenv("REDIS_DB"); v != "" {
		if db, err := strconv.Atoi(v); err == nil {
			cfg.RedisDb = db
		} else {
			return nil, fmt.Errorf("invalid REDIS_DB value: %s", v)
		}
	}
	if v := os.Getenv("PLATFORM_URL"); v != "" {
		cfg.PlatformURL = v
	}

	if v := os.Getenv("CERT_PATH"); v != "" {
		cfg.CertPath = v
	}

	if v := os.Getenv("CERT"); v != "" {
		cfg.Cert = v
	}

	if v := os.Getenv("KEY"); v != "" {
		cfg.KeyPath = v
	}
	if v := os.Getenv("SOCKET_DIR"); v != "" {
		cfg.SocketDir = v
	}

	if v := os.Getenv("TLS_SERVER_NAME"); v != "" {
		cfg.TLSServerName = v
	}
	// CLI flags
	uuid := flag.String("uuid", cfg.UUID, "Key owner UUID")
	token := flag.String("token", cfg.Token, "SSH agent token")
	redisAddr := flag.String("redis", cfg.RedisAddr, "Redis address")
	redisPass := flag.String("redis-pass", cfg.RedisPass, "Redis password")
	redisb := flag.Int("redis-db", cfg.RedisDb, "Redis database number")
	platformURL := flag.String("platform", cfg.PlatformURL, "Platform URL")
	certPath := flag.String("cert", cfg.CertPath, "Platform certificate path")
	keyPath := flag.String("key", cfg.KeyPath, "Platform private key path")
	socketDir := flag.String("socket-dir", cfg.SocketDir, "Socket directory for agent socket")
	tlsServerName := flag.String("tls-server-name", cfg.TLSServerName, "TLS server name for platform cert validation")
	config := flag.String("config", "", "Path to config YAML file")
	flag.Parse()
	cfg.UUID = *uuid
	cfg.Token = *token
	cfg.RedisAddr = *redisAddr
	cfg.RedisPass = *redisPass
	cfg.RedisDb = *redisb
	cfg.PlatformURL = *platformURL
	cfg.CertPath = *certPath
	cfg.KeyPath = *keyPath
	cfg.SocketDir = *socketDir
	cfg.TLSServerName = *tlsServerName
	cfg.config = *config
	return cfg, nil
}
