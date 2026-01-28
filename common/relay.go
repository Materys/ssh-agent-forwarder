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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)


// SetupTLSConfig loads the root CA and returns a tls.Config for QUIC
func SetupTLSConfig(certData []byte, serverName string) (*tls.Config, error) {
	rootCAs := x509.NewCertPool()
	
	if !rootCAs.AppendCertsFromPEM(certData) {
		log.Fatalf("[forwarder] Failed to add platform certificate to root CAs.\n  HINT: The certificate may be invalid or corrupted.")
		return nil, fmt.Errorf("Failed to add platform certificate to root CAs.\n  HINT: The certificate may be invalid or corrupted.")
	}
	tlsConf := &tls.Config{
		RootCAs:            rootCAs,
		ServerName:         serverName,
		NextProtos:         []string{"ssh-agent-forwarder"},
		InsecureSkipVerify: false, // never allow insecure certs
	}
	return tlsConf, nil
}

func SetupTLSConfigFromCertPath(certPath, serverName string) (*tls.Config, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("[forwarder] Failed to read platform certificate at '%s': %v\n  HINT: Check the file path, permissions, and that the file exists.", certPath, err)
		return nil, err
	}

	return SetupTLSConfig(certData, serverName);
} 

type RelayStatus struct {
	StreamInBytes  chan []byte
	StreamOutBytes chan []byte
	SocketInBytes  chan []byte
	SocketOutBytes chan []byte
}

func SetupRelay() *RelayStatus {
	return &RelayStatus{
		StreamInBytes:  make(chan []byte, 10),
		StreamOutBytes: make(chan []byte, 10),
		SocketInBytes:  make(chan []byte, 10),
		SocketOutBytes: make(chan []byte, 10),
	}
}

type RelayCallbacks struct {
	Setup          func(relay *RelayStatus, state interface{}, cfg *Config) error
	HandleChannels func(relay *RelayStatus, state interface{}, cfg *Config, ctx context.Context) error
}

func MainRelay(relay *RelayStatus, state interface{}, callbacks RelayCallbacks, name string, vinfo *VersionInfoData, ctx context.Context) error {

	// Parse --config flag early
	configPath := ""
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			break
		}
	}
	if configPath == "" {
		configPath = name + ".yaml"
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		PrintUnifiedUsageAndExit(name, name+".yaml", fmt.Sprintf(" Config error: %v\n  HINT: Check your config file, environment variables, and command line arguments.", err), "")
	}
	if !ValidateUUID(cfg.UUID) {
		PrintUnifiedUsageAndExit(name, name+".yaml", fmt.Sprintf(" Invalid UUID: %s\n  HINT: Set a valid UUID in config, env, or CLI (e.g. --uuid=...)\n  See ssh-agent-forwarder.yaml.", cfg.UUID), "")
	}
	if cfg.Token == "" {
		PrintUnifiedUsageAndExit(name, name+".yaml", "No token provided.\n  HINT: Set SSH_AGENT_TOKEN in config, env, or CLI (e.g. --token=...)\n  See ssh-agent-forwarder.yaml.", "")
	}

	platformAddr := cfg.PlatformURL
	if platformAddr == "" {
		platformAddr = "localhost:4242"
	}
	uuid := cfg.UUID
	token := cfg.Token
	if uuid == "" {
		PrintUnifiedUsageAndExit(name, name+".yaml", "KEY_OWNER_UUID (cfg.UUID) not set", "")
	}
	if token == "" {
		PrintUnifiedUsageAndExit(name, name+".yaml", "SSH_AGENT_TOKEN (cfg.Token) not set", "")
	}

	var tlsConf *tls.Config;
	if (cfg.Cert != "") {
		log.Println("Using cert data from config")
		tlsConf, err = SetupTLSConfig([]byte(cfg.Cert), cfg.TLSServerName)
	} else {
		log.Println("Using cert path from config")
		tlsConf, err = SetupTLSConfigFromCertPath(cfg.CertPath, cfg.TLSServerName)
	}
	
	if err != nil {
		return err
	}

	relayChannels := SetupRelay()

	if callbacks.Setup != nil {
		if err := callbacks.Setup(relayChannels, state, cfg); err != nil {
			return fmt.Errorf("relay setup failed: %w", err)
		}
	}

	go func() {
		for {
			quicConfig := &quic.Config{
				MaxIdleTimeout:  20 * time.Second,
				KeepAlivePeriod: 15 * time.Second,
			}
			log.Printf("[%s] Connecting to platform at %s...", name, platformAddr)
			conn, err := quic.DialAddr(ctx, platformAddr, tlsConf, quicConfig)
			if err != nil {
				log.Printf("[%s] Failed to connect to platform at %s: %v", name, platformAddr, err)
				time.Sleep(15 * time.Second)
				continue
			}
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				log.Printf("[%s] Failed to open QUIC stream: %v", name, err)
				conn.CloseWithError(0, "stream open failed")
				time.Sleep(15 * time.Second)
				continue
			}
			ackMsg, _, err := DoHandshake(stream, uuid, name, token, vinfo)
			if err != nil {
				log.Printf("[%s] Handshake failed: %v", name, err)
				stream.Close()
				conn.CloseWithError(0, "handshake failed")
				time.Sleep(15 * time.Second)
				continue
			}
			log.Printf("[%s] Handshake complete, received valid ack for UUID=%q, Nonce=%q, ServerVersion=%d", name, ackMsg.UUID, ackMsg.Nonce, ackMsg.Version)

			ctx, cancelFunc := context.WithCancel(ctx)

			go func() {
				for {
					select {
					case <-ctx.Done():
						log.Printf("[%s] [stream] Context cancelled, stopping read goroutine", name)
						return
					default:
					}
					msgBytes, err := ReadLPMessage(stream, MaxAgentMessageSize)
					if err != nil {
						stream.Close()
						conn.CloseWithError(0, "stream read failed")
						log.Printf("[%s] [stream] Read error: %v", name, err)
						cancelFunc() // Cancel the context to stop the write goroutine
						return
					}
					relayChannels.StreamInBytes <- msgBytes
				}
			}()

			go func() {
				for {
					select {
					case <-ctx.Done():
						log.Printf("[%s] [stream] Context cancelled, stopping write goroutine", name)
						return
					case msgBytes := <-relayChannels.StreamOutBytes:
						if err := WriteLPMessage(stream, msgBytes); err != nil {
							stream.Close()
							conn.CloseWithError(0, "stream write failed")
							log.Printf("[%s] [stream] Write error: %v", name, err)
							cancelFunc() // Cancel the context to stop the read goroutine
							return
						}
					}
				}
			}()
			<-ctx.Done()
			stream.Close()
			conn.CloseWithError(0, "bye")
			time.Sleep(5 * time.Second)
		}
	}()

	if callbacks.HandleChannels != nil {
		if err := callbacks.HandleChannels(relayChannels, state, cfg, ctx); err != nil {
			return fmt.Errorf("handle channels failed: %w", err)
		}
	} else {
		return fmt.Errorf("no HandleChannels callback provided")
	}
	select {}
}
