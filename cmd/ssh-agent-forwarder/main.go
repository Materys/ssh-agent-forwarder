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
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/Materys/agent-forwarder/common"
)

var VersionInfo *common.VersionInfoData = common.BuildVersionInfoData(
	1, []uint32{1},
)

type ForwarderState struct {
	realAgentSock string
}

func main() {
	fwstate := &ForwarderState{
		realAgentSock: os.Getenv("SSH_AUTH_SOCK"),
	}

	callbacks := common.RelayCallbacks{
		Setup: func(relay *common.RelayStatus, _state interface{}, _ *common.Config) error {
			state := _state.(*ForwarderState)
			if fwstate.realAgentSock == "" {
				return fmt.Errorf("SSH_AUTH_SOCK not set")
			}
			log.Printf("[forwarder] Using SSH_AUTH_SOCK=%s", fwstate.realAgentSock)
			agentInfo, err := os.Stat(state.realAgentSock)
			if err != nil {
				return fmt.Errorf("[forwarder] Failed to stat SSH_AUTH_SOCK '%s': %v\n  HINT: Check that the ssh-agent is running and the socket path is correct.", state.realAgentSock, err)
			}
			if agentInfo.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("[forwarder] SSH_AUTH_SOCK is not a socket: %s\n  HINT: The path must point to a UNIX domain socket created by ssh-agent.", state.realAgentSock)
			}
			if agentInfo.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("[forwarder] SSH_AUTH_SOCK permissions are too open: %o (must not be accessible by group/others)\n  HINT: Run 'chmod 700 %s' to restrict access.", agentInfo.Mode().Perm(), state.realAgentSock)
			}
			return nil
		},
		HandleChannels: func(relayChannels *common.RelayStatus, _state interface{}, cfg *common.Config, ctx context.Context) error {
			state := _state.(*ForwarderState)
			// Goroutine: manages the local agent socket. specific to the forwarder
			go func() {
				for {
					log.Printf("[forwarder] Connecting to real agent at %s...", state.realAgentSock)
					realAgent, err := net.Dial("unix", state.realAgentSock)
					if err != nil {
						log.Printf("[forwarder] Failed to connect to real agent: %v", err)
						time.Sleep(5 * time.Second)
						continue
					}

					ctx, cancel_func := context.WithCancel(context.Background())

					// Write goroutine with context cancellation
					go func() {
						for {
							select {
							case <-ctx.Done():
								log.Printf("[forwarder] [socket] Context cancelled, stopping write goroutine")
								return
							case b := <-relayChannels.SocketOutBytes:
								n, err := realAgent.Write(b)
								if err != nil {
									log.Printf("[forwarder] [socket] Client write error: %v", err)
									return
								} else {
									log.Printf("[forwarder] [socket] Sent %d bytes to real agent", n)
								}
							}
						}
					}()

					// Read goroutine
					go func() {
						buf := make([]byte, common.MaxAgentMessageSize)
						for {
							select {
							case <-ctx.Done():
								log.Printf("[forwarder] [socket] Context cancelled, stopping read goroutine")
								return
							default:
							}
							n, err := realAgent.Read(buf)
							if n > 0 && err == nil {
								log.Printf("[forwarder] [socket] Received %d bytes from real agent", n)
								relayChannels.SocketInBytes <- buf[:n]
							} else {
								if err == io.EOF {
									log.Printf("[forwarder] [socket] Real agent disconnected.")
								} else {
									log.Printf("[forwarder] [socket] Real agent read error: %v", err)
								}
								relayChannels.SocketInBytes <- common.PACKET_SSH_AGENT_FAILURE
								realAgent.Close()
								cancel_func() // Cancel the context to stop the write goroutine
								return
							}
						}
					}()

					<-ctx.Done()

					realAgent.Close() // Close the real agent connection on error or cancellation
				}
			}()

			// Goroutine: protocol relay logic
			currentNonce := ""
			go func() {
				for {
					buf := <-relayChannels.SocketInBytes
					log.Printf("[forwarder] -> platform: %s", common.ParseAgentRequest(buf))

					// On sending SSH_AGENT_IDENTITIES_ANSWER, filter identities if configured
					buf, err := common.FilterIdentitiesInAgentResponse(buf, cfg.AllowedIdentities)
					if err != nil {
						log.Printf("[forwarder] Identity filtering error: %v", err)
						// Proceed with unfiltered response on error
					}

					msgBytes, err := common.WrapAgentPacket(buf, cfg.UUID, currentNonce, cfg.Token)
					if err != nil {
						log.Printf("[forwarder] HMAC wrap error: %v", err)
						break
					}
					relayChannels.StreamOutBytes <- msgBytes
				}
			}()
			go func() {
				for {
					msgBytes := <-relayChannels.StreamInBytes
					payload, nonceReceived, err := common.UnwrapAndVerifyAgentPacket(msgBytes, cfg.UUID, "", cfg.Token, false)
					currentNonce = nonceReceived // Update current nonce for logging
					if err != nil {
						log.Printf("[forwarder] HMAC/nonce verify error: %v", err)
						continue
					}
					log.Printf("[forwarder] <- platform: %s (nonce=%s)", common.ParseAgentRequest(payload), nonceReceived)

					msgType, err := common.GetMsgType(payload)
					var wrapError error = nil
					var errMsg []byte

					if err != nil {
						log.Printf("[forwarder] Failed to get message type: %v", err)
						errMsg, wrapError = common.WrapAgentPacket(common.PACKET_SSH_AGENT_FAILURE, cfg.UUID, currentNonce, cfg.Token)
						relayChannels.StreamOutBytes <- errMsg
						continue
					}

					if !common.IsMsgTypeAllowed(msgType, common.SshAgentRequestWhitelist) {
						log.Printf("[forwarder] Disallowed message type: 0x%02x", msgType)
						errMsg, wrapError = common.WrapAgentPacket(common.PACKET_SSH_AGENT_FAILURE, cfg.UUID, currentNonce, cfg.Token)
						relayChannels.StreamOutBytes <- errMsg
						continue
					}

					if wrapError != nil {
						log.Printf("[forwarder] HMAC wrap error: %v", wrapError)
						break
					}

					relayChannels.SocketOutBytes <- payload
				}
			}()
			return nil
		},
	}

	log.Printf("[forwarder] Starting SSH Agent Forwarder version %d", VersionInfo.Version)

	err := common.MainRelay(
		common.SetupRelay(),
		fwstate,
		callbacks,
		"ssh-agent-forwarder",
		VersionInfo,
		context.Background(),
	)
	if err != nil {
		log.Fatalf("[forwarder] Relay error: %v", err)
		os.Exit(1)
	}
}
