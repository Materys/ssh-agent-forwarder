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
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Materys/agent-forwarder/common"
)

var VersionInfo *common.VersionInfoData = common.BuildVersionInfoData(
	1, []uint32{1},
)

type EndpointState struct {
	endpointSock string
}

func main() {
	endstate := &EndpointState{}
	callbacks := common.RelayCallbacks{
		Setup: func(relay *common.RelayStatus, _state interface{}, cfg *common.Config) error {
			state := _state.(*EndpointState)
			if cfg.SocketDir == "" {
				xdgDir := os.Getenv("XDG_RUNTIME_DIR")
				if xdgDir != "" {
					cfg.SocketDir = xdgDir
				} else {
					home := os.Getenv("HOME")
					if home != "" {
						cfg.SocketDir = filepath.Join(home, ".agent-endpoint")
					} else {
						cfg.SocketDir = "/tmp"
					}
				}
			}
			if err := os.MkdirAll(cfg.SocketDir, 0700); err != nil {
				return fmt.Errorf("[endpoint] Failed to create socket dir '%s': %v\n  HINT: Check directory permissions and disk space.", cfg.SocketDir, err)
			}
			endpointSock := filepath.Join(cfg.SocketDir, "agent-endpoint.sock")
			if err := os.Remove(endpointSock); err != nil && !os.IsNotExist(err) {
				log.Printf("[endpoint] Warning: could not remove old socket %s: %v", endpointSock, err)
			}
			state.endpointSock = endpointSock
			log.Printf("[endpoint] Using socket path: %s", state.endpointSock)
			return nil
		},
		HandleChannels: func(relayChannels *common.RelayStatus, _state interface{}, cfg *common.Config, ctx context.Context) error {
			state := _state.(*EndpointState)

			go func() {
				for {
					ln, err := net.Listen("unix", state.endpointSock)
					if err != nil {
						log.Printf("[endpoint] [socket] Failed to listen on unix socket: %v", err)
						time.Sleep(5 * time.Second)
						continue
					}
					log.Printf("[endpoint] [socket] Listening for local ssh-agent connections on %s", state.endpointSock)
					//write a file to notify that the socket is ready
					readyFile := state.endpointSock + ".ready"
					f, err := os.Create(readyFile)
					if err != nil {
						log.Printf("[endpoint] [socket] Warning: could not create ready file %s: %v", readyFile, err)
					} else {
						f.Close()
						log.Printf("[endpoint] [socket] Created ready file %s", readyFile)
					}
					// Wait for a working stream from the platform
					for {
						clientConn, err := ln.Accept()
						if err != nil {
							log.Printf("[endpoint] [socket] Accept error: %v", err)
							ln.Close()                  // Close the listener to retry
							time.Sleep(5 * time.Second) // Wait before retrying
							break                       // Exit the loop to retry listening
						}
						log.Printf("[endpoint] (DEBUG) Accepted new local ssh-agent client connection")

						//write packets inside the socket
						ctx, cancel_func := context.WithCancel(ctx)
						go func() {
							for {
								select {
								case <-ctx.Done():
									log.Printf("[endpoint] [socket] Context cancelled, stopping write goroutine")
									return // Exit the goroutine if context is cancelled
								case b := <-relayChannels.SocketOutBytes:
									clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
									n, err := clientConn.Write(b)
									if err != nil {
										log.Printf("[endpoint] [socket] Client write error: %v", err)
										cancel_func()
										return
									} else {
										log.Printf("[endpoint] [socket] Sent %d bytes to local ssh-agent client", n)
									}
								}
							}
						}()

						//read packets from the socket
						go func() {
							buf := make([]byte, common.MaxAgentMessageSize)
							for {
								select {
								case <-ctx.Done():
									log.Printf("[endpoint] [socket] Context cancelled, stopping read goroutine")
									return // Exit the goroutine if context is cancelled
								default:
								}
								n, err := clientConn.Read(buf)
								if n > 0 {
									log.Printf("[endpoint] [socket] Received %d bytes from local ssh-agent client", n)
									relayChannels.SocketInBytes <- buf[:n] // Send to channel for processing
								}
								if err != nil {
									if err == io.EOF {
										log.Printf("[endpoint] [socket] Client disconnected.")
									} else {
										log.Printf("[endpoint] [socket] Client read error: %v", err)
									}
									clientConn.Close()
									cancel_func() // Cancel the context to stop the write goroutine
									return
								}
							}
						}()

						<-ctx.Done()

						clientConn.Close() // Close the client connection on error
					}
				}
			}()

			sendNonce := uint64(1 + (rand.Int63() & 0x7FFFFFFF))
			recvNonce := sendNonce
			go func() {
				for {
					buf := <-relayChannels.SocketInBytes
					{
						sendNonce++
						recvNonce = sendNonce // Reset recvNonce to match sendNonce for the next message
						if len(buf) < 4 {
							log.Printf("[endpoint] Received malformed message from socket: %x", buf)
							continue
						}
						//the first 4 bytes are the length of the message (uint32)
						agent_message_size := int(binary.BigEndian.Uint32(buf[:4]))
						if agent_message_size < 0 || agent_message_size > common.MaxAgentMessageSize {
							log.Printf("[endpoint] Received invalid agent message size: %d", agent_message_size)
							continue
						}
						//check that the message is complete
						for {
							if len(buf) >= 4+agent_message_size {
								break
							}
							log.Printf("[endpoint] Received partial message from socket, waiting for more data... %d bytes received, expected %d bytes", len(buf), 4+agent_message_size)
							append_buf := <-relayChannels.SocketInBytes
							if len(append_buf) == 0 {
								log.Printf("[endpoint] Received empty message from socket, ignoring")
								continue
							}
							buf = append(buf, append_buf...)
						}

						log.Printf("[endpoint] -> platform: %s", common.ParseAgentRequest(buf))
						nonceStr := fmt.Sprintf("%d", sendNonce)
						msgBytes, err := common.WrapAgentPacket(buf, cfg.UUID, nonceStr, cfg.Token)
						if err != nil {
							log.Printf("[endpoint] HMAC wrap error: %v\n  HINT: This may indicate a bug or a protocol mismatch.", err)
							break
						}
						relayChannels.StreamOutBytes <- msgBytes // Send to channel for processing
					}
				}
			}()
			go func() {
				for {
					msgBytes := <-relayChannels.StreamInBytes // Wait for bytes from the stream
					expectedNonce := fmt.Sprintf("%d", recvNonce)
					payload, _, err := common.UnwrapAndVerifyAgentPacket(msgBytes, cfg.UUID, expectedNonce, cfg.Token, true)
					if err != nil {
						log.Printf("[endpoint] HMAC/nonce verify error: %v\n  HINT: This may indicate a protocol mismatch, replay attack, or corrupted packet.", err)
						continue
					}
					log.Printf("[endpoint] <- platform: %s", common.ParseAgentResponse(payload))

					msgType, err := common.GetMsgType(payload)
					var wrapError error = nil
					var errMsg []byte

					if err != nil {
						log.Printf("[forwarder] Failed to get message type: %v", err)
						errMsg, wrapError = common.WrapAgentPacket(common.PACKET_SSH_AGENT_FAILURE, cfg.UUID, expectedNonce, cfg.Token)
						relayChannels.StreamOutBytes <- errMsg
						continue
					}

					if !common.IsMsgTypeAllowed(msgType, common.SshAgentResponseWhitelist) {
						log.Printf("[forwarder] Disallowed message type: 0x%02x", msgType)
						errMsg, wrapError = common.WrapAgentPacket(common.PACKET_SSH_AGENT_FAILURE, cfg.UUID, expectedNonce, cfg.Token)
						relayChannels.StreamOutBytes <- errMsg
						continue
					}

					if wrapError != nil {
						log.Printf("[forwarder] HMAC wrap error: %v", wrapError)
						break
					}

					relayChannels.SocketOutBytes <- payload // Send to channel for processing
					//recvNonce++               // increment nonce for each received message
				}
			}()
			return nil
		},
	}

	log.Printf("[endpoint] Starting ssh-agent-endpoint version %d", VersionInfo.Version)

	err := common.MainRelay(
		common.SetupRelay(),
		endstate,
		callbacks,
		"ssh-agent-endpoint",
		VersionInfo,
		context.Background(),
	)

	if err != nil {
		log.Printf("[endpoint] Relay error: %v\n  HINT: Check your configuration, network connectivity, and ensure the platform is reachable.", err)
		os.Exit(1)
	}
}
