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
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Materys/agent-forwarder/common"
	"github.com/quic-go/quic-go"
)

var VersionInfo *common.VersionInfoData = common.BuildVersionInfoData(
	1, []uint32{1},
)

// RemoteEndpointConnection holds info about a connected forwarder
// Add a field for the QUIC connection and stream
type RemoteEndpointConnection struct {
	UUID              string
	LastHello         int64
	channelChannelIn  chan chan []byte //to send a new channel to the forwarder loop
	channelChannelOut chan chan []byte
	outputChannel     map[uint]chan []byte //the channels that the forwarder loop manages for each stream
	inputChannel      map[uint]chan []byte
	streamChannel     chan *quic.Stream // channel to send streams to the forwarder loop
	connChannel       chan *quic.Conn   // channel to send connections to the forwarder loop
	Conn              *quic.Conn
	Stream            *quic.Stream
	Cancel            *context.CancelFunc // relay cancel function
	Context           *context.Context    // context for this connection
	SyncMutex         sync.Mutex          // protect access to this connection
}

var global_unique_uint = uint(0)
var global_unique_uint_mutex sync.Mutex

func getUniqueUint() uint {
	global_unique_uint_mutex.Lock()
	defer global_unique_uint_mutex.Unlock()
	unique := global_unique_uint
	global_unique_uint++
	return unique
}

// PlatformState holds all connection state for the platform
type PlatformState struct {
	forwarders   map[string]*RemoteEndpointConnection // uuid -> conn
	forwardersMu sync.Mutex
	endpointsMu  sync.Mutex
}

func main() {
	log.Printf("[platform] Starting SSH Platform version %d", VersionInfo.Version)

	// Parse --config flag early
	configPath := ""
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			break
		}
	}
	if configPath == "" {
		configPath = "ssh-platform.yaml"
	}

	// Set up logging to a file in plain text mode, flush on exit
	logFile, err := os.OpenFile("platform_end2end.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("[platform] Failed to open log file: %v\n  HINT: Check file permissions and disk space.", err)
	}
	defer func() {
		logFile.Sync()
		logFile.Close()
	}()
	log.SetOutput(logFile)
	log.SetOutput(os.Stdout) // also log to stdout
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := common.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("[platform] Config error: %v\n  HINT: Check your config file, environment variables, and command line arguments.\n  You can specify a config file with --config <file.yaml> or set env vars.", err)
	}
	if cfg.PlatformURL == "" {
		printUnifiedUsageAndExit("[platform] Missing required configuration: platform_url (used for listening address).")
	}
	if cfg.CertPath == "" {
		printUnifiedUsageAndExit("[platform] Missing required configuration: cert_path.")
	}
	if cfg.KeyPath == "" {
		printUnifiedUsageAndExit("[platform] Missing required configuration: key_path.")
	}
	redis := common.RedisFromConfig(cfg)
	ctx := context.Background()

	state := &PlatformState{
		forwarders:   make(map[string]*RemoteEndpointConnection),
		forwardersMu: sync.Mutex{},
		endpointsMu:  sync.Mutex{},
	}

	addr := cfg.PlatformURL
	tlsConf := generateTLSConfigFromConfig(cfg)
	quicConfig := &quic.Config{
		MaxIdleTimeout:  20 * time.Second, // Set a max idle timeout to close idle connections
		KeepAlivePeriod: 15 * time.Second, // Set a keep-alive period to prevent idle connections from being closed
		// Set other QUIC options as needed
	}
	listener, err := quic.ListenAddr(addr, tlsConf, quicConfig)
	if err != nil {
		log.Fatalf("[platform] Failed to start QUIC listener on %s: %v\n  HINT: Check that the address is available and the TLS certificate/key are valid.\n  CertPath: %s\n  KeyPath: %s", addr, err, cfg.CertPath, cfg.KeyPath)
	}
	log.Printf("[platform] Listening for forwarders/endpoints on %s (QUIC)...", addr)

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			log.Printf("Listener error: %v", err)
			continue
		}
		go handleQUIC(state, conn, redis, VersionInfo, ctx)
	}
}

// printUnifiedUsageAndExit prints a unified usage/help message for all executables and exits (now shared from common)
func printUnifiedUsageAndExit(msg string) {
	common.PrintUnifiedUsageAndExit(
		"ssh-platform",
		"ssh-platform.yaml",
		msg,
		"This pattern is shared by all executables (endpoint, forwarder, platform).",
	)
}

// handleQUIC handles both forwarder and endpoint connections
func handleQUIC(state *PlatformState, conn *quic.Conn, redis *common.RedisClient, versionInfo *common.VersionInfoData, ctx context.Context) {
	log.Printf("[platform] New QUIC connection from: %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("[platform] Failed to accept QUIC stream: %v\n  HINT: Check network connectivity and client status.", err)
		return
	}
	// Do NOT defer stream.Close() -- keep it open for agent traffic

	// Perform handshake ONCE, accept either role
	log.Printf("[platform] (DEBUG) Attempting handshake (role=any): ConnRemote=%s, ConnLocal=%s", conn.RemoteAddr(), conn.LocalAddr())
	helloMsg, err := common.HandleHandshake(stream, func(uuid string) (string, error) {
		return redis.GetToken(ctx, uuid)
	}, ([]string{"ssh-agent-endpoint", "ssh-agent-forwarder"}), versionInfo)

	if err != nil {
		log.Printf("[platform] Handshake failed: %v\n  HINT: Check that the connecting client is using the correct UUID/token/version and that clocks are synchronized.\n  Error: %v", err, err)
		return
	}
	log.Printf("[platform] Parsed hello message: UUID=%q, Timestamp=%d, Nonce=%q, Role=%q, ConnRemote=%s, ConnLocal=%s, ClientVersion=%d", helloMsg.UUID, helloMsg.Timestamp, helloMsg.Nonce, helloMsg.Role, conn.RemoteAddr(), conn.LocalAddr(), helloMsg.Version)
	if helloMsg.Role == "ssh-agent-endpoint" {
		log.Printf("[platform] (DEBUG) Registering endpoint: UUID=%s, ConnRemote=%s, ConnLocal=%s, Stream=%p", helloMsg.UUID, conn.RemoteAddr(), conn.LocalAddr(), stream)
		// Accept agent traffic from endpoint and relay to forwarder
		log.Printf("[platform] (DEBUG) Entering endpoint agent relay for UUID=%s, EndpointConnRemote=%s, EndpointConnLocal=%s, EndpointStreamID=%d", helloMsg.UUID, conn.RemoteAddr(), conn.LocalAddr(), stream.StreamID())
		// find the forwarder for this endpoint

		forwarder, ok := state.forwarders[helloMsg.UUID]
		ttot := 0
		for t := 1; t < 300; {
			if ok {
				break
			}
			time.Sleep(time.Duration(t*1000) * time.Millisecond) // wait for a forwarder to connect
			ttot += t
			t *= 2
			forwarder, ok = state.forwarders[helloMsg.UUID]
		}
		if !ok {
			log.Printf("[platform] No forwarder found for endpoint: %s, after waiting for %d seconds", helloMsg.UUID, ttot)
			return
		}
		log.Printf("[platform] Found forwarder for endpoint: %s after %d seconds", helloMsg.UUID, ttot)
		//communication loop: read from endpoint stream and use the forwarder channels to send the data to the forwarder
		outputChannel := make(chan []byte, 10)       // buffered channel to avoid blocking
		inputChannel := make(chan []byte, 10)        // buffered channel to avoid blocking
		forwarder.channelChannelOut <- outputChannel // send the output channel to the forwarder loop
		forwarder.channelChannelIn <- inputChannel   // send the input channel to the forwarder loop
	conn_loop:
		for {
			select {
			case <-conn.Context().Done():
				log.Printf("[platform] Endpoint connection for UUID=%s closed", helloMsg.UUID)
				break conn_loop
			default:
				// Read from the endpoint stream
				msgBytes, err := common.ReadLPMessage(stream, common.MaxAgentMessageSize)
				if err != nil {
					log.Printf("[platform] ReadLPMessage error: %v\n  HINT: Check that the endpoint is sending valid agent messages and that the connection is stable.", err)
					// If we can't read from the stream, close it and the connection
					stream.Close()
					conn.CloseWithError(quic.ApplicationErrorCode(common.ERR_READ_LPMESSAGE_FAIL), "ReadLPMessage failed")
					break conn_loop
				}
				log.Printf("[platform] <- [endpoint] received %d bytes from endpoint %s", len(msgBytes), helloMsg.UUID)
				// Send the message to the forwarder input channel
				outputChannel <- msgBytes
				log.Printf("[platform] -> [forwarder] sent %d bytes to forwarder %s", len(msgBytes), helloMsg.UUID)
				// Now wait for the reply from the forwarder
				replBytes := <-inputChannel
				log.Printf("[platform] <- [forwarder] received %d bytes from forwarder %s", len(replBytes), helloMsg.UUID)
				if len(replBytes) == 0 {
					log.Printf("[platform] No reply from forwarder %s, closing connection", helloMsg.UUID)
					stream.Close()
					conn.CloseWithError(quic.ApplicationErrorCode(common.ERR_FORWARDER_NO_REPLY), "No reply from forwarder")
					break conn_loop
				}
				// Write the reply back to the endpoint stream
				if err := common.WriteLPMessage(stream, replBytes); err != nil {
					log.Printf("[platform] WriteLPMessage error: %v\n  HINT: Check that the endpoint stream is writable and that the connection is stable.", err)
					// If we can't write to the stream, close it and the connection
					stream.Close()
					conn.CloseWithError(quic.ApplicationErrorCode(common.ERR_WRITE_LPMESSAGE_FAIL), "WriteLPMessage failed")
					break conn_loop
				}
				log.Printf("[platform] -> [endpoint] sent %d bytes to endpoint %s", len(replBytes), helloMsg.UUID)
			}
		}
		// If we reach here, the endpoint connection was closed
		close(inputChannel)
		close(outputChannel)
		log.Printf("[platform] Endpoint connection for UUID=%s closed", helloMsg.UUID)
		return
	} else if helloMsg.Role == "ssh-agent-forwarder" {
		log.Printf("[platform] (DEBUG) Registering forwarder: UUID=%s, ConnRemote=%s, ConnLocal=%s, StreamID=%d", helloMsg.UUID, conn.RemoteAddr(), conn.LocalAddr(), stream.StreamID())
		state.forwardersMu.Lock()
		// Always replace the old forwarder connection with the new one
		//free the old forwarder connection if it exists
		if oldFwd, exists := state.forwarders[helloMsg.UUID]; exists {
			// create a new connection and stream and send it to the forwarder loop
			oldFwd.Conn = conn     // update the connection
			oldFwd.Stream = stream // update the stream
			// wait for the lock to be released
			oldFwd.streamChannel <- stream // send the new stream to the forwarder loop
			oldFwd.connChannel <- conn     // send the new connection to the forwarder loop
		} else {
			nctx, cancel := context.WithCancel(ctx)
			s := &RemoteEndpointConnection{
				UUID:              helloMsg.UUID,
				LastHello:         helloMsg.Timestamp,
				Conn:              conn,
				Stream:            stream,
				Cancel:            &cancel,
				Context:           &nctx,
				channelChannelOut: make(chan chan []byte),
				channelChannelIn:  make(chan chan []byte),
				outputChannel:     make(map[uint]chan []byte),
				inputChannel:      make(map[uint]chan []byte),
				streamChannel:     make(chan *quic.Stream), // unbuffered, since it is also used to synchronize the stream creation
				connChannel:       make(chan *quic.Conn),   // unbuffered, since it is also used to synchronize the connection creation
			}
			state.forwarders[helloMsg.UUID] = s
			go func() {
				forwarder, ok := state.forwarders[helloMsg.UUID]
				stream := (*quic.Stream)(nil) // initialize stream to nil
				conn := (*quic.Conn)(nil)     // initialize conn to nil
				if !ok {
					log.Printf("[platform] Forwarder %s not found, exiting loop", helloMsg.UUID)
					return
				}
				log.Printf("[platform] Starting forwarder loop for UUID=%s", helloMsg.UUID)
				token, err := redis.GetToken(ctx, helloMsg.UUID)
				if err != nil {
					log.Printf("[platform] Failed to get token for UUID=%s: %v", helloMsg.UUID, err)
				}
				get_new_stream_from_channel := func() {
				stream_wait_loop:
					for stream == nil {
						select {
						case <-(*forwarder.Context).Done():
							break stream_wait_loop
						case stream = <-forwarder.streamChannel:
							conn = <-forwarder.connChannel // update the connection
						}
					}
					log.Printf("[platform] New stream received for forwarder %s, %p", helloMsg.UUID, conn)
				}
				send_error := func(error_code int, error_msg string, sent_msg *common.ProtocolMessage, inCh chan []byte) {
					stream.Close()
					stream.CancelRead(quic.StreamErrorCode(error_code))
					stream.CancelWrite(quic.StreamErrorCode(error_code))
					conn.CloseWithError(quic.ApplicationErrorCode(error_code), error_msg)
					forwarder.Conn = nil // clear the connection to avoid further writes
					forwarder.Stream = nil
					stream = nil // reset stream to nil
					conn = nil   // reset conn to nil
					repl_err, err := common.WrapAgentPacket(common.PACKET_SSH_AGENT_FAILURE, sent_msg.UUID, sent_msg.Nonce, token)
					if err != nil {
						log.Printf("[platform] Failed to wrap SSH_AGENT_FAILURE message: %v", err)
						inCh <- []byte("")
					} else {
						inCh <- repl_err
					}
				}
				get_new_stream_from_channel() // get the first stream from the channel
				type byteWithId struct {
					id   uint
					data []byte
				}
				aggregatedOutputChannel := make(chan byteWithId, 10) // buffered channel to avoid blocking
				doAggregation := func(outch chan []byte, id uint, ctx context.Context, endCallback func(uint)) {
				aggrLoop:
					for {
						select {
						case <-ctx.Done():
							log.Printf("[platform] Aggregation context cancelled, stopping aggregation for id %d", id)
							break aggrLoop
						case data, ok := <-outch:
							if !ok {
								log.Printf("[platform] Output channel %d closed, stopping aggregation", id)
								break aggrLoop
							}
							aggregatedOutputChannel <- byteWithId{id: id, data: data}
						}
					}
					endCallback(id)
				}
				channelMapLock := sync.Mutex{}
			forwarder_loop:
				for {
					forwarder, ok = state.forwarders[helloMsg.UUID]
					if !ok {
						log.Printf("[platform] Forwarder %s not found, exiting loop", helloMsg.UUID)
						return
					}
					select {
					//check if the connection is open
					case <-func() <-chan struct{} {
						if conn != nil {
							return conn.Context().Done()
						}
						// If conn is nil, return a closed channel to avoid blocking
						ch := make(chan struct{})
						close(ch)
						return ch
					}():
						log.Printf("[platform] Connection for forwarder %s closed with id %p, waiting for a new one", helloMsg.UUID, conn)
						stream = nil                  // reset stream to nil
						conn = nil                    // reset conn to nil
						get_new_stream_from_channel() // wait for a new stream from the channel
					case <-(*forwarder.Context).Done():
						break forwarder_loop // exit the loop if the context is done
					case stream = <-state.forwarders[helloMsg.UUID].streamChannel:
						// Handle new stream from the forwarder
						if stream == nil {
							get_new_stream_from_channel()
						} else {
							conn = <-state.forwarders[helloMsg.UUID].connChannel // get the connection from the channel
							log.Printf("[platform] Received new stream from forwarder %s", helloMsg.UUID)
						}
					case outChannel := <-forwarder.channelChannelOut:
						inChannel := <-forwarder.channelChannelIn
						uid := getUniqueUint() // get a unique ID for this channel
						log.Printf("[platform] Handling new output channel from forwarder %s with id %d", helloMsg.UUID, uid)
						channelMapLock.Lock()
						forwarder.outputChannel[uid] = outChannel // store the output channel in the map
						forwarder.inputChannel[uid] = inChannel   // store the input channel in
						channelMapLock.Unlock()
						go doAggregation(outChannel, uid, *forwarder.Context, func(id uint) {
							log.Printf("[platform] Aggregation for channel %d completed", id)
							channelMapLock.Lock()
							delete(forwarder.outputChannel, id) // remove the output channel from the map
							delete(forwarder.inputChannel, id)  // remove the input channel from the map
							channelMapLock.Unlock()
						}) // start a goroutine to aggregate the output channel
						log.Printf("[platform] setup of new output channel done %s with id %d", helloMsg.UUID, uid)

						// Start a goroutine to aggregate the output channel
					case _msgBytes := <-aggregatedOutputChannel:
						log.Printf("[platform] Received output for forwarder %s", helloMsg.UUID)
						msgBytes := _msgBytes.data
						id := _msgBytes.id
						channelMapLock.Lock()
						inputChannel := forwarder.inputChannel[id]
						channelMapLock.Unlock()
						sent_msg, err := common.UnmarshalProtocolMessage(msgBytes, "")
						if err != nil {
							log.Printf("[platform] Failed to unmarshal received message from endpoint message: %v", err)
							inputChannel <- []byte("")
							continue
						}
						if err := common.WriteLPMessage(stream, msgBytes); err != nil {
							log.Printf("[platform] -> [forwarder] WriteLPMessage error: %v", err)
							// If we can't write to the stream, close it and the connection. A new stream will be created when a new connection will arrive
							// send an error message to the endpoint (SSH_AGENT_FAILURE)
							//get nonce from the sent message
							send_error(common.ERR_WRITE_LPMESSAGE_FAIL, "WriteLPMessage failed", sent_msg, inputChannel)
							get_new_stream_from_channel()
						} else {
							//wait the reply from the forwarder
							log.Printf("[platform] -> [forwarder] sent %d bytes", len(msgBytes))
							// Now wait for the reply from the forwarder
							replyBytes, err := common.ReadLPMessage(stream, common.MaxAgentMessageSize)
							if err != nil {
								log.Printf("[platform] -> [forwarder] ReadLPMessage error: %v", err)
								// If we can't read from the stream, close it and the connection. A new stream will be created when a new connection will arrive
								send_error(common.ERR_READ_LPMESSAGE_FAIL, "ReadLPMessage failed", sent_msg, inputChannel)
								get_new_stream_from_channel() // get a new stream from the channel
							} else {
								//parse the reply message and check the nonce
								replyMsg, err := common.UnmarshalProtocolMessage(replyBytes, "")
								send_error_packet := func() {
									repl_err, err := common.WrapAgentPacket(common.PACKET_SSH_AGENT_FAILURE, sent_msg.UUID, sent_msg.Nonce, token)
									if err != nil {
										log.Printf("[platform] Failed to wrap SSH_AGENT_FAILURE message: %v", err)
										inputChannel <- []byte("")
									} else {
										inputChannel <- repl_err
									}
								}
								if err != nil {
									log.Printf("[platform] Failed to unmarshal reply message: %v", err)
									send_error_packet()
									continue
								}
								if replyMsg.Nonce != sent_msg.Nonce {
									log.Printf("[platform] Nonce mismatch for uuid %s in reply message: got %q, want %q", helloMsg.UUID, replyMsg.Nonce, sent_msg.Nonce)
									send_error_packet()
									continue
								}
								log.Printf("[platform] <- [forwarder] received %d bytes", len(replyBytes))
								inputChannel <- replyBytes // send the reply to the input channel for the endpoint
							}
						}

					}
				}
				log.Printf("[platform] Forwarder loop for UUID=%s exited", helloMsg.UUID)
			}()
			s.streamChannel <- stream // make the forwarder loop aware of the new stream so it can start reading from it
			s.connChannel <- conn     // make the forwarder loop aware of the new connection so it can start reading from it
		}
		log.Printf("[platform] Registered/updated forwarder: %s", helloMsg.UUID)
		state.forwardersMu.Unlock()
		//wait for the connection to be closed
		<-conn.Context().Done()
		log.Printf("[platform] Forwarder connection for UUID=%s with id %p closed", helloMsg.UUID, conn)
	} else {
		log.Printf("[platform] Unknown role: %q for UUID=%s", helloMsg.Role, helloMsg.UUID)
	}
}

func generateTLSConfigFromConfig(cfg *common.Config) *tls.Config {
	certPath := cfg.CertPath
	keyPath := cfg.KeyPath
	if certPath == "" || keyPath == "" {
		log.Fatalf("[platform] CERT and KEY must be set in config or environment variables for TLS.\n  HINT: Set cert_path and key_path in config, CERT and KEY env vars, or --cert/--key CLI flags.\n  See ssh-platform.yaml.")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("[platform] Failed to load TLS cert/key (cert: %s, key: %s): %v\n  HINT: Check that the files exist, are readable, and are valid PEM files.", certPath, keyPath, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"ssh-agent-forwarder"},
	}
}
