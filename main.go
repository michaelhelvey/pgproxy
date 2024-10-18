package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/michaelhelvey/pgproxy/internal/codec"
	"github.com/michaelhelvey/pgproxy/internal/remote"
)

// -------------------------------------------------------------------------------------------------
// Global variables and initialization
// -------------------------------------------------------------------------------------------------

var logLevel = new(slog.LevelVar)
var configPath string

func parseFlags() {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stdout,
			&slog.HandlerOptions{AddSource: true, Level: logLevel},
		),
	)
	slog.SetDefault(logger)
	logLevelFlag := flag.String("log-level", "INFO", "set log level for program")
	flag.Parse()

	switch *logLevelFlag {
	case "DEBUG":
		logLevel.Set(slog.LevelDebug)
	case "INFO":
		logLevel.Set(slog.LevelInfo)
	case "WARN":
		logLevel.Set(slog.LevelWarn)
	case "ERROR":
		logLevel.Set(slog.LevelError)
	default:
		panic(fmt.Errorf("unknown log level: '%s'", *logLevelFlag))
	}

	if flag.NArg() < 1 {
		panic("expected config file option")
	}

	configPath = flag.Args()[0]
}

func writePacket(conn net.Conn, packet codec.Message) error {
	_, err := conn.Write(packet.Data)
	if err != nil {
		return fmt.Errorf("could not write packet of type %d back to client: %w", packet.Type, err)
	}

	return nil
}

// Reads from client connection until the startup sequence is complete and a remote connection
// is allocated
func handleClientStartup(client net.Conn, reader *bufio.Reader, configs []remote.ConfigEntry) error {
	for {
		message, err := codec.ReadMessage(reader)
		if err != nil {
			slog.Error("could not parse message from client", "error", err)
			client.Close()
			return nil
		}

		if message.Type == codec.MessageTypeTerminate {
			slog.Info("terminating connection", "clientAddr", client.RemoteAddr().String())
			client.Close()
			return nil
		}

		if message.Type == codec.MessageTypeSSLRequest {
			response := []byte{'N'}
			_, err = client.Write(response)
			if err != nil {
				return err
			}
		}

		if message.Type == codec.MessageTypeStartup {
			params, err := message.ParseStartupParameters()
			if err != nil {
				return err
			}
			slog.Debug("parsed startup parameters", "params", params)

			remoteConn, err := remote.GetOrAllocConnection(client, configs, &params.Params)
			if err != nil {
				return err
			}

			slog.Debug("allocated remote connection for new client", "client", remoteConn)

			if err = writePacket(client, codec.NewAuthenticationOkMessage()); err != nil {
				return err
			}

			// FIXME: need to respect remote for these packets
			if err = writePacket(client, codec.NewParameterStatus("client_encoding", "UTF8")); err != nil {
				return err
			}

			if err = writePacket(client, codec.NewParameterStatus("DateStyle", "ISO")); err != nil {
				return err
			}

			if err = writePacket(
				client,
				codec.NewNotice(
					fmt.Sprintf("PGPROXY: proxy successfully connected through to remote at: %s", remoteConn.RemoteAddr().String()),
				),
			); err != nil {
				return err
			}

			if err = writePacket(client, codec.NewReadyForQueryMessage(codec.BackendTransactionStatusIdle)); err != nil {
				return err
			}

			return nil
		}
	}
}

func handleClient(conn net.Conn, configs []remote.ConfigEntry) {
	addr := conn.RemoteAddr().String()
	slog.Info("handling new client connection", "addr", addr)
	reader := bufio.NewReader(conn)

	// 1) handle startup sequence
	err := handleClientStartup(conn, reader, configs)
	if err != nil {
		slog.Error("fatal: error in startup sequence", "error", err)
		conn.Close()
		return
	}

	remoteConn, err := remote.GetOrAllocConnection(conn, configs, nil)
	if err != nil {
		slog.Error("fatal: could not get remote connection after successful startup sequence", "error", err)
		conn.Close()
		return
	}

	slog.Debug("initializing bidirectional copy between client and remote")

	remoteReader := bufio.NewReader(remoteConn)

	var wg sync.WaitGroup

	wg.Add(2)
	client := make(chan bool)
	server := make(chan bool)

	go func() {
		// asynchronously copy every message from the remote back to the client
		defer func() {
			// when we exit, signal the client
			client <- true
		}()
		defer wg.Done()

		for {
			select {
			case <-server:
				slog.Info("server->client process: exiting because received quit flag")
				return
			default:
				message, err := codec.ReadMessage(remoteReader)
				if err != nil {
					slog.Error("fatal: error reading from remote", "error", err)
					return
				}
				slog.Debug("handling message from remote", "message", message)

				_, err = conn.Write(message.Data)

				if err != nil {
					slog.Error("fatal: error writing message to client", "error", err)
					return
				}
			}
		}
	}()

	go func() {
		// copy every message from the client to the remote
		defer func() {
			server <- true
		}()
		defer wg.Done()

		for {
			select {
			case <-client:
				slog.Info("client->server process: exiting because received quit flag")
				return
			default:
				message, err := codec.ReadMessage(reader)
				if err != nil {
					slog.Error("fatal: error reading client message", "error", err)
					return
				}
				slog.Debug("handling message from client", "message", message)

				if message.Type == codec.MessageTypeTerminate {
					slog.Info("client exiting after terminate message")
					return
				}

				_, err = remoteConn.Write(message.Data)

				if err != nil {
					slog.Error("fatal: error writing to remote", "error", err)
					return
				}
			}
		}
	}()

	wg.Wait()
	fmt.Println("CLEANING UP")
	err = remote.Cleanup(conn)
	if err != nil {
		slog.Error("error cleaning up remote connection", "error", err)
	}

	err = conn.Close()
	if err != nil {
		slog.Error("error cleaning up client connection", "error", err)
	}
	slog.Info("exiting from client handler", "client", conn.RemoteAddr().String())
}

func server() error {
	configs, err := remote.ReadConfigFromFile(configPath)
	if err != nil {
		return fmt.Errorf("could not read config from file: %w", err)
	}
	slog.Info("read proxy config", "config", configs)

	ln, err := net.Listen("tcp", "127.0.0.1:5433")
	if err != nil {
		return fmt.Errorf("could not listen on 5433: %w", err)
	}

	slog.Info("server listening on port 5433")

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("error accepting connection", "error", err)
		}

		go handleClient(conn, configs)
	}
}

func main() {
	parseFlags()

	err := server()
	if err != nil {
		panic(fmt.Errorf("could not start server: %w", err))
	}
}
