package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/michaelhelvey/pgproxy/internal/codec"
)

// -------------------------------------------------------------------------------------------------
// Global variables and initialization
// -------------------------------------------------------------------------------------------------

var logLevel = new(slog.LevelVar)

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
}

func writePacket(conn net.Conn, packet codec.Message) error {
	_, err := conn.Write(packet.Data)
	if err != nil {
		return fmt.Errorf("could not write packet of type %d back to client: %w", packet.Type, err)
	}

	return nil
}

func handleMessage(conn net.Conn, message *codec.Message) (bool, error) {
	var err error
	if message.Type == codec.MessageTypeTerminate {
		slog.Info("terminating connection", "clientAddr", conn.RemoteAddr().String())
		return true, nil
	}

	if message.Type == codec.MessageTypeSSLRequest {
		response := []byte{'N'}
		_, err = conn.Write(response)
		if err != nil {
			return false, err
		}

		return false, nil
	}

	if message.Type == codec.MessageTypeStartup {
		if err = writePacket(conn, codec.NewAuthenticationOkMessage()); err != nil {
			return false, err
		}

		if err = writePacket(conn, codec.NewParameterStatus("client_encoding", "UTF8")); err != nil {
			return false, err
		}

		// Some clients care about this parameter and will send a 'set datestyle' query if we don't
		// preempt it here...doesn't really matter but makes testing simpler with psycopg2
		if err = writePacket(conn, codec.NewParameterStatus("DateStyle", "ISO")); err != nil {
			return false, err
		}

		if err = writePacket(conn, codec.NewReadyForQueryMessage(codec.BackendTransactionStatusIdle)); err != nil {
			return false, err
		}

		return false, nil
	}

	return false, fmt.Errorf("unhandled message type %c", message.Type)
}

func handleClient(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	slog.Info("handling new client connection", "addr", addr)
	var parser codec.MessageParser
	reader := bufio.NewReader(conn)

	for {
		message, err := parser.ReadMessage(reader)
		if err != nil {
			slog.Error("could not parse message from client", "error", err)
			conn.Close()
			return
		}
		slog.Debug("parsed message from client", "addr", addr, "message", message)
		shouldClose, err := handleMessage(conn, message)
		if err != nil {
			slog.Error(fmt.Sprintf("error in message handler: %s", err))
		}

		if shouldClose {
			conn.Close()
			break
		}
	}
}

func server() error {
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

		go handleClient(conn)
	}
}

func main() {
	parseFlags()

	err := server()
	if err != nil {
		panic(fmt.Errorf("could not start server: %w", err))
	}
}
