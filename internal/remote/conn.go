package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/michaelhelvey/pgproxy/internal/codec"
)

var AssociatedClients = make(map[net.Conn]*pgx.Conn)

func GetOrAllocConnection(client net.Conn, configs []ConfigEntry, params *codec.ConnectionParams) (remote net.Conn, err error) {

	if params == nil {
		remote := AssociatedClients[client]
		if remote == nil {
			return nil, errors.New("no associated client")
		}

		return remote.PgConn().Conn(), nil
	}

	var entry *ConfigEntry = nil
	for _, e := range configs {
		if e.Match.Database == (*params)["database"] {
			entry = &e
		}
	}

	if entry == nil {
		return nil, fmt.Errorf("could not match against database=%s", (*params)["database"])
	}

	provider := getProvider(entry.Provider)
	if provider == nil {
		return nil, fmt.Errorf("could not identify auth provider for type %s", entry.Provider)
	}

	conn, err := provider.GetConnection(entry.ProviderMeta)
	if err != nil {
		return nil, err
	}

	AssociatedClients[client] = conn
	return AssociatedClients[client].PgConn().Conn(), nil
}

func Cleanup(client net.Conn) error {
	remote := AssociatedClients[client]
	if remote == nil {
		return errors.New("no associated client")
	}

	return remote.Close(context.Background())
}

type ConfigMatch struct {
	// for now just match on the database of the connection params
	Database string `json:"database"`
}

type ConfigEntry struct {
	// human readable identifier for the entry
	Name string `json:"name"`
	// how to identify the connection based on params
	Match ConfigMatch `json:"match"`
	// what type to cast provider meta to
	Provider string `json:"provider"`
	// some kind data used by the provider
	ProviderMeta map[string]string `json:"provider_meta"`
}

type ConfigProvider interface {
	GetConnection(metadata map[string]string) (*pgx.Conn, error)
}

type StaticProvider struct{}

func (p StaticProvider) GetConnection(metadata map[string]string) (*pgx.Conn, error) {
	url := metadata["url"]
	if len(url) == 0 {
		return nil, errors.New("not able to find required 'url' key on provider_meta")
	}

	slog.Info("StaticProvider: getting new connection from url", "url", url)

	return pgx.Connect(context.Background(), url)
}

func getProvider(typ string) ConfigProvider {
	switch typ {
	case "static":
		return StaticProvider{}
	default:
		return nil
	}
}

func ReadConfigFromFile(path string) ([]ConfigEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []ConfigEntry
	err = json.Unmarshal(data, &entries)
	if err != nil {
		return nil, err
	}

	return entries, nil
}
