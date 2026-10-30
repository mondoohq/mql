// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/mssql/connection"
	"go.mondoo.com/mql/providers/mssql/resources"
)

const (
	DefaultConnectionType = "mssql"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Options: map[string]string{},
	}

	flagString := func(name string) string {
		if x, ok := flags[name]; ok && len(x.Value) != 0 {
			return string(x.Value)
		}
		return ""
	}
	flagBool := func(name string) bool {
		if x, ok := flags[name]; ok {
			if b, ok := x.RawData().Value.(bool); ok {
				return b
			}
		}
		return false
	}

	// The target host may be given as the positional argument or via --host.
	if len(req.Args) > 0 {
		conf.Host = req.Args[0]
	}
	if h := flagString("host"); h != "" {
		conf.Host = h
	}

	for _, name := range []string{"instance", "database", "auth", "encrypt"} {
		if v := flagString(name); v != "" {
			conf.Options[name] = v
		}
	}
	// port is an int flag, so its primitive value is an int64, not a string.
	if x, ok := flags["port"]; ok {
		if p, ok := x.RawData().Value.(int64); ok && p != 0 {
			conf.Options["port"] = strconv.FormatInt(p, 10)
		}
	}
	if flagBool("trust-server-certificate") {
		conf.Options["trust-server-certificate"] = "true"
	}

	user := flagString("user")
	askPass := flagBool("ask-pass")

	// A token is a complete authentication method on its own; combining it with
	// a password is ambiguous, so reject that up front.
	if flagString("token") != "" && (flagString("password") != "" || askPass) {
		return nil, errors.New("cannot combine --token with --password or --ask-pass; choose one authentication method")
	}

	if token := flagString("token"); token != "" {
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:   vault.CredentialType_bearer,
			User:   user,
			Secret: []byte(token),
		})
	} else {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, flagString("password")))
	}

	// discovery flags
	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	} else {
		discoverTargets = []string{connection.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	// We only need to run the detection step when we don't have any asset information yet.
	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	inv, err := s.discover(conn)
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inv,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.MssqlConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.MssqlConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewMssqlConnection(connId, asset, conf)
		}
		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = conn.ID()
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.MssqlConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.MssqlConnection) error {
	instanceID := conn.InstanceID()

	// A database-scoped connection is a single-database asset discovered under
	// the instance; otherwise the asset is the instance itself.
	if db := conn.Database(); db != "" {
		if err := checkScopedDatabase(conn, db); err != nil {
			return err
		}
		id := connection.NewMssqlDatabaseIdentifier(instanceID, db)
		asset.Id = id
		asset.Name = db
		asset.Platform = connection.NewMssqlDatabasePlatform(instanceID, db)
		asset.PlatformIds = []string{id}
		return nil
	}

	// Confirm reachability and enrich the platform with the product version.
	client, err := conn.Client()
	if err != nil {
		return err
	}
	var version string
	if err := client.QueryRowContext(context.Background(),
		"SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128))").Scan(&version); err != nil {
		return err
	}

	id := connection.NewMssqlInstanceIdentifier(instanceID)
	asset.Id = id
	asset.Name = instanceID
	asset.Platform = connection.NewMssqlInstancePlatform(instanceID)
	asset.Platform.Version = version
	asset.PlatformIds = []string{id}
	return nil
}

// checkScopedDatabase confirms a --database scope names a database the scan
// can open. Without it the connection is never dialed until the first query,
// so a missing or OFFLINE database failed every field separately and the run
// still exited 0.
func checkScopedDatabase(conn *connection.MssqlConnection, db string) error {
	client, err := conn.Client()
	if err != nil {
		return err
	}
	// DATABASEPROPERTYEX reads the state without needing VIEW ANY DATABASE,
	// and is NULL for a database that does not exist.
	var state sql.NullString
	err = client.QueryRowContext(context.Background(),
		"SELECT CAST(DATABASEPROPERTYEX(@p1, 'Status') AS NVARCHAR(60))", sql.Named("p1", db)).Scan(&state)
	if err != nil {
		return fmt.Errorf("cannot open database %q: %w", db, err)
	}
	return scopedDatabaseState(db, state)
}

// scopedDatabaseState turns the status of the scoped database into an error
// unless the database exists and is ONLINE.
func scopedDatabaseState(db string, state sql.NullString) error {
	if !state.Valid {
		return fmt.Errorf("database %q not found on the instance", db)
	}
	if state.String != "ONLINE" {
		return fmt.Errorf("database %q is %s, not ONLINE", db, state.String)
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
