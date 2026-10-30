// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/mysqldb/connection"
	"go.mondoo.com/mql/providers/mysqldb/resources"
)

const (
	DefaultConnectionType = "mysqldb"
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

	if len(req.Args) > 0 {
		conf.Host = req.Args[0]
	}
	if h := flagString("host"); h != "" {
		conf.Host = h
	}

	for _, name := range []string{"database", "tls-mode", "tls-ca", "tls-cert", "tls-key", "tls-server-name"} {
		if v := flagString(name); v != "" {
			conf.Options[name] = v
		}
	}
	if x, ok := flags["port"]; ok {
		if p, ok := x.RawData().Value.(int64); ok && p != 0 {
			conf.Options["port"] = strconv.FormatInt(p, 10)
		}
	}

	user := flagString("user")
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, flagString("password")))

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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.MysqldbConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.MysqldbConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewMysqldbConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.MysqldbConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.MysqldbConnection) error {
	serverID, err := conn.ServerID()
	if err != nil {
		return err
	}
	flavor, err := conn.Flavor()
	if err != nil {
		return err
	}

	if db := conn.ScopedDatabase(); db != "" {
		id := connection.NewMysqldbDatabaseIdentifier(serverID, db)
		asset.Id = id
		asset.Name = db
		asset.Platform = connection.NewMysqldbDatabasePlatform(serverID, db)
		asset.PlatformIds = []string{id}
		return nil
	}

	client, err := conn.Client()
	if err != nil {
		return err
	}
	var version string
	if err := client.QueryRowContext(context.Background(), "SELECT @@version").Scan(&version); err != nil {
		return err
	}

	id := connection.NewMysqldbServerIdentifier(serverID)
	asset.Id = id
	asset.Name = conn.Conf.Host
	asset.Platform = connection.NewMysqldbServerPlatform(serverID, flavor)
	asset.Platform.Version = version
	asset.PlatformIds = []string{id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
