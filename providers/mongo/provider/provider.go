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
	"go.mondoo.com/mql/providers/mongo/connection"
	"go.mondoo.com/mql/providers/mongo/resources"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	DefaultConnectionType = "mongo"
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

	if len(req.Args) > 0 {
		conf.Host = req.Args[0]
	}
	if h := flagString("host"); h != "" {
		conf.Host = h
	}

	for _, name := range []string{"auth-db", "tls-ca"} {
		if v := flagString(name); v != "" {
			conf.Options[name] = v
		}
	}
	if flagBool("tls") {
		conf.Options["tls"] = "true"
	}
	if flagBool("tls-insecure") {
		conf.Options["tls-insecure"] = "true"
	}
	if x, ok := flags["port"]; ok {
		if p, ok := x.RawData().Value.(int64); ok && p != 0 {
			conf.Options["port"] = strconv.FormatInt(p, 10)
		}
	}

	user := flagString("user")
	if user != "" || flagString("password") != "" || flagBool("ask-pass") {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, flagString("password")))
	}
	// Take a password out of a mongodb:// host before it lands in the asset.
	// Runs after the flags so --user and --password win over the host's
	// user info.
	connection.MoveURICredentials(conf)

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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.MongoConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.MongoConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewMongoConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.MongoConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.MongoConnection) error {
	serverID := conn.ServerID()

	if db := conn.ScopedDatabase(); db != "" {
		id := connection.NewMongoDatabaseIdentifier(serverID, db)
		asset.Id = id
		asset.Name = db
		asset.Platform = connection.NewMongoDatabasePlatform(serverID, db)
		asset.PlatformIds = []string{id}
		return nil
	}

	var buildInfo bson.M
	if err := conn.RunAdminCommand(bson.D{{Key: "buildInfo", Value: 1}}, &buildInfo); err != nil {
		return err
	}

	id := connection.NewMongoServerIdentifier(serverID)
	asset.Id = id
	asset.Name = conn.DisplayName()
	asset.Platform = connection.NewMongoServerPlatform(serverID)
	if v, ok := buildInfo["version"].(string); ok {
		asset.Platform.Version = v
	}
	asset.PlatformIds = []string{id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
