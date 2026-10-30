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
	"go.mondoo.com/mql/providers/redisdb/connection"
	"go.mondoo.com/mql/providers/redisdb/resources"
)

const (
	DefaultConnectionType = "redisdb"
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

	for _, name := range []string{"tls-ca", "tls-cert", "tls-key"} {
		if v := flagString(name); v != "" {
			conf.Options[name] = v
		}
	}
	for _, name := range []string{"tls", "tls-insecure"} {
		if x, ok := flags[name]; ok && x.RawData().Value == true {
			conf.Options[name] = "true"
		}
	}
	for _, name := range []string{"port", "database"} {
		if x, ok := flags[name]; ok {
			if v, ok := x.RawData().Value.(int64); ok && v != 0 {
				conf.Options[name] = strconv.FormatInt(v, 10)
			}
		}
	}

	user := flagString("user")
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, flagString("password")))

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

	return &plugin.ConnectRes{
		Id:    conn.ID(),
		Name:  conn.Name(),
		Asset: req.Asset,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.RedisdbConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.RedisdbConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewRedisdbConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.RedisdbConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.RedisdbConnection) error {
	serverID := conn.ServerID()

	client, err := conn.Client()
	if err != nil {
		return err
	}
	info, err := client.Info(conn.Context(), "server").Result()
	if err != nil {
		return err
	}
	fields := connection.ParseInfo(info)

	title := "Redis"
	version := fields["redis_version"]
	if fields["valkey_version"] != "" || fields["server_name"] == "valkey" {
		title = "Valkey"
		if v := fields["valkey_version"]; v != "" {
			version = v
		}
	}

	id := connection.NewRedisServerIdentifier(serverID)
	asset.Id = id
	asset.Name = conn.Conf.Host
	asset.Platform = connection.NewRedisServerPlatform(serverID, title)
	asset.Platform.Version = version
	asset.PlatformIds = []string{id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
