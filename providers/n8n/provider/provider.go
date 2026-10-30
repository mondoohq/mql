// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/n8n/connection"
	"go.mondoo.com/mql/providers/n8n/resources"
)

const (
	DefaultConnectionType = "n8n"
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
		conf.Options[connection.OptionURL] = req.Args[0]
	}
	if u := flagString("url"); u != "" {
		conf.Options[connection.OptionURL] = u
	}

	apiKey := flagString("api-key")
	if apiKey == "" {
		apiKey = os.Getenv(connection.EnvAPIKeyVar)
	}
	if apiKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))
	}

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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.N8nConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewN8nConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.N8nConnection), nil
}

// detect identifies the instance by its address. The Public API exposes no
// instance ID, so the host is the stable key.
func (s *Service) detect(asset *inventory.Asset, conn *connection.N8nConnection) error {
	host := connection.InstanceHost(conn.InstanceURL())
	id := connection.NewN8nInstanceIdentifier(host)
	asset.Id = id
	asset.Name = "n8n " + host
	asset.Platform = connection.NewN8nInstancePlatform(host)
	asset.PlatformIds = []string{id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
