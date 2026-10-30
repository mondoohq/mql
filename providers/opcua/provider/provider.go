// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"

	"github.com/mozillazg/go-slugify"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/opcua/connection"
	"go.mondoo.com/mql/providers/opcua/resources"
)

const ConnectionType = "opcua"

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
		Options: make(map[string]string),
	}

	// Do custom flag parsing. Every option key the connection reads has to be
	// copied here: a key that is never written is silently absent from
	// conf.Options and the flag behind it becomes a no-op.
	for flag, option := range map[string]string{
		"endpoint":        connection.OptionEndpoint,
		"security-policy": connection.OptionSecurityPolicy,
		"security-mode":   connection.OptionSecurityMode,
		"cert-file":       connection.OptionCertFile,
		"key-file":        connection.OptionKeyFile,
	} {
		if x, ok := flags[flag]; ok && len(x.Value) != 0 {
			conf.Options[option] = string(x.Value)
		}
	}

	username := ""
	if x, ok := flags["username"]; ok && len(x.Value) != 0 {
		username = string(x.Value)
	}
	password := ""
	if x, ok := flags["password"]; ok && len(x.Value) != 0 {
		password = string(x.Value)
	}
	if username != "" || password != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(username, password))
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.OpcuaConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewOpcuaConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.OpcuaConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.OpcuaConnection) error {
	asset.Name = conn.Conf.Host

	asset.Platform = &inventory.Platform{}
	PlatformByName("opcua").Apply(asset.Platform)

	// Add platform ID
	endpoint := conn.Endpoint()
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/opcua/" + slugify.Slugify(endpoint)}
	return nil
}
