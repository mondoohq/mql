// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
	"go.mondoo.com/mql/v13/providers/gusto/connection"
	"go.mondoo.com/mql/v13/providers/gusto/resources"
)

const (
	DefaultConnectionType = "gusto"
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

	token := ""
	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		token = string(x.Value)
	}
	if token == "" {
		token = os.Getenv("GUSTO_API_TOKEN")
	}
	if token == "" {
		return nil, errors.New("no Gusto token provided, use --token or GUSTO_API_TOKEN")
	}
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))

	if x, ok := flags["api-base"]; ok && len(x.Value) != 0 {
		conf.Options["api-base"] = string(x.Value)
	}
	if x, ok := flags["api-version"]; ok && len(x.Value) != 0 {
		conf.Options["api-version"] = string(x.Value)
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
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.GustoConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewGustoConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		var upstreamClient *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstreamClient, err = req.Upstream.InitClient(context.Background())
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
			upstreamClient), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.GustoConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.GustoConnection) error {
	id, err := conn.Identifier(context.Background())
	if err != nil {
		return err
	}
	asset.Id = "gusto"
	asset.Name = "Gusto company " + id
	asset.Platform = &inventory.Platform{
		Name:                  "gusto",
		Family:                []string{"gusto"},
		Kind:                  "api",
		Title:                 "Gusto",
		Runtime:               "gusto",
		TechnologyUrlSegments: []string{"saas", "gusto", "company"},
	}
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/gusto/company/" + id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
