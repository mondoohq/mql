// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/openai/connection"
	"go.mondoo.com/mql/providers/openai/resources"
)

const (
	DefaultConnectionType = "openai"
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

	if token, ok := flags["token"]; ok {
		conf.Options[connection.TokenOption] = string(token.Value)
	}

	if adminToken, ok := flags["admin-token"]; ok {
		conf.Options[connection.AdminTokenOption] = string(adminToken.Value)
	}

	if org, ok := flags["organization"]; ok {
		conf.Options[connection.OrganizationOption] = string(org.Value)
	}

	if project, ok := flags["project"]; ok {
		conf.Options[connection.ProjectOption] = string(project.Value)
	}

	if baseURL, ok := flags["base-url"]; ok {
		conf.Options[connection.BaseURLOption] = string(baseURL.Value)
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.OpenaiConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewOpenaiConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.OpenaiConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.OpenaiConnection) error {
	orgName := conn.OrganizationName()
	orgID := conn.Organization()

	name := "OpenAI"
	if orgName != "" {
		name = "OpenAI (" + orgName + ")"
	} else if orgID != "" {
		name = "OpenAI (" + orgID + ")"
	}

	identifier := conn.Identifier()
	asset.Name = name
	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"ai", "openai", identifier},
	}
	connection.PlatformByName("openai").Apply(asset.Platform)

	asset.PlatformIds = []string{conn.PlatformId()}

	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
