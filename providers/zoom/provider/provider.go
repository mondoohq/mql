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
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/zoom/connection"
	"go.mondoo.com/mql/providers/zoom/resources"
)

const (
	DefaultConnectionType = "zoom"

	// PlatformIDZoomAccount is the platform id prefix for a Zoom account.
	PlatformIDZoomAccount = "//platformid.api.mondoo.app/runtime/zoom/account/"
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

	if v, ok := flags[connection.OPTION_ACCOUNT_ID]; ok && len(v.Value) != 0 {
		conf.Options[connection.OPTION_ACCOUNT_ID] = string(v.Value)
	}
	if v, ok := flags[connection.OPTION_CLIENT_ID]; ok && len(v.Value) != 0 {
		conf.Options[connection.OPTION_CLIENT_ID] = string(v.Value)
	}
	if v, ok := flags[connection.OPTION_CLIENT_SECRET]; ok && len(v.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}

	return &plugin.ParseCLIRes{
		Asset: &inventory.Asset{
			Name:        "Zoom",
			Connections: []*inventory.Config{conf},
		},
	}, nil
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ZoomConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewZoomConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		// Verify access to the Zoom account
		if err := conn.Verify(); err != nil {
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

	return runtime.Connection.(*connection.ZoomConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.ZoomConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = "Zoom account " + conn.AccountID()

	asset.Platform = &inventory.Platform{
		Name:    "zoom",
		Family:  []string{"zoom"},
		Kind:    "api",
		Runtime: "zoom",
		Title:   "Zoom",
	}

	asset.PlatformIds = []string{PlatformIDZoomAccount + conn.AccountID()}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
