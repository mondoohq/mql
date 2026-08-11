// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/v13/providers/firebase/connection"
	"go.mondoo.com/mql/v13/providers/firebase/resources"
)

const (
	DefaultConnectionType = "firebase"
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

	if x, ok := flags["project-id"]; ok && len(x.Value) != 0 {
		conf.Options["project-id"] = string(x.Value)
	}
	if x, ok := flags["api-key"]; ok && len(x.Value) != 0 {
		conf.Options["api-key"] = string(x.Value)
	}
	if x, ok := flags["domain"]; ok && len(x.Value) != 0 {
		conf.Options["domain"] = string(x.Value)
	}

	// Treat first positional argument as domain
	if len(req.Args) > 0 {
		conf.Options["domain"] = req.Args[0]
	}

	name := "Firebase"
	if pid, ok := conf.Options["project-id"]; ok && pid != "" {
		name = "Firebase Project " + pid
	} else if d, ok := conf.Options["domain"]; ok && d != "" {
		name = "Firebase " + d
	}

	asset := inventory.Asset{
		Name:        name,
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.FirebaseConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewFirebaseConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		var up *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			up, err = req.Upstream.InitClient(context.Background())
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
			up), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.FirebaseConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.FirebaseConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = conn.Name()
	if conn.ProjectId() != "" {
		asset.Name = "Firebase Project " + conn.ProjectId()
	} else if conn.Domain() != "" {
		asset.Name = "Firebase " + conn.Domain()
	}

	asset.Platform = conn.PlatformInfo()
	asset.PlatformIds = []string{conn.Identifier()}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
