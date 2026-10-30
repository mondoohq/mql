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
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/providers/portainer/resources"
)

const (
	DefaultConnectionType = "portainer"
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

	// The instance address is given positionally, like other host-target
	// providers (e.g. `cnspec scan portainer portainer.example.com:9443`). The --address
	// flag is kept as an explicit alternative, and the connection falls back to
	// PORTAINER_ADDRESS when neither is set.
	if len(req.Args) > 0 && req.Args[0] != "" {
		conf.Options[connection.OptionAddress] = req.Args[0]
	} else if x, ok := flags["address"]; ok && len(x.Value) != 0 {
		conf.Options[connection.OptionAddress] = string(x.Value)
	}

	if x, ok := flags["insecure"]; ok {
		if v, isBool := x.RawData().Value.(bool); isBool && v {
			conf.Options[connection.OptionInsecure] = "true"
		}
	}

	if x, ok := flags["access-token"]; ok && len(x.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(x.Value)))
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.PortainerConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewPortainerConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.PortainerConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.PortainerConnection) error {
	// A connection scoped to a discovered environment describes that
	// environment rather than the instance as a whole.
	if platform, platformID, name := conn.SubAssetPlatform(); platform != nil {
		asset.Name = name
		asset.Platform = platform
		asset.PlatformIds = []string{platformID}
		return nil
	}

	// keep a user-provided asset name; otherwise label it "Portainer Server <hostname>"
	// (falling back to plain "Portainer Server" when the hostname is unknown)
	if asset.Name == "" {
		asset.Name = "Portainer Server"
		if h := conn.Hostname(); h != "" {
			asset.Name = "Portainer Server " + h
		}
	}
	platform := connection.InstancePlatform()
	// `asset.version` is the canonical, cross-provider way to ask what version
	// something is, and every root carries `asset` (ADR 031). The connection
	// already knows it.
	platform.Version = conn.Version()
	asset.Platform = platform
	asset.PlatformIds = []string{connection.NewInstancePlatformID(conn.InstanceKey())}
	return nil
}

func (s *Service) discover(conn *connection.PortainerConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime)
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
