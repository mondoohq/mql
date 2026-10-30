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
	"go.mondoo.com/mql/providers/hetzner/connection"
	"go.mondoo.com/mql/providers/hetzner/resources"
)

const DefaultConnectionType = "hetzner"

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

	if v, ok := flags[connection.OPTION_TOKEN]; ok && len(v.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}
	if v, ok := flags[connection.OPTION_ENDPOINT]; ok && len(v.Value) != 0 {
		conf.Options[connection.OPTION_ENDPOINT] = string(v.Value)
	}

	// Discovery expands the project into specific child assets (firewalls
	// and load balancers). Default to "auto" so a plain `hetzner` scan
	// surfaces per-resource assets alongside the project.
	discoverTargets := []string{connection.DiscoveryAuto}
	if v, ok := flags["discover"]; ok && len(v.Array) != 0 {
		discoverTargets = discoverTargets[:0]
		for i := range v.Array {
			discoverTargets = append(discoverTargets, string(v.Array[i].Value))
		}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	asset := &inventory.Asset{
		Name:        "Hetzner Cloud",
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: asset}, nil
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

func (s *Service) discover(conn *connection.HetznerConnection) (*inventory.Inventory, error) {
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.HetznerConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewHetznerConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

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

	return runtime.Connection.(*connection.HetznerConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.HetznerConnection) error {
	// A connection scoped to a single discovered sub-asset carries its
	// type and id in the connection options; surface the specific
	// platform for it instead of the project root.
	if platform, platformID, name := conn.SubAssetPlatform(); platform != nil {
		asset.Id = platformID
		asset.Name = name
		asset.Platform = platform
		asset.PlatformIds = []string{platformID}
		return nil
	}

	asset.Id = conn.Conf.Type
	asset.Platform = conn.PlatformInfo()
	asset.PlatformIds = []string{conn.Identifier()}
	if asset.Name == "" {
		asset.Name = "Hetzner Cloud"
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
