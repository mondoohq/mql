// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/exoscale/connection"
	"go.mondoo.com/mql/providers/exoscale/resources"
)

const DefaultConnectionType = "exoscale"

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

	var key, secret string
	if v, ok := flags[connection.OPTION_API_KEY]; ok && len(v.Value) != 0 {
		key = string(v.Value)
	}
	if v, ok := flags[connection.OPTION_API_SECRET]; ok && len(v.Value) != 0 {
		secret = string(v.Value)
	}
	if key != "" || secret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(key, secret))
	}

	// --filters keys the provider does not know are dropped, so a typo reads
	// as a filter that did nothing rather than one that appears accepted.
	if v, ok := flags["filters"]; ok {
		for k, val := range v.Map {
			if slices.Contains(connection.FilterOptKeys, k) {
				conf.Options[k] = string(val.Value)
			}
		}
	}

	if v, ok := flags[connection.OPTION_ZONES]; ok && len(v.Array) != 0 {
		zones := make([]string, 0, len(v.Array))
		for i := range v.Array {
			zones = append(zones, string(v.Array[i].Value))
		}
		conf.Options[connection.OPTION_ZONES] = strings.Join(zones, ",")
	}

	// Discovery expands the organization into child assets. Default to "auto"
	// so a plain `exoscale` scan surfaces them alongside the organization.
	discoverTargets := []string{connection.DiscoveryAuto}
	if v, ok := flags["discover"]; ok && len(v.Array) != 0 {
		discoverTargets = discoverTargets[:0]
		for i := range v.Array {
			discoverTargets = append(discoverTargets, string(v.Array[i].Value))
		}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	asset := &inventory.Asset{
		Name:        "Exoscale",
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

func (s *Service) discover(conn *connection.ExoscaleConnection) (*inventory.Inventory, error) {
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ExoscaleConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewExoscaleConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.ExoscaleConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.ExoscaleConnection) error {
	// A connection scoped to a single discovered child asset carries its kind
	// and id in the connection options; surface that platform instead of the
	// organization.
	if sub, id, ok := conn.SubAsset(); ok {
		platformID := conn.SubAssetIdentifier(sub, conn.Conf.Options[connection.OptionZone], id)
		asset.Id = platformID
		asset.Platform = sub.NewPlatform()
		asset.PlatformIds = []string{platformID}
		if asset.Name == "" {
			asset.Name = sub.Title + " " + id
		}
		return nil
	}

	asset.Id = conn.Conf.Type
	asset.Platform = conn.PlatformInfo()
	asset.PlatformIds = []string{conn.Identifier()}
	// Replace only the generic CLI default; an inventory-supplied name wins.
	if asset.Name == "" || asset.Name == "Exoscale" {
		asset.Name = "Exoscale"
		if org := conn.Org(); org != nil && org.Name != "" {
			asset.Name = "Exoscale " + org.Name
		}
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
