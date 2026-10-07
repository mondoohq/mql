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
	"go.mondoo.com/mql/providers/ibm/connection"
	"go.mondoo.com/mql/providers/ibm/resources"
)

const DefaultConnectionType = "ibm"

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

	if v, ok := flags["api-key"]; ok && len(v.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}
	if v, ok := flags[connection.OptionAPIKeyFile]; ok && len(v.Value) != 0 {
		conf.Options[connection.OptionAPIKeyFile] = string(v.Value)
	}
	if v, ok := flags[connection.OptionRegions]; ok && len(v.Array) != 0 {
		regions := make([]string, 0, len(v.Array))
		for i := range v.Array {
			regions = append(regions, string(v.Array[i].Value))
		}
		conf.Options[connection.OptionRegions] = strings.Join(regions, ",")
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

	// Discovery expands the account into child assets. Default to "auto"
	// so a plain `ibm` scan surfaces them alongside the account.
	discoverTargets := []string{connection.DiscoveryAuto}
	if v, ok := flags["discover"]; ok && len(v.Array) != 0 {
		discoverTargets = discoverTargets[:0]
		for i := range v.Array {
			discoverTargets = append(discoverTargets, string(v.Array[i].Value))
		}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	asset := &inventory.Asset{
		Name:        "IBM Cloud",
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

func (s *Service) discover(conn *connection.IbmConnection) (*inventory.Inventory, error) {
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.IbmConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewIbmConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.IbmConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.IbmConnection) error {
	// A connection scoped to a single discovered child asset carries its kind
	// and id in the connection options; surface that platform instead of the
	// organization.
	if sub, id, ok := conn.SubAsset(); ok {
		platformID := conn.SubAssetIdentifier(sub, id)
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
	if asset.Name == "" || asset.Name == "IBM Cloud" {
		asset.Name = "IBM Cloud account " + conn.AccountID()
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
