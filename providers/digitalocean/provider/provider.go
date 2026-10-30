// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/providers/digitalocean/resources"
)

const (
	DefaultConnectionType = "digitalocean"
)

// filterOptPrefixes are the --filters keys the provider understands. Anything
// else is dropped rather than silently stored, so a typo surfaces as a filter
// that plainly did nothing instead of one that appears accepted.
var filterOptPrefixes = []string{
	"regions",
	"exclude:regions",
	"tags",
	"exclude:tags",
}

// parseFlagsToFiltersOpts flattens the --filters key-value flag into connection
// options the connection reads back through DiscoveryFiltersFromOpts.
func parseFlagsToFiltersOpts(flags map[string]*llx.Primitive) map[string]string {
	opts := map[string]string{}

	x, ok := flags["filters"]
	if !ok || len(x.Map) == 0 {
		return opts
	}
	for k, v := range x.Map {
		if slices.Contains(filterOptPrefixes, k) {
			opts[k] = string(v.Value)
		}
	}
	return opts
}

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
		token = os.Getenv("DIGITALOCEAN_TOKEN")
	}
	if token != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))
	}

	// Discovery expands the account into specific child assets
	// (databases, Kubernetes clusters, load balancers, firewalls,
	// Spaces buckets, and GradientAI agents). Default to "auto" so a
	// plain `digitalocean` scan surfaces per-resource assets alongside
	// the account.
	discoverTargets := []string{connection.DiscoveryAuto}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		discoverTargets = discoverTargets[:0]
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	maps.Copy(conf.Options, parseFlagsToFiltersOpts(flags))

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

func (s *Service) discover(conn *connection.DigitaloceanConnection) (*inventory.Inventory, error) {
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.DigitaloceanConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewDigitaloceanConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.DigitaloceanConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.DigitaloceanConnection) error {
	// A connection scoped to a single discovered sub-asset carries its
	// type and id in the connection options; surface the specific
	// platform for it instead of the account root.
	if platform, platformID, name := conn.SubAssetPlatform(); platform != nil {
		asset.Id = platformID
		asset.Name = name
		asset.Platform = platform
		asset.PlatformIds = []string{platformID}
		return nil
	}

	asset.Id = conn.Conf.Type
	asset.Name = "DigitalOcean Account"
	asset.Platform = connection.AccountPlatform()
	asset.PlatformIds = []string{connection.NewAccountIdentifier(conn.AccountUUID())}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
