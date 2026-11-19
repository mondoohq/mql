// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/codesphere/connection"
	"go.mondoo.com/mql/providers/codesphere/resources"
)

const (
	DefaultConnectionType = "codesphere"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

// flagOrEnv returns a string flag, or the environment variable when the flag
// is unset.
func flagOrEnv(flags map[string]*llx.Primitive, name, env string) string {
	if x, ok := flags[name]; ok && len(x.Value) != 0 {
		return string(x.Value)
	}
	return os.Getenv(env)
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

	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	} else {
		discoverTargets = []string{connection.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	apiURL := flagOrEnv(flags, "api", "CS_API")
	if _, err := connection.ParseAPIURL(apiURL); err != nil {
		return nil, err
	}
	if apiURL != "" {
		conf.Options[connection.OptionAPIURL] = apiURL
	}
	if v := flagOrEnv(flags, "org", "CS_ORG_ID"); v != "" {
		conf.Options[connection.OptionOrgFilter] = v
	}
	if v := flagOrEnv(flags, "resource-group", "CS_RESOURCE_GROUP_ID"); v != "" {
		conf.Options[connection.OptionResourceGroupID] = v
	}

	if token := flagOrEnv(flags, "token", "CS_TOKEN"); token != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))
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

	// Discovered child assets arrive with their platform already set.
	if req.Asset.Platform == nil {
		s.detect(req.Asset, conn)
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
		// Which kind this asset actually is; the static Root can only name one
		// for a provider serving several (ADR 031).
		Root: assetRoot(req.Asset.GetPlatform()),
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.CodesphereConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewCodesphereConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.CodesphereConnection), nil
}

// detect stamps the connection asset as the installation: the catalog
// (images, plans, data centers, service providers) and everything that sits
// outside an organization. It is identified by the API host, since nothing in
// the API names the installation or the token's owner.
func (s *Service) detect(asset *inventory.Asset, conn *connection.CodesphereConnection) {
	host := conn.Host()
	asset.Platform = connection.NewInstallationPlatform(host)
	asset.PlatformIds = []string{connection.InstallationID(host)}
	if asset.Name == "" {
		asset.Name = "Codesphere " + host
	}
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
