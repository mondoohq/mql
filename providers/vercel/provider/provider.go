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
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/providers/vercel/resources"
)

const (
	DefaultConnectionType = "vercel"
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

	// discovery flags
	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	} else {
		discoverTargets = []string{connection.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	// optional team scoping
	if x, ok := flags["team"]; ok && len(x.Value) != 0 {
		conf.Options["team"] = string(x.Value)
	}

	token := ""
	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		token = string(x.Value)
	}
	if token == "" {
		token = os.Getenv("VERCEL_TOKEN")
	}
	if token == "" {
		token = os.Getenv("VERCEL_API_TOKEN")
	}
	if token != "" {
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
		// Which kind this asset actually is; the static Root can only name one
		// for a provider serving several (ADR 031).
		Root: assetRoot(req.Asset.GetPlatform()),
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.VercelConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.VercelConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewVercelConnection(connId, asset, conf)
		}
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

	return runtime.Connection.(*connection.VercelConnection), nil
}

// detect leaves the root connection asset without a fixed platform: it is a
// discovery root that emits vercel-team and vercel-project child assets.
func (s *Service) detect(asset *inventory.Asset, conn *connection.VercelConnection) error {
	// When the asset is already scoped to a specific team or project (a
	// discovered child asset), stamp the matching platform.
	conf := conn.Asset().Connections[0]
	if projectID := conf.Options["projectId"]; projectID != "" {
		asset.Platform = connection.NewVercelProjectPlatform(conf.Options["teamId"], projectID)
		asset.PlatformIds = []string{connection.NewVercelProjectIdentifier(projectID)}
		return nil
	}
	if teamID := conf.Options["teamId"]; teamID != "" {
		asset.Platform = connection.NewVercelTeamPlatform(teamID)
		asset.PlatformIds = []string{connection.NewVercelTeamIdentifier(teamID)}
		return nil
	}

	// The unscoped root is a discovery root that emits team and project child
	// assets. Give it a stable name so it does not surface as an empty label.
	if asset.Name == "" {
		asset.Name = "Vercel"
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
