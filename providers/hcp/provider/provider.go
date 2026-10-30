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
	"go.mondoo.com/mql/providers/hcp/connection"
	"go.mondoo.com/mql/providers/hcp/resources"
)

const (
	DefaultConnectionType = "hcp"
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

	flagOrEnv := func(name, env string) string {
		if x, ok := flags[name]; ok && len(x.Value) != 0 {
			return string(x.Value)
		}
		return os.Getenv(env)
	}

	clientID := flagOrEnv("client-id", "HCP_CLIENT_ID")
	clientSecret := flagOrEnv("client-secret", "HCP_CLIENT_SECRET")
	orgID := flagOrEnv("org-id", "HCP_ORGANIZATION_ID")
	projectID := flagOrEnv("project-id", "HCP_PROJECT_ID")

	// A project id scopes to a single project; otherwise the connection is
	// rooted at the organization and discovers its projects.
	if projectID != "" {
		conf.Options[connection.OptionScope] = connection.ScopeProject
		conf.Options[connection.OptionProjectID] = projectID
	} else {
		conf.Options[connection.OptionScope] = connection.ScopeOrg
	}
	if orgID != "" {
		conf.Options[connection.OptionOrgID] = orgID
	}
	if clientID != "" {
		conf.Options[connection.OptionClientID] = clientID
	}
	if clientSecret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(connection.CredentialClientSecret, clientSecret))
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

	// We only need to run the detection step when we don't have any asset
	// information yet (discovered child assets arrive with a platform set).
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.HcpConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.HcpConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewHcpConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.HcpConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.HcpConnection) error {
	// Resolve the organization id up front so the org asset's platform id and
	// name are populated even when --org-id was not supplied.
	if conn.Scope() == connection.ScopeOrg {
		if _, err := conn.EnsureOrgID(context.Background()); err != nil {
			return err
		}
	}

	platform, err := conn.PlatformInfo()
	if err != nil {
		return err
	}
	asset.Platform = platform

	switch conn.Scope() {
	case connection.ScopeOrg:
		asset.Id = "hcp-org-" + conn.OrgID()
		asset.Name = "HCP organization " + conn.OrgID()
		asset.PlatformIds = []string{connection.NewPlatformID(connection.ScopeOrg, conn.OrgID())}
	case connection.ScopeProject:
		asset.Id = "hcp-project-" + conn.ProjectID()
		if asset.Name == "" {
			asset.Name = "HCP project " + conn.ProjectID()
		}
		asset.PlatformIds = []string{connection.NewPlatformID(connection.ScopeProject, conn.ProjectID())}
	default:
		asset.Id = "hcp-" + conn.Scope() + "-" + conn.ResourceID()
		if asset.Name == "" {
			asset.Name = "HCP " + conn.Scope() + " " + conn.ResourceID()
		}
		asset.PlatformIds = []string{connection.NewPlatformID(conn.Scope(), conn.ProjectID(), conn.ResourceID())}
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
