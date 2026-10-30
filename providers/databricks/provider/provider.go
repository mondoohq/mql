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
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/providers/databricks/resources"
)

const (
	DefaultConnectionType = "databricks"
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

	accountID := flagOrEnv("account-id", "DATABRICKS_ACCOUNT_ID")
	host := flagOrEnv("host", "DATABRICKS_HOST")
	clientID := flagOrEnv("client-id", "DATABRICKS_CLIENT_ID")
	clientSecret := flagOrEnv("client-secret", "DATABRICKS_CLIENT_SECRET")
	token := flagOrEnv("token", "DATABRICKS_TOKEN")

	// An account id routes to the account console (which discovers workspaces);
	// otherwise we connect a single workspace directly.
	if accountID != "" {
		conf.Options[connection.OptionPlane] = connection.PlaneAccount
		conf.Options[connection.OptionAccountID] = accountID
	} else {
		conf.Options[connection.OptionPlane] = connection.PlaneWorkspace
	}
	if host != "" {
		conf.Options[connection.OptionHost] = host
	}
	if clientID != "" {
		conf.Options[connection.OptionClientID] = clientID
	}
	if clientSecret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(connection.CredentialClientSecret, clientSecret))
	}
	if token != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(connection.CredentialToken, token))
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.DatabricksConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.DatabricksConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewDatabricksConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.DatabricksConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.DatabricksConnection) error {
	platform, err := conn.PlatformInfo()
	if err != nil {
		return err
	}
	asset.Platform = platform

	switch conn.Plane() {
	case connection.PlaneAccount:
		asset.Id = "databricks-account-" + conn.AccountID()
		asset.Name = "Databricks account " + conn.AccountID()
		asset.PlatformIds = []string{connection.NewDatabricksAccountIdentifier(conn.AccountID())}
	case connection.PlaneWorkspace:
		id := conn.WorkspaceID()
		if id == "" {
			id = conn.Host()
		}
		asset.Id = "databricks-workspace-" + id
		if asset.Name == "" {
			asset.Name = "Databricks workspace " + id
		}
		asset.PlatformIds = []string{connection.NewDatabricksWorkspaceIdentifier(id)}
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
