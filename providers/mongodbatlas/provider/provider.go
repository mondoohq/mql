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
	"go.mondoo.com/mql/providers/mongodbatlas/connection"
	"go.mondoo.com/mql/providers/mongodbatlas/resources"
)

const (
	DefaultConnectionType = "mongodbatlas"
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

	orgID := flagOrEnv("org-id", "MONGODB_ATLAS_ORG_ID")
	projectID := flagOrEnv("project-id", "MONGODB_ATLAS_PROJECT_ID")
	publicKey := flagOrEnv("public-key", "MONGODB_ATLAS_PUBLIC_KEY")
	privateKey := flagOrEnv("private-key", "MONGODB_ATLAS_PRIVATE_KEY")
	clientID := flagOrEnv("client-id", "MONGODB_ATLAS_CLIENT_ID")
	clientSecret := flagOrEnv("client-secret", "MONGODB_ATLAS_CLIENT_SECRET")

	// A project id scopes to a single project; otherwise we connect to the
	// organization and discover its projects.
	if projectID != "" {
		conf.Options[connection.OptionPlane] = connection.PlaneProject
		conf.Options[connection.OptionProjectID] = projectID
	} else {
		conf.Options[connection.OptionPlane] = connection.PlaneOrg
	}
	if orgID != "" {
		conf.Options[connection.OptionOrgID] = orgID
	}
	if publicKey != "" {
		conf.Options[connection.OptionPublicKey] = publicKey
	}
	if clientID != "" {
		conf.Options[connection.OptionClientID] = clientID
	}
	if privateKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(connection.CredentialPrivateKey, privateKey))
	}
	if clientSecret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(connection.CredentialClientSecret, clientSecret))
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.MongoDBAtlasConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.MongoDBAtlasConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewMongoDBAtlasConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.MongoDBAtlasConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.MongoDBAtlasConnection) error {
	// Resolve the organization id up front so the org asset's platform id and
	// name are populated even when --org-id was not supplied.
	if conn.Plane() == connection.PlaneOrg {
		if _, err := conn.EnsureOrgID(context.Background()); err != nil {
			return err
		}
	}

	platform, err := conn.PlatformInfo()
	if err != nil {
		return err
	}
	asset.Platform = platform

	switch conn.Plane() {
	case connection.PlaneOrg:
		asset.Id = "atlas-org-" + conn.OrgID()
		asset.Name = "MongoDB Atlas organization " + conn.OrgID()
		asset.PlatformIds = []string{connection.NewMongoDBAtlasOrgIdentifier(conn.OrgID())}
	case connection.PlaneProject:
		asset.Id = "atlas-project-" + conn.ProjectID()
		if asset.Name == "" {
			asset.Name = "MongoDB Atlas project " + conn.ProjectID()
		}
		asset.PlatformIds = []string{connection.NewMongoDBAtlasProjectIdentifier(conn.ProjectID())}
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
