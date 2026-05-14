// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
	"go.mondoo.com/mql/v13/providers/rippling/connection"
	"go.mondoo.com/mql/v13/providers/rippling/resources"
)

const (
	DefaultConnectionType = "rippling"
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

	clientID := flagOrEnv(flags, "client-id", "RIPPLING_CLIENT_ID")
	clientSecret := flagOrEnv(flags, "client-secret", "RIPPLING_CLIENT_SECRET")
	refreshToken := flagOrEnv(flags, "refresh-token", "RIPPLING_REFRESH_TOKEN")
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return nil, errors.New("Rippling OAuth credentials required: pass --client-id, --client-secret and --refresh-token (or set RIPPLING_CLIENT_ID, RIPPLING_CLIENT_SECRET, and RIPPLING_REFRESH_TOKEN)")
	}
	conf.Credentials = append(conf.Credentials,
		vault.NewPasswordCredential(clientID, clientSecret),
		&vault.Credential{Type: vault.CredentialType_bearer, Secret: []byte(refreshToken)},
	)

	if x, ok := flags["api-base"]; ok && len(x.Value) != 0 {
		conf.Options["api-base"] = string(x.Value)
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// flagOrEnv returns the value of a CLI flag, falling back to an environment
// variable when the flag was not supplied.
func flagOrEnv(flags map[string]*llx.Primitive, flag, env string) string {
	if x, ok := flags[flag]; ok && len(x.Value) != 0 {
		return string(x.Value)
	}
	return os.Getenv(env)
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.RipplingConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewRipplingConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		var upstreamClient *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstreamClient, err = req.Upstream.InitClient(context.Background())
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
			upstreamClient), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.RipplingConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.RipplingConnection) error {
	id, err := conn.Identifier(context.Background())
	if err != nil {
		return err
	}
	asset.Id = "rippling"
	asset.Name = "Rippling company " + id
	asset.Platform = &inventory.Platform{
		Name:                  "rippling",
		Family:                []string{"rippling"},
		Kind:                  "api",
		Title:                 "Rippling",
		Runtime:               "rippling",
		TechnologyUrlSegments: []string{"saas", "rippling", "company"},
	}
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/rippling/company/" + id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
