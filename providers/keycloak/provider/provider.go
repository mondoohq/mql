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
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/providers/keycloak/resources"
)

const (
	DefaultConnectionType = "keycloak"
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

	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	} else {
		discoverTargets = []string{connection.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	for flag, env := range map[string]string{
		"url":        "KEYCLOAK_URL",
		"realm":      "KEYCLOAK_REALM",
		"auth-realm": "KEYCLOAK_AUTH_REALM",
		"client-id":  "KEYCLOAK_CLIENT_ID",
		"username":   "KEYCLOAK_USERNAME",
		"ca-cert":    "KEYCLOAK_CA_CERT",
	} {
		value := flagValue(flags, flag)
		if value == "" {
			value = os.Getenv(env)
		}
		if value != "" {
			conf.Options[flag] = value
		}
	}

	// The user password carries the user name so the connection can tell it
	// apart from a client secret, which is stored without one.
	password := flagValue(flags, "password")
	if password == "" {
		password = os.Getenv("KEYCLOAK_PASSWORD")
	}
	if password != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(conf.Options["username"], password))
	}

	clientSecret := flagValue(flags, "client-secret")
	if clientSecret == "" {
		clientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
	}
	if clientSecret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", clientSecret))
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func flagValue(flags map[string]*llx.Primitive, name string) string {
	if x, ok := flags[name]; ok && len(x.Value) != 0 {
		return string(x.Value)
	}
	return ""
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.KeycloakConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewKeycloakConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.KeycloakConnection), nil
}

// detect stamps the platform of a realm asset. A connection that names no realm
// stays without a platform: it is a discovery root that emits one
// keycloak-realm asset per realm the credentials can read.
func (s *Service) detect(asset *inventory.Asset, conn *connection.KeycloakConnection) error {
	if realm := conn.RealmFilter(); realm != "" {
		asset.Platform = connection.NewKeycloakRealmPlatform(conn.Host(), realm)
		asset.PlatformIds = []string{connection.NewKeycloakRealmIdentifier(conn.Host(), realm)}
		if asset.Name == "" {
			asset.Name = conn.Host() + "/" + realm
		}
		return nil
	}

	// Give the discovery root a stable name so it does not surface as an empty
	// label in scan output.
	if asset.Name == "" {
		asset.Name = conn.Host()
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
