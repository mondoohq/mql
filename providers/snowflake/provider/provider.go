// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/snowflake/connection"
	"go.mondoo.com/mql/providers/snowflake/resources"
)

const (
	DefaultConnectionType = "snowflake"
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

	// Do custom flag parsing here
	user := ""
	if x, ok := flags["user"]; ok && len(x.Value) != 0 {
		user = string(x.Value)
	}

	flagSet := func(name string) bool {
		x, ok := flags[name]
		return ok && len(x.Value) != 0
	}
	askPass := false
	if x, ok := flags["ask-pass"]; ok {
		if b, ok := x.RawData().Value.(bool); ok {
			askPass = b
		}
	}

	// A programmatic access token is a complete authentication method on its own;
	// combining it with a password is ambiguous, so reject that up front.
	if flagSet("token") && (flagSet("password") || askPass) {
		return nil, errors.New("cannot combine --token with --password or --ask-pass; choose one authentication method")
	}

	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		// A programmatic access token (PAT) authenticates as a bearer token.
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:   vault.CredentialType_bearer,
			User:   user,
			Secret: x.Value,
		})
	}

	if x, ok := flags["password"]; ok && len(x.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, string(x.Value)))
	}

	if x, ok := flags["identity-file"]; ok && len(x.Value) != 0 {
		credential, err := vault.NewPrivateKeyCredentialFromPath(user, string(x.Value), "")
		if err != nil {
			return nil, err
		}
		conf.Credentials = append(conf.Credentials, credential)
	}

	if x, ok := flags["account"]; ok && len(x.Value) != 0 {
		conf.Options["account"] = string(x.Value)
	}

	if x, ok := flags["region"]; ok && len(x.Value) != 0 {
		conf.Options["region"] = string(x.Value)
	}

	if x, ok := flags["role"]; ok && len(x.Value) != 0 {
		conf.Options["role"] = string(x.Value)
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
		// Which kind this asset actually is; the static Root can only name one
		// for a provider serving several (ADR 031).
		Root: assetRoot(req.Asset.GetPlatform()),
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.SnowflakeConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.SnowflakeConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewSnowflakeConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.SnowflakeConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.SnowflakeConnection) error {
	account, err := conn.Account()
	if err != nil {
		return err
	}

	// A database-scoped connection is a single-database asset discovered under
	// the account; otherwise the asset is the account itself.
	if conn.IsDatabaseScoped() {
		db := conn.Database()
		asset.Id = connection.NewSnowflakeDatabaseIdentifier(account, db)
		asset.Name = db
		asset.Platform = connection.NewSnowflakeDatabasePlatform(account, db)
		asset.PlatformIds = []string{connection.NewSnowflakeDatabaseIdentifier(account, db)}
		return nil
	}

	asset.Id = conn.Conf.Type
	asset.Name = conn.Conf.Host
	asset.Platform = connection.NewSnowflakeAccountPlatform(account)
	asset.PlatformIds = []string{connection.NewSnowflakeAccountIdentifier(account)}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
