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
	"go.mondoo.com/mql/providers/fastly/connection"
	"go.mondoo.com/mql/providers/fastly/resources"
)

const (
	DefaultConnectionType = "fastly"
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

	flagString := func(name string) string {
		if x, ok := flags[name]; ok && len(x.Value) != 0 {
			return string(x.Value)
		}
		return ""
	}

	if u := flagString("base-url"); u != "" {
		conf.Options[connection.OptionBaseURL] = u
	}

	token := flagString("api-token")
	if token == "" {
		token = os.Getenv(connection.EnvAPIKeyVar)
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

	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	return &plugin.ConnectRes{
		Id:    conn.ID(),
		Name:  conn.Name(),
		Asset: req.Asset,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.FastlyConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewFastlyConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.FastlyConnection), nil
}

// detect identifies the account by the customer the API token belongs to.
func (s *Service) detect(asset *inventory.Asset, conn *connection.FastlyConnection) error {
	customerID := conn.CustomerID()
	if customerID == "" {
		// A token without an associated customer still authenticates, but has
		// no stable account id to key on.
		customerID = "unknown"
	}
	id := connection.NewFastlyAccountIdentifier(customerID)
	asset.Id = id
	asset.Name = "Fastly account " + customerID
	asset.Platform = connection.NewFastlyAccountPlatform(customerID)
	asset.PlatformIds = []string{id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
