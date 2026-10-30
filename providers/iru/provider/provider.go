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
	"go.mondoo.com/mql/providers/iru/connection"
	"go.mondoo.com/mql/providers/iru/resources"
)

const DefaultConnectionType = "iru"

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

	subdomain := flagOrEnv(flags, "subdomain", "IRU_SUBDOMAIN")
	token := flagOrEnv(flags, "token", "IRU_TOKEN")

	conf := &inventory.Config{
		Type: req.Connector,
		Options: map[string]string{
			connection.OptionSubdomain: subdomain,
		},
	}

	if token != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))
	}

	asset := &inventory.Asset{
		Name:        "Iru",
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: asset}, nil
}

func flagOrEnv(flags map[string]*llx.Primitive, flagName, envName string) string {
	if v, ok := flags[flagName]; ok && len(v.Value) != 0 {
		return string(v.Value)
	}
	return os.Getenv(envName)
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
		s.detect(req.Asset, conn)
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.IruConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewIruConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		up, err := getUpstream(req)
		if err != nil {
			return nil, err
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
			up,
		), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.IruConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.IruConnection) {
	asset.Id = conn.Conf.Type
	asset.Name = conn.Conf.Options[connection.OptionSubdomain]
	asset.Platform = conn.PlatformInfo()
	asset.PlatformIds = []string{conn.Identifier()}
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not implemented")
}

func getUpstream(req *plugin.ConnectReq) (*upstream.UpstreamClient, error) {
	if req.Upstream != nil && !req.Upstream.Incognito {
		return req.Upstream.InitClient(context.Background())
	}
	return nil, nil
}
