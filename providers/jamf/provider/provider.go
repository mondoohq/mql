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

	"go.mondoo.com/mql/providers/jamf/connection"
	"go.mondoo.com/mql/providers/jamf/resources"
)

const ConnectionType = "jamf"

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

	// Resolve credentials: flags take precedence over env vars
	clientId := flagOrEnv(flags, "client-id", "JAMF_CLIENT_ID")
	clientSecret := flagOrEnv(flags, "client-secret", "JAMF_CLIENT_SECRET")
	instanceDomain := flagOrEnv(flags, "instance-domain", "JAMF_INSTANCE_DOMAIN")

	conf := &inventory.Config{
		Type: req.Connector,
		Options: map[string]string{
			"instance_domain": instanceDomain,
		},
	}

	if clientId != "" && clientSecret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(clientId, clientSecret))
	}

	asset := &inventory.Asset{
		Name:        "Jamf",
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

	// Populate asset platform info (if missing)
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.JamfConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewJamfConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.JamfConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.JamfConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = conn.Conf.Options["instance_domain"]

	platform, err := conn.PlatformInfo()
	if err != nil {
		return err
	}

	// The Jamf Pro version belongs on the asset: `asset.version` is the
	// canonical, cross-provider way to ask what version something is, and every
	// root carries `asset` (ADR 031). A provider-specific `version` field is a
	// second spelling of the same fact.
	if info, err := conn.Client.GetJamfProVersion(); err == nil && info != nil && info.Version != nil {
		platform.Version = *info.Version
	}

	asset.Platform = platform
	asset.PlatformIds = []string{conn.Identifier()}
	return nil
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
