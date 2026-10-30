// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/jumpcloud/connection"
	"go.mondoo.com/mql/providers/jumpcloud/resources"
)

const DefaultConnectionType = "jumpcloud"

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

	apiKey := flagOrEnv(flags, "api-key", "JUMPCLOUD_API_KEY")
	if apiKey == "" {
		return nil, errors.New("jumpcloud provider requires an API key, pass --api-key or set JUMPCLOUD_API_KEY")
	}
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))

	if orgID := flagOrEnv(flags, "org-id", "JUMPCLOUD_ORG_ID"); orgID != "" {
		conf.Options["org-id"] = orgID
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// flagOrEnv reads a CLI flag, falling back to an environment variable when the
// flag was not given. Values are trimmed so a key pasted with a trailing
// newline, and a flag passed as whitespace, are both treated as absent rather
// than sent to the API as a malformed credential.
func flagOrEnv(flags map[string]*llx.Primitive, flag, env string) string {
	if x, ok := flags[flag]; ok {
		if v := strings.TrimSpace(string(x.Value)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(os.Getenv(env))
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.JumpcloudConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewJumpcloudConnection(connId, asset, conf)
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

		asset.Connections[0].Id = connId
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

	return runtime.Connection.(*connection.JumpcloudConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.JumpcloudConnection) error {
	id, err := conn.OrganizationID()
	if err != nil {
		return err
	}

	asset.Name = "JumpCloud Organization " + id
	asset.Platform = &inventory.Platform{
		Name:                  "jumpcloud-org",
		Family:                []string{"jumpcloud"},
		Kind:                  "api",
		Title:                 "JumpCloud Organization",
		Runtime:               "jumpcloud",
		TechnologyUrlSegments: []string{"saas", "jumpcloud", "org"},
	}
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/jumpcloud/organization/" + id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
