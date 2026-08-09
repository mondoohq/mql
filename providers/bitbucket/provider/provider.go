// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
	"go.mondoo.com/mql/v13/providers/bitbucket/resources"
)

const (
	DefaultConnectionType = "bitbucket"

	// PlatformIDBitbucketWorkspace is the platform id prefix for a Bitbucket
	// Cloud workspace.
	PlatformIDBitbucketWorkspace = "//platformid.api.mondoo.app/runtime/bitbucket/workspace/"
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

	var username string
	if v, ok := flags[connection.OPTION_USERNAME]; ok && len(v.Value) != 0 {
		username = string(v.Value)
		conf.Options[connection.OPTION_USERNAME] = username
	}
	if v, ok := flags[connection.OPTION_WORKSPACE]; ok && len(v.Value) != 0 {
		conf.Options[connection.OPTION_WORKSPACE] = string(v.Value)
	}
	if v, ok := flags[connection.OPTION_TOKEN]; ok && len(v.Value) != 0 {
		// Access Token: no username attached to the credential.
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}
	if v, ok := flags[connection.OPTION_APP_PASSWORD]; ok && len(v.Value) != 0 {
		// App Password: the credential's User field carries the username so
		// the connection can tell the two auth modes apart.
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(username, string(v.Value)))
	}

	return &plugin.ParseCLIRes{
		Asset: &inventory.Asset{
			Name:        "Bitbucket",
			Connections: []*inventory.Config{conf},
		},
	}, nil
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.BitbucketConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewBitbucketConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		// Verify access to the Bitbucket workspace
		if err := conn.Verify(); err != nil {
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

	return runtime.Connection.(*connection.BitbucketConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.BitbucketConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = conn.Workspace()

	asset.Platform = &inventory.Platform{
		Name:    "bitbucket",
		Family:  []string{"bitbucket"},
		Kind:    "api",
		Runtime: "bitbucket",
		Title:   "Bitbucket",
	}

	asset.PlatformIds = []string{PlatformIDBitbucketWorkspace + conn.Workspace()}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
