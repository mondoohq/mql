// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/circleci/connection"
	"go.mondoo.com/mql/providers/circleci/resources"
)

const (
	DefaultConnectionType = "circleci"

	// PlatformIDPrefix is the platform id prefix for a CircleCI asset.
	PlatformIDPrefix = "//platformid.api.mondoo.app/runtime/circleci/"
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

	if v, ok := flags[connection.OPTION_TOKEN]; ok && len(v.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}

	asset := inventory.Asset{
		Name:        "CircleCI",
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.CircleciConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewCircleciConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		// Fail fast: validate the token against /me before handing back a
		// connection that would otherwise surface auth failures lazily on
		// the first resource query.
		if _, err := conn.Verify(); err != nil {
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

	return runtime.Connection.(*connection.CircleciConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.CircleciConnection) error {
	asset.Id = conn.Conf.Type

	asset.Platform = &inventory.Platform{
		Name:    "circleci",
		Family:  []string{"circleci"},
		Kind:    "api",
		Runtime: "circleci",
		Title:   "CircleCI",
	}

	// Scope the platform id to the token's primary organization when one is
	// visible, since a CircleCI token is generally issued for a single org's
	// use. Tokens that can see no organization (e.g. a personal token with no
	// org collaborations yet) fall back to the authenticated user.
	orgs, err := conn.Client().GetCollaborations(context.Background())
	if err != nil {
		return err
	}
	if len(orgs) > 0 {
		// GetCollaborations does not promise a stable order, so sort before
		// picking one. Without this a multi-org token yields a different
		// platform id per scan and upstream sees a new asset every time.
		slices.SortFunc(orgs, func(a, b connection.Collaboration) int {
			return strings.Compare(a.ID, b.ID)
		})
		asset.Name = orgs[0].Name
		asset.PlatformIds = []string{PlatformIDPrefix + "org/" + orgs[0].ID}
		return nil
	}

	user, err := conn.Verify()
	if err != nil {
		return err
	}
	asset.Name = user.Login
	asset.PlatformIds = []string{PlatformIDPrefix + "user/" + user.ID}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
