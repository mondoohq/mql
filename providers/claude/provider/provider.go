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
	"go.mondoo.com/mql/providers/claude/connection"
	"go.mondoo.com/mql/providers/claude/resources"
)

const (
	DefaultConnectionType = "claude"
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

	if token, ok := flags["token"]; ok {
		conf.Options[connection.TokenOption] = string(token.Value)
	}

	if adminToken, ok := flags["admin-token"]; ok {
		conf.Options[connection.AdminTokenOption] = string(adminToken.Value)
	}

	if v, ok := flags["identity-token-file"]; ok {
		conf.Options[connection.IdentityTokenFileOption] = string(v.Value)
	}
	if v, ok := flags["federation-rule-id"]; ok {
		conf.Options[connection.FederationRuleIDOption] = string(v.Value)
	}
	if v, ok := flags["organization-id"]; ok {
		conf.Options[connection.OrganizationIDOption] = string(v.Value)
	}
	if v, ok := flags["service-account-id"]; ok {
		conf.Options[connection.ServiceAccountIDOption] = string(v.Value)
	}
	if v, ok := flags["workspace-id"]; ok {
		conf.Options[connection.WorkspaceIDOption] = string(v.Value)
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ClaudeConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewClaudeConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.ClaudeConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.ClaudeConnection) error {
	name, platform, platformIDs := claudeAssetIdentity(
		conn.OrgID(),
		conn.OrgName(),
		conn.Conf.Options[connection.WorkspaceIDOption],
		conn.Host(),
	)
	asset.Name = name
	asset.Platform = platform
	asset.PlatformIds = platformIDs
	return nil
}

// claudeAssetIdentity picks the asset name, platform, and platform IDs from the
// scoping information available on the connection. A concrete workspace wins
// over the organization, which in turn wins over the bare API host. A
// workspace-id of "default" is treated as "no workspace" and falls through to
// the organization.
func claudeAssetIdentity(orgID, orgName, workspaceID, host string) (string, *inventory.Platform, []string) {
	switch {
	case workspaceID != "" && workspaceID != "default":
		return "Claude Workspace " + workspaceID,
			connection.NewClaudeWorkspacePlatform(orgID, workspaceID),
			[]string{connection.NewClaudeWorkspaceIdentifier(workspaceID)}
	case orgID != "":
		name := "Claude Organization"
		if orgName != "" {
			name = "Claude Organization " + orgName
		}
		return name,
			connection.NewClaudeOrgPlatform(orgID),
			[]string{connection.NewClaudeOrgIdentifier(orgID)}
	default:
		return "Claude (" + host + ")",
			connection.NewClaudeAPIPlatform(host),
			[]string{"//platformid.api.mondoo.app/runtime/claude/host/" + host}
	}
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
