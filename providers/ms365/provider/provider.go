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
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/providers/ms365/resources"
)

const (
	ConnectionType = "ms365"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

// flagBytes safely reads a flag's raw value. Unset flags (including keys the
// running command never registered) are absent from the map, so a direct
// lookup yields a nil primitive.
func flagBytes(flags map[string]*llx.Primitive, key string) []byte {
	if p, ok := flags[key]; ok && p != nil {
		return p.Value
	}
	return nil
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.GetFlags()

	tenantId := flagBytes(flags, "tenant-id")
	clientId := flagBytes(flags, "client-id")
	clientSecret := flagBytes(flags, "client-secret")
	certificatePath := flagBytes(flags, "certificate-path")
	certificateSecret := flagBytes(flags, "certificate-secret")
	organization := flagBytes(flags, "organization")
	sharepointUrl := flagBytes(flags, "sharepoint-url")
	authMethod := flagBytes(flags, "auth-method")

	opts := map[string]string{}
	creds := []*vault.Credential{}

	opts[connection.OptionTenantID] = string(tenantId)
	opts[connection.OptionClientID] = string(clientId)
	opts[connection.OptionOrganization] = string(organization)
	opts[connection.OptionSharepointUrl] = string(sharepointUrl)
	if len(authMethod) > 0 {
		opts[connection.OptionAuthMethod] = string(authMethod)
	}

	if len(clientSecret) > 0 {
		creds = append(creds, &vault.Credential{
			Type:   vault.CredentialType_password,
			Secret: clientSecret,
		})
	} else if len(certificatePath) > 0 {
		creds = append(creds, &vault.Credential{
			Type:           vault.CredentialType_pkcs12,
			PrivateKeyPath: string(certificatePath),
			Password:       string(certificateSecret),
		})
	}
	config := &inventory.Config{
		Type:        "ms365",
		Discover:    &inventory.Discovery{Targets: []string{"auto"}},
		Credentials: creds,
		Options:     opts,
	}
	asset := inventory.Asset{
		Connections: []*inventory.Config{config},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
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

	// discovery assets for further scanning
	inventory, err := s.discover(conn, conn.Conf)
	if err != nil {
		return nil, err
	}

	// TODO: discovery of related assets and use them in the inventory below
	return &plugin.ConnectRes{
		Id:        uint32(conn.ID()),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inventory,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.Ms365Connection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewMs365Connection(connId, asset, conf)
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

	return runtime.Connection.(*connection.Ms365Connection), nil
}

// ms365Platform returns the platform descriptor reported for a Microsoft 365
// asset. Both the directly-connected asset (detect) and the discovered tenant
// asset (discover) use this so the reported platform name stays consistent
// regardless of whether discovery ran.
func ms365Platform() *inventory.Platform {
	return &inventory.Platform{
		Name:                  "microsoft365",
		Runtime:               "ms-graph",
		Kind:                  "api",
		Title:                 "Microsoft 365",
		TechnologyUrlSegments: []string{"saas", "ms365"},
	}
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.Ms365Connection) error {
	asset.Platform = ms365Platform()

	return nil
}

func (s *Service) discover(conn *connection.Ms365Connection, conf *inventory.Config) (*inventory.Inventory, error) {
	if conn.Conf.Discover == nil {
		return nil, nil
	}

	_, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	identifier := conn.PlatformId()
	tenantAsset := &inventory.Asset{
		PlatformIds: []string{identifier},
		Name:        "Microsoft 365 tenant " + conn.TenantId(),
		Platform:    ms365Platform(),
		Connections: []*inventory.Config{conf.Clone()}, // pass-in the current config
		Labels: map[string]string{
			"azure.com/tenant": conn.TenantId(),
		},
		State: inventory.State_STATE_ONLINE,
	}
	inventory := &inventory.Inventory{
		Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{tenantAsset}},
	}

	return inventory, nil
}
