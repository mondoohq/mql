// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/huggingface/connection"
	"go.mondoo.com/mql/providers/huggingface/resources"
)

const (
	DefaultConnectionType = "huggingface"
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

	if ns, ok := flags["namespace"]; ok {
		conf.Options[connection.NamespaceOption] = string(ns.Value)
	}

	if nsType, ok := flags["namespace-type"]; ok {
		val := string(nsType.Value)
		if val != connection.NamespaceTypeUser && val != connection.NamespaceTypeOrg {
			return nil, fmt.Errorf("invalid --namespace-type %q: must be %q or %q", val, connection.NamespaceTypeUser, connection.NamespaceTypeOrg)
		}
		conf.Options[connection.NamespaceType] = val
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.HuggingfaceConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewHuggingfaceConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.HuggingfaceConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.HuggingfaceConnection) error {
	user, err := conn.Client().WhoAmI(context.Background())
	if err != nil {
		return fmt.Errorf("failed to authenticate with Hugging Face API: %w", err)
	}

	ns := conn.Namespace()
	nsType := conn.NsType()

	if ns == "" {
		ns = user.Name
		nsType = connection.NamespaceTypeUser
	}

	switch nsType {
	case connection.NamespaceTypeOrg:
		asset.Name = "Hugging Face Organization (" + ns + ")"
		asset.PlatformIds = []string{connection.PlatformIdHuggingfaceOrg + ns}
		asset.Platform = connection.NewHuggingfaceOrgPlatform(ns)
	default:
		asset.Name = "Hugging Face User (" + ns + ")"
		asset.PlatformIds = []string{connection.PlatformIdHuggingfaceUser + ns}
		asset.Platform = connection.NewHuggingfaceUserPlatform(ns)
	}

	return nil
}

func (s *Service) discover(conn *connection.HuggingfaceConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	// Org-scoped child connections (created by a previous discover call) should
	// not re-discover — they already represent a single namespace.
	if conn.Namespace() != "" {
		return nil, nil
	}

	user, err := conn.Client().WhoAmI(context.Background())
	if err != nil {
		return nil, err
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	for _, org := range user.Orgs {
		cloned := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		cloned.Options[connection.NamespaceOption] = org.Name
		cloned.Options[connection.NamespaceType] = connection.NamespaceTypeOrg

		asset := &inventory.Asset{
			PlatformIds: []string{connection.PlatformIdHuggingfaceOrg + org.Name},
			Name:        "Hugging Face Organization (" + org.Name + ")",
			Platform:    connection.NewHuggingfaceOrgPlatform(org.Name),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{cloned},
		}
		in.Spec.Assets = append(in.Spec.Assets, asset)
	}

	return in, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
