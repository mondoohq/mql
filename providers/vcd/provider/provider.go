// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/vcd/connection"
	"go.mondoo.com/mql/providers/vcd/resources"
)

const ConnectionType = "vcd"

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

	conn := &inventory.Config{
		Type:    req.Connector,
		Options: make(map[string]string),
	}

	// custom flag parsing
	user := ""
	if x, ok := flags["user"]; ok && len(x.Value) != 0 {
		user = string(x.Value)
	}
	if user != "" {
		conn.Options["user"] = user
	}

	if x, ok := flags["password"]; ok && len(x.Value) != 0 {
		conn.Credentials = append(conn.Credentials, vault.NewPasswordCredential(user, string(x.Value)))
	}

	if x, ok := flags["host"]; ok && len(x.Value) != 0 {
		conn.Host = string(x.Value)
	}

	organization := ""
	if x, ok := flags["organization"]; ok && len(x.Value) != 0 {
		organization = string(x.Value)
	}
	if organization != "" {
		conn.Options["organization"] = organization
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conn},
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.VcdConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewVcdConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.VcdConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.VcdConnection) error {
	asset.Name = conn.Conf.Host

	c := conn.Client()
	vcdVersion, err := c.Client.GetVcdFullVersion()
	if err != nil {
		return err
	}

	digits := vcdVersion.Version.Segments()

	asset.Platform = &inventory.Platform{
		Title:   "VMware Cloud Director " + conn.Conf.Host,
		Version: fmt.Sprintf("%d.%d.%d", digits[0], digits[1], digits[2]),
		Build:   strconv.Itoa(digits[3]),
		Labels: map[string]string{
			"vcd.vmware.com/api-version": c.Client.APIVersion,
		},
	}
	PlatformByName("vcd").Apply(asset.Platform)

	// TODO: Add platform IDs
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/vcd/host/" + conn.Conf.Host}
	return nil
}
