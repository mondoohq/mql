// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
	"go.mondoo.com/mql/v13/providers/jenkins/connection"
	"go.mondoo.com/mql/v13/providers/jenkins/resources"
)

const (
	DefaultConnectionType = "jenkins"

	// PlatformIDJenkinsUrl is the platform id prefix for a Jenkins controller.
	PlatformIDJenkinsUrl = "//platformid.api.mondoo.app/runtime/jenkins/url/"
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

	if v, ok := flags[connection.OPTION_URL]; ok && len(v.Value) != 0 {
		conf.Options[connection.OPTION_URL] = string(v.Value)
	}
	if v, ok := flags[connection.OPTION_USER]; ok && len(v.Value) != 0 {
		conf.Options[connection.OPTION_USER] = string(v.Value)
	}
	if v, ok := flags[connection.OPTION_TOKEN]; ok && len(v.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}

	return &plugin.ParseCLIRes{
		Asset: &inventory.Asset{
			Name:        "Jenkins",
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.JenkinsConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewJenkinsConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.JenkinsConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.JenkinsConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = conn.BaseUrl()

	asset.Platform = &inventory.Platform{
		Name:    "jenkins",
		Family:  []string{"jenkins"},
		Kind:    "api",
		Runtime: "jenkins",
		Title:   "Jenkins",
	}

	asset.PlatformIds = []string{PlatformIDJenkinsUrl + strings.ToLower(conn.BaseUrl())}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
