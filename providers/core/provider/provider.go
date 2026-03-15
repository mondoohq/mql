// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/recording"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/v13/providers/core/resources"
	"go.mondoo.com/mql/v13/types"
)

const defaultConnection uint32 = 1

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	return nil, errors.New("core doesn't offer any connectors")
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	connectionId := defaultConnection
	runtime, err := s.AddRuntime(req.Asset.Connections[0], func(connId uint32) (*plugin.Runtime, error) {
		connectionId = connId
		var upstream *upstream.UpstreamClient
		var err error
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		return plugin.NewRuntime(
			nil,
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

	asset := req.Asset

	assetArgs := recording.CreateAssetResourceArgs(asset)
	_, err = resources.CreateResource(runtime, "asset", assetArgs)
	if err != nil {
		return nil, errors.New("failed to init core, cannot set asset metadata")
	}

	if len(asset.Connections) > 0 {
		_, err = resources.CreateResource(runtime, "mondoo", map[string]*llx.RawData{
			"capabilities": llx.ArrayData(llx.TArr2Raw(asset.Connections[0].Capabilities), types.String),
		})
		if err != nil {
			return nil, errors.New("failed to init core, cannot set connection metadata")
		}
	}

	return &plugin.ConnectRes{
		Id:   connectionId,
		Name: "core",
	}, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return s.Connect(req, callback)
}
