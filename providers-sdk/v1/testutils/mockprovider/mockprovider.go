// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mockprovider

import (
	"errors"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/testutils/mockprovider/resources"
	"go.mondoo.com/mql/utils/syncx"
)

var Config = plugin.Provider{
	Name:       "mock",
	ID:         "go.mondoo.com/mql/providers-sdk/v1/testutils/mockprovider",
	Version:    "0.0.0",
	Connectors: []plugin.Connector{},
}

type Service struct {
	plugin.Service
	runtimes         map[uint32]*plugin.Runtime
	lastConnectionID uint32
}

func Init() *Service {
	return &Service{
		runtimes: map[uint32]*plugin.Runtime{},
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	return nil, errors.New("core doesn't offer any connectors")
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	s.lastConnectionID++
	connID := s.lastConnectionID
	runtime := &plugin.Runtime{
		Resources:    &syncx.Map[plugin.Resource]{},
		Callback:     callback,
		HasRecording: req.HasRecording,
	}
	s.runtimes[connID] = runtime

	return &plugin.ConnectRes{
		Id:   connID,
		Name: "mockprovider",
		// Every real provider echoes the asset it connected. The runtime reads
		// it back to check whether the connection switched providers, so
		// leaving it nil makes Runtime.Connect fail before it gets there.
		Asset: req.Asset,
	}, nil
}

// MockConnect connects against recorded data rather than a live target, which
// is what the builtin mock provider calls when it replays a recorded asset.
//
// This stand-in used to refuse the call, on the reasoning that a mock provider
// is the caller of MockConnect and never its callee. That is true of
// providers/mock.go; it is not true of this file, which stands in for a
// *target* provider - the thing being replayed - and every real provider
// implements this. Refusing it made an asset served by this provider
// unreachable through a recording, which cross-asset resolution (ADR 031)
// needs.
//
// There is no live target here to differ from, so the recording flag is the
// whole difference.
func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil {
		return nil, errors.New("no connection data provided")
	}
	mocked := *req
	mocked.HasRecording = true
	return s.Connect(&mocked, callback)
}

// Shutdown is automatically called when the shell closes.
// It is not necessary to implement this method.
// If you want to do some cleanup, you can do it here.
func (s *Service) Shutdown(req *plugin.ShutdownReq) (*plugin.ShutdownRes, error) {
	return &plugin.ShutdownRes{}, nil
}

// ResolveAsset answers plugin.AssetSource for this provider's resources. It
// overrides the embedded plugin.Service for the same reason Disconnect does:
// this provider keeps its own runtimes map, so the embedded implementation
// would look in an empty one.
func (s *Service) ResolveAsset(req *plugin.ResolveAssetReq) (*plugin.ResolveAssetRes, error) {
	if req == nil {
		return &plugin.ResolveAssetRes{}, nil
	}
	runtime, ok := s.runtimes[req.Connection]
	if !ok {
		return &plugin.ResolveAssetRes{}, nil
	}
	resource, ok := runtime.Resources.Get(req.ResourceType + "\x00" + req.ResourceId)
	if !ok {
		return &plugin.ResolveAssetRes{}, nil
	}
	source, ok := resource.(plugin.AssetSource)
	if !ok {
		return &plugin.ResolveAssetRes{}, nil
	}
	asset, err := source.MqlAsset()
	if err != nil {
		return nil, err
	}
	return &plugin.ResolveAssetRes{Asset: asset}, nil
}

// Disconnect releases a connection. This provider tracks its own runtimes
// map, so it overrides the embedded plugin.Service.Disconnect (which operates
// on a separate, uninitialized map and would otherwise flush a nil memoizer).
func (s *Service) Disconnect(req *plugin.DisconnectReq) (*plugin.DisconnectRes, error) {
	delete(s.runtimes, req.Connection)
	return &plugin.DisconnectRes{}, nil
}

func (s *Service) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	runtime, ok := s.runtimes[req.Connection]
	if !ok {
		return nil, errors.New("connection " + strconv.FormatUint(uint64(req.Connection), 10) + " not found")
	}

	args := plugin.PrimitiveArgsToRawDataArgs(req.Args, runtime)

	if req.ResourceId == "" && req.Field == "" {
		res, err := resources.CreateResource(runtime, req.Resource, args)
		if err != nil {
			return nil, err
		}

		rd := llx.ResourceData(res, req.Resource).Result()
		return &plugin.DataRes{
			Data: rd.Data,
		}, nil
	}

	resource, ok := runtime.Resources.Get(req.Resource + "\x00" + req.ResourceId)
	if !ok {
		return nil, errors.New("resource '" + req.Resource + "' (id: " + req.ResourceId + ") doesn't exist")
	}

	return resources.GetData(resource, req.Field, args), nil
}

func (s *Service) StoreData(req *plugin.StoreReq) (*plugin.StoreRes, error) {
	runtime, ok := s.runtimes[req.Connection]
	if !ok {
		return nil, errors.New("connection " + strconv.FormatUint(uint64(req.Connection), 10) + " not found")
	}

	var errs []string
	for i := range req.Resources {
		info := req.Resources[i]

		args, err := plugin.ProtoArgsToRawDataArgs(info.Fields)
		if err != nil {
			errs = append(errs, "failed to add cached "+info.Name+" (id: "+info.Id+"), failed to parse arguments")
			continue
		}

		resource, ok := runtime.Resources.Get(info.Name + "\x00" + info.Id)
		if !ok {
			resource, err = resources.CreateResource(runtime, info.Name, args)
			if err != nil {
				errs = append(errs, "failed to add cached "+info.Name+" (id: "+info.Id+"), creation failed: "+err.Error())
				continue
			}

			runtime.Resources.Set(info.Name+"\x00"+info.Id, resource)
		}

		for k, v := range args {
			if err := resources.SetData(resource, k, v); err != nil {
				errs = append(errs, "failed to add cached "+info.Name+" (id: "+info.Id+"), field error: "+err.Error())
			}
		}
	}

	if len(errs) != 0 {
		return nil, errors.New(strings.Join(errs, ", "))
	}
	return &plugin.StoreRes{}, nil
}
