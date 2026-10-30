// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Interface to use mql as a plugin
package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "ifenohXaoHoh3Iequeg0iuph2gaeth",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"provider": &ProviderPluginImpl{},
}

type Closer interface {
	Close()
}

type ProviderCallback interface {
	Collect(req *DataRes) error
	GetRecording(req *DataReq) (*ResourceData, error)
	GetData(req *DataReq) (*DataRes, error)
}

// StaticProvider is a provider that requires no connection to other providers.
type StaticProvider interface {
	StaticName() string
}

// ProviderPlugin is the interface that we're exposing as a plugin.
type ProviderPlugin interface {
	Heartbeat(req *HeartbeatReq) (*HeartbeatRes, error)
	// Translations returns this provider's downgrade catalog (ADR 040 part 6).
	// plugin.Service answers it with an empty catalog, so a provider that has
	// no translations to offer needs no code at all.
	Translations(req *TranslationsReq) (*TranslationsRes, error)
	ParseCLI(req *ParseCLIReq) (*ParseCLIRes, error)
	Connect(req *ConnectReq, callback ProviderCallback) (*ConnectRes, error)
	Disconnect(req *DisconnectReq) (*DisconnectRes, error)
	MockConnect(req *ConnectReq, callback ProviderCallback) (*ConnectRes, error)
	Shutdown(req *ShutdownReq) (*ShutdownRes, error)
	GetData(req *DataReq) (*DataRes, error)
	StoreData(req *StoreReq) (*StoreRes, error)
	// ResolveAsset returns the asset one of this provider's resources stands
	// for, with the connection needed to reach it (ADR 031). plugin.Service
	// answers it from the resource itself, so a provider whose resources
	// implement AssetSource needs no code at all, and one whose resources are
	// not assets answers nothing.
	ResolveAsset(req *ResolveAssetReq) (*ResolveAssetRes, error)
}

// ContextDataReader optionally carries cancellation through a provider call.
// ProviderPlugin remains compatible with providers that predate this interface.
type ContextDataReader interface {
	GetDataContext(context.Context, *DataReq) (*DataRes, error)
}

// ContextDataWriter optionally carries cancellation through resource storage.
type ContextDataWriter interface {
	StoreDataContext(context.Context, *StoreReq) (*StoreRes, error)
}

// GetDataContext uses cancellation when the provider supports it. Legacy
// in-process implementations must finish their own work; a host-side deadline
// cannot terminate an arbitrary Go function.
func GetDataContext(ctx context.Context, provider ProviderPlugin, req *DataReq) (*DataRes, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var res *DataRes
	var err error
	if contextual, ok := provider.(ContextDataReader); ok {
		res, err = contextual.GetDataContext(ctx, req)
	} else {
		res, err = provider.GetData(req)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return res, err
}

// StoreDataContext uses cancellation when the provider supports it.
func StoreDataContext(ctx context.Context, provider ProviderPlugin, req *StoreReq) (*StoreRes, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var res *StoreRes
	var err error
	if contextual, ok := provider.(ContextDataWriter); ok {
		res, err = contextual.StoreDataContext(ctx, req)
	} else {
		res, err = provider.StoreData(req)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return res, err
}

// This is the implementation of plugin.Plugin so we can serve/consume this.
// We also implement GRPCPlugin so that this plugin can be served over
// gRPC.
type ProviderPluginImpl struct {
	plugin.NetRPCUnsupportedPlugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl ProviderPlugin
}

func (p *ProviderPluginImpl) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	RegisterProviderPluginServer(s, &GRPCServer{
		Impl:   p.Impl,
		broker: broker,
	})
	return nil
}

func (p *ProviderPluginImpl) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &GRPCClient{
		client: NewProviderPluginClient(c),
		broker: broker,
	}, nil
}

var _ plugin.GRPCPlugin = &ProviderPluginImpl{}
