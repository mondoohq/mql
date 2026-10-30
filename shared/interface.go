// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Interface to use mql as a plugin
package shared

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/shared/proto"
	"go.mondoo.com/mql/utils/iox"
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
	"mql": &MqlPlugin{},
}

// MqlQuery is the interface that we're exposing as a plugin.
type MqlQuery interface {
	RunQuery(conf *proto.RunQueryConfig, runtime *providers.Runtime, out iox.OutputHelper) error
}

// This is the implementation of plugin.Plugin so we can serve/consume this.
// We also implement GRPCPlugin so that this plugin can be served over
// gRPC.
type MqlPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl MqlQuery
}

func (p *MqlPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterMqlQueryServer(s, &GRPCServer{
		Impl:   p.Impl,
		broker: broker,
	})
	return nil
}

func (p *MqlPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &GRPCClient{
		client: proto.NewMqlQueryClient(c),
		broker: broker,
	}, nil
}

var _ plugin.GRPCPlugin = &MqlPlugin{}
