// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"context"

	hclog "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/shared/proto"
	"go.mondoo.com/mql/utils/iox"
	"google.golang.org/grpc"
)

func init() {
	var x MqlQuery = &GRPCClient{}
	_ = x
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	broker *plugin.GRPCBroker
	client proto.MqlQueryClient
}

func (m *GRPCClient) RunQuery(conf *proto.RunQueryConfig, runtime *providers.Runtime, out iox.OutputHelper) error {
	helper := &GRPCOutputHelperServer{Impl: &iox.IOWriter{out}}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		proto.RegisterOutputHelperServer(s, helper)

		return s
	}

	brokerID := m.broker.NextId()
	conf.CallbackServer = brokerID
	go m.broker.AcceptAndServe(brokerID, serverFunc)

	_, err := m.client.RunQuery(context.Background(), conf)

	s.Stop()
	return err
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl   MqlQuery
	broker *plugin.GRPCBroker
	proto.UnimplementedMqlQueryServer
}

func (m *GRPCServer) RunQuery(ctx context.Context, req *proto.RunQueryConfig) (*proto.Empty, error) {
	conn, err := m.broker.Dial(req.CallbackServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	a := &GRPCOutputHelperClient{proto.NewOutputHelperClient(conn)}
	panic("UNCLEAR HOW TO GET RUNTIME YET")
	return &proto.Empty{}, m.Impl.RunQuery(req, nil, a)
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCOutputHelperClient struct{ client proto.OutputHelperClient }

// NOTE: we do NOT return the number of written bytes, because we felt
// it was not important to have this value at this stage of the tool.
// Once the use-case arises it will be added to the plugin, so please
// submit an issue if you feel it should be there.
// The type is still built this way to support the most common interfaces
// for io.Writer.
func (m *GRPCOutputHelperClient) Write(b []byte) (int, error) {
	_, err := m.client.Write(context.Background(), &proto.String{
		Data: string(b),
	})
	if err != nil {
		hclog.Default().Info("out.Write", "client", "start", "err", err)
		return 0, err
	}
	return 0, nil
}

func (m *GRPCOutputHelperClient) WriteString(s string) error {
	_, err := m.client.Write(context.Background(), &proto.String{
		Data: s,
	})
	if err != nil {
		hclog.Default().Info("out.Write", "client", "start", "err", err)
		return err
	}
	return nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCOutputHelperServer struct {
	// This is the real implementation
	Impl iox.OutputHelper
	proto.UnsafeOutputHelperServer
}

var empty proto.Empty

func (m *GRPCOutputHelperServer) Write(ctx context.Context, req *proto.String) (resp *proto.Empty, err error) {
	return &empty, m.Impl.WriteString(req.Data)
}
