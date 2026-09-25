// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"bytes"
	"context"
	"errors"
	"runtime/debug"
	"time"
	"unicode/utf8"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/status"
)

func init() {
	var x ProviderPlugin = &GRPCClient{}
	_ = x
	encoding.RegisterCodecV2(&Codec{
		fallback: encoding.GetCodecV2("proto"),
	})
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	broker *plugin.GRPCBroker
	client ProviderPluginClient
}

// Heartbeat sends one beat to the provider. The requested interval doubles as
// the call deadline: a beat that cannot be delivered within the window the
// provider is holding us to is worthless, and blocking on it forever would stop
// the beat stream entirely — which is precisely what makes the provider's
// watchdog reap a healthy process.
func (m *GRPCClient) Heartbeat(req *HeartbeatReq) (*HeartbeatRes, error) {
	if req.Interval == 0 {
		return m.client.Heartbeat(context.Background(), req)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Interval))
	defer cancel()
	return m.client.Heartbeat(ctx, req)
}

func (m *GRPCClient) ParseCLI(req *ParseCLIReq) (*ParseCLIRes, error) {
	return m.client.ParseCLI(context.Background(), req)
}

func (m *GRPCClient) connect(req *ConnectReq, callback ProviderCallback) {
	helper := &GRPCProviderCallbackServer{Impl: callback}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		RegisterProviderCallbackServer(s, helper)
		return s
	}

	brokerID := m.broker.NextId()
	req.CallbackServer = brokerID
	go m.broker.AcceptAndServe(brokerID, serverFunc)

	// Note: the reverse connection is not closed explicitly. It stays open
	// until the process is eventually stopped. Connect should only be called
	// once per connected asset, thus the reverse connection is also only
	// open for the duration of said connection.
	// In the future, we may want to explicitly disconnect and re-use providers.
}

func (m *GRPCClient) Connect(req *ConnectReq, callback ProviderCallback) (*ConnectRes, error) {
	m.connect(req, callback)
	return m.client.Connect(context.Background(), req)
}

func (m *GRPCClient) Disconnect(req *DisconnectReq) (*DisconnectRes, error) {
	return m.client.Disconnect(context.Background(), req)
}

func (m *GRPCClient) MockConnect(req *ConnectReq, callback ProviderCallback) (*ConnectRes, error) {
	m.connect(req, callback)
	return m.client.MockConnect(context.Background(), req)
}

func (m *GRPCClient) Shutdown(req *ShutdownReq) (*ShutdownRes, error) {
	return m.client.Shutdown(context.Background(), req)
}

func (m *GRPCClient) GetData(req *DataReq) (*DataRes, error) {
	return m.client.GetData(context.Background(), req)
}

func (m *GRPCClient) StoreData(req *StoreReq) (*StoreRes, error) {
	return m.client.StoreData(context.Background(), req)
}

func (m *GRPCClient) Translations(req *TranslationsReq) (*TranslationsRes, error) {
	return m.client.Translations(context.Background(), req)
}

func (m *GRPCClient) ResolveAsset(req *ResolveAssetReq) (*ResolveAssetRes, error) {
	return m.client.ResolveAsset(context.Background(), req)
}

// recoverPanic converts a panic into a gRPC Internal error. The full stack
// trace is logged locally; only a short message is sent over the wire.
// The message is prefixed with "panic in provider " so the caller can
// distinguish recovered panics from other Internal errors.
func recoverPanic(method string, retErr *error) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		log.Error().Str("method", method).Interface("panic", r).Str("stack", string(stack)).Msg("recovered panic in provider")
		*retErr = status.Errorf(codes.Internal, "panic in provider %s: %v", method, r)
	}
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl   ProviderPlugin
	broker *plugin.GRPCBroker
	UnimplementedProviderPluginServer
}

// requestTracker is implemented by every provider service that embeds
// *plugin.Service. It lets us tell the heartbeat watchdog that the parent
// process is alive because it is, right now, waiting on us.
type requestTracker interface {
	TrackRequest() func()
}

// trackRequest marks a request as in flight and returns the function that marks
// it as done. Heartbeat and Shutdown are deliberately not tracked: the former is
// the liveness signal itself, the latter means we are going away anyway.
func (m *GRPCServer) trackRequest() func() {
	if t, ok := m.Impl.(requestTracker); ok {
		return t.TrackRequest()
	}
	return func() {}
}

func (m *GRPCServer) Heartbeat(ctx context.Context, req *HeartbeatReq) (*HeartbeatRes, error) {
	return m.Impl.Heartbeat(req)
}

func (m *GRPCServer) Translations(ctx context.Context, req *TranslationsReq) (resp *TranslationsRes, err error) {
	defer recoverPanic("Translations", &err)
	defer m.trackRequest()()
	return m.Impl.Translations(req)
}

func (m *GRPCServer) ResolveAsset(ctx context.Context, req *ResolveAssetReq) (resp *ResolveAssetRes, err error) {
	defer recoverPanic("ResolveAsset", &err)
	defer m.trackRequest()()
	return m.Impl.ResolveAsset(req)
}

func (m *GRPCServer) ParseCLI(ctx context.Context, req *ParseCLIReq) (resp *ParseCLIRes, err error) {
	defer m.trackRequest()()
	defer recoverPanic("ParseCLI", &err)
	return m.Impl.ParseCLI(req)
}

func (m *GRPCServer) Connect(ctx context.Context, req *ConnectReq) (resp *ConnectRes, err error) {
	defer m.trackRequest()()
	defer recoverPanic("Connect", &err)
	ReadFeatures(req.Features)
	conn, err := m.broker.Dial(req.CallbackServer)
	if err != nil {
		return nil, err
	}

	// Note: we do not close the connection from this side. It will get closed
	// when the plugin caller decides to kill the process.

	a := &GRPCProviderCallbackClient{NewProviderCallbackClient(conn)}
	res, err := m.Impl.Connect(req, a)
	if err != nil {
		// Normalize here rather than trusting every provider to wrap in a fixed
		// order: this runs in the provider process, so errors.Is sees the
		// sentinel the provider actually wrapped (ADR 045).
		return nil, normalizeConnectError(err)
	}
	return res, nil
}

func (m *GRPCServer) Disconnect(ctx context.Context, req *DisconnectReq) (resp *DisconnectRes, err error) {
	defer m.trackRequest()()
	defer recoverPanic("Disconnect", &err)
	return m.Impl.Disconnect(req)
}

func (m *GRPCServer) MockConnect(ctx context.Context, req *ConnectReq) (resp *ConnectRes, err error) {
	defer m.trackRequest()()
	defer recoverPanic("MockConnect", &err)
	ReadFeatures(req.Features)
	conn, err := m.broker.Dial(req.CallbackServer)
	if err != nil {
		return nil, err
	}

	// Note: we do not close the connection from this side. It will get closed
	// when the plugin caller decides to kill the process.

	a := &GRPCProviderCallbackClient{NewProviderCallbackClient(conn)}
	res, err := m.Impl.MockConnect(req, a)
	if err != nil {
		// Normalize here rather than trusting every provider to wrap in a fixed
		// order: this runs in the provider process, so errors.Is sees the
		// sentinel the provider actually wrapped (ADR 045).
		return nil, normalizeConnectError(err)
	}
	return res, nil
}

func (m *GRPCServer) Shutdown(ctx context.Context, req *ShutdownReq) (resp *ShutdownRes, err error) {
	defer recoverPanic("Shutdown", &err)
	return m.Impl.Shutdown(req)
}

func (m *GRPCServer) GetData(ctx context.Context, req *DataReq) (resp *DataRes, err error) {
	defer m.trackRequest()()
	defer recoverPanic("GetData", &err)
	resp, err = m.Impl.GetData(req)
	if err != nil {
		return nil, err
	}
	sanitizeDataRes(resp)
	return resp, nil
}

func (m *GRPCServer) StoreData(ctx context.Context, req *StoreReq) (resp *StoreRes, err error) {
	defer m.trackRequest()()
	defer recoverPanic("StoreData", &err)
	return m.Impl.StoreData(req)
}

// GRPCClient is an implementation of ProviderCallback that talks over RPC.
type GRPCProviderCallbackClient struct{ client ProviderCallbackClient }

func (m *GRPCProviderCallbackClient) Collect(req *DataRes) error {
	_, err := m.client.Collect(context.Background(), req)
	return err
}

func (m *GRPCProviderCallbackClient) GetRecording(req *DataReq) (*ResourceData, error) {
	return m.client.GetRecording(context.Background(), req)
}

func (m *GRPCProviderCallbackClient) GetData(req *DataReq) (*DataRes, error) {
	resp, err := m.client.GetData(context.Background(), req)
	if err != nil {
		return nil, err
	}
	sanitizeDataRes(resp)
	return resp, nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCProviderCallbackServer struct {
	// This is the real implementation
	Impl ProviderCallback
	UnsafeProviderCallbackServer
}

var empty CollectRes

func (m *GRPCProviderCallbackServer) Collect(ctx context.Context, req *DataRes) (resp *CollectRes, err error) {
	return &empty, m.Impl.Collect(req)
}

func (m *GRPCProviderCallbackServer) GetRecording(ctx context.Context, req *DataReq) (resp *ResourceData, err error) {
	return m.Impl.GetRecording(req)
}

func (m *GRPCProviderCallbackServer) GetData(ctx context.Context, req *DataReq) (resp *DataRes, err error) {
	resp, err = m.Impl.GetData(req)
	if err != nil {
		return nil, err
	}
	sanitizeDataRes(resp)
	return resp, nil
}

func sanitizeDataRes(res *DataRes) {
	if res == nil {
		return
	}
	res.Error = sanitizeUtf8(res.Error)
	if res.Data == nil {
		return
	}
}

func sanitizeUtf8(s string) string {
	// This is a workaround for the fact that some providers
	// return can non-UTF8 strings on Windows. We need to sanitize them
	// to avoid issues with gRPC serialization.
	if utf8.ValidString(s) {
		return s
	}
	var buf bytes.Buffer
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid byte, skip it
			i++
			continue
		}
		buf.WriteRune(r)
		i += size
	}
	return buf.String()
}

// normalizeConnectError puts a Connect outcome the caller has to recognize into
// its wire form, and leaves every other error exactly as the provider wrote it.
func normalizeConnectError(err error) error {
	if errors.Is(err, ErrNoMatch) {
		return NoMatchStatus(err)
	}
	return err
}
