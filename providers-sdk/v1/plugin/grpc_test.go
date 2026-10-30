// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type blockingContextProvider struct {
	ProviderPlugin
	entered chan struct{}
	exited  chan struct{}
}

func (p *blockingContextProvider) GetDataContext(ctx context.Context, _ *DataReq) (*DataRes, error) {
	close(p.entered)
	<-ctx.Done()
	close(p.exited)
	return nil, status.FromContextError(ctx.Err()).Err()
}

func (p *blockingContextProvider) StoreDataContext(ctx context.Context, _ *StoreReq) (*StoreRes, error) {
	close(p.entered)
	<-ctx.Done()
	close(p.exited)
	return nil, status.FromContextError(ctx.Err()).Err()
}

func TestGRPCDataCallsForwardCancellation(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			provider := &blockingContextProvider{entered: make(chan struct{}), exited: make(chan struct{})}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			RegisterProviderPluginServer(server, &GRPCServer{Impl: provider})
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			conn, err := grpc.NewClient("passthrough:///provider", grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			client := &GRPCClient{client: NewProviderPluginClient(conn)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				if operation == "read" {
					_, err = client.GetDataContext(ctx, &DataReq{})
				} else {
					_, err = client.StoreDataContext(ctx, &StoreReq{})
				}
				done <- err
			}()
			select {
			case <-provider.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("provider did not receive the request")
			}
			cancel()
			select {
			case err := <-done:
				require.Equal(t, codes.Canceled, status.Code(err))
			case <-time.After(5 * time.Second):
				t.Fatal("client ignored cancellation")
			}
			select {
			case <-provider.exited:
			case <-time.After(5 * time.Second):
				t.Fatal("server discarded the request context")
			}
		})
	}
}

func TestRecoverPanic(t *testing.T) {
	t.Run("recovers string panic", func(t *testing.T) {
		var err error
		func() {
			defer recoverPanic("TestMethod", &err)
			panic("something went wrong")
		}()

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Equal(t, "panic in provider TestMethod: something went wrong", st.Message())
		assert.NotContains(t, st.Message(), "goroutine") // stack trace stays in log, not on the wire
	})

	t.Run("recovers nil pointer panic", func(t *testing.T) {
		var err error
		func() {
			defer recoverPanic("GetData", &err)
			var s *string
			_ = *s // nil pointer dereference
		}()

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "panic in provider GetData")
	})

	t.Run("no panic leaves error nil", func(t *testing.T) {
		var err error
		func() {
			defer recoverPanic("TestMethod", &err)
			// no panic
		}()

		assert.NoError(t, err)
	})
}
