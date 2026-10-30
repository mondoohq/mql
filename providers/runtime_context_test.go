// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type queryContextProvider struct {
	plugin.ProviderPlugin
	read  func(context.Context, *plugin.DataReq) (*plugin.DataRes, error)
	write func(context.Context, *plugin.StoreReq) (*plugin.StoreRes, error)
}

func (p *queryContextProvider) GetDataContext(ctx context.Context, req *plugin.DataReq) (*plugin.DataRes, error) {
	return p.read(ctx, req)
}

func (p *queryContextProvider) StoreDataContext(ctx context.Context, req *plugin.StoreReq) (*plugin.StoreRes, error) {
	return p.write(ctx, req)
}

func runtimeWithContextProvider(t *testing.T, provider plugin.ProviderPlugin) *Runtime {
	t.Helper()
	ctrl := gomock.NewController(t)
	coordinator := NewMockProvidersCoordinator(ctrl)
	schema := NewMockResourcesSchema(ctrl)
	coordinator.EXPECT().Schema().AnyTimes().Return(schema)
	schema.EXPECT().Lookup("probe").AnyTimes().Return(&resources.ResourceInfo{
		Id: "probe", Name: "probe", Provider: BuiltinCoreID,
		Fields: map[string]*resources.Field{"value": {Name: "value", Provider: BuiltinCoreID}},
	})
	connected := &ConnectedProvider{
		Instance:   &RunningProvider{ID: BuiltinCoreID, Name: "probe", Plugin: provider},
		Connection: &plugin.ConnectRes{Id: 1},
	}
	return &Runtime{
		coordinator: coordinator, recording: recording.Null{}, Provider: connected,
		providers: map[string]*ConnectedProvider{BuiltinCoreID: connected},
	}
}

func TestRuntimeQueryCancellationDoesNotMarkProviderCrashed(t *testing.T) {
	for _, operation := range []string{"create", "field", "clone", "store"} {
		t.Run(operation, func(t *testing.T) {
			entered := make(chan struct{})
			block := func(ctx context.Context) error {
				close(entered)
				<-ctx.Done()
				// gRPC represents client cancellation this way. The runtime must
				// not confuse it with go-plugin closing a crashed connection.
				return status.Error(codes.Canceled, "request cancelled")
			}
			provider := &queryContextProvider{
				read: func(ctx context.Context, req *plugin.DataReq) (*plugin.DataRes, error) {
					if ctx.Done() != nil {
						return nil, block(ctx)
					}
					return &plugin.DataRes{Data: llx.ResourceData(&llx.MockResource{Name: "probe", ID: "one"}, "probe").Result().Data}, nil
				},
				write: func(ctx context.Context, _ *plugin.StoreReq) (*plugin.StoreRes, error) {
					return nil, block(ctx)
				},
			}
			runtime := runtimeWithContextProvider(t, provider)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bound := runtime.WithContext(ctx)
			done := make(chan error, 1)
			go func() {
				var err error
				resource := &llx.MockResource{Name: "probe", ID: "one"}
				switch operation {
				case "create":
					_, err = bound.CreateResource("probe", nil)
				case "field":
					err = bound.WatchAndUpdate(resource, "value", "watch", func(any, error) {})
				case "clone":
					_, err = bound.CloneResource(resource, "two", []string{"value"}, map[string]*llx.Primitive{})
				case "store":
					_, err = bound.CloneResource(resource, "two", nil, map[string]*llx.Primitive{})
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("query context did not reach the provider")
			}
			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(5 * time.Second):
				t.Fatal("provider ignored query cancellation")
			}
			require.False(t, runtime.Provider.Instance.isClosed)
			require.Empty(t, runtime.CriticalErrors())
			// A query-local cancellation must leave the original runtime usable.
			resource, err := runtime.CreateResource("probe", nil)
			require.NoError(t, err)
			require.Equal(t, "one", resource.MqlID())
		})
	}
}

func TestRuntimeQueryContextsRemainIndependent(t *testing.T) {
	type key struct{}
	entered := make(chan struct{})
	provider := &queryContextProvider{read: func(ctx context.Context, _ *plugin.DataReq) (*plugin.DataRes, error) {
		if ctx.Value(key{}) == "blocked" {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &plugin.DataRes{Data: llx.BoolData(true).Result().Data}, nil
	}}
	runtime := runtimeWithContextProvider(t, provider)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "blocked"))
	defer cancel()
	blocked := runtime.WithContext(ctx)
	other := runtime.WithContext(context.Background())
	resource := &llx.MockResource{Name: "probe", ID: "one"}
	done := make(chan error, 1)
	go func() { done <- blocked.WatchAndUpdate(resource, "value", "blocked", func(any, error) {}) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked query did not start")
	}
	cancel()
	require.NoError(t, other.WatchAndUpdate(resource, "value", "other", func(value any, err error) {
		require.NoError(t, err)
		require.Equal(t, true, value)
	}))
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled query did not return")
	}
}
