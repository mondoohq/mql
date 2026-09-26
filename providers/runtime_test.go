// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRuntimeClose(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance: &RunningProvider{
				Name: "test",
			},
		},
	}

	// Make sure the runtime was removed from the coordinator
	mockC.EXPECT().RemoveRuntime(r).Times(1)

	// Close the runtime
	r.Close()

	// Make sure the runtime is closed and the schema is empty
	assert.True(t, r.isClosed)
}

func TestRuntime_LookupResource(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance: &RunningProvider{
				ID:   "test",
				Name: "test",
			},
		},
	}

	resName := "testResource"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: BuiltinCoreID,
	})

	// Lookup the resource
	info, err := r.lookupResource(resName)
	require.NoError(t, err)
	assert.Equal(t, resName, info.Name)
	assert.Equal(t, BuiltinCoreID, info.Provider)
}

func TestRuntime_LookupResource_CoreOverridesAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance: &RunningProvider{
				ID:   "test",
				Name: "test",
			},
		},
	}

	resName := "testResource"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name: resName,
		Others: []*resources.ResourceInfo{
			{Name: resName, Provider: "other"},
			{Name: resName, Provider: "test"}, // This matches the provider for the runtime
			{Name: resName, Provider: BuiltinCoreID},
		},
		Provider: "another",
	})

	// Lookup the resource
	info, err := r.lookupResource(resName)
	require.NoError(t, err)
	assert.Equal(t, resName, info.Name)
	assert.Equal(t, BuiltinCoreID, info.Provider) // we should get back the core resource
}

func TestRuntime_LookupResource_ProviderOverridesOthers(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance: &RunningProvider{
				ID:   "test",
				Name: "test",
			},
		},
	}

	resName := "testResource"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name: resName,
		Others: []*resources.ResourceInfo{
			{Name: resName, Provider: "other"},
			{Name: resName, Provider: "test"}, // This matches the provider for the runtime
		},
		Provider: "another",
	})

	// Lookup the resource
	info, err := r.lookupResource(resName)
	require.NoError(t, err)
	assert.Equal(t, resName, info.Name)
	assert.Equal(t, "test", info.Provider) // we should get back the core resource
}

func TestRuntime_LookupFieldProvider(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	p := &ConnectedProvider{
		Instance: &RunningProvider{
			ID:   BuiltinCoreID,
			Name: "test",
		},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			BuiltinCoreID: p,
		},
		Provider: p,
	}

	resName := "testResource"
	fieldName := "testField"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: BuiltinCoreID,
		Fields: map[string]*resources.Field{
			fieldName: {Name: fieldName, Provider: BuiltinCoreID},
		},
	})

	// Lookup the field
	_, res, field, err := r.lookupFieldProvider(resName, fieldName)
	require.NoError(t, err)
	assert.Equal(t, resName, res.Name)
	assert.Equal(t, BuiltinCoreID, res.Provider)
	assert.Equal(t, fieldName, field.Name)
	assert.Equal(t, BuiltinCoreID, field.Provider)
}

func TestRuntime_LookupFieldProvider_CoreOverridesAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	p := &ConnectedProvider{
		Instance: &RunningProvider{
			ID:   "test",
			Name: "test",
		},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			BuiltinCoreID: p,
		},
		Provider: p,
	}

	resName := "testResource"
	fieldName := "testField"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: BuiltinCoreID,
		Fields: map[string]*resources.Field{
			fieldName: {
				Name:     fieldName,
				Provider: "test",
				Others: []*resources.Field{
					{Name: fieldName, Provider: "other"},
					{Name: fieldName, Provider: BuiltinCoreID},
					{Name: fieldName, Provider: "test"}, // This matches the provider for the runtime
				},
			},
		},
	})

	// Lookup the field
	_, res, field, err := r.lookupFieldProvider(resName, fieldName)
	require.NoError(t, err)
	assert.Equal(t, resName, res.Name)
	assert.Equal(t, BuiltinCoreID, res.Provider) // we should get back the core resource

	assert.Equal(t, fieldName, field.Name)
	assert.Equal(t, BuiltinCoreID, field.Provider) // we should get back the core field
}

func TestRuntime_LookupFieldProvider_CoreOverridesAll_ResourceInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	p := &ConnectedProvider{
		Instance: &RunningProvider{
			ID:   BuiltinCoreID,
			Name: "test",
		},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			BuiltinCoreID: p,
		},
		Provider: p,
	}

	// Here the core provider definition for the field is in another resource info
	resName := "testResource"
	fieldName := "testField"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name: resName,
		Others: []*resources.ResourceInfo{
			{Name: resName, Provider: "other"},
			{Name: resName, Provider: "test"}, // This matches the provider for the runtime
			{
				Name:     resName,
				Provider: BuiltinCoreID,
				Fields: map[string]*resources.Field{
					fieldName: {Name: fieldName, Provider: BuiltinCoreID},
				},
			},
		},
		Provider: "another",
		Fields: map[string]*resources.Field{
			fieldName: {
				Name:     fieldName,
				Provider: "test",
				Others: []*resources.Field{
					{Name: fieldName, Provider: "other"},
					{Name: fieldName, Provider: "another"},
				},
			},
		},
	})

	// Lookup the field
	_, res, field, err := r.lookupFieldProvider(resName, fieldName)
	require.NoError(t, err)
	assert.Equal(t, resName, res.Name)
	assert.Equal(t, BuiltinCoreID, res.Provider) // we should get back the core resource

	assert.Equal(t, fieldName, field.Name)
	assert.Equal(t, BuiltinCoreID, field.Provider) // we should get back the core field
}

func TestRuntime_LookupFieldProvider_ProviderOverridesOthers(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	p := &ConnectedProvider{
		Instance: &RunningProvider{
			ID:   "test",
			Name: "test",
		},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			"test": p,
		},
		Provider: p,
	}

	resName := "testResource"
	fieldName := "testField"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: "test",
		Fields: map[string]*resources.Field{
			fieldName: {
				Name:     fieldName,
				Provider: "another",
				Others: []*resources.Field{
					{Name: fieldName, Provider: "other"},
					{Name: fieldName, Provider: "test"}, // This matches the provider for the runtime
				},
			},
		},
	})

	// Lookup the field
	_, res, field, err := r.lookupFieldProvider(resName, fieldName)
	require.NoError(t, err)
	assert.Equal(t, resName, res.Name)
	assert.Equal(t, "test", res.Provider)
	assert.Equal(t, fieldName, field.Name)
	assert.Equal(t, "test", field.Provider)
}

func TestRuntime_LookupFieldProvider_ProviderOverridesOthers_ResourceInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	p := &ConnectedProvider{
		Instance: &RunningProvider{
			ID:   "test",
			Name: "test",
		},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			"test": p,
		},
		Provider: p,
	}

	// Here the core provider definition for the field is in another resource info
	resName := "testResource"
	fieldName := "testField"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: "test",
		Others: []*resources.ResourceInfo{
			{Name: resName, Provider: "another"},
			{Name: resName, Provider: "test"}, // This matches the provider for the runtime
			{
				Name:     resName,
				Provider: "test",
				Fields: map[string]*resources.Field{
					fieldName: {Name: fieldName, Provider: "test"},
				},
			},
		},
		Fields: map[string]*resources.Field{
			fieldName: {
				Name:     fieldName,
				Provider: "another",
				Others: []*resources.Field{
					{Name: fieldName, Provider: "other"},
				},
			},
		},
	})

	// Lookup the field
	_, res, field, err := r.lookupFieldProvider(resName, fieldName)
	require.NoError(t, err)
	assert.Equal(t, resName, res.Name)
	assert.Equal(t, "test", res.Provider)
	assert.Equal(t, fieldName, field.Name)
	assert.Equal(t, "test", field.Provider)
}

// When two sibling providers both declare the same top-level resource
// (e.g. `vulnmgmt` is defined by both `os` and `vsphere`) and the active
// connector is a third provider whose ID matches neither — for example,
// the `sbom` connector spawning `os` via MockConnect — the schema merge
// picks a non-deterministic "primary". If the primary doesn't match an
// already-running provider on this runtime, lookupFieldProvider would
// previously fall through to spawning the unrelated provider and calling
// Connect() on the asset, which gets rejected with ErrUnsupportedProvider.
// The fix prefers any already-running provider over starting a new one,
// because a provider in r.providers is known-compatible with the asset.
func TestRuntime_LookupFieldProvider_PrefersRunningProviderForCrossProviderResource(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)

	// Active connector ("sbom") does not implement the resource itself; it
	// has initialized "os" via MockConnect, so "os" is in r.providers.
	connector := &ConnectedProvider{
		Instance: &RunningProvider{ID: "sbom", Name: "sbom"},
	}
	osProvider := &ConnectedProvider{
		Instance: &RunningProvider{ID: "os", Name: "os"},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			"sbom": connector,
			"os":   osProvider,
		},
		Provider: connector,
	}

	resName := "vulnmgmt"
	fieldName := "advisories"
	// Simulate the non-deterministic case where "vsphere" wins as primary
	// during schema aggregation. "os" is present as an Other.
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: "vsphere",
		Fields: map[string]*resources.Field{
			fieldName: {
				Name:     fieldName,
				Provider: "vsphere",
				Others: []*resources.Field{
					{Name: fieldName, Provider: "os"},
				},
			},
		},
	})

	provider, _, field, err := r.lookupFieldProvider(resName, fieldName)
	require.NoError(t, err)
	assert.Equal(t, "os", field.Provider,
		"should route to the already-running provider, not the non-running primary")
	assert.Equal(t, osProvider, provider)
}

// When the priority loop matches an entry (core or the active connector),
// the running-provider fallback must not override that intentional choice
// — even if another provider that happens to be in r.providers also
// implements the field. This guards against the case where core is the
// declared owner of a field but is handled by the static-provider branch
// (not via r.providers): without the priorityMatched guard, the fallback
// would silently swap in the running sibling.
//
// We verify by setting up the scenario where the priority pick (core) is
// not in r.providers, so the function falls through to addProvider. By
// stubbing GetRunningProvider to error, we can inspect which provider ID
// the runtime tried to spawn — it must be the priority-matched one, never
// the running sibling.
func TestRuntime_LookupFieldProvider_DoesNotOverridePriorityMatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)

	connector := &ConnectedProvider{
		Instance: &RunningProvider{ID: "connector", Name: "connector"},
	}
	siblingProvider := &ConnectedProvider{
		Instance: &RunningProvider{ID: "sibling", Name: "sibling"},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			"connector": connector,
			"sibling":   siblingProvider,
			// BuiltinCoreID intentionally NOT in r.providers — simulates core
			// being served by the static-provider path.
		},
		Provider: connector,
	}

	resName := "testResource"
	fieldName := "testField"
	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).Times(1).Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: "another",
		Fields: map[string]*resources.Field{
			fieldName: {
				Name:     fieldName,
				Provider: "another",
				Others: []*resources.Field{
					{Name: fieldName, Provider: BuiltinCoreID}, // wins priority
					{Name: fieldName, Provider: "sibling"},     // would win fallback if unguarded
				},
			},
		},
	})
	// Capture which provider ID the runtime tries to spawn after priority
	// resolution. The expectation only matches BuiltinCoreID — if the guard
	// were missing and "sibling" replaced the priority pick, the call would
	// be GetRunningProvider("sibling", ...) and the mock would fail with an
	// unexpected-call error.
	mockC.EXPECT().
		GetRunningProvider(BuiltinCoreID, gomock.Any()).
		Times(1).
		Return(nil, errors.New("simulated: not exercising real spawn"))

	_, _, _, err := r.lookupFieldProvider(resName, fieldName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start provider '"+BuiltinCoreID+"'",
		"priority match must not be overridden by the running-provider fallback")
}

// When two sibling providers are both initialized and neither matches the
// priority entries, the tie-breaker must be deterministic. We sort by
// provider ID and pick the first; without the sort, Go map iteration would
// make the choice randomly per process and reintroduce the exact flake this
// PR fixes. Run the lookup repeatedly with a fresh controller each iteration
// to verify the choice is stable across Go's randomized map order.
//
// To exercise the fallback, the primary fieldInfo.Provider must NOT itself
// be running on the runtime — otherwise the early-return at "provider in
// r.providers" short-circuits before the fallback runs. So the field's
// declared primary here is `gamma` (unloaded), with `alpha` and `beta` as
// running siblings; the tie-breaker chooses between them.
func TestRuntime_LookupFieldProvider_TieBreakerIsDeterministic(t *testing.T) {
	const iterations = 50

	runOnce := func(t *testing.T) string {
		ctrl := gomock.NewController(t)
		mockC := NewMockProvidersCoordinator(ctrl)
		mockSchema := NewMockResourcesSchema(ctrl)

		connector := &ConnectedProvider{
			Instance: &RunningProvider{ID: "connector", Name: "connector"},
		}
		alpha := &ConnectedProvider{
			Instance: &RunningProvider{ID: "alpha", Name: "alpha"},
		}
		beta := &ConnectedProvider{
			Instance: &RunningProvider{ID: "beta", Name: "beta"},
		}
		r := &Runtime{
			coordinator: mockC,
			recording:   recording.Null{},
			providers: map[string]*ConnectedProvider{
				"connector": connector,
				"alpha":     alpha,
				"beta":      beta,
				// "gamma" intentionally NOT here — forces the fallback path.
			},
			Provider: connector,
		}

		mockC.EXPECT().Schema().Times(1).Return(mockSchema)
		mockSchema.EXPECT().Lookup("testResource").Times(1).Return(&resources.ResourceInfo{
			Name:     "testResource",
			Provider: "gamma",
			Fields: map[string]*resources.Field{
				"testField": {
					Name:     "testField",
					Provider: "gamma",
					Others: []*resources.Field{
						{Name: "testField", Provider: "alpha"},
						{Name: "testField", Provider: "beta"},
					},
				},
			},
		})

		_, _, field, err := r.lookupFieldProvider("testResource", "testField")
		require.NoError(t, err)
		return field.Provider
	}

	for i := range iterations {
		if got := runOnce(t); got != "alpha" {
			t.Fatalf("iteration %d: tie-breaker should pick alphabetically-first running sibling, got %q", i, got)
		}
	}
}

// When no entry in fieldsPerProvider corresponds to an already-running
// provider, the fallback is a no-op: fieldInfo stays as the primary and
// the existing code path proceeds to spawn the new provider. This verifies
// the fallback doesn't change behavior in the "actually need to spawn"
// case — a regression here would silently break previously-working queries.
func TestRuntime_LookupFieldProvider_FallsThroughWhenNoSiblingRunning(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)

	connector := &ConnectedProvider{
		Instance: &RunningProvider{ID: "connector", Name: "connector"},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers: map[string]*ConnectedProvider{
			"connector": connector,
			// "needed" provider is NOT in r.providers — fallback should
			// retain fieldInfo.Provider = "needed" and the existing code
			// path will try to spawn it.
		},
		Provider: connector,
	}

	mockC.EXPECT().Schema().Times(1).Return(mockSchema)
	mockSchema.EXPECT().Lookup("testResource").Times(1).Return(&resources.ResourceInfo{
		Name:     "testResource",
		Provider: "needed",
		Fields: map[string]*resources.Field{
			"testField": {Name: "testField", Provider: "needed"},
		},
	})

	// Spawn path: GetRunningProvider is called for "needed". Returning an
	// error short-circuits the test without exercising real connection
	// machinery — we just want to confirm fieldInfo wasn't mutated and the
	// existing addProvider path is reached.
	mockC.EXPECT().
		GetRunningProvider("needed", gomock.Any()).
		Times(1).
		Return(nil, errors.New("simulated: not exercising real spawn"))

	_, _, _, err := r.lookupFieldProvider("testResource", "testField")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start provider 'needed'",
		"the fallback should leave fieldInfo.Provider == 'needed' and reach the existing spawn path")
}

func TestRuntime_CriticalErrors_Empty(t *testing.T) {
	r := &Runtime{}
	assert.Empty(t, r.CriticalErrors())
}

func TestRuntime_HandlePluginError_PanicRecordsCriticalError(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{
		Instance: &RunningProvider{Name: "aws"},
	}

	panicErr := status.Error(codes.Internal, "panic in provider aws: runtime error: nil pointer")
	handled, err := r.handlePluginError(panicErr, provider, "aws.ec2.instance", "tags")

	assert.True(t, handled)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider panicked")
	assert.Contains(t, err.Error(), "resource=aws.ec2.instance")
	assert.Contains(t, err.Error(), "field=tags")

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.Contains(t, critErrs[0].Error(), "provider panicked")
	assert.Contains(t, critErrs[0].Error(), "resource=aws.ec2.instance")
}

func TestRuntime_HandlePluginError_CrashRecordsCriticalError(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{
		Instance: &RunningProvider{Name: "aws"},
	}

	crashErr := status.Error(codes.Unavailable, "connection lost")
	handled, err := r.handlePluginError(crashErr, provider, "aws.ec2.instance", "")

	assert.False(t, handled)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider crashed")
	assert.Contains(t, err.Error(), "resource=aws.ec2.instance")

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.Contains(t, critErrs[0].Error(), "provider crashed")
}

// fakeDialRefusedErr builds a *net.OpError shaped exactly like what a real
// failed TCP dial to a dead loopback port returns -- its Error() renders as
// "dial tcp 127.0.0.1:<port>: connect: connection refused", the same text
// production observed, but constructed so the test doesn't depend on actual
// OS networking behavior (which can vary or be sandboxed in CI).
func fakeDialRefusedErr(port int) *net.OpError {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port},
		Err:  os.NewSyscallError("connect", syscall.ECONNREFUSED),
	}
}

func TestRuntime_HandlePluginError_TransportErrorRecordsCriticalError(t *testing.T) {
	r := &Runtime{}
	// proc set: this simulates an out-of-process (subprocess-backed)
	// provider, the same signal coordinator.go's subprocess-launching path
	// sets on a real plugin. Only for such a provider does a transport-
	// shaped error mean the plugin's own connection died.
	instance := &RunningProvider{Name: "aws", proc: &processTracker{}}
	// Skip awaitExit's 2s grace wait for an exit this bare tracker will
	// never report -- same trick exit_status_unix_test.go uses.
	instance.exitGraceExpired.Store(true)
	provider := &ConnectedProvider{Instance: instance}

	// A genuine transport failure (no gRPC status): a real *net.OpError, the
	// shape a failed dial to a dead loopback port actually takes.
	transportErr := fakeDialRefusedErr(1234)
	handled, err := r.handlePluginError(transportErr, provider, "aws.ec2.instance", "securityGroups")

	assert.False(t, handled)
	require.Error(t, err)

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.Contains(t, critErrs[0].Error(), "provider crashed")
	assert.Contains(t, critErrs[0].Error(), "resource=aws.ec2.instance")
	assert.Contains(t, critErrs[0].Error(), "field=securityGroups")
	// Same as the codes.Unavailable/codes.Canceled branch: a genuine
	// transport error means the provider process is gone, so it's recorded
	// via recordCrash and the provider is marked closed.
	assert.True(t, instance.isClosed)
}

// TestRuntime_HandlePluginError_NonTransportBareErrorPassesThroughUnchanged
// is the regression test for the misclassification that broke
// cli/printer's TestPrinter_Assessment: an ordinary application error (e.g.
// "cannot find user with name 'notthere'" from a bad `user(name: ...)`
// lookup) never carries a gRPC status either -- the builtin/core provider
// and plugin mocks return Go errors straight from resource code, with no
// gRPC involved at all. Such an error must come back completely unchanged,
// must not be recorded as a critical error, and must not mark the provider
// crashed (which would poison every later field for the rest of the run
// with this one lookup's error, as it did before this fix).
func TestRuntime_HandlePluginError_NonTransportBareErrorPassesThroughUnchanged(t *testing.T) {
	r := &Runtime{}
	instance := &RunningProvider{Name: "os"}
	provider := &ConnectedProvider{Instance: instance}

	appErr := errors.New("cannot find user with name 'notthere'")
	handled, err := r.handlePluginError(appErr, provider, "user", "")

	assert.False(t, handled)
	require.Error(t, err)
	assert.Same(t, appErr, err)
	assert.Equal(t, "cannot find user with name 'notthere'", err.Error())

	assert.Empty(t, r.CriticalErrors())
	assert.False(t, instance.isClosed)

	// A second, unrelated ordinary error on the same provider must also
	// pass through untouched -- proving the first one didn't leave the
	// provider in some half-crashed state.
	otherErr := errors.New("cannot find group with name 'admins'")
	_, err2 := r.handlePluginError(otherErr, provider, "group", "")
	assert.Same(t, otherErr, err2)
	assert.Empty(t, r.CriticalErrors())
	assert.False(t, instance.isClosed)
}

// TestRuntime_HandlePluginError_BuiltinProviderTransportShapedErrorPassesThrough
// is the narrower follow-up to the regression above: a *net.OpError, an
// ECONNREFUSED, or an io.EOF are exactly as ordinary for a BUILTIN/
// in-process provider as any other Go error. A builtin `port`/`http.get`
// check against a closed port genuinely returns *net.OpError/ECONNREFUSED,
// and a file read past its end genuinely returns io.EOF -- from a call that
// never went through a plugin RPC at all, since RunningProvider.proc (nil
// here, exactly as for every entry in builtin.go's builtinProviders map) is
// what the rest of this file already uses to know whether there is a
// subprocess in the first place (see awaitExit). Even though these errors
// match isTransportFailure's shapes, they must be returned unchanged,
// unrecorded, and must not mark the provider closed.
func TestRuntime_HandlePluginError_BuiltinProviderTransportShapedErrorPassesThrough(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"net.OpError/ECONNREFUSED", fakeDialRefusedErr(80)},
		{"io.EOF", io.EOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{}
			instance := &RunningProvider{Name: "os"} // proc == nil: builtin/in-process
			provider := &ConnectedProvider{Instance: instance}

			handled, err := r.handlePluginError(tc.err, provider, "os.port", "")

			assert.False(t, handled)
			require.Error(t, err)
			assert.Same(t, tc.err, err)
			assert.Empty(t, r.CriticalErrors())
			assert.False(t, instance.isClosed)
		})
	}
}

// TestRuntime_HandlePluginError_OutOfProcessTransportErrorRecordsCrash mirrors
// the test above for a provider that DOES run out of process (proc set):
// the very same error shapes now mean the plugin's own connection died, so
// they must be recorded as a crash, once.
func TestRuntime_HandlePluginError_OutOfProcessTransportErrorRecordsCrash(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"net.OpError/ECONNREFUSED", fakeDialRefusedErr(80)},
		{"io.EOF", io.EOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{}
			instance := &RunningProvider{Name: "aws", proc: &processTracker{}}
			instance.exitGraceExpired.Store(true)
			provider := &ConnectedProvider{Instance: instance}

			handled, err := r.handlePluginError(tc.err, provider, "aws.ec2.instance", "")

			assert.False(t, handled)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "provider crashed")
			assert.True(t, instance.isClosed)
			require.Len(t, r.CriticalErrors(), 1)
		})
	}
}

// TestRuntime_HandlePluginError_RepeatedTransportErrorsDedupe reproduces a
// provider that keeps failing every remaining field with a genuine
// transport error (no gRPC status) after it dies -- e.g. every later call
// redials the same dead loopback port and observes the same
// "connection refused" failure. Before routing the !ok branch's genuine
// transport failures through recordCrash, each of these calls built and
// recorded its own critical error, one per field. It must instead collapse
// into a single stored diagnostic and a single critical error, the same
// guarantee the codes.Unavailable/codes.Canceled branch already has.
func TestRuntime_HandlePluginError_RepeatedTransportErrorsDedupe(t *testing.T) {
	r := &Runtime{}
	instance := &RunningProvider{Name: "os", proc: &processTracker{}}
	instance.exitGraceExpired.Store(true)
	provider := &ConnectedProvider{Instance: instance}

	transportErr := fakeDialRefusedErr(52487)

	_, firstErr := r.handlePluginError(transportErr, provider, "os.file", "content")
	require.Error(t, firstErr)

	_, secondErr := r.handlePluginError(transportErr, provider, "os.file", "permissions")
	require.Error(t, secondErr)

	_, thirdErr := r.handlePluginError(transportErr, provider, "os.file", "owner")
	require.Error(t, thirdErr)

	// The exact same diagnostic every time, not a freshly rebuilt one per
	// field (the second/third calls also don't carry that field's own
	// resource/field context, proving they short-circuited via crashError()
	// rather than reclassifying).
	assert.Equal(t, firstErr.Error(), secondErr.Error())
	assert.Equal(t, firstErr.Error(), thirdErr.Error())
	assert.Contains(t, firstErr.Error(), "field=content")
	assert.NotContains(t, secondErr.Error(), "field=permissions")
	assert.NotContains(t, thirdErr.Error(), "field=owner")

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.True(t, instance.isClosed)
}

func TestRuntime_HandlePluginError_NonPanicInternalDoesNotRecordCriticalError(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{
		Instance: &RunningProvider{Name: "aws"},
	}

	internalErr := status.Error(codes.Internal, "some other internal error")
	handled, err := r.handlePluginError(internalErr, provider, "", "")

	assert.False(t, handled)
	require.Error(t, err)
	assert.Empty(t, r.CriticalErrors())
}

func TestRuntime_CriticalErrors_MultiplePanics(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{
		Instance: &RunningProvider{Name: "aws"},
	}

	for range 3 {
		panicErr := status.Error(codes.Internal, "panic in provider aws: error")
		r.handlePluginError(panicErr, provider, "", "") // nolint:errcheck
	}

	assert.Len(t, r.CriticalErrors(), 3)
}

func TestRuntime_HandlePluginError_CrashIncludesVersionAndUptime(t *testing.T) {
	r := &Runtime{}
	instance := &RunningProvider{
		Name:      "os",
		Version:   "13.5.0",
		startedAt: time.Now().Add(-3 * time.Second),
	}
	provider := &ConnectedProvider{Instance: instance}

	crashErr := status.Error(codes.Unavailable, "error reading from server: EOF")
	_, err := r.handlePluginError(crashErr, provider, "npm.packages", "list")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "version=13.5.0")
	assert.Contains(t, err.Error(), "uptime=")
	// uptime=3s (approximately) — just confirm it's a duration string
	assert.Contains(t, err.Error(), "subprocess=running")
}

func TestRuntime_HandlePluginError_CrashIncludesPanicTail(t *testing.T) {
	r := &Runtime{}
	buf := newCrashLogBuffer(io.Discard, 100)
	_, _ = buf.Write([]byte("2026-05-04 starting up\n"))
	_, _ = buf.Write([]byte("panic: runtime error: invalid memory address\n"))
	_, _ = buf.Write([]byte("[signal SIGSEGV]\n"))
	_, _ = buf.Write([]byte("goroutine 1:\n"))
	_, _ = buf.Write([]byte("\tpkg.Func()\n"))

	instance := &RunningProvider{
		Name:     "os",
		Version:  "13.5.0",
		crashLog: buf,
	}
	provider := &ConnectedProvider{Instance: instance}

	crashErr := status.Error(codes.Unavailable, "error reading from server: EOF")
	_, err := r.handlePluginError(crashErr, provider, "npm.packages", "list")

	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "plugin stderr (panic/fatal trace):")
	assert.Contains(t, msg, "panic: runtime error: invalid memory address")
	assert.Contains(t, msg, "goroutine 1:")
	// The pre-panic startup line must not be in the panic-trace section.
	tailIdx := mustIndex(t, msg, "plugin stderr (panic/fatal trace):")
	assert.NotContains(t, msg[tailIdx:], "starting up")
}

func TestRuntime_HandlePluginError_CrashFallsBackToRecentStderr(t *testing.T) {
	// No panic marker — we should still surface recent stderr lines so the
	// caller has something to look at (e.g. for OOM-killed subprocesses that
	// die without writing a panic trace).
	r := &Runtime{}
	buf := newCrashLogBuffer(io.Discard, 100)
	_, _ = buf.Write([]byte("2026-05-04 querying /var/lib\n"))
	_, _ = buf.Write([]byte("2026-05-04 found 1024 entries\n"))

	instance := &RunningProvider{
		Name:     "os",
		crashLog: buf,
	}
	provider := &ConnectedProvider{Instance: instance}

	crashErr := status.Error(codes.Unavailable, "error reading from server: EOF")
	_, err := r.handlePluginError(crashErr, provider, "files.find", "list")

	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "plugin stderr (last 2 lines):")
	assert.Contains(t, msg, "querying /var/lib")
	assert.Contains(t, msg, "found 1024 entries")
}

func TestRuntime_HandlePluginError_CrashIncludesHeartbeatTrigger(t *testing.T) {
	r := &Runtime{}
	instance := &RunningProvider{
		Name:            "os",
		heartbeatFailed: true,
	}
	provider := &ConnectedProvider{Instance: instance}

	crashErr := status.Error(codes.Unavailable, "error reading from server: EOF")
	_, err := r.handlePluginError(crashErr, provider, "windows", "optionalFeatures")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "trigger=heartbeat-timeout")
}

func TestRuntime_HandlePluginError_CrashTailIsTruncated(t *testing.T) {
	// A panic that produces hundreds of stack frames (e.g. with a large
	// runtime goroutine dump) must not balloon the error string. Verify
	// the cap kicks in and a truncation marker is appended.
	r := &Runtime{}
	buf := newCrashLogBuffer(io.Discard, 500)
	_, _ = buf.Write([]byte("panic: too much\n"))
	for i := range 300 {
		_, _ = buf.Write([]byte(strconv.Itoa(i) + " frame\n"))
	}

	instance := &RunningProvider{Name: "os", crashLog: buf}
	provider := &ConnectedProvider{Instance: instance}

	crashErr := status.Error(codes.Unavailable, "EOF")
	_, err := r.handlePluginError(crashErr, provider, "x", "y")

	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "panic: too much")
	assert.Contains(t, msg, "(trace truncated)")
	// Frame 0..79 should be present (cap is 80, including the panic line
	// that's 79 frames). Frame 200 should not.
	assert.Contains(t, msg, "0 frame")
	assert.NotContains(t, msg, "200 frame")
}

func TestRuntime_HandlePluginError_CrashWithoutContextStaysCompact(t *testing.T) {
	// A bare RunningProvider (no version, no startedAt, no buffer) should not
	// produce extra noise — the message is just the original crash text.
	r := &Runtime{}
	provider := &ConnectedProvider{
		Instance: &RunningProvider{Name: "aws"},
	}

	crashErr := status.Error(codes.Unavailable, "connection lost")
	_, err := r.handlePluginError(crashErr, provider, "", "")

	require.Error(t, err)
	msg := err.Error()
	assert.NotContains(t, msg, "version=")
	assert.NotContains(t, msg, "uptime=")
	assert.NotContains(t, msg, "plugin stderr")
}

// TestRuntime_HandlePluginError_CanceledIsClassifiedAsCrash covers a provider
// whose very first observed failure is codes.Canceled ("grpc: the client
// connection is closing") rather than Unavailable -- e.g. go-plugin tears the
// client down and the next in-flight RPC observes the teardown before a
// fresh dial ever gets attempted. Before this change codes.Canceled fell
// through handlePluginError's switch unclassified: no crash diagnostics, no
// critical error, isClosed left false.
func TestRuntime_HandlePluginError_CanceledIsClassifiedAsCrash(t *testing.T) {
	r := &Runtime{}
	instance := &RunningProvider{Name: "os"}
	provider := &ConnectedProvider{Instance: instance}

	canceledErr := status.Error(codes.Canceled, "grpc: the client connection is closing")
	handled, err := r.handlePluginError(canceledErr, provider, "os.file", "content")

	assert.False(t, handled)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider crashed")
	assert.Contains(t, err.Error(), "resource=os.file")

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.True(t, instance.isClosed)
}

// TestRuntime_HandlePluginError_CanceledAfterCrashIsDeduped reproduces the
// second raw error text seen in production: an initial GetData call observes
// codes.Unavailable (the plugin crashed) and records a diagnostic, then a
// later field on the same provider observes codes.Canceled as go-plugin
// finishes tearing the connection down. The second call must fold into the
// first diagnostic rather than surfacing "grpc: the client connection is
// closing" raw and unrecorded, and must not add a second critical error.
func TestRuntime_HandlePluginError_CanceledAfterCrashIsDeduped(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{Instance: &RunningProvider{Name: "os"}}

	unavailableErr := status.Error(codes.Unavailable, `connection error: desc = "transport: error while dialing: dial tcp 127.0.0.1:52487: connectex: No connection could be made because the target machine actively refused it."`)
	_, firstErr := r.handlePluginError(unavailableErr, provider, "os.file", "content")
	require.Error(t, firstErr)
	assert.Contains(t, firstErr.Error(), "provider crashed")

	canceledErr := status.Error(codes.Canceled, "grpc: the client connection is closing")
	_, secondErr := r.handlePluginError(canceledErr, provider, "os.file", "permissions")
	require.Error(t, secondErr)

	// The exact same diagnostic comes back both times, not the raw Canceled
	// text and not a freshly rebuilt one for the second field.
	assert.Equal(t, firstErr.Error(), secondErr.Error())
	assert.NotContains(t, secondErr.Error(), "client connection is closing")

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
}

// TestRuntime_HandlePluginError_AnyErrorAfterCrashIsDeduped shows the
// short-circuit at the top of handlePluginError is not keyed to a specific
// gRPC code: once a provider has a stored diagnostic, ANY further error --
// including a bare transport error with no gRPC status at all -- folds into
// it instead of going through classification (and re-recording) again.
func TestRuntime_HandlePluginError_AnyErrorAfterCrashIsDeduped(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{Instance: &RunningProvider{Name: "os"}}

	unavailableErr := status.Error(codes.Unavailable, "error reading from server: EOF")
	_, firstErr := r.handlePluginError(unavailableErr, provider, "os.file", "content")
	require.Error(t, firstErr)

	bareErr := errors.New("connection error: desc = transport: error while dialing: dial tcp 127.0.0.1:52487: connect: connection refused")
	_, secondErr := r.handlePluginError(bareErr, provider, "os.file", "permissions")
	require.Error(t, secondErr)

	assert.Equal(t, firstErr.Error(), secondErr.Error())
	assert.NotContains(t, secondErr.Error(), "connection refused")

	require.Len(t, r.CriticalErrors(), 1)
}

// TestRuntime_CreateResource_WrapsCrashDiagnostics is the regression test for
// the primary bypass this PR fixes: CreateResource used to return whatever
// error GetData handed back verbatim, so a crashed provider's raw
// "rpc error: code = Unavailable ..." text ended up stored as the field's
// error instead of the "provider crashed" diagnostic every other path
// produces. llx.go's blockExecutor.createResource stores this error exactly
// as returned, so this is also the hot path a scan actually exercises for
// every resource instantiation.
func TestRuntime_CreateResource_WrapsCrashDiagnostics(t *testing.T) {
	resName := "os.file"
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	mockPlugin := NewMockProviderPlugin(ctrl)

	const providerID = "go.mondoo.com/mql/providers/os"
	p := &ConnectedProvider{
		Instance:   &RunningProvider{ID: providerID, Name: "os", Plugin: mockPlugin},
		Connection: &plugin.ConnectRes{Id: 1},
	}

	mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).AnyTimes().Return(&resources.ResourceInfo{
		Id: resName, Name: resName, Provider: providerID,
	})

	rawCrash := status.Error(codes.Unavailable, `connection error: desc = "transport: error while dialing: dial tcp 127.0.0.1:52487: connectex: No connection could be made because the target machine actively refused it."`)
	mockPlugin.EXPECT().GetData(gomock.Any()).Times(1).Return(nil, rawCrash)

	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers:   map[string]*ConnectedProvider{providerID: p},
		Provider:    p,
	}

	_, err := r.CreateResource(resName, nil)
	require.Error(t, err)
	// Classified and attributed, not the bare RPC text CreateResource used to
	// return verbatim (the raw text still rides along inside the diagnostic).
	assert.True(t, strings.HasPrefix(err.Error(), "the 'os' provider crashed (resource=os.file):"), "got: %s", err.Error())

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.True(t, p.Instance.isClosed)
}

// TestRuntime_CreateResource_ShortCircuitsOnceProviderCrashed covers the
// short-circuit: once a provider is known dead, CreateResource must not
// dial it again for the next resource -- it returns the stored crash
// diagnostic straight away. GetData is expected Times(0) to prove no RPC is
// attempted.
func TestRuntime_CreateResource_ShortCircuitsOnceProviderCrashed(t *testing.T) {
	resName := "os.file"
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	mockPlugin := NewMockProviderPlugin(ctrl)

	const providerID = "go.mondoo.com/mql/providers/os"
	instance := &RunningProvider{ID: providerID, Name: "os", Plugin: mockPlugin}
	p := &ConnectedProvider{Instance: instance, Connection: &plugin.ConnectRes{Id: 1}}

	mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).AnyTimes().Return(&resources.ResourceInfo{
		Id: resName, Name: resName, Provider: providerID,
	})
	mockPlugin.EXPECT().GetData(gomock.Any()).Times(0)

	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers:   map[string]*ConnectedProvider{providerID: p},
		Provider:    p,
	}

	stored, _ := instance.recordCrash(func() error {
		return errors.New("the 'os' provider crashed: connection refused")
	})

	_, err := r.CreateResource(resName, nil)
	require.Error(t, err)
	assert.Equal(t, stored.Error(), err.Error())
}

// TestRuntime_WatchAndUpdate_ShortCircuitsOnceProviderCrashed mirrors the
// CreateResource short-circuit test for the field-read path: once a provider
// is known dead, watchAndUpdate must not call GetData (or, for a
// cross-provider field, StoreData) again.
func TestRuntime_WatchAndUpdate_ShortCircuitsOnceProviderCrashed(t *testing.T) {
	resName := "testResource"
	fieldName := "testField"
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	mockPlugin := NewMockProviderPlugin(ctrl)

	instance := &RunningProvider{ID: BuiltinCoreID, Name: "test", Plugin: mockPlugin}
	p := &ConnectedProvider{Instance: instance, Connection: &plugin.ConnectRes{Id: 1}}

	mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
	mockSchema.EXPECT().Lookup(resName).AnyTimes().Return(&resources.ResourceInfo{
		Name:     resName,
		Provider: BuiltinCoreID,
		Fields: map[string]*resources.Field{
			fieldName: {Name: fieldName, Provider: BuiltinCoreID},
		},
	})
	mockPlugin.EXPECT().GetData(gomock.Any()).Times(0)
	mockPlugin.EXPECT().StoreData(gomock.Any()).Times(0)

	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		providers:   map[string]*ConnectedProvider{BuiltinCoreID: p},
		Provider:    p,
	}

	stored, _ := instance.recordCrash(func() error {
		return errors.New("the 'test' provider crashed: connection refused")
	})

	_, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
	require.Error(t, err)
	assert.Equal(t, stored.Error(), err.Error())
}

func mustIndex(t *testing.T, s, sub string) int {
	t.Helper()
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	t.Fatalf("substring %q not found in %q", sub, s)
	return -1
}

// TestSyncAssetMetadata covers the copy that makes upstream-synced asset metadata
// visible to providers. Discovery hands out an independent clone of the connection
// asset, so without this copy an annotation added after connecting never reaches the
// `asset` resource, and a policy or risk factor keyed on a server-side annotation
// silently never matches.
func TestSyncAssetMetadata(t *testing.T) {
	const key = "mondoo.com/internet-exposed"

	newProvider := func(a *inventory.Asset) *ConnectedProvider {
		return &ConnectedProvider{Connection: &plugin.ConnectRes{Asset: a}}
	}

	t.Run("annotations synced from upstream reach the connection asset", func(t *testing.T) {
		connAsset := &inventory.Asset{Annotations: map[string]string{"owner": "platform"}}
		provider := newProvider(connAsset)

		// what cnspec does after SynchronizeAssets: mutate its own clone
		updated := &inventory.Asset{Annotations: map[string]string{"owner": "platform", key: "true"}}
		syncAssetMetadata(provider, updated)

		assert.Equal(t, "true", connAsset.Annotations[key])
		assert.Equal(t, "platform", connAsset.Annotations["owner"])

		// and therefore the asset resource built from it exposes the annotation
		args := recording.CreateAssetResourceArgs(connAsset)
		annotations, ok := args["annotations"].Value.(map[string]any)
		require.True(t, ok, "annotations arg should be a map")
		assert.Equal(t, "true", annotations[key])
	})

	t.Run("labels are synced too", func(t *testing.T) {
		connAsset := &inventory.Asset{}
		provider := newProvider(connAsset)
		syncAssetMetadata(provider, &inventory.Asset{
			Labels: map[string]string{"mondoo.com/project-id": "p-1"},
		})
		assert.Equal(t, "p-1", connAsset.Labels["mondoo.com/project-id"])
	})

	t.Run("nil maps do not erase existing metadata", func(t *testing.T) {
		connAsset := &inventory.Asset{
			Labels:      map[string]string{"a": "1"},
			Annotations: map[string]string{"b": "2"},
		}
		provider := newProvider(connAsset)
		syncAssetMetadata(provider, &inventory.Asset{})
		assert.Equal(t, map[string]string{"a": "1"}, connAsset.Labels)
		assert.Equal(t, map[string]string{"b": "2"}, connAsset.Annotations)
	})

	t.Run("tolerates nil provider, connection, and asset", func(t *testing.T) {
		assert.NotPanics(t, func() {
			syncAssetMetadata(nil, &inventory.Asset{})
			syncAssetMetadata(&ConnectedProvider{}, &inventory.Asset{})
			syncAssetMetadata(newProvider(nil), &inventory.Asset{})
			syncAssetMetadata(newProvider(&inventory.Asset{}), nil)
		})
	})

	t.Run("no-op when the updated asset is the connection asset", func(t *testing.T) {
		same := &inventory.Asset{Annotations: map[string]string{key: "true"}}
		assert.NotPanics(t, func() { syncAssetMetadata(newProvider(same), same) })
		assert.Equal(t, "true", same.Annotations[key])
	})
}

// AssetRoot is read on every compile (mqlc.NewConfigFrom), so it has to answer
// from the main provider without consulting the coordinator, and it has to
// answer at all before anything is connected. See ADR 031.
func TestAssetRoot(t *testing.T) {
	t.Run("the connection's answer wins", func(t *testing.T) {
		r := &Runtime{Provider: &ConnectedProvider{
			Instance:   &RunningProvider{Name: "os", Root: "os.any"},
			Connection: &plugin.ConnectRes{Root: "os.linux"},
		}}
		assert.Equal(t, "os.linux", r.AssetRoot(), "the connection knows which platform it reached")
		assert.Equal(t, "os.any", r.DeclaredAssetRoot(), "the declaration stays the union")
	})

	// Every provider that has not implemented the ConnectRes field yet, which
	// is all of them but os.
	t.Run("falls back to the declaration", func(t *testing.T) {
		r := &Runtime{Provider: &ConnectedProvider{
			Instance:   &RunningProvider{Name: "os", Root: "os.any"},
			Connection: &plugin.ConnectRes{},
		}}
		assert.Equal(t, "os.any", r.AssetRoot())
	})

	t.Run("from the main provider", func(t *testing.T) {
		r := &Runtime{Provider: &ConnectedProvider{
			Instance: &RunningProvider{Name: "os", Root: "os.any"},
		}}
		assert.Equal(t, "os.any", r.AssetRoot())
	})

	// A provider that declares no root leaves `_` failing, which is the state
	// every provider starts in.
	t.Run("provider declares none", func(t *testing.T) {
		r := &Runtime{Provider: &ConnectedProvider{Instance: &RunningProvider{Name: "aws"}}}
		assert.Equal(t, "", r.AssetRoot())
	})

	t.Run("no provider yet", func(t *testing.T) {
		assert.Equal(t, "", (&Runtime{}).AssetRoot())
		assert.Equal(t, "", (&Runtime{Provider: &ConnectedProvider{}}).AssetRoot())
	})
}

func TestDeclaresPeer(t *testing.T) {
	r := &Runtime{}
	caller := &RunningProvider{
		Name: "os",
		ID:   "go.mondoo.com/mql/providers/os",
		Requires: []plugin.ProviderDep{
			{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "13.0.0"},
		},
	}

	t.Run("declared by id", func(t *testing.T) {
		min, ok := r.declaresPeer(caller, "go.mondoo.com/mql/providers/network")
		assert.True(t, ok)
		assert.Equal(t, "13.0.0", min)
	})

	// A v14 caller against an installed pre-v14 peer: the peer reports its old
	// ID, which no normalized declaration names. Both legacy forms must match,
	// or a correctly-declared call gets logged as legacy-only and the whitelist
	// retirement signal never converges.
	for _, legacyID := range []string{
		"go.mondoo.com/cnquery/providers/network",
		"go.mondoo.com/cnquery/v9/providers/network",
	} {
		t.Run("declared by name when the peer reports "+legacyID, func(t *testing.T) {
			min, ok := r.declaresPeer(caller, legacyID)
			assert.True(t, ok)
			assert.Equal(t, "13.0.0", min)
		})
	}

	t.Run("self is always allowed", func(t *testing.T) {
		_, ok := r.declaresPeer(caller, "go.mondoo.com/mql/providers/os")
		assert.True(t, ok)
	})

	t.Run("undeclared", func(t *testing.T) {
		_, ok := r.declaresPeer(caller, "go.mondoo.com/mql/providers/aws")
		assert.False(t, ok)
	})
}

func TestCheckPeerVersion(t *testing.T) {
	peer := func(v string) *RunningProvider {
		return &RunningProvider{Name: "network", Version: v}
	}

	assert.NoError(t, checkPeerVersion(peer("13.3.0"), "13.0.0"), "newer peer satisfies the floor")
	assert.NoError(t, checkPeerVersion(peer("13.0.0"), "13.0.0"), "exact match satisfies the floor")
	assert.NoError(t, checkPeerVersion(peer("13.3.0"), ""), "no declared floor is no constraint")
	assert.NoError(t, checkPeerVersion(peer(""), "13.0.0"), "unknown peer version is not evidence of a mismatch")
	assert.NoError(t, checkPeerVersion(peer("not-a-version"), "13.0.0"), "unparseable version must not break the call")

	err := checkPeerVersion(peer("12.9.0"), "13.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "older than the required 13.0.0")
}

// ADR 046: the executor is where a provider's classification would otherwise be
// rebuilt as an anonymous error, so the rehydration gets its own coverage.
func TestRuntime_WatchAndUpdate_RehydratesTheErrorKind(t *testing.T) {
	resName := "testResource"
	fieldName := "testField"

	newRuntime := func(t *testing.T, res *plugin.DataRes) *Runtime {
		ctrl := gomock.NewController(t)
		mockC := NewMockProvidersCoordinator(ctrl)
		mockSchema := NewMockResourcesSchema(ctrl)
		mockPlugin := NewMockProviderPlugin(ctrl)

		p := &ConnectedProvider{
			Instance: &RunningProvider{
				ID:     BuiltinCoreID,
				Name:   "test",
				Plugin: mockPlugin,
			},
			Connection: &plugin.ConnectRes{Id: 1},
		}

		mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
		mockSchema.EXPECT().Lookup(resName).AnyTimes().Return(&resources.ResourceInfo{
			Name:     resName,
			Provider: BuiltinCoreID,
			Fields: map[string]*resources.Field{
				fieldName: {Name: fieldName, Provider: BuiltinCoreID},
			},
		})
		mockPlugin.EXPECT().GetData(gomock.Any()).Times(1).Return(res, nil)

		return &Runtime{
			coordinator: mockC,
			recording:   recording.Null{},
			providers:   map[string]*ConnectedProvider{BuiltinCoreID: p},
			Provider:    p,
		}
	}

	t.Run("a classified error arrives classified", func(t *testing.T) {
		r := newRuntime(t, &plugin.DataRes{
			Error: "AccessDenied: not authorized to perform ec2:DescribeInstances",
			ErrorDetail: &llx.ErrorDetail{
				Kind:        llx.ErrorKind_ERROR_KIND_FORBIDDEN,
				Scope:       llx.ErrorScope_ERROR_SCOPE_PARTITION,
				ScopeId:     "eu-west-1",
				Permissions: []string{"ec2:DescribeInstances"},
			},
		})

		raw, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
		require.NoError(t, err)
		require.NotNil(t, raw)
		require.Error(t, raw.Error)

		assert.True(t, errors.Is(raw.Error, llx.ErrForbidden))
		// The target's own words survive; the kind rides beside them.
		assert.Equal(t, "AccessDenied: not authorized to perform ec2:DescribeInstances", raw.Error.Error())

		var typed *llx.Error
		require.True(t, errors.As(raw.Error, &typed))
		assert.Equal(t, "eu-west-1", typed.ScopeID)
		assert.Equal(t, []string{"ec2:DescribeInstances"}, typed.Permissions)
	})

	t.Run("an unclassified error stays unclassified", func(t *testing.T) {
		// Every provider that has not been migrated yet takes this path, and
		// has to behave exactly as it did before.
		r := newRuntime(t, &plugin.DataRes{Error: "something broke"})

		raw, err := r.watchAndUpdate(resName, "id-2", fieldName, "")
		require.NoError(t, err)
		require.Error(t, raw.Error)
		assert.Equal(t, "something broke", raw.Error.Error())
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(raw.Error))
	})

	// ADR 046 §8: a partial field keeps its value, and its gaps ride beside it
	// rather than in the error slot.
	partial := func() *plugin.DataRes {
		return &plugin.DataRes{
			Data: llx.ArrayPrimitive([]*llx.Primitive{llx.StringPrimitive("eip-1")}, types.String),
			CoverageGaps: []*llx.CoverageGap{{
				Error: "AccessDenied",
				Detail: &llx.ErrorDetail{
					Kind:    llx.ErrorKind_ERROR_KIND_FORBIDDEN,
					Scope:   llx.ErrorScope_ERROR_SCOPE_PARTITION,
					ScopeId: "eu-west-1",
				},
			}},
		}
	}

	t.Run("a partial field keeps its value and its gaps", func(t *testing.T) {
		r := newRuntime(t, partial())

		raw, err := r.watchAndUpdate(resName, "id-3", fieldName, "")
		require.NoError(t, err)
		require.NoError(t, raw.Error)
		assert.Equal(t, []any{"eip-1"}, raw.Value)
		require.Len(t, raw.CoverageGaps, 1)
		assert.True(t, errors.Is(raw.CoverageGaps[0], llx.ErrForbidden))
		assert.Equal(t, "eu-west-1", raw.CoverageGaps[0].ScopeID)
	})

	t.Run("the executor's callback receives the gaps as a partial", func(t *testing.T) {
		r := newRuntime(t, partial())

		var gotValue any
		var gotErr error
		err := r.WatchAndUpdate(&llx.MockResource{Name: resName, ID: "id-4"}, fieldName, "", func(res any, err error) {
			gotValue, gotErr = res, err
		})
		require.NoError(t, err)
		assert.Equal(t, []any{"eip-1"}, gotValue)
		gaps, ok := llx.CoverageGapsOf(gotErr)
		require.True(t, ok, "a partial field must not reach the executor as a plain error")
		require.Len(t, gaps, 1)
		assert.Equal(t, "eu-west-1", gaps[0].ScopeID)
	})
}

// ADR 046 phase 8: once a connection reports an ASSET-scoped failure, every
// later call on it is answered with that failure instead of reaching the
// provider, and the answer is the one the provider would have given.
func TestRuntime_ShortCircuitsAfterAssetScopedFailure(t *testing.T) {
	resName := "testResource"
	fieldName := "testField"

	unauthenticated := &plugin.DataRes{
		Error: "401 Unauthorized: token expired",
		ErrorDetail: &llx.ErrorDetail{
			Kind:  llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED,
			Scope: llx.ErrorScope_ERROR_SCOPE_ASSET,
		},
	}

	// newRuntime expects exactly `calls` GetData requests on the provider.
	newRuntime := func(t *testing.T, calls int, res *plugin.DataRes) (*Runtime, *ConnectedProvider) {
		ctrl := gomock.NewController(t)
		mockC := NewMockProvidersCoordinator(ctrl)
		mockSchema := NewMockResourcesSchema(ctrl)
		mockPlugin := NewMockProviderPlugin(ctrl)

		p := &ConnectedProvider{
			Instance:   &RunningProvider{ID: BuiltinCoreID, Name: "test", Plugin: mockPlugin},
			Connection: &plugin.ConnectRes{Id: 1},
		}

		mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
		mockSchema.EXPECT().Lookup(resName).AnyTimes().Return(&resources.ResourceInfo{
			Id:       resName,
			Name:     resName,
			Provider: BuiltinCoreID,
			Fields: map[string]*resources.Field{
				fieldName: {Name: fieldName, Provider: BuiltinCoreID},
			},
		})
		mockPlugin.EXPECT().GetData(gomock.Any()).Times(calls).Return(res, nil)

		return &Runtime{
			coordinator: mockC,
			recording:   recording.Null{},
			providers:   map[string]*ConnectedProvider{BuiltinCoreID: p},
			Provider:    p,
		}, p
	}

	t.Run("later fields repeat the failure without calling the provider", func(t *testing.T) {
		r, _ := newRuntime(t, 1, unauthenticated)

		first, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
		require.NoError(t, err)
		require.Error(t, first.Error)

		second, err := r.watchAndUpdate(resName, "id-2", fieldName, "")
		require.NoError(t, err, "the short-circuit is field data, not a runtime failure")
		require.Error(t, second.Error)
		assert.True(t, errors.Is(second.Error, llx.ErrUnauthenticated))
		assert.Equal(t, first.Error.Error(), second.Error.Error())
	})

	t.Run("later resources repeat the failure without calling the provider", func(t *testing.T) {
		r, _ := newRuntime(t, 1, unauthenticated)

		_, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
		require.NoError(t, err)

		_, err = r.CreateResource(resName, nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrUnauthenticated))
	})

	t.Run("a failure scoped narrower than the asset does not short-circuit", func(t *testing.T) {
		r, _ := newRuntime(t, 2, &plugin.DataRes{
			Error: "AccessDenied",
			ErrorDetail: &llx.ErrorDetail{
				Kind:  llx.ErrorKind_ERROR_KIND_FORBIDDEN,
				Scope: llx.ErrorScope_ERROR_SCOPE_FIELD,
			},
		})

		_, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
		require.NoError(t, err)
		_, err = r.watchAndUpdate(resName, "id-2", fieldName, "")
		require.NoError(t, err)
	})

	t.Run("an unclassified failure does not short-circuit", func(t *testing.T) {
		r, _ := newRuntime(t, 2, &plugin.DataRes{Error: "401 Unauthorized"})

		_, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
		require.NoError(t, err)
		_, err = r.watchAndUpdate(resName, "id-2", fieldName, "")
		require.NoError(t, err)
	})

	t.Run("a new connection clears the failure", func(t *testing.T) {
		r, _ := newRuntime(t, 2, unauthenticated)

		_, err := r.watchAndUpdate(resName, "id-1", fieldName, "")
		require.NoError(t, err)

		r.setProviderConnection(&plugin.ConnectRes{Id: 2}, nil)

		_, err = r.watchAndUpdate(resName, "id-2", fieldName, "")
		require.NoError(t, err)
	})

	t.Run("another asset on the same provider process is not affected", func(t *testing.T) {
		// The provider process is shared across assets; the failure belongs
		// to one asset's connection.
		_, failing := newRuntime(t, 0, nil)
		other := &ConnectedProvider{Instance: failing.Instance, Connection: &plugin.ConnectRes{Id: 2}}

		require.True(t, failing.noteAssetFailure(llx.Unauthenticated(nil, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))))
		assert.NotNil(t, failing.failedAsset())
		assert.Nil(t, other.failedAsset())
	})

	t.Run("the first asset-scoped failure wins", func(t *testing.T) {
		_, p := newRuntime(t, 0, nil)

		first := llx.Unauthenticated(errors.New("first"), llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
		second := llx.Unauthenticated(errors.New("second"), llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
		assert.True(t, p.noteAssetFailure(first))
		assert.False(t, p.noteAssetFailure(second))
		assert.Equal(t, "first", p.failedAsset().Error())
	})
}
