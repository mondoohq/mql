// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
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

func TestRuntime_HandlePluginError_TransportErrorRecordsCriticalError(t *testing.T) {
	r := &Runtime{}
	provider := &ConnectedProvider{
		Instance: &RunningProvider{Name: "aws"},
	}

	// Raw transport errors (e.g. "dial tcp") don't carry a gRPC status.
	transportErr := errors.New("connection error: desc = transport: error while dialing: dial tcp 127.0.0.1:1234: connect: connection refused")
	handled, err := r.handlePluginError(transportErr, provider, "aws.ec2.instance", "securityGroups")

	assert.False(t, handled)
	require.Error(t, err)

	critErrs := r.CriticalErrors()
	require.Len(t, critErrs, 1)
	assert.Contains(t, critErrs[0].Error(), "provider connection failed")
	assert.Contains(t, critErrs[0].Error(), "resource=aws.ec2.instance")
	assert.Contains(t, critErrs[0].Error(), "field=securityGroups")
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
}
