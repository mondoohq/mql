// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
)

// The builtin mock and sbom services are one instance shared by every runtime in
// the process. They used to keep the runtime they were working for in a field,
// assigned by SetRecording and read back at connect time, so the runtime they
// used was whichever one set a recording last rather than the one connecting.
//
// These tests pin the replacement: the runtime comes from the connect callback,
// which belongs to exactly one runtime by construction.

func runtimeWithOwnRecording(assetName string) *Runtime {
	return &Runtime{
		recording: &multiAssetRecording{assets: []*recording.Asset{
			// No connections on the recorded asset, so connect stops right
			// after choosing it. Which asset it chose is the thing under test.
			{Asset: &inventory.Asset{Name: assetName}},
		}},
	}
}

// One service instance for every connect, as in production: builtin.go
// registers a single &mockProviderService{} for the whole process. Sharing it
// here is what makes these tests able to catch per-service state.
var sharedMockService = &mockProviderService{}

func connectMock(rt *Runtime, assetName string) error {
	_, err := sharedMockService.Connect(
		&plugin.ConnectReq{Asset: &inventory.Asset{Name: assetName}},
		&providerCallbacks{runtime: rt},
	)
	return err
}

func TestBuiltinServiceUsesTheConnectingRuntime(t *testing.T) {
	a := runtimeWithOwnRecording("asset-a")
	b := runtimeWithOwnRecording("asset-b")

	// Each connect looks in its own caller's recording. With a shared field
	// both of these would read whichever runtime touched the service last, so
	// one of the two would report the wrong asset as missing.
	assert.ErrorContains(t, connectMock(a, "asset-a"), "no connections found in asset",
		"runtime a found asset-a in its own recording")
	assert.ErrorContains(t, connectMock(b, "asset-a"), `no recording found for asset asset-a`,
		"runtime b has no asset-a, and must not answer from a's recording")

	// And the other way round, so neither result is an accident of ordering.
	assert.ErrorContains(t, connectMock(b, "asset-b"), "no connections found in asset")
	assert.ErrorContains(t, connectMock(a, "asset-b"), `no recording found for asset asset-b`)
}

// Cross-asset resolution (ADR 031) connects several assets at once, which is
// what turned the shared field from a latent problem into a real one. Run with
// -race.
func TestBuiltinServiceConnectsConcurrently(t *testing.T) {
	const n = 8

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			name := "asset-" + strconv.Itoa(i)
			errs[i] = connectMock(runtimeWithOwnRecording(name), name)
		})
	}
	wg.Wait()

	for i, err := range errs {
		// Every one of them found its own asset. A shared field makes this the
		// "no recording found" error for all but the last writer.
		assert.ErrorContains(t, err, "no connections found in asset", "connect %d", i)
	}
}

// A caller with no in-process runtime is an error, not a dereference. Two
// connect call sites in this package already pass a nil callback (the
// cross-provider sibling connects); they cannot reach these services today, and
// this is what happens if that ever changes.
func TestBuiltinServiceRejectsACallbackWithNoRuntime(t *testing.T) {
	req := &plugin.ConnectReq{Asset: &inventory.Asset{Name: "asset-a"}}

	for _, callback := range []plugin.ProviderCallback{
		nil,
		(*providerCallbacks)(nil),
		&providerCallbacks{},
	} {
		_, err := sharedMockService.Connect(req, callback)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs an in-process runtime")

		// sbom carries the same shared-instance problem and the same fix. Its
		// connect needs a file on disk and an upstream recording, so this is
		// the part of it that can be pinned cheaply: it demands the runtime
		// from the callback before it does anything else.
		_, err = (&sbomProviderService{}).Connect(req, callback)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs an in-process runtime")

		_, err = runtimeFromCallback(callback)
		assert.Error(t, err)
	}
}
