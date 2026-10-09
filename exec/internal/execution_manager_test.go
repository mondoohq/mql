// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

func TestExecutionManagerRecoversPanic(t *testing.T) {
	runQueue := make(chan runQueueItem, 1)
	resultChan := make(chan *llx.RawResult, 1)
	em := newExecutionManager(nil, nil, runQueue, resultChan, time.Second)
	em.Start()

	// A nil code bundle panics inside executeCodeBundle. The manager must
	// recover and surface it as an unrecoverable error instead of crashing.
	runQueue <- runQueueItem{}

	select {
	case err := <-em.Err():
		require.ErrorContains(t, err, "panic during query execution")
	case <-time.After(5 * time.Second):
		t.Fatal("expected the execution manager to report the panic as an error")
	}

	em.Stop()
}

var emptySchema = &resources.Schema{Resources: map[string]*resources.ResourceInfo{}}

// staticRuntime runs queries that need no resources.
type staticRuntime struct{}

func (staticRuntime) AssetMRN() string                  { return "" }
func (staticRuntime) Unregister(string) error           { return nil }
func (staticRuntime) Schema() resources.ResourcesSchema { return emptySchema }
func (staticRuntime) Close()                            {}
func (staticRuntime) Recording() llx.Recording          { return nil }
func (staticRuntime) SetRecording(llx.Recording) error  { return nil }
func (staticRuntime) AssetUpdated(*inventory.Asset)     {}
func (staticRuntime) CreateResource(string, map[string]*llx.Primitive) (llx.Resource, error) {
	return nil, errors.New("no resources")
}
func (staticRuntime) CloneResource(llx.Resource, string, []string, map[string]*llx.Primitive) (llx.Resource, error) {
	return nil, errors.New("no resources")
}
func (staticRuntime) WatchAndUpdate(llx.Resource, string, string, func(any, error)) error {
	return errors.New("no resources")
}

func compileStatic(t *testing.T, query string) *llx.CodeBundle {
	t.Helper()
	bundle, err := mqlc.Compile(query, nil, mqlc.NewConfig(emptySchema, mql.DefaultFeatures))
	require.NoError(t, err)
	return bundle
}

// A query that panics while it runs fails with the panic as its error, and the
// next query still runs: one broken query must not drop every other result.
func TestExecutionManagerPanicFailsOnlyThatQuery(t *testing.T) {
	// `true && true` with its right operand swapped for a string: the bool &&
	// bool builtin asserts a bool and panics, as a bug in a builtin would.
	broken := compileStatic(t, "true && true")
	var patched bool
	for _, c := range broken.CodeV2.Blocks[0].Chunks {
		if c.Function != nil && strings.HasPrefix(c.Id, "&&") {
			c.Function.Args[0] = llx.StringPrimitive("not a bool")
			patched = true
		}
	}
	require.True(t, patched, "no && chunk to break")
	good := compileStatic(t, "true && false")

	runQueue := make(chan runQueueItem, 2)
	resultChan := make(chan *llx.RawResult, 16)
	em := newExecutionManager(emptySchema, staticRuntime{}, runQueue, resultChan, 5*time.Second)
	em.Start()
	defer em.Stop()

	runQueue <- runQueueItem{codeBundle: broken}
	runQueue <- runQueueItem{codeBundle: good}

	want := map[string]bool{}
	for _, c := range CodepointChecksums(broken) {
		want[c] = true
	}
	for _, c := range CodepointChecksums(good) {
		want[c] = true
	}
	brokenEntry := broken.CodeV2.Checksums[broken.CodeV2.Blocks[0].Entrypoints[0]]
	goodEntry := good.CodeV2.Checksums[good.CodeV2.Blocks[0].Entrypoints[0]]

	got := map[string]*llx.RawResult{}
	deadline := time.After(5 * time.Second)
	for len(got) < len(want) {
		select {
		case rr := <-resultChan:
			got[rr.CodeID] = rr
		case err := <-em.Err():
			t.Fatalf("a panic in one query stopped the execution manager: %v", err)
		case <-deadline:
			t.Fatalf("timed out with %d of %d results", len(got), len(want))
		}
	}

	require.NotNil(t, got[brokenEntry])
	require.ErrorContains(t, got[brokenEntry].Data.Error, "panic during query execution")
	require.NotNil(t, got[goodEntry])
	require.NoError(t, got[goodEntry].Data.Error)
	require.Equal(t, false, got[goodEntry].Data.Value)
}
