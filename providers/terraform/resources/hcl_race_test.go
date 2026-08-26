// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// newHclRaceRuntime builds a fresh runtime (and therefore a fresh terraform
// singleton) backed by a real parsed HCL config with several resource blocks.
func newHclRaceRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "hcl", Options: map[string]string{"path": "../provider/testdata/terraform"}},
		},
	}
	conn, err := connection.NewHclConnection(1, asset)
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// TestHclCache_ConcurrentAccess is a regression test for the intermittent
// `terraform.resources` empty-list bug reported in mondoohq/mql#8966. In a real
// policy scan several terraform.* collection fields (blocks, providers,
// datasources, ...) and the terraform.resources init all resolve concurrently
// against the same terraform singleton. Before the fix each funneled into
// refreshCache -> GetBlocks -> the unsynchronized GetOrCompute, so multiple
// goroutines parsed and wrote the shared cache at once, and terraform.resources
// init read the internal slice without holding the lock — a data race whose
// visible symptom (an empty resources list) surfaced non-deterministically
// depending on scheduling and memory ordering.
//
// Run with -race to surface any regression of the data race; the length
// assertion catches the user-visible symptom (terraform.resources.length == 0).
func TestHclCache_ConcurrentAccess(t *testing.T) {
	const iterations = 300

	for i := 0; i < iterations; i++ {
		rt := newHclRaceRuntime(t)

		tfraw, err := CreateResource(rt, "terraform", map[string]*llx.RawData{})
		require.NoError(t, err)
		tf := tfraw.(*mqlTerraform)

		var wg sync.WaitGroup

		// Writers: concurrent field resolutions that all populate the shared
		// cache via ensureCache.
		for _, get := range []func() *plugin.TValue[[]any]{
			tf.GetBlocks, tf.GetProviders, tf.GetDatasources, tf.GetVariables, tf.GetOutputs,
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				get()
			}()
		}

		// Readers: terraform.resources init, which reads the internal
		// `resources` slice.
		gotLen := make([]int, 3)
		for r := range gotLen {
			wg.Add(1)
			go func() {
				defer wg.Done()
				args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
				if err != nil {
					return
				}
				gotLen[r] = len(args["list"].Value.([]any))
			}()
		}

		wg.Wait()

		for r, l := range gotLen {
			require.Positivef(t, l, "iteration %d reader %d: terraform.resources came back empty", i, r)
		}
	}
}

// TestTerraformResources_UnfilteredStableID is a regression test for the second
// half of mondoohq/mql#8966. The unfiltered `terraform.resources` list (no
// selector args) must carry a stable, NON-EMPTY __id.
//
// Why it matters: resources are cached in the runtime keyed by
// name+"\x00"+__id. An empty __id makes the unfiltered list share the constant
// slot "terraform.resources\x00". When a policy resolves the unfiltered list
// (e.g. `terraform.resources.where(...)`) concurrently with several
// `terraform.resources("type")` selector instances — exactly what happens when
// AWS/GCP checks and an inventory query run against the same asset — that
// shared empty-id slot races and the unfiltered list intermittently resolves
// empty, so `.all(...)` passes vacuously. A non-empty id takes the normal,
// race-free cache path (selector instances, which already carry a checksum id,
// were never affected).
//
// This asserts the invariant directly (deterministic) rather than the flaky
// race symptom: if the id ever regresses to "" this fails immediately, and
// selector forms must keep their own distinct non-empty ids.
func TestTerraformResources_UnfilteredStableID(t *testing.T) {
	rt := newHclRaceRuntime(t)

	bare, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	bareID := bare["__id"].Value.(string)
	require.NotEmpty(t, bareID,
		"unfiltered terraform.resources must have a non-empty __id (mondoohq/mql#8966)")
	require.Positive(t, len(bare["list"].Value.([]any)),
		"unfiltered terraform.resources must not be empty")

	// A selector form must resolve to a different, non-empty id so it neither
	// collides with the unfiltered slot nor with other selectors.
	sel, _, err := initTerraformResources(rt, map[string]*llx.RawData{
		"resource": llx.StringData("aws_instance"),
	})
	require.NoError(t, err)
	selID := sel["__id"].Value.(string)
	require.NotEmpty(t, selID)
	require.NotEqual(t, bareID, selID,
		"terraform.resources(\"type\") must not share the unfiltered list's __id")

	sel2, _, err := initTerraformResources(rt, map[string]*llx.RawData{
		"resource": llx.StringData("aws_s3_bucket"),
	})
	require.NoError(t, err)
	require.NotEqual(t, selID, sel2["__id"].Value.(string),
		"distinct terraform.resources(\"type\") selectors must have distinct __ids")
}

// TestNewMqlHclBlock_ConcurrentStamping is a regression test for a data race in
// newMqlHclBlock. It wrote r.block and r.cachedFile unconditionally after
// CreateResource — but CreateResource returns the ALREADY CACHED instance when
// the __id matches. Two goroutines reaching the same block through
// terraform.blocks and terraform.file(path).blocks therefore wrote the same
// struct fields at the same time.
//
// Run with -race; the fix must also leave the internals correctly populated.
func TestNewMqlHclBlock_ConcurrentStamping(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		rt := newHclRaceRuntime(t)

		tfraw, err := CreateResource(rt, "terraform", map[string]*llx.RawData{})
		require.NoError(t, err)
		tf := tfraw.(*mqlTerraform)

		filesRaw, err := tf.files()
		require.NoError(t, err)
		require.NotEmpty(t, filesRaw)

		var wg sync.WaitGroup
		// One goroutine walks every block through the terraform singleton...
		wg.Add(1)
		go func() {
			defer wg.Done()
			tf.GetBlocks()
		}()
		// ... while others re-list the same blocks per file, which hits the
		// same cached terraform.block instances.
		for f := range filesRaw {
			file := filesRaw[f].(*mqlTerraformFile)
			wg.Add(1)
			go func() {
				defer wg.Done()
				blocks, err := file.blocks()
				if err != nil {
					return
				}
				for b := range blocks {
					// Read the internals the other goroutines are stamping.
					_ = blocks[b].(*mqlTerraformBlock).block.Data
				}
			}()
		}
		wg.Wait()

		blocks, err := tf.blocks()
		require.NoError(t, err)
		for b := range blocks {
			block := blocks[b].(*mqlTerraformBlock)
			require.NotNil(t, block.block.Data, "block internals must still be populated")
			require.NotNil(t, block.cachedFile.Data, "file internals must still be populated")
		}
	}
}
