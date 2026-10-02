// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// TestNewMqlModule_ConcurrentStamping is a regression test for a data race in
// newMqlModule, the sibling of the one fixed in newMqlHclBlock.
//
// newMqlModule wrote tmr.module unconditionally after CreateResource, but
// CreateResource returns the ALREADY CACHED instance when the __id matches. The
// same *connection.Module is reachable three ways -- terraform.state.modules
// walks the whole tree, terraform.state.rootModule takes the root, and
// rootModule.childModules takes each child -- and each of those is a separate
// field resolution that can run in its own goroutine. So two goroutines wrote
// the same struct field while a third read it in resources() / childModules().
//
// The goroutines call the accessor bodies (modules, rootModule, childModules)
// rather than the generated Get* wrappers on purpose: plugin.GetOrCompute is
// itself unsynchronized, and routing through it would report that separate,
// SDK-wide TValue race instead of this one.
//
// Run with -race to surface a regression; the assertions afterwards catch the
// user-visible symptom, a module whose internals never got populated and whose
// resources therefore come back empty.
func TestNewMqlModule_ConcurrentStamping(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		rt := newRuntimeForStateJSON(t, stateWithModules)

		stateRaw, err := CreateResource(rt, "terraform.state", map[string]*llx.RawData{})
		require.NoError(t, err)
		state := stateRaw.(*mqlTerraformState)

		var wg sync.WaitGroup

		// Writer 1: the flattened walk stamps every module in the tree.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = state.modules()
		}()

		// Writer 2: the root module, then its children -- the same structs the
		// flattened walk is stamping.
		wg.Add(1)
		go func() {
			defer wg.Done()
			root, err := state.rootModule()
			if err != nil || root == nil {
				return
			}
			children, err := root.childModules()
			if err != nil {
				return
			}
			for c := range children {
				// Read the internals the other goroutines are stamping.
				_ = children[c].(*mqlTerraformStateModule).module.Load()
			}
		}()

		// Writer 3: a second flattened walk, which hands back the same cached
		// instances and re-stamps them. This is what the terraform.state.module
		// address lookup does internally.
		wg.Add(1)
		go func() {
			defer wg.Done()
			modules, err := state.modules()
			if err != nil {
				return
			}
			for m := range modules {
				_, _ = modules[m].(*mqlTerraformStateModule).resources()
			}
		}()

		// Reader: picks the instance straight out of the runtime cache, the way
		// the runtime does when it resolves a field on an already-created
		// resource. This one never calls newMqlModule, so it has no
		// happens-before edge to the stamp -- CreateResource caches the
		// instance BEFORE the caller stamps it. A write-side-only guard leaves
		// this read racing.
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := "terraform.state.module\x00terraform.state.module/address/module.vpc"
			for a := 0; a < 200; a++ {
				cached, ok := rt.Resources.Get(key)
				if !ok {
					continue
				}
				_, _ = cached.(*mqlTerraformStateModule).resources()
				_, _ = cached.(*mqlTerraformStateModule).childModules()
				return
			}
		}()

		wg.Wait()

		modules, err := state.modules()
		require.NoError(t, err)
		require.Len(t, modules, 2, "root module plus module.vpc")
		for m := range modules {
			module := modules[m].(*mqlTerraformStateModule)
			require.NotNil(t, module.module.Load(), "module internals must still be populated")
		}
	}
}

// TestNewMqlStateOutput_ConcurrentStamping covers the same shape in outputs().
//
// plugin.GetOrCompute is unsynchronized -- it checks IsSet, computes, then
// assigns -- so two goroutines resolving terraform.state.outputs both miss the
// check and both run the accessor body. The second CreateResource returns the
// cached terraform.state.output, and both goroutines then wrote so.output while
// value() and type read it.
func TestNewMqlStateOutput_ConcurrentStamping(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		rt := newRuntimeForStateJSON(t, stateWithModules)

		stateRaw, err := CreateResource(rt, "terraform.state", map[string]*llx.RawData{})
		require.NoError(t, err)
		state := stateRaw.(*mqlTerraformState)

		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outputs, err := state.outputs()
				if err != nil {
					return
				}
				for o := range outputs {
					// Reads the internal the other goroutines are stamping.
					_, _ = outputs[o].(*mqlTerraformStateOutput).value()
				}
			}()
		}
		wg.Wait()

		outputs, err := state.outputs()
		require.NoError(t, err)
		require.Len(t, outputs, 1)
		for o := range outputs {
			output := outputs[o].(*mqlTerraformStateOutput)
			require.NotNil(t, output.output.Load(), "output internals must still be populated")
		}
	}
}
