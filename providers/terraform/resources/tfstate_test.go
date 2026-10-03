// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// newRuntimeForStateJSON builds a runtime over a real state connection reading
// the supplied JSON, mirroring newRuntimeForDir for HCL assets.
func newRuntimeForStateJSON(t *testing.T, stateJSON string) *plugin.Runtime {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terraform.tfstate")
	require.NoError(t, os.WriteFile(path, []byte(stateJSON), 0o600))

	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "state", Options: map[string]string{"path": path}},
		},
	}
	conn, err := connection.NewStateConnection(1, asset)
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// newRuntimeForPlanJSON builds a runtime over a real plan connection reading
// the supplied JSON.
func newRuntimeForPlanJSON(t *testing.T, planJSON string) *plugin.Runtime {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	require.NoError(t, os.WriteFile(path, []byte(planJSON), 0o600))

	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "plan", Options: map[string]string{"path": path}},
		},
	}
	conn, err := connection.NewPlanConnection(1, asset)
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

const stateWithModules = `{
  "format_version": "1.0",
  "terraform_version": "1.6.0",
  "values": {
    "outputs": {
      "endpoint": { "sensitive": false, "value": "https://example.com", "type": "string" }
    },
    "root_module": {
      "resources": [
        { "address": "aws_s3_bucket.root", "mode": "managed", "type": "aws_s3_bucket", "name": "root" }
      ],
      "child_modules": [
        {
          "address": "module.vpc",
          "resources": [
            { "address": "aws_subnet.a", "mode": "managed", "type": "aws_subnet", "name": "a" }
          ]
        }
      ]
    }
  }
}`

// TestTerraformStateOutput_InitOnNonStateAssetDoesNotPanic is a regression test
// for a nil-pointer crash on terraform.state.output(...) against an HCL asset.
//
// The init used CreateResource("terraform.state", nil), which does NOT run
// initTerraformState, so the "cannot find state" guard was bypassed. conn.State()
// returns (nil, nil) for HCL and plan assets, and outputs() then dereferenced
// the nil state.
func TestTerraformStateOutput_InitOnNonStateAssetDoesNotPanic(t *testing.T) {
	rt := newRuntimeForDir(t, writeTfDir(t, map[string]string{
		"main.tf": "resource \"aws_s3_bucket\" \"b\" {}\n",
	}))

	require.NotPanics(t, func() {
		_, _, err := initTerraformStateOutput(rt, map[string]*llx.RawData{
			"identifier": llx.StringData("x"),
		})
		assert.Error(t, err, "there is no state on an HCL asset, so the lookup must report that")
	})
}

// TestTerraformStateModule_InitOnNonStateAssetDoesNotPanic covers the sibling
// init, which had the same shape.
func TestTerraformStateModule_InitOnNonStateAssetDoesNotPanic(t *testing.T) {
	rt := newRuntimeForDir(t, writeTfDir(t, map[string]string{
		"main.tf": "resource \"aws_s3_bucket\" \"b\" {}\n",
	}))

	require.NotPanics(t, func() {
		_, _, err := initTerraformStateModule(rt, map[string]*llx.RawData{
			"identifier": llx.StringData("module.vpc"),
		})
		assert.Error(t, err, "there is no state on an HCL asset, so the lookup must report that")
	})
}

// TestTerraformStateAccessors_NilStateDoNotPanic covers the belt-and-braces
// guards: every terraform.state collection accessor assumed a non-nil state and
// only checked state.Values.
func TestTerraformStateAccessors_NilStateDoNotPanic(t *testing.T) {
	runtime := &plugin.Runtime{
		Connection: &connection.Connection{},
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	newState := func() *mqlTerraformState {
		s := &mqlTerraformState{}
		s.MqlRuntime = runtime
		return s
	}

	require.NotPanics(t, func() {
		_, err := newState().outputs()
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
	})
	require.NotPanics(t, func() {
		_, err := newState().rootModule()
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
	})
	require.NotPanics(t, func() {
		_, err := newState().modules()
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
	})
	require.NotPanics(t, func() {
		_, err := newState().resources()
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
	})
}

// TestTerraformState_OutputLookupDoesNotPoisonTheSingleton is a regression test
// for the uninitialized terraform.state instance being cached.
//
// terraform.state's id() is a constant, so the CreateResource in the output
// init registered an instance whose formatVersion/terraformVersion were never
// populated under the shared "terraform.state" cache key. A later, correct
// NewResource then returned that husk, and formatVersion read as unset —
// surfacing client-side as "llx: encountered a primitive with no type
// information". Whether a scan saw it depended purely on query order.
func TestTerraformState_OutputLookupDoesNotPoisonTheSingleton(t *testing.T) {
	rt := newRuntimeForStateJSON(t, stateWithModules)

	// Ask for an output FIRST — this is the order that poisoned the cache.
	_, res, err := initTerraformStateOutput(rt, map[string]*llx.RawData{
		"identifier": llx.StringData("endpoint"),
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	// Now resolve the state itself; it must be fully initialized.
	obj, err := NewResource(rt, "terraform.state", map[string]*llx.RawData{})
	require.NoError(t, err)
	state := obj.(*mqlTerraformState)
	assert.Equal(t, "1.0", state.FormatVersion.Data,
		"terraform.state.formatVersion must be populated regardless of query order")
	assert.Equal(t, "1.6.0", state.TerraformVersion.Data)
}

// TestTerraformState_ModuleLookupDoesNotPoisonTheSingleton is the same
// regression through terraform.state.module(...).
func TestTerraformState_ModuleLookupDoesNotPoisonTheSingleton(t *testing.T) {
	rt := newRuntimeForStateJSON(t, stateWithModules)

	_, res, err := initTerraformStateModule(rt, map[string]*llx.RawData{
		"identifier": llx.StringData("module.vpc"),
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	obj, err := NewResource(rt, "terraform.state", map[string]*llx.RawData{})
	require.NoError(t, err)
	state := obj.(*mqlTerraformState)
	assert.Equal(t, "1.0", state.FormatVersion.Data,
		"terraform.state.formatVersion must be populated regardless of query order")
}

// TestTerraformStateModule_MissReportsNotFound is a regression test for the
// lookup-miss husk.
//
// On a miss the init deleted "identifier" and returned (args, nil, nil), so the
// runtime built a module with no address. id() then returned the bare
// "terraform.module" — exactly the id of the ROOT module, whose address is
// omitted in state — so the husk and the root module shared a cache key and a
// typo'd address silently resolved to the root module's contents.
func TestTerraformStateModule_MissReportsNotFound(t *testing.T) {
	rt := newRuntimeForStateJSON(t, stateWithModules)

	_, res, err := initTerraformStateModule(rt, map[string]*llx.RawData{
		"identifier": llx.StringData("module.nope"),
	})
	require.Error(t, err, "a module address that does not exist must be reported, not faked")
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "module.nope")
	assert.ErrorIs(t, err, llx.ErrNotFound)
}

// TestTerraformStateOutput_MissReportsNotFound covers the sibling fall-through.
func TestTerraformStateOutput_MissReportsNotFound(t *testing.T) {
	rt := newRuntimeForStateJSON(t, stateWithModules)

	_, res, err := initTerraformStateOutput(rt, map[string]*llx.RawData{
		"identifier": llx.StringData("nope"),
	})
	require.Error(t, err, "an output that does not exist must be reported, not faked")
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "nope")
	assert.ErrorIs(t, err, llx.ErrNotFound)
}

// TestTerraformStateModule_RootModuleIDIsDistinct pins the root module's id
// away from the generic husk id it used to share.
func TestTerraformStateModule_RootModuleIDIsDistinct(t *testing.T) {
	rt := newRuntimeForStateJSON(t, stateWithModules)

	obj, err := NewResource(rt, "terraform.state", map[string]*llx.RawData{})
	require.NoError(t, err)
	root, err := obj.(*mqlTerraformState).rootModule()
	require.NoError(t, err)
	require.NotNil(t, root)

	id, err := root.id()
	require.NoError(t, err)
	assert.NotEqual(t, "terraform.module", id,
		"the root module must not use the id a blank module would compute")
	assert.Contains(t, id, "root")
}

// TestTerraformStateInits_NullArgumentDoNotPanic is a regression test for the
// bare `.(string)` assertions on init arguments. The schema enforces the type,
// but RawData.Value is still nil for a null argument, and
// `interface{}(nil).(string)` panics — taking the whole scan down, since query
// blocks run in goroutines.
func TestTerraformStateInits_NullArgumentDoNotPanic(t *testing.T) {
	rt := newRuntimeForStateJSON(t, stateWithModules)

	require.NotPanics(t, func() {
		_, _, _ = initTerraformStateOutput(rt, map[string]*llx.RawData{
			"identifier": {Value: nil},
		})
	})
	require.NotPanics(t, func() {
		_, _, _ = initTerraformStateModule(rt, map[string]*llx.RawData{
			"identifier": {Value: nil},
		})
	})
}

// TestTerraformStateResource_DeposedKeyDisambiguatesID is a regression test for
// terraform.state.resource ids that ignore deposedKey.
//
// Terraform records a deposed object as a separate entry with the SAME address,
// distinguished only by deposed_key. Both entries hashed to one cache key, so
// the deposed object was invisible while the list still reported two.
func TestTerraformStateResource_DeposedKeyDisambiguatesID(t *testing.T) {
	rt := newRuntimeForStateJSON(t, `{
  "format_version": "1.0",
  "terraform_version": "1.6.0",
  "values": {
    "root_module": {
      "resources": [
        { "address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web" },
        { "address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web", "deposed_key": "abc12345" }
      ]
    }
  }
}`)

	obj, err := NewResource(rt, "terraform.state", map[string]*llx.RawData{})
	require.NoError(t, err)
	list, err := obj.(*mqlTerraformState).resources()
	require.NoError(t, err)
	require.Len(t, list, 2)

	ids := map[string]bool{}
	for i := range list {
		id, err := list[i].(*mqlTerraformStateResource).id()
		require.NoError(t, err)
		ids[id] = true
	}
	assert.Len(t, ids, 2, "a deposed object must not share a cache key with the current object")
}

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
