// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
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
		assert.Error(t, err)
	})
	require.NotPanics(t, func() {
		_, err := newState().rootModule()
		assert.Error(t, err)
	})
	require.NotPanics(t, func() {
		_, err := newState().modules()
		assert.Error(t, err)
	})
	require.NotPanics(t, func() {
		_, err := newState().resources()
		assert.Error(t, err)
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
