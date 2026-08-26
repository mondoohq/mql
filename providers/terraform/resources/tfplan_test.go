// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// TestTerraformPlanResourceChanges_NilPlan verifies that resourceChanges() does
// not panic when the connection carries no plan. conn.Plan() returns nil for
// non-plan assets (HCL/state), and this accessor dereferenced it without a
// guard while its sibling accessors guarded it. A zero-value Connection mirrors
// what NewStateConnection / an HCL connection produce (no plan set).
func TestTerraformPlanResourceChanges_NilPlan(t *testing.T) {
	runtime := &plugin.Runtime{Connection: &connection.Connection{}}
	p := &mqlTerraformPlan{}
	p.MqlRuntime = runtime

	res, err := p.resourceChanges()
	require.NoError(t, err)
	assert.Empty(t, res)
}

// TestTerraformPlan_NilPlanSetsStaticFields is a regression test for
// terraform.plan.applyable / .errored / .variables resolving UNSET on an asset
// with no plan.
//
// The nil-plan branch of the init filled in only formatVersion,
// terraformVersion and resourceChanges. MQL three-valued logic then made
// `terraform.plan { !errored && applyable }` evaluate to TRUE over two nulls,
// so a "the plan is clean" assertion passed on an asset that carries no plan
// at all.
func TestTerraformPlan_NilPlanSetsStaticFields(t *testing.T) {
	runtime := &plugin.Runtime{
		Connection: &connection.Connection{},
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	args, _, err := initTerraformPlan(runtime, map[string]*llx.RawData{})
	require.NoError(t, err)
	require.NotNil(t, args)

	require.Contains(t, args, "applyable", "applyable must be set, not left unset")
	assert.Equal(t, false, args["applyable"].Value)
	require.Contains(t, args, "errored", "errored must be set, not left unset")
	assert.Equal(t, false, args["errored"].Value)
	require.Contains(t, args, "variables", "variables must be set, not left unset")
	assert.Empty(t, args["variables"].Value)
}

// TestTerraformPlanResourceChange_DeposedDisambiguatesID is a regression test
// for the resourceChange / proposedChange ids dropping the `deposed` key.
//
// Terraform emits a separate resource_changes entry for a deposed object with
// the SAME address, distinguished only by `deposed`. Both hashed to one cache
// key, so the deposed change was invisible while resourceChanges.length still
// counted two.
func TestTerraformPlanResourceChange_DeposedDisambiguatesID(t *testing.T) {
	rt := newRuntimeForPlanJSON(t, `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "resource_changes": [
    {
      "address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
      "change": { "actions": ["update"] }
    },
    {
      "address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
      "deposed": "abc12345",
      "change": { "actions": ["delete"] }
    }
  ]
}`)

	obj, err := NewResource(rt, "terraform.plan", map[string]*llx.RawData{})
	require.NoError(t, err)
	list, err := obj.(*mqlTerraformPlan).resourceChanges()
	require.NoError(t, err)
	require.Len(t, list, 2)

	changeIDs := map[string]bool{}
	proposedIDs := map[string]bool{}
	for i := range list {
		rc := list[i].(*mqlTerraformPlanResourceChange)
		id, err := rc.id()
		require.NoError(t, err)
		changeIDs[id] = true

		pid, err := rc.Change.Data.id()
		require.NoError(t, err)
		proposedIDs[pid] = true
	}
	assert.Len(t, changeIDs, 2, "a deposed change must not share a cache key with the current change")
	assert.Len(t, proposedIDs, 2, "the proposed change carries the same collision")

	// And the two entries must really be distinct objects with distinct actions.
	actions := map[string]bool{}
	for i := range list {
		rc := list[i].(*mqlTerraformPlanResourceChange)
		actions[rc.Change.Data.Actions.Data[0].(string)] = true
	}
	assert.Equal(t, map[string]bool{"update": true, "delete": true}, actions)
}

// TestTerraformPlanVariables_ValuelessVariableIsKept is a regression test for
// plan variables with no value being dropped entirely.
//
// Variable.Value is a json.RawMessage with omitempty, so a variable serialized
// as {} decodes to nil and json.Unmarshal(nil, ...) fails — and the loop
// `continue`d, deleting the variable from the list. An audit asserting "every
// declared variable has a value" therefore could not see the one that does not.
func TestTerraformPlanVariables_ValuelessVariableIsKept(t *testing.T) {
	rt := newRuntimeForPlanJSON(t, `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "variables": {
    "region": { "value": "us-east-1" },
    "db_password": {}
  }
}`)

	args, _, err := initTerraformPlan(rt, map[string]*llx.RawData{})
	require.NoError(t, err)

	list := args["variables"].Value.([]any)
	require.Len(t, list, 2, "a variable with no value must still be listed")

	byName := map[string]*mqlTerraformPlanVariable{}
	for i := range list {
		v := list[i].(*mqlTerraformPlanVariable)
		byName[v.Name.Data] = v
	}
	require.Contains(t, byName, "db_password")
	assert.Equal(t, "us-east-1", byName["region"].Value.Data)
	assert.Nil(t, byName["db_password"].Value.Data,
		"the valueless variable must read as null, not be missing")
}
