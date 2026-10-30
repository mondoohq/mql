// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// TestPolicyAssignmentDecode pins the struct tags on the hand-rolled policy
// assignment decode. The Microsoft.Authorization/policyAssignments response is
// unmarshalled by hand rather than through the SDK, so a mistyped tag yields a
// zero value with no error: an assignment that excludes a whole subscription
// would report an empty notScopes, and a System assignment created by Defender
// would be indistinguishable from one an operator made.
func TestPolicyAssignmentDecode(t *testing.T) {
	// Shaped after the documented 2022-06-01 response.
	raw := `{
	  "id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny-public-storage",
	  "type": "Microsoft.Authorization/policyAssignments",
	  "name": "deny-public-storage",
	  "location": "eastus",
	  "identity": {
	    "type": "SystemAssigned",
	    "principalId": "11111111-1111-1111-1111-111111111111",
	    "tenantId": "22222222-2222-2222-2222-222222222222"
	  },
	  "properties": {
	    "displayName": "Deny public storage accounts",
	    "description": "Blocks anonymous blob access",
	    "assignmentType": "Custom",
	    "enforcementMode": "Default",
	    "metadata": { "assignedBy": "Ops", "category": "Storage", "createdBy": "abc" },
	    "definitionVersion": "1.*",
	    "effectiveDefinitionVersion": "1.2.0",
	    "latestDefinitionVersion": "1.3.0",
	    "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/def-1",
	    "scope": "/subscriptions/sub-1",
	    "notScopes": ["/subscriptions/sub-1/resourceGroups/sandbox"],
	    "nonComplianceMessages": [{ "message": "Storage must be private" }],
	    "overrides": [{ "kind": "policyEffect", "value": "audit" }],
	    "resourceSelectors": [{ "name": "byLocation" }],
	    "parameters": { "effect": { "value": "Deny" } }
	  }
	}`

	var pa PolicyAssignment
	require.NoError(t, json.Unmarshal([]byte(raw), &pa))

	assert.Equal(t, "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny-public-storage", pa.ID)
	assert.Equal(t, "eastus", pa.Location)
	assert.Equal(t, "Deny public storage accounts", pa.Properties.DisplayName)
	assert.Equal(t, "Custom", pa.Properties.AssignmentType)
	assert.Equal(t, "/providers/Microsoft.Authorization/policyDefinitions/def-1", pa.Properties.PolicyDefinitionID)
	assert.Equal(t, "1.*", pa.Properties.DefinitionVersion)
	assert.Equal(t, "1.2.0", pa.Properties.EffectiveDefinitionVersion)
	assert.Equal(t, "1.3.0", pa.Properties.LatestDefinitionVersion)
	assert.Equal(t, "SystemAssigned", pa.Identity.Type)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", pa.Identity.PrincipalID)

	require.Len(t, pa.Properties.NotScopes, 1)
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/sandbox", pa.Properties.NotScopes[0])
	assert.Len(t, pa.Properties.NonComplianceMessages, 1)
	assert.Len(t, pa.Properties.Overrides, 1)
	assert.Len(t, pa.Properties.ResourceSelectors, 1)

	// Metadata is open-ended. A closed struct here would keep only "category"
	// and silently drop assignedBy and createdBy.
	assert.Equal(t, "Ops", pa.Properties.Metadata["assignedBy"])
	assert.Equal(t, "Storage", pa.Properties.Metadata["category"])
	assert.Equal(t, "abc", pa.Properties.Metadata["createdBy"])
}

// TestPolicyAssignmentDecodeAbsentFields checks that an assignment carrying
// none of the optional properties decodes to empty rather than to a wrong
// value, so `assignmentType == "System"` does not match a plain assignment.
func TestPolicyAssignmentDecodeAbsentFields(t *testing.T) {
	raw := `{
	  "id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/minimal",
	  "name": "minimal",
	  "properties": { "scope": "/subscriptions/sub-1" }
	}`

	var pa PolicyAssignment
	require.NoError(t, json.Unmarshal([]byte(raw), &pa))

	assert.Empty(t, pa.Properties.AssignmentType)
	assert.Empty(t, pa.Properties.DefinitionVersion)
	assert.Empty(t, pa.Location)
	assert.Nil(t, pa.Properties.NotScopes)
	assert.Nil(t, pa.Properties.Metadata)
	assert.Empty(t, pa.Identity.PrincipalID)
}

// TestManagementGroupFromScope covers the parsing behind the policyDefinition
// reference. A definition held at a management group needs a different SDK call
// than a subscription-scoped one, and picking the wrong one returns a 404 that
// surfaces as a null reference rather than an error.
func TestManagementGroupFromScope(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		want    string
		wantErr bool
	}{
		{
			name: "management group scoped",
			id:   "/providers/Microsoft.Management/managementGroups/mg-prod/providers/Microsoft.Authorization/policyDefinitions/def-1",
			want: "mg-prod",
		},
		{
			name: "case-insensitive provider segment",
			id:   "/providers/microsoft.management/managementgroups/mg-prod/providers/Microsoft.Authorization/policyDefinitions/def-1",
			want: "mg-prod",
		},
		{
			name: "group is the final segment",
			id:   "/providers/Microsoft.Management/managementGroups/mg-root",
			want: "mg-root",
		},
		{
			name:    "subscription scoped is not a management group",
			id:      "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/def-1",
			wantErr: true,
		},
		{
			name:    "empty group name",
			id:      "/providers/Microsoft.Management/managementGroups/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := managementGroupFromScope(tt.id)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestAnySlice covers the widening helper used to serialize the policy
// assignment's typed SDK slices. Nil elements must be dropped rather than
// serialized as null entries.
func TestAnySlice(t *testing.T) {
	type msg struct{ Message string }

	a := msg{Message: "one"}
	b := msg{Message: "two"}

	assert.Empty(t, anySlice[msg](nil))
	assert.Len(t, anySlice([]*msg{&a, &b}), 2)
	assert.Len(t, anySlice([]*msg{&a, nil, &b}), 2)
}

// TestJsonToDictSlice checks that each element becomes its own dict, since the
// []dict fields on the policy assignment are read element by element.
func TestJsonToDictSlice(t *testing.T) {
	out, err := jsonToDictSlice([]any{
		map[string]any{"kind": "policyEffect", "value": "audit"},
		map[string]any{"kind": "policyEffect", "value": "deny"},
	})
	require.NoError(t, err)
	require.Len(t, out, 2)

	first, ok := out[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "audit", first["value"])

	// An empty input must produce an empty list rather than nil, so the field
	// reports "no overrides" instead of null.
	empty, err := jsonToDictSlice(nil)
	require.NoError(t, err)
	assert.NotNil(t, empty)
	assert.Empty(t, empty)
}

// TestPolicyDefinitionNameFromID covers the three ID shapes a policy assignment
// can point at. ParseResourceID is deliberately not used for this: it requires
// a subscription segment and errors without one, which rejects both built-in
// definitions and management-group-scoped ones. Built-ins back the majority of
// assignments, so that route would fail the common case -- this test pins the
// shapes that must keep working.
func TestPolicyDefinitionNameFromID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "built-in definition",
			id:   "/providers/Microsoft.Authorization/policyDefinitions/def-1",
			want: "def-1",
		},
		{
			name: "subscription-scoped custom definition",
			id:   "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/custom-deny",
			want: "custom-deny",
		},
		{
			name: "management-group-scoped definition",
			id:   "/providers/Microsoft.Management/managementGroups/mg-prod/providers/Microsoft.Authorization/policyDefinitions/mg-deny",
			want: "mg-deny",
		},
		{
			name: "trailing slash",
			id:   "/providers/Microsoft.Authorization/policyDefinitions/def-1/",
			want: "def-1",
		},
		{
			name: "bare name",
			id:   "def-1",
			want: "def-1",
		},
		{
			name: "no name to take",
			id:   "/",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, policyDefinitionNameFromID(tt.id))
		})
	}
}

// TestParseResourceIDRejectsBuiltInPolicyIDs is the evidence behind the comment
// on policyDefinitionNameFromID. If ParseResourceID ever gains support for
// subscription-less IDs, this test fails and the hand-rolled helper can be
// replaced with it.
func TestParseResourceIDRejectsBuiltInPolicyIDs(t *testing.T) {
	_, err := ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/def-1")
	require.Error(t, err, "ParseResourceID now handles built-in policy definition IDs; policyDefinitionNameFromID can be replaced")

	_, err = ParseResourceID("/providers/Microsoft.Management/managementGroups/mg-prod/providers/Microsoft.Authorization/policyDefinitions/def-1")
	require.Error(t, err, "ParseResourceID now handles management-group-scoped policy definition IDs")
}

// TestDiskNilPropertiesReportsNullNotUnset pins the fields added by this change
// on a disk that arrives without a Properties block. They must be present in
// the args as explicit nulls: an absent key leaves the field unset, which
// crosses the plugin boundary with no type information and surfaces as an
// unattributed null rather than as "not reported".
func TestDiskNilPropertiesReportsNullNotUnset(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	res, err := diskToMql(runtime, compute.Disk{
		ID:   new("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/disks/d1"),
		Name: new("d1"),
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	for _, tc := range []struct {
		field string
		state plugin.State
	}{
		{field: "securityType", state: res.SecurityType.State},
		{field: "confidentialVmVersion", state: res.ConfidentialVmVersion.State},
		{field: "encryptionSettingsVersion", state: res.EncryptionSettingsVersion.State},
		{field: "osType", state: res.OsType.State},
		{field: "diskSizeGB", state: res.DiskSizeGB.State},
		{field: "optimizedForFrequentAttach", state: res.OptimizedForFrequentAttach.State},
	} {
		assert.NotEqualf(t, plugin.State(0), tc.state,
			"%s is unset on a nil-Properties disk; it must be an explicit null", tc.field)
	}
}
