// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:fix inline
func ptr[T any](v T) *T { return new(v) }

// assignmentTargetJSON is the wire shape Graph returns for a group assignment
// carrying an include filter. Tests that care about how filter metadata is
// stored MUST go through the SDK deserializer with a payload like this rather
// than calling SetAdditionalData directly: kiota decides per property whether a
// value lands in the typed backing store or in AdditionalData, and in the
// latter case stores it as a *string. A hand-built map[string]any{"k": "v"} is
// a shape the deserializer never produces, so a test using one passes happily
// over code that cannot read real responses.
const assignmentTargetJSON = `{
  "@odata.type": "#microsoft.graph.groupAssignmentTarget",
  "groupId": "group-abc",
  "deviceAndAppManagementAssignmentFilterId": "filter-1",
  "deviceAndAppManagementAssignmentFilterType": "include"
}`

func TestAdditionalDataString(t *testing.T) {
	bag := map[string]any{
		"str":     "plain",
		"ptr":     new("pointed"),
		"nilPtr":  (*string)(nil),
		"notText": 42,
		"untyped": nil,
	}
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"string value", "str", "plain"},
		{"pointer value is dereferenced", "ptr", "pointed"},
		{"nil pointer yields empty", "nilPtr", ""},
		{"non-string yields empty", "notText", ""},
		{"nil value yields empty", "untyped", ""},
		{"missing key yields empty", "absent", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, additionalDataString(bag, tc.key))
		})
	}
}

func TestTrimOdataType(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"strips graph namespace", "#microsoft.graph.groupAssignmentTarget", "groupAssignmentTarget"},
		{"unrelated prefix kept", "#other.namespace.thing", "#other.namespace.thing"},
		{"shorter than prefix kept", "#microsoft", "#microsoft"},
		{"empty string kept", "", ""},
		{"prefix-only string kept", "#microsoft.graph.", "#microsoft.graph."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, trimOdataType(tc.in))
		})
	}
}

func TestAssignmentTargetInfo_Nil(t *testing.T) {
	tt, gid, ex, ft, fid := assignmentTargetInfo(nil)
	assert.Empty(t, tt)
	assert.Empty(t, gid)
	assert.False(t, ex)
	assert.Empty(t, ft)
	assert.Empty(t, fid)
}

// TestAssignmentTargetInfo_GroupTarget decodes the real Graph payload rather
// than seeding AdditionalData by hand. On v1 the filter properties have no
// field deserializer, so they land in AdditionalData as *string.
func TestAssignmentTargetInfo_GroupTarget(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(assignmentTargetJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDeviceAndAppManagementAssignmentTargetFromDiscriminatorValue)
	require.NoError(t, err)
	target := parsed.(models.DeviceAndAppManagementAssignmentTargetable)

	tt, gid, ex, ft, fid := assignmentTargetInfo(target)
	assert.Equal(t, "groupAssignmentTarget", tt)
	assert.Equal(t, "group-abc", gid)
	assert.False(t, ex)
	assert.Equal(t, "include", ft)
	assert.Equal(t, "filter-1", fid)
}

func TestAssignmentTargetInfo_ExclusionGroupTarget(t *testing.T) {
	target := models.NewExclusionGroupAssignmentTarget()
	target.SetOdataType(new("#microsoft.graph.exclusionGroupAssignmentTarget"))
	target.SetGroupId(new("group-xyz"))

	tt, gid, ex, ft, fid := assignmentTargetInfo(target)
	assert.Equal(t, "exclusionGroupAssignmentTarget", tt)
	assert.Equal(t, "group-xyz", gid)
	assert.True(t, ex)
	assert.Empty(t, ft)
	assert.Empty(t, fid)
}

func TestAssignmentTargetInfo_FilterAdditionalDataWrongTypes(t *testing.T) {
	target := models.NewGroupAssignmentTarget()
	target.SetAdditionalData(map[string]any{
		"deviceAndAppManagementAssignmentFilterType": 42, // not a string
		"deviceAndAppManagementAssignmentFilterId":   nil,
	})

	_, _, _, ft, fid := assignmentTargetInfo(target)
	assert.Empty(t, ft, "non-string filterType should not be extracted")
	assert.Empty(t, fid, "nil filterId should not be extracted")
}

// TestBetaAssignmentTargetInfo_GroupTarget decodes the real Graph payload. On
// beta the filter properties ARE registered field deserializers, so they are
// consumed into the typed backing store and AdditionalData is left empty --
// the opposite of v1, and the reason the typed getters are required here.
func TestBetaAssignmentTargetInfo_GroupTarget(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(assignmentTargetJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateDeviceAndAppManagementAssignmentTargetFromDiscriminatorValue)
	require.NoError(t, err)
	target := parsed.(betamodels.DeviceAndAppManagementAssignmentTargetable)

	assert.Empty(t, target.GetAdditionalData(),
		"beta registers the filter properties as typed fields, so nothing should reach AdditionalData")

	tt, gid, ex, ft, fid := betaAssignmentTargetInfo(target)
	assert.Equal(t, "groupAssignmentTarget", tt)
	assert.Equal(t, "group-abc", gid)
	assert.False(t, ex)
	assert.Equal(t, "include", ft)
	assert.Equal(t, "filter-1", fid)
}

// A target with no filter reports the enum's documented "none", not an empty
// string, so .lr's declared none|include|exclude set holds on every path.
func TestBetaAssignmentTargetInfo_NoFilter(t *testing.T) {
	const noFilter = `{"@odata.type":"#microsoft.graph.groupAssignmentTarget","groupId":"g"}`
	node, err := kjson.NewJsonParseNode([]byte(noFilter))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateDeviceAndAppManagementAssignmentTargetFromDiscriminatorValue)
	require.NoError(t, err)

	_, _, _, ft, fid := betaAssignmentTargetInfo(parsed.(betamodels.DeviceAndAppManagementAssignmentTargetable))
	assert.Empty(t, ft, "an absent filterType stays empty rather than defaulting to none")
	assert.Empty(t, fid)
}

func TestBetaAssignmentTargetInfo_ExclusionGroupTarget(t *testing.T) {
	target := betamodels.NewExclusionGroupAssignmentTarget()
	target.SetGroupId(new("beta-excl"))

	_, gid, ex, _, _ := betaAssignmentTargetInfo(target)
	assert.Equal(t, "beta-excl", gid)
	assert.True(t, ex)
}

func TestBetaAssignmentTargetInfo_Nil(t *testing.T) {
	tt, gid, ex, ft, fid := betaAssignmentTargetInfo(nil)
	assert.Empty(t, tt)
	assert.Empty(t, gid)
	assert.False(t, ex)
	assert.Empty(t, ft)
	assert.Empty(t, fid)
}
