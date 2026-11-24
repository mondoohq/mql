// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeApprovalSettings(t *testing.T) {
	// Synthetic: response shape from the GitLab merge request approval
	// settings API documentation; no target was read.
	raw := []byte(`{
		"allow_author_approval": {"value": false, "locked": true, "inherited_from": "instance"},
		"allow_committer_approval": {"value": true, "locked": false},
		"allow_overrides_to_approver_list_per_merge_request": {"value": true, "locked": false},
		"retain_approvals_on_push": {"value": false, "locked": false},
		"require_password_to_approve": null,
		"require_reauthentication_to_approve": {"locked": false}
	}`)

	settings, err := decodeApprovalSettings(raw)
	require.NoError(t, err)

	author, ok := settings["allow_author_approval"]
	require.True(t, ok)
	require.NotNil(t, author.Value)
	assert.False(t, *author.Value)
	require.NotNil(t, author.Locked)
	assert.True(t, *author.Locked)
	require.NotNil(t, author.InheritedFrom)
	assert.Equal(t, "instance", *author.InheritedFrom)

	committer, ok := settings["allow_committer_approval"]
	require.True(t, ok)
	assert.True(t, *committer.Value)
	assert.Nil(t, committer.InheritedFrom, "a value that is not inherited has no origin")

	retain, ok := settings["retain_approvals_on_push"]
	require.True(t, ok)
	assert.False(t, *retain.Value, "an explicit false is reported, not dropped")

	_, ok = settings["selective_code_owner_removals"]
	assert.False(t, ok, "groups do not report this setting, so it must stay null rather than read as false")
	_, ok = settings["require_password_to_approve"]
	assert.False(t, ok, "an explicit null is not a setting")
	_, ok = settings["require_reauthentication_to_approve"]
	assert.False(t, ok, "a setting without a value is not a setting")
}

func TestDecodeApprovalSettingsCoversEveryField(t *testing.T) {
	// Synthetic: every attribute the API documents, each with value true, so a
	// mistyped key in approvalSettingFields drops out of the result.
	raw := []byte(`{
		"allow_author_approval": {"value": true},
		"allow_committer_approval": {"value": true},
		"allow_overrides_to_approver_list_per_merge_request": {"value": true},
		"retain_approvals_on_push": {"value": true},
		"selective_code_owner_removals": {"value": true},
		"require_password_to_approve": {"value": true},
		"require_reauthentication_to_approve": {"value": true}
	}`)

	settings, err := decodeApprovalSettings(raw)
	require.NoError(t, err)
	assert.Len(t, settings, len(approvalSettingFields))
	for _, f := range approvalSettingFields {
		s, ok := settings[f.key]
		if assert.True(t, ok, f.key) {
			assert.True(t, *s.Value, f.key)
		}
	}
}

func TestDecodeApprovalSettingsRejectsMalformedInput(t *testing.T) {
	// Synthetic: a setting whose value is not a boolean.
	_, err := decodeApprovalSettings([]byte(`{"allow_author_approval": {"value": "yes"}}`))
	assert.Error(t, err)

	_, err = decodeApprovalSettings([]byte(`[]`))
	assert.Error(t, err)
}
