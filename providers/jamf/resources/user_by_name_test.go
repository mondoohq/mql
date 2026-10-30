// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestInitJamfUserByName_BareResourceIsEmptyState(t *testing.T) {
	// No id, no name → not an error, just an empty resource.
	args, res, err := initJamfUserByName(nil, map[string]*llx.RawData{})
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.NotNil(t, args)
}

func TestInitJamfUserByName_EmptyNameIsRejected(t *testing.T) {
	// Empty string would call /users/name/ on the API, which the user almost
	// certainly didn't mean. Reject early so we don't fan that out into a
	// confusing HTTP error.
	_, _, err := initJamfUserByName(nil, map[string]*llx.RawData{
		"name": llx.StringData(""),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty name")
}

func TestInitJamfUserByName_IdAlreadyPresentSkipsAPI(t *testing.T) {
	// runtime is nil — if the function tried to make an API call it would
	// panic. The point is that pre-hydrated args take the fast path.
	args := map[string]*llx.RawData{
		"id":   llx.IntData(int64(42)),
		"name": llx.StringData("jsmith"),
	}
	got, res, err := initJamfUserByName(nil, args)
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.Equal(t, args, got)
}
