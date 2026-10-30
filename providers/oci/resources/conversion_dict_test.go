// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/apiaccesscontrol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestDictSlice(t *testing.T) {
	t.Run("an absent list is empty, not nil", func(t *testing.T) {
		var absent []apiaccesscontrol.PrivilegedApiRequestOperationDetails

		got, err := dictSlice(absent)
		require.NoError(t, err)
		assert.NotNil(t, got, "a nil here is the one thing this helper exists to prevent")
		assert.Empty(t, got)
	})

	t.Run("an empty list is empty", func(t *testing.T) {
		got, err := dictSlice([]apiaccesscontrol.PrivilegedApiRequestOperationDetails{})
		require.NoError(t, err)
		assert.Equal(t, []any{}, got)
	})

	t.Run("entries are carried through", func(t *testing.T) {
		got, err := dictSlice([]apiaccesscontrol.PrivilegedApiRequestOperationDetails{
			{
				ApiName:        new("GetSecretBundle"),
				AttributeNames: []string{"secretContent"},
			},
		})
		require.NoError(t, err)
		require.Len(t, got, 1)

		entry, ok := got[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "GetSecretBundle", entry["apiName"])
	})

	t.Run("this is the behaviour convert.JsonToDictSlice does not have", func(t *testing.T) {
		// Pinning the difference rather than describing it: encoding/json sets
		// a slice to nil for a JSON null, so the empty slice the converter
		// starts with does not survive a nil input. Should that ever change
		// upstream, this test says the wrapper is redundant rather than
		// leaving it as unexplained defensive code.
		var absent []apiaccesscontrol.PrivilegedApiRequestOperationDetails

		raw, err := convert.JsonToDictSlice(absent)
		require.NoError(t, err)
		assert.Nil(t, raw, "convert.JsonToDictSlice returns nil for an absent list")
	})
}
