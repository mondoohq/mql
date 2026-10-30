// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestNormalizeOwnerType(t *testing.T) {
	str := func(s string) *string { return &s }
	tests := []struct {
		name string
		in   *string
		want *string
	}{
		{"user", str("#microsoft.graph.user"), str("user")},
		{"servicePrincipal", str("#microsoft.graph.servicePrincipal"), str("servicePrincipal")},
		{"device", str("#microsoft.graph.device"), str("device")},
		{"already short", str("user"), str("user")},
		{"unknown prefix untouched", str("#custom.type"), str("#custom.type")},
		{"nil", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeOwnerType(tc.in)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

// A group owner is either a user or a service principal. Selecting both
// accessors on a mixed list must not error: the accessor for the type the
// owner is NOT must return (nil, nil) with the field marked null, rather than
// returning an error that aborts the whole owners selection.
func TestGroupOwnerAccessorsReturnNullForWrongType(t *testing.T) {
	t.Run("user() on a service principal owner", func(t *testing.T) {
		owner := &mqlMicrosoftGroupOwner{}
		owner.OwnerType.Data = "servicePrincipal"
		owner.OwnerType.State = plugin.StateIsSet

		u, err := owner.user()
		require.NoError(t, err)
		assert.Nil(t, u)
		assert.NotZero(t, owner.User.State&plugin.StateIsNull, "user field should be marked null")
	})

	t.Run("servicePrincipal() on a user owner", func(t *testing.T) {
		owner := &mqlMicrosoftGroupOwner{}
		owner.OwnerType.Data = "user"
		owner.OwnerType.State = plugin.StateIsSet

		sp, err := owner.servicePrincipal()
		require.NoError(t, err)
		assert.Nil(t, sp)
		assert.NotZero(t, owner.ServicePrincipal.State&plugin.StateIsNull, "servicePrincipal field should be marked null")
	})
}
