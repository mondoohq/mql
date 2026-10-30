// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// setRestrictions builds the restrictions resource in the shape apiKeys()
// produces it: every field explicitly set, with the "no restrictions of this
// kind" case represented by a nil dict / empty list rather than an unset field.
func setRestrictions(android, browser, ios, server any, apiTargets []any) *mqlGcpProjectApiKeyRestrictions {
	return &mqlGcpProjectApiKeyRestrictions{
		AndroidKeyRestrictions: plugin.TValue[any]{Data: android, State: plugin.StateIsSet},
		BrowserKeyRestrictions: plugin.TValue[any]{Data: browser, State: plugin.StateIsSet},
		IosKeyRestrictions:     plugin.TValue[any]{Data: ios, State: plugin.StateIsSet},
		ServerKeyRestrictions:  plugin.TValue[any]{Data: server, State: plugin.StateIsSet},
		ApiTargets:             plugin.TValue[[]any]{Data: apiTargets, State: plugin.StateIsSet},
	}
}

// TestApiKeyUnrestricted pins the predicate that made this bug findable.
//
// The Keys.List response omits the whole `restrictions` block for a key with no
// restrictions, so apiKeys() previously built the restrictions resource only
// when k.Restrictions != nil. That left `restrictions` NULL for exactly the
// fully-unrestricted keys, making `unrestricted` unreachable for them: the
// all-empty case below could never occur in practice.
func TestApiKeyUnrestricted(t *testing.T) {
	dict := map[string]any{"allowedIps": []any{"10.0.0.0/8"}}
	target := []any{map[string]any{"service": "storage.googleapis.com"}}

	tests := []struct {
		name string
		res  *mqlGcpProjectApiKeyRestrictions
		want bool
	}{
		{
			// The case the API represents by omitting the block entirely.
			name: "no restrictions at all",
			res:  setRestrictions(nil, nil, nil, nil, []any{}),
			want: true,
		},
		{
			name: "server ip restriction only",
			res:  setRestrictions(nil, nil, nil, dict, []any{}),
			want: false,
		},
		{
			name: "android restriction only",
			res:  setRestrictions(dict, nil, nil, nil, []any{}),
			want: false,
		},
		{
			name: "browser restriction only",
			res:  setRestrictions(nil, dict, nil, nil, []any{}),
			want: false,
		},
		{
			name: "ios restriction only",
			res:  setRestrictions(nil, nil, dict, nil, []any{}),
			want: false,
		},
		{
			// An API-target restriction alone still narrows the key.
			name: "api targets only",
			res:  setRestrictions(nil, nil, nil, nil, target),
			want: false,
		},
		{
			name: "nil api target slice counts as none",
			res:  setRestrictions(nil, nil, nil, nil, nil),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.res.unrestricted()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestApiKeyAppliedRestrictionTypes checks the companion accessor reports the
// empty list (not null) for an unrestricted key, so a caller can tell "no
// restrictions" from "could not read the restrictions".
func TestApiKeyAppliedRestrictionTypes(t *testing.T) {
	dict := map[string]any{"allowedIps": []any{"10.0.0.0/8"}}

	t.Run("unrestricted key reports an empty list", func(t *testing.T) {
		got, err := setRestrictions(nil, nil, nil, nil, []any{}).appliedRestrictionTypes()
		require.NoError(t, err)
		assert.Empty(t, got)
		assert.NotNil(t, got, "must be an empty list, not null")
	})

	t.Run("restricted key names the applied types", func(t *testing.T) {
		got, err := setRestrictions(nil, nil, nil, dict, []any{}).appliedRestrictionTypes()
		require.NoError(t, err)
		assert.Contains(t, got, "serverKeyRestrictions")
	})
}
