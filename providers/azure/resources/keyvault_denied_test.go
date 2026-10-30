// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestIsKeyVaultReadRefused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// The vault lists fine on the control plane and refuses its contents
		// on the data plane. This is the shape a subscription Reader hits on
		// every vault in the subscription.
		{"403 is refused", armError(http.StatusForbidden, ""), true},
		// A token carrying no data-plane access at all.
		{"401 is refused", armError(http.StatusUnauthorized, ""), true},
		// An absence, not a refusal: the empty list is the honest answer.
		{"404 is not a refusal", armError(http.StatusNotFound, ""), false},
		// Neither of these proves anything about the contents.
		{"429 is not a refusal", armError(http.StatusTooManyRequests, ""), false},
		{"500 is not a refusal", armError(http.StatusInternalServerError, ""), false},
		{"a transport failure is not a refusal", errors.New("dial tcp: i/o timeout"), false},
		{"nil is not a refusal", nil, false},
		{
			"a wrapped response error is still classified",
			errors.Join(errors.New("listing keys"), armError(http.StatusForbidden, "")),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isKeyVaultReadRefused(tt.err))
		})
	}
}

// A refused read must report null, not an empty list. An empty list is a claim
// that the vault holds nothing, and `keys.none(...)` passes on it -- so
// reporting one for contents nobody was allowed to read is a silent pass on
// unexamined key material.
func TestKeyVaultPageFaultRefusedReportsNullNotEmpty(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized} {
		var field plugin.TValue[[]any]

		res, err := keyVaultPageFault(&field, nil, "azure key vault keys", armError(status, ""))

		require.NoError(t, err)
		assert.Nil(t, res)
		assert.True(t, field.State&plugin.StateIsNull != 0, "status %d must report null", status)
		assert.True(t, field.State&plugin.StateIsSet != 0, "status %d must mark the field resolved", status)
	}
}

// A 404 means the resource provider genuinely has nothing here, so the empty
// list is correct and a null would understate what is known.
func TestKeyVaultPageFaultAbsentReportsEmptyList(t *testing.T) {
	var field plugin.TValue[[]any]

	res, err := keyVaultPageFault(&field, nil, "azure key vault keys", armError(http.StatusNotFound, ""))

	require.NoError(t, err)
	assert.Equal(t, []any{}, res)
	assert.Zero(t, field.State, "an absence must not mark the field null")
}

// A throttle or a server error says nothing about the contents. Degrading
// either one would report an authoritative answer derived from no data.
func TestKeyVaultPageFaultFatalStaysAnError(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		var field plugin.TValue[[]any]

		_, err := keyVaultPageFault(&field, nil, "azure key vault keys", armError(status, ""))

		require.Error(t, err, "status %d must surface", status)
		assert.Zero(t, field.State, "status %d must not mark the field null", status)
	}
}

// Once any row has been read, a fault can only be an error: returning the rows
// collected so far would present a truncated collection as a complete one, and
// nothing downstream can tell the difference.
func TestKeyVaultPageFaultPartialWalkIsAnError(t *testing.T) {
	var field plugin.TValue[[]any]
	collected := []any{"key-one"}

	res, err := keyVaultPageFault(&field, collected, "azure key vault keys", armError(http.StatusForbidden, ""))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not read all azure key vault keys")
	assert.Nil(t, res)
	assert.Zero(t, field.State, "a truncated walk must not be reported as null")
}
