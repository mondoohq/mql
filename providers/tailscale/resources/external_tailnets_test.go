// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	tsclient "tailscale.com/client/tailscale/v2"
)

func TestSortedExternalTailnets_SortsByAliasAndKeepsValues(t *testing.T) {
	in := map[string]tsclient.ExternalTailnet{
		"partner": {
			ExternalID:                "T2222CNTRL",
			AllowIncomingConnections:  true,
			AllowExternalReferencesTo: []string{"group:eng", "tag:prod"},
		},
		"acme": {ExternalID: "T1111CNTRL"},
		"mid":  {ExternalID: "T3333CNTRL", AllowIncomingConnections: true},
	}

	out := sortedExternalTailnets(in)
	require.Len(t, out, 3)

	assert.Equal(t, "acme", out[0].name)
	assert.Equal(t, "mid", out[1].name)
	assert.Equal(t, "partner", out[2].name)

	// Each alias must stay paired with its own entry after sorting.
	assert.Equal(t, "T1111CNTRL", out[0].ExternalID)
	assert.False(t, out[0].AllowIncomingConnections)
	assert.Empty(t, out[0].AllowExternalReferencesTo)

	assert.Equal(t, "T3333CNTRL", out[1].ExternalID)
	assert.True(t, out[1].AllowIncomingConnections)

	assert.Equal(t, "T2222CNTRL", out[2].ExternalID)
	assert.True(t, out[2].AllowIncomingConnections)
	assert.Equal(t, []string{"group:eng", "tag:prod"}, out[2].AllowExternalReferencesTo)
}

func TestSortedExternalTailnets_NoSectionIsEmpty(t *testing.T) {
	assert.Empty(t, sortedExternalTailnets(nil))
	assert.Empty(t, sortedExternalTailnets(map[string]tsclient.ExternalTailnet{}))
}

// The policy JSON keys are what the Tailscale docs define for the
// externalTailnets section; a mismatched SDK tag would decode to zero values
// and report every external tailnet as unable to connect in.
func TestExternalTailnets_DecodeFromPolicyJSON(t *testing.T) {
	body := `{
		"externalTailnets": {
			"partner": {
				"externalID": "T2222CNTRL",
				"allowIncomingConnections": true,
				"allowExternalReferencesTo": ["group:eng"]
			}
		}
	}`

	var acl tsclient.ACL
	require.NoError(t, json.Unmarshal([]byte(body), &acl))

	out := sortedExternalTailnets(acl.ExternalTailnets)
	require.Len(t, out, 1)
	assert.Equal(t, "partner", out[0].name)
	assert.Equal(t, "T2222CNTRL", out[0].ExternalID)
	assert.True(t, out[0].AllowIncomingConnections)
	assert.Equal(t, []string{"group:eng"}, out[0].AllowExternalReferencesTo)
}

func TestClassifyOrganizationTailnetsError(t *testing.T) {
	t.Run("403 is forbidden and names the scope", func(t *testing.T) {
		err := classifyOrganizationTailnetsError(tsclient.APIError{Status: 403, Message: "forbidden"})
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		var lerr *llx.Error
		require.True(t, errors.As(err, &lerr))
		assert.Equal(t, []string{"tailnets:read"}, lerr.Permissions)
	})

	t.Run("404 is not classified", func(t *testing.T) {
		err := classifyOrganizationTailnetsError(tsclient.APIError{Status: 404, Message: "not found"})
		assert.False(t, errors.Is(err, llx.ErrForbidden))
	})

	t.Run("transport error is not classified", func(t *testing.T) {
		err := classifyOrganizationTailnetsError(errors.New("dial tcp: connection refused"))
		assert.False(t, errors.Is(err, llx.ErrForbidden))
	})
}
