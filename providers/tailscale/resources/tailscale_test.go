// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

// tailscaleWithSettings returns a tailscale resource whose settings cache is
// already populated from the given API response body, so accessors never call
// the API.
func tailscaleWithSettings(t *testing.T, body string) *mqlTailscale {
	t.Helper()
	var s tsclient.TailnetSettings
	require.NoError(t, json.Unmarshal([]byte(body), &s))
	ts := &mqlTailscale{}
	ts.settings = &s
	ts.settingsFetched.Store(true)
	return ts
}

func TestRouteSelection(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		routeSelection string
		null           bool
		regional       bool
	}{
		{
			name:           "regional routing reports both fields",
			body:           `{"routeSelection":"regional-routing","regionalRoutingOn":true}`,
			routeSelection: "regional-routing",
			regional:       true,
		},
		{
			name:           "regional routing with failover is not plain regional routing",
			body:           `{"routeSelection":"regional-routing-failover","regionalRoutingOn":false}`,
			routeSelection: "regional-routing-failover",
			regional:       false,
		},
		{
			name:           "active-passive failover",
			body:           `{"routeSelection":"active-passive-failover","regionalRoutingOn":false}`,
			routeSelection: "active-passive-failover",
			regional:       false,
		},
		{
			name:     "absent routeSelection is null",
			body:     `{"regionalRoutingOn":true}`,
			null:     true,
			regional: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := tailscaleWithSettings(t, tc.body)

			got, err := ts.routeSelection()
			require.NoError(t, err)
			assert.Equal(t, tc.routeSelection, got)
			assert.Equal(t, tc.null, ts.RouteSelection.IsNull())

			regional, err := ts.regionalRoutingEnabled()
			require.NoError(t, err)
			assert.Equal(t, tc.regional, regional)
		})
	}
}
