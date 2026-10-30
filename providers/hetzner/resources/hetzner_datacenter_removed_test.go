// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
)

func TestIsRemovedAPIEndpoint(t *testing.T) {
	// The answer Hetzner gives for a withdrawn endpoint. GET /v1/datacenters
	// answers this way after 2026-10-01.
	t.Run("a withdrawn endpoint is recognized", func(t *testing.T) {
		err := hcloud.Error{Code: hcloud.ErrorDeprecatedAPIEndpoint, Message: "removed"}
		assert.True(t, isRemovedAPIEndpoint(err))
	})

	t.Run("through wrapping", func(t *testing.T) {
		err := fmt.Errorf("listing datacenters: %w",
			hcloud.Error{Code: hcloud.ErrorDeprecatedAPIEndpoint, Message: "removed"})
		assert.True(t, isRemovedAPIEndpoint(err))
	})

	// Everything below is a different situation and must not be reported as a
	// withdrawn endpoint, or a real failure would be laundered into a null.
	for _, code := range []hcloud.ErrorCode{
		hcloud.ErrorCodeNotFound,
		hcloud.ErrorCodeUnauthorized,
		hcloud.ErrorCodeForbidden,
		hcloud.ErrorCodeRateLimitExceeded,
		hcloud.ErrorCodeServerError,
	} {
		t.Run(string(code)+" is not a withdrawal", func(t *testing.T) {
			assert.False(t, isRemovedAPIEndpoint(hcloud.Error{Code: code}))
		})
	}

	t.Run("a transport error carries no hcloud code", func(t *testing.T) {
		assert.False(t, isRemovedAPIEndpoint(errors.New("dial tcp: no such host")))
	})

	t.Run("nil is not a match", func(t *testing.T) {
		assert.False(t, isRemovedAPIEndpoint(nil))
	})
}

// paginate is the only path a list reaches the accessor through, so the
// withdrawal has to survive it. If translateHcloudError ever swallowed this
// code the way it swallows a 404, paginate would report an empty list and the
// null branch in datacenters() would be unreachable.
func TestRemovedEndpointSurvivesPaginate(t *testing.T) {
	removed := hcloud.Error{Code: hcloud.ErrorDeprecatedAPIEndpoint, Message: "removed"}
	_, err := paginate(func(hcloud.ListOpts) ([]*hcloud.Datacenter, *hcloud.Response, error) {
		return nil, nil, removed
	})
	require.Error(t, err, "a withdrawn endpoint must not be reported as an empty list")
	assert.True(t, isRemovedAPIEndpoint(err))

	// Contrast: a 404 collection genuinely is empty, and still is.
	out, err := paginate(func(hcloud.ListOpts) ([]*hcloud.Datacenter, *hcloud.Response, error) {
		return nil, nil, hcloud.Error{Code: hcloud.ErrorCodeNotFound}
	})
	require.NoError(t, err)
	assert.Empty(t, out)
}

// hetznerRuntime points a real connection at a test server.
func hetznerRuntime(t *testing.T, h http.HandlerFunc) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	conn, err := connection.NewHetznerConnection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OPTION_TOKEN:    "test-token",
			connection.OPTION_ENDPOINT: srv.URL,
		},
	})
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn}
}

// The response Hetzner serves for the withdrawn datacenters endpoint.
const removedEndpointBody = `{"error":{"code":"deprecated_api_endpoint","message":"The API functionality was removed"}}`

// After 2026-10-01 the datacenters endpoint is gone. The field must read null,
// not an empty list: an empty list would claim the project has no datacenters,
// when in truth none can be read any more.
func TestDatacentersReadNullOnceWithdrawn(t *testing.T) {
	runtime := hetznerRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(removedEndpointBody))
	})

	h := &mqlHetzner{MqlRuntime: runtime}
	out, err := h.datacenters()
	require.NoError(t, err, "a withdrawn endpoint should not fail the field")
	assert.Nil(t, out)
	assert.NotZero(t, h.Datacenters.State&plugin.StateIsNull,
		"the field must be null, not an empty list")
}

// A failure that is not the withdrawal still has to propagate, or an outage
// would read as "no datacenters".
func TestDatacentersPropagateOtherFailures(t *testing.T) {
	runtime := hetznerRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"bad token"}}`))
	})

	h := &mqlHetzner{MqlRuntime: runtime}
	_, err := h.datacenters()
	require.Error(t, err)
	assert.Zero(t, h.Datacenters.State&plugin.StateIsNull)
}

// The init cannot report null, so it has to say what happened and name the
// replacement rather than surfacing a bare 410.
func TestDatacenterInitExplainsWithdrawal(t *testing.T) {
	runtime := hetznerRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(removedEndpointBody))
	})

	_, res, err := initHetznerDatacenter(runtime, map[string]*llx.RawData{"id": llx.IntData(4)})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "withdrew the datacenters API")
	assert.Contains(t, err.Error(), "hetzner.serverType.locations")
}
