// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// teamsRuntime points a real connection at a server that answers the
// organization teams endpoint with the given status and body.
func teamsRuntime(t *testing.T, status int, body string) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/organizations/teams", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("DIGITALOCEAN_TOKEN", "test-token")
	conn, err := connection.NewDigitaloceanConnection(0, &inventory.Asset{},
		&inventory.Config{Options: map[string]string{}})
	require.NoError(t, err)

	base, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	conn.Client().BaseURL = base

	return &plugin.Runtime{Connection: conn}
}

// TestTeamsUnreadableIsNull pins the distinction the accessor exists to make.
//
// A token with no organization context cannot read the teams. That is not the
// same fact as "this organization has no teams", and reporting it as an empty
// list is worse than useless: `.none()` and `.all()` over an empty list are
// vacuously true, so every assertion about teams passes on an account nobody
// was allowed to look at. Null carries no answer and fails those closed.
//
// The state has to be set proactively. Returning a nil slice is not enough -
// the runtime cannot tell a nil slice from an empty one and serializes both as
// [], which is exactly how this shipped.
func TestTeamsUnreadableIsNull(t *testing.T) {
	for _, status := range []int{
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusPreconditionFailed,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			r := &mqlDigitalocean{MqlRuntime: teamsRuntime(t, status,
				`{"id":"forbidden","message":"You are not authorized to perform this operation"}`)}

			out, err := r.teams()

			require.NoError(t, err, "an unreadable teams list is not a scan failure")
			assert.Nil(t, out)
			assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.Teams.State,
				"unreadable teams must be null; an empty list would pass .none() vacuously")
		})
	}
}

// A read that succeeded and found nothing is a real answer, and has to stay an
// empty list - turning it into null would fail assertions that should pass.
func TestTeamsEmptyStaysEmpty(t *testing.T) {
	r := &mqlDigitalocean{MqlRuntime: teamsRuntime(t, http.StatusOK, `{"teams":[]}`)}

	out, err := r.teams()

	require.NoError(t, err)
	assert.NotNil(t, out, "a successful read with no teams is [], not null")
	assert.Empty(t, out)
	assert.Equal(t, plugin.State(0), r.Teams.State,
		"the accessor must not pre-mark the field when it has a real answer")
}

// A rejected token is a plain failure and must surface as one.
func TestTeamsUnauthorizedIsError(t *testing.T) {
	r := &mqlDigitalocean{MqlRuntime: teamsRuntime(t, http.StatusUnauthorized,
		`{"id":"unauthorized","message":"Unable to authenticate you"}`)}

	_, err := r.teams()

	require.Error(t, err, "401 must not be laundered into null or an empty list")
}
