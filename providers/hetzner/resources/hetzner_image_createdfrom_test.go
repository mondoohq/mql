// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
)

// snapshotFrom builds a snapshot image taken from server 5, on a runtime whose
// API answers every request with the given status and body.
func snapshotFrom(t *testing.T, status int, body string) (*mqlHetznerImage, *string) {
	t.Helper()
	var requested string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	conn, err := connection.NewHetznerConnection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OPTION_TOKEN:    "test-token",
			connection.OPTION_ENDPOINT: srv.URL,
		},
	})
	require.NoError(t, err)
	runtime := plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	img, err := newMqlHetznerImage(runtime, &hcloud.Image{
		ID:          1,
		Type:        hcloud.ImageTypeSnapshot,
		CreatedFrom: &hcloud.Server{ID: 5, Name: "retired"},
	})
	require.NoError(t, err)
	return img, &requested
}

// A snapshot keeps naming the server it came from after that server is
// deleted. The reference then points at nothing, which is a genuine absence
// and reads null, not a lookup error.
func TestImageCreatedFromDeletedServerIsNull(t *testing.T) {
	img, requested := snapshotFrom(t, http.StatusNotFound,
		`{"error":{"code":"not_found","message":"server with ID '5' not found"}}`)

	s, err := img.createdFrom()
	require.NoError(t, err)
	assert.Nil(t, s)
	assert.Equal(t, "/servers/5", *requested)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, img.CreatedFrom.State)
}

// Only a missing server is an absence. A refused or failed lookup says nothing
// about whether the server exists and must still surface.
func TestImageCreatedFromOtherFailuresPropagate(t *testing.T) {
	img, _ := snapshotFrom(t, http.StatusForbidden,
		`{"error":{"code":"forbidden","message":"insufficient permissions"}}`)

	s, err := img.createdFrom()
	require.Error(t, err)
	assert.Nil(t, s)
	assert.False(t, errors.Is(err, errResourceNotFound))
	assert.Zero(t, img.CreatedFrom.State&plugin.StateIsNull)
}

func TestImageCreatedFromExistingServer(t *testing.T) {
	img, _ := snapshotFrom(t, http.StatusOK,
		`{"server":{"id":5,"name":"origin","status":"running","public_net":{},"private_net":[],"labels":{}}}`)

	s, err := img.createdFrom()
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, int64(5), s.Id.Data)
	assert.Equal(t, "origin", s.Name.Data)
}

// The sentinel has to survive the message format the inits have always used.
func TestNotFoundErrWrapsSentinel(t *testing.T) {
	err := notFoundErr("server", 5)
	assert.True(t, errors.Is(err, errResourceNotFound))
	assert.Equal(t, "hetzner server not found: 5", err.Error())
}
