// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListEmailServersDecodesBareArray is the regression for an org that has
// configured a custom SMTP server getting an unmarshal error instead of its
// servers. `/api/v1/email-servers` answers with a bare array, but the SDK
// types the response as an EmailServerListResponse object, so the generated
// call fails with "cannot unmarshal array into Go value of type
// okta._EmailServerListResponse" and takes the whole collection down.
func TestListEmailServersDecodesBareArray(t *testing.T) {
	t.Parallel()
	rt := &singlePageRoundTripper{
		body: `[{"id":"ces1","alias":"primary","host":"smtp.example.com","port":587,"username":"mailer","enabled":true},
		        {"id":"ces2","alias":"backup","host":"smtp2.example.com","port":25,"username":"relay","enabled":false}]`,
	}

	servers, _, err := fakeClient(rt).ListEmailServers(context.Background())
	require.NoError(t, err)
	require.Len(t, servers, 2)

	assert.Equal(t, "ces1", *servers[0].Id)
	assert.Equal(t, "primary", *servers[0].Alias)
	assert.Equal(t, "smtp.example.com", *servers[0].Host)
	assert.Equal(t, int32(587), *servers[0].Port)
	assert.Equal(t, "mailer", *servers[0].Username)
	assert.True(t, *servers[0].Enabled)

	// The disabled server must not read as enabled: `enabled` is the field an
	// audit keys on, and a dropped false would report a live relay.
	assert.False(t, *servers[1].Enabled)
	assert.Equal(t, int32(25), *servers[1].Port)
}

func TestDecodeOktaEmailServers(t *testing.T) {
	t.Parallel()

	t.Run("bare array, the shape the API sends", func(t *testing.T) {
		servers, err := decodeOktaEmailServers(json.RawMessage(
			`[{"id":"ces1","alias":"primary"}]`))
		require.NoError(t, err)
		require.Len(t, servers, 1)
		assert.Equal(t, "ces1", *servers[0].Id)
	})

	t.Run("wrapped object, the shape the SDK model describes", func(t *testing.T) {
		servers, err := decodeOktaEmailServers(json.RawMessage(
			`{"email-servers":[{"id":"ces9","alias":"wrapped"}]}`))
		require.NoError(t, err)
		require.Len(t, servers, 1)
		assert.Equal(t, "ces9", *servers[0].Id)
		assert.Equal(t, "wrapped", *servers[0].Alias)
	})

	t.Run("empty array is no servers, not an error", func(t *testing.T) {
		servers, err := decodeOktaEmailServers(json.RawMessage(`[]`))
		require.NoError(t, err)
		assert.Empty(t, servers)
	})

	t.Run("empty body is no servers", func(t *testing.T) {
		servers, err := decodeOktaEmailServers(nil)
		require.NoError(t, err)
		assert.Empty(t, servers)
	})

	t.Run("neither shape is an error, not a silent empty", func(t *testing.T) {
		_, err := decodeOktaEmailServers(json.RawMessage(`"unexpected"`))
		require.Error(t, err)
	})
}
