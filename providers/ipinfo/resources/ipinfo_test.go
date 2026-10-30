// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func nullIP() plugin.TValue[llx.RawIP] {
	return plugin.TValue[llx.RawIP]{State: plugin.StateIsNull | plugin.StateIsSet}
}

func setIP(ip string) plugin.TValue[llx.RawIP] {
	return plugin.TValue[llx.RawIP]{Data: llx.RawIP{IP: net.ParseIP(ip)}, State: plugin.StateIsSet}
}

func TestIpinfoID(t *testing.T) {
	// A public-IP query (requested = null) keys as "self".
	public := &mqlIpinfo{Requested_ip: nullIP()}
	publicID, err := public.id()
	require.NoError(t, err)
	assert.Equal(t, "ipinfo\x00self", publicID)

	// An explicit query keys on the requested address.
	explicit := &mqlIpinfo{Requested_ip: setIP("8.8.8.8")}
	explicitID, err := explicit.id()
	require.NoError(t, err)
	assert.Equal(t, "ipinfo\x00"+(llx.RawIP{IP: net.ParseIP("8.8.8.8")}).String(), explicitID)

	// Regression: the public query and an explicit query for that SAME address
	// return the same IP but must be DISTINCT resources. Keying on the returned
	// IP collided them (and crossed requested_ip); keying on the request keeps
	// them apart.
	assert.NotEqual(t, publicID, explicitID, "public vs explicit-same-IP must not collide")

	// Different explicit IPs are distinct.
	otherID, err := (&mqlIpinfo{Requested_ip: setIP("1.1.1.1")}).id()
	require.NoError(t, err)
	assert.NotEqual(t, explicitID, otherID)
}

func TestRequestedIP(t *testing.T) {
	t.Run("absent arg -> nil, no error (query own public IP)", func(t *testing.T) {
		got, err := requestedIP(map[string]*llx.RawData{})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("valid ip arg", func(t *testing.T) {
		got, err := requestedIP(map[string]*llx.RawData{
			"ip": llx.IPData(llx.RawIP{IP: net.ParseIP("8.8.8.8")}),
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.Equal(net.ParseIP("8.8.8.8")))
	})

	t.Run("wrong type -> error", func(t *testing.T) {
		_, err := requestedIP(map[string]*llx.RawData{"ip": llx.StringData("8.8.8.8")})
		require.Error(t, err)
	})

	t.Run("empty ip -> error", func(t *testing.T) {
		_, err := requestedIP(map[string]*llx.RawData{"ip": llx.IPData(llx.RawIP{IP: nil})})
		require.Error(t, err)
	})
}
