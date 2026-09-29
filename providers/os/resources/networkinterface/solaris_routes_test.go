// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Captured from `netstat -rnv` on Oracle Solaris 11.4.86 (OCI) with a vnic
// carrying two addresses and IPv6 link-local on net0.
func TestParseSolarisNetstatRoutes(t *testing.T) {
	data, err := os.ReadFile("./testdata/solaris114_netstat_rnv.txt")
	require.NoError(t, err)

	routes := parseSolarisNetstatRoutes(string(data))
	require.Len(t, routes, 8)

	assert.Equal(t, Route{
		Destination: "0.0.0.0/0",
		Gateway:     "10.77.1.1",
		Flags:       []string{"GATEWAY", "UP"},
		Interface:   "net0",
	}, routes[0])
	assert.True(t, routes[0].IsDefaultRoute())
	assert.True(t, routes[0].IsIPv4())

	assert.Equal(t, "10.77.1.0/24", routes[1].Destination)
	assert.Equal(t, []string{"UP"}, routes[1].Flags)

	assert.Equal(t, "127.0.0.1/32", routes[2].Destination)
	assert.Equal(t, []string{"HOST", "UP"}, routes[2].Flags)
	assert.Equal(t, "lo0", routes[2].Interface)

	assert.Equal(t, "169.254.0.0/16", routes[3].Destination)
	assert.Equal(t, "192.168.77.0/24", routes[4].Destination)
	assert.Equal(t, "vnic0", routes[4].Interface)

	assert.Equal(t, "::1/128", routes[6].Destination)
	assert.Equal(t, "fe80::/10", routes[7].Destination)
	assert.Equal(t, "fe80::17ff:fe04:b9e2", routes[7].Gateway)
	assert.True(t, routes[7].IsIPv6())
}

func TestParseSolarisNetstatRoutesBlankDevice(t *testing.T) {
	in := `IRE Table: IPv4
  Destination             Mask           Gateway          Device  MTU  Ref Flg  Out  In/Fwd
-------------------- --------------- -------------------- ------ ----- --- --- ----- ------
10.9.0.0             255.255.0.0     10.1.1.1                     1500   1 UGS      0      0
10.8.0.0             255.255.0.0     10.1.1.1                     1500   1 UGR      0      0
`
	routes := parseSolarisNetstatRoutes(in)
	require.Len(t, routes, 1, "the reject route is left out")
	assert.Equal(t, "10.9.0.0/16", routes[0].Destination)
	assert.Equal(t, "", routes[0].Interface)
	assert.Equal(t, []string{"GATEWAY", "STATIC", "UP"}, routes[0].Flags)
}
