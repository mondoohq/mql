// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Captured from `netstat -rn` on AIX 7.3 TL4 SP2 (PowerVS) with a static
// route to 198.51.100.0/24 and an alias address 192.0.2.10 on en0.
func TestParseAixNetstatRoutes(t *testing.T) {
	data, err := os.ReadFile("./testdata/aix73_netstat_rn.txt")
	require.NoError(t, err)

	routes := parseAixNetstatRoutes(string(data))

	dests := []string{}
	for _, r := range routes {
		dests = append(dests, r.Destination+" "+r.Interface)
	}
	assert.Equal(t, []string{
		"0.0.0.0/0 en0",
		"127.0.0.0/8 lo0",
		"192.0.2.10/32 en0",
		"192.0.2.10/32 lo0",
		"192.168.234.32/32 en0",
		"192.168.234.32/29 en0",
		"192.168.234.35/32 lo0",
		"192.168.234.39/32 en0",
		"198.51.100.0/24 en0",
		"::1/128 lo0",
		"fe80::/64 en1",
		"fe80::80de:eff:fe65:c1a/128 lo0",
	}, dests)

	assert.Equal(t, Route{
		Destination: "0.0.0.0/0",
		Gateway:     "192.168.234.33",
		Flags:       []string{"GATEWAY", "UP"},
		Interface:   "en0",
	}, routes[0])
	assert.True(t, routes[0].IsDefaultRoute())

	static := routes[8]
	assert.Equal(t, "192.168.234.33", static.Gateway)
	assert.Equal(t, []string{"GATEWAY", "UP"}, static.Flags)

	broadcast := routes[4]
	assert.Equal(t, []string{"BROADCAST", "HOST", "STATIC", "UP"}, broadcast.Flags)

	loopback := routes[9]
	assert.Equal(t, "::1", loopback.Gateway)
	assert.False(t, loopback.IsIPv4())

	// the gateway column of a route to a local address is empty
	local := routes[11]
	assert.Equal(t, "", local.Gateway)
	assert.Contains(t, local.Flags, "LOCAL")
}

func TestAixIPv4Destination(t *testing.T) {
	for in, want := range map[string]string{
		"default":           "0.0.0.0/0",
		"127/8":             "127.0.0.0/8",
		"198.51.100/24":     "198.51.100.0/24",
		"10/8":              "10.0.0.0/8",
		"192.168.234.32/29": "192.168.234.32/29",
		"192.168.234.35":    "192.168.234.35/32",
		"1.2.3.4.5":         "",
		"10/33":             "",
		"link#2":            "",
	} {
		assert.Equal(t, want, aixIPv4Destination(in), in)
	}
}

func TestAixIPv6Destination(t *testing.T) {
	for in, want := range map[string]string{
		"default":     "::/0",
		"::1%1":       "::1/128",
		"fe80::/64":   "fe80::/64",
		"ff01::%1/16": "ff01::/16",
		"fe80::/129":  "",
		"fe80::/x":    "",
		"link#3":      "",
	} {
		assert.Equal(t, want, aixIPv6Destination(in), in)
	}
}
