// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseIpRouteJSON_TableFields covers the fields that a host with VRFs
// needs. `ip -json route show table all` reports them, and without the table
// two routes for the same prefix in two VRFs look like one route.
func TestParseIpRouteJSON_TableFields(t *testing.T) {
	detector := &linuxRouteDetector{}
	output := `[
		{"dst":"default","gateway":"192.0.2.1","dev":"swp1","protocol":"bgp","metric":20,"table":"main","flags":[]},
		{"dst":"10.100.0.0/16","dev":"cluster","protocol":"kernel","scope":"link","prefsrc":"10.100.0.5","table":"1005","flags":[]},
		{"type":"unicast","dst":"192.168.10.0/24","protocol":"static","table":"1007","flags":[]}
	]`

	routes, err := detector.parseIpRouteJSON(output)
	require.NoError(t, err)
	require.Len(t, routes, 3)

	assert.Equal(t, "0.0.0.0", routes[0].Destination)
	assert.Equal(t, "main", routes[0].Table)
	assert.Equal(t, "bgp", routes[0].Protocol)
	assert.Equal(t, int64(20), routes[0].Metric)

	// A VRF route carries the numeric table of the VRF.
	assert.Equal(t, "1005", routes[1].Table)
	assert.Equal(t, "kernel", routes[1].Protocol)
	assert.Equal(t, "link", routes[1].Scope)
	assert.Equal(t, "10.100.0.5", routes[1].Source)
	assert.Equal(t, "cluster", routes[1].Interface)

	assert.Equal(t, "unicast", routes[2].Type)
	assert.Equal(t, "1007", routes[2].Table)
}

// TestParseLinuxRoutesFromProc_MainTable pins that the IPv4 proc source
// reports the main table and the metric. That source really is main-only,
// unlike the IPv6 one.
func TestParseLinuxRoutesFromProc_MainTable(t *testing.T) {
	detector := &linuxRouteDetector{}
	// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
	output := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"

	routes, err := detector.parseLinuxRoutesFromProc(output)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, "main", routes[0].Table)
	assert.Equal(t, int64(100), routes[0].Metric)
	assert.Equal(t, "0.0.0.0/0", routes[0].Destination)
}

// TestParseLinuxIPv6RoutesFromProc_NoTableClaim pins that the IPv6 proc
// source leaves the table empty. It holds the routes of every table and
// names none of them, so claiming main would be wrong.
func TestParseLinuxIPv6RoutesFromProc_NoTableClaim(t *testing.T) {
	detector := &linuxRouteDetector{}
	// destination prefixlen source srcprefixlen nexthop metric ref use flags device
	output := "20010db8000000000000000000000000 20 " +
		"00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 00000400 00000000 00000000 00000001 swp1\n"

	routes, err := detector.parseLinuxIPv6RoutesFromProc(output)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, "", routes[0].Table)
	assert.Equal(t, int64(1024), routes[0].Metric)
	assert.Equal(t, "swp1", routes[0].Interface)
}
