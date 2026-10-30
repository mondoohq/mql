// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func loadFreebsdRoutes(t *testing.T, name string) []Route {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	routes, err := parseFreebsdNetstatRoutes(string(data))
	require.NoError(t, err)
	return routes
}

// `netstat -rnW --libxo json` captured on a FreeBSD 13.5-RELEASE EC2 instance.
// 13.x writes ::1 as the gateway of the reject routes and names the host's own
// link-local address with its ena0 scope.
func TestParseFreebsdNetstatRoutes_13(t *testing.T) {
	routes := loadFreebsdRoutes(t, "freebsd13_netstat_rnW.json")

	assert.Equal(t, []Route{
		{Destination: "0.0.0.0/0", Gateway: "172.17.2.1", Flags: []string{"GATEWAY", "STATIC", "UP"}, Interface: "ena0"},
		{Destination: "127.0.0.1/32", Gateway: "link#2", Flags: []string{"HOST", "UP"}, Interface: "lo0"},
		{Destination: "172.17.2.0/24", Gateway: "link#1", Flags: []string{"UP"}, Interface: "ena0"},
		{Destination: "172.17.2.41/32", Gateway: "link#1", Flags: []string{"HOST", "STATIC", "UP"}, Interface: "lo0"},
		{Destination: "::1/128", Gateway: "link#2", Flags: []string{"HOST", "STATIC", "UP"}, Interface: "lo0"},
		{Destination: "fe80::%ena0/64", Gateway: "link#1", Flags: []string{"UP"}, Interface: "ena0"},
		{Destination: "fe80::4ff:faff:fec9:b7d3%ena0/128", Gateway: "link#1", Flags: []string{"HOST", "STATIC", "UP"}, Interface: "lo0"},
		{Destination: "fe80::%lo0/64", Gateway: "link#2", Flags: []string{"UP"}, Interface: "lo0"},
		{Destination: "fe80::1%lo0/128", Gateway: "link#2", Flags: []string{"HOST", "STATIC", "UP"}, Interface: "lo0"},
	}, routes)
}

// Captured on FreeBSD 14.5-RELEASE and 15.1-RELEASE EC2 instances. Both add a
// nhop-kidx key and write link#2 as the gateway of the reject routes.
func TestParseFreebsdNetstatRoutes_14_15(t *testing.T) {
	for _, tc := range []struct {
		file    string
		localIP string
		localLL string
	}{
		{"freebsd14_netstat_rnW.json", "172.17.2.106/32", "fe80::4ff:d0ff:fee3:9f9f%lo0/128"},
		{"freebsd15_netstat_rnW.json", "172.17.2.254/32", "fe80::4ff:daff:febe:3ed9%lo0/128"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			routes := loadFreebsdRoutes(t, tc.file)

			dests := make([]string, 0, len(routes))
			for _, r := range routes {
				dests = append(dests, r.Destination)
			}
			assert.Equal(t, []string{
				"0.0.0.0/0", "127.0.0.1/32", "172.17.2.0/24", tc.localIP,
				"::1/128", "fe80::%ena0/64", tc.localLL, "fe80::%lo0/64", "fe80::1%lo0/128",
			}, dests)

			def := routes[0]
			assert.True(t, def.IsDefaultRoute())
			assert.True(t, def.IsIPv4())
			assert.Equal(t, "172.17.2.1", def.Gateway)
			assert.Equal(t, "ena0", def.Interface)
		})
	}
}

func TestParseFreebsdNetstatRoutes_IPv6Default(t *testing.T) {
	// netstat names both families' default routes "default"; only the family
	// the entry sits in tells them apart. Shape as FreeBSD 14.5 prints it.
	out := `{"statistics": {"route-information": {"route-table": {"rt-family": [
	{"address-family":"Internet", "rt-entry": [{"destination":"default","gateway":"10.0.0.1","flags":"UGS","flags_pretty":["up","gateway","static"],"interface-name":"vtnet0"}]},
	{"address-family":"Internet6", "rt-entry": [
		{"destination":"default","gateway":"fe80::1%vtnet0","flags":"UG","flags_pretty":["up","gateway"],"interface-name":"vtnet0"},
		{"destination":"2001:db8::/64","gateway":"link#1","flags":"U","flags_pretty":["up"],"interface-name":"vtnet0"},
		{"destination":"2001:db8:1::/48","gateway":"::1","flags":"UGSB","flags_pretty":["up","gateway","static","blackhole"],"interface-name":"lo0"},
		{"destination":"ff01::%vtnet0/32","gateway":"link#1","flags":"U","flags_pretty":["up"],"interface-name":"vtnet0"}
	]}]}}}}`

	routes, err := parseFreebsdNetstatRoutes(out)
	require.NoError(t, err)
	assert.Equal(t, []Route{
		{Destination: "0.0.0.0/0", Gateway: "10.0.0.1", Flags: []string{"GATEWAY", "STATIC", "UP"}, Interface: "vtnet0"},
		{Destination: "::/0", Gateway: "fe80::1%vtnet0", Flags: []string{"GATEWAY", "UP"}, Interface: "vtnet0"},
		{Destination: "2001:db8::/64", Gateway: "link#1", Flags: []string{"UP"}, Interface: "vtnet0"},
	}, routes)
}

func TestParseFreebsdNetstatRoutes_Malformed(t *testing.T) {
	_, err := parseFreebsdNetstatRoutes("Routing tables\n\nInternet:\n")
	assert.Error(t, err)
}

func TestFreebsdRouteFlags_MatchBSDFlagNames(t *testing.T) {
	// Every name netstat prints in flags_pretty must land on the name
	// bsdRouteFlagsMap gives the same RTF_* bit, so a query on flags reads the
	// same on FreeBSD as on macOS.
	assert.Equal(t,
		[]string{"BLACKHOLE", "BROADCAST", "DONE", "DYNAMIC", "GATEWAY", "HOST", "MODIFIED", "PROTO1", "PROTO2", "PROTO3", "REJECT", "STATIC", "UP", "XRESOLVE"},
		freebsdRouteFlags([]string{"up", "gateway", "host", "reject", "dynamic", "modified", "done", "xresolve", "static", "proto1", "proto2", "proto3", "blackhole", "broadcast", "up"}),
	)
	known := map[string]bool{}
	for _, name := range bsdRouteFlagsMap {
		known[name] = true
	}
	for _, f := range freebsdRouteFlags([]string{"up", "gateway", "host", "reject", "dynamic", "modified", "done", "xresolve", "static", "proto1", "proto2", "proto3", "blackhole", "broadcast"}) {
		assert.True(t, known[f], "flag %s has no bsdRouteFlagsMap entry", f)
	}
}

func TestRoutes_UnsupportedBSDs(t *testing.T) {
	// OpenBSD, NetBSD and DragonFly have no libxo in netstat; they keep the
	// unsupported answer rather than running a command that cannot work.
	for _, name := range []string{"openbsd", "netbsd", "dragonflybsd"} {
		_, err := Routes(nil, &inventory.Platform{Name: name, Family: []string{"bsd", "unix", "os"}})
		assert.ErrorContains(t, err, "not supported", name)
	}
}
