// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/require"
)

// decodeLikeEapi mirrors how goeapi decodes a command response into one of the
// structs in this package: mapstructure with TagName "json" and
// WeaklyTypedInput OFF.
//
// goeapi imports mitchellh/mapstructure; this uses the maintained go-viper
// fork, which this repo requires and which keeps the same type strictness.
// That strictness is the whole point: it is what refuses a string for an
// int64 field, and therefore what reproduces the failure a device produces.
//
// The distinction matters. encoding/json will happily read a JSON string into
// a string field and a JSON number into an int64 field, and will also coerce
// in ways mapstructure will not. Decoding a fixture with encoding/json
// therefore proves nothing about what happens in production: a struct field
// typed int64 against a device that sends a string decodes fine in the test
// and fails on the wire, taking the whole resource down with it.
func decodeLikeEapi(t *testing.T, fixture string, out any) error {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "live", fixture))
	require.NoError(t, err)

	var generic map[string]any
	require.NoError(t, json.Unmarshal(raw, &generic))

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "json",
		Result:  out,
	})
	require.NoError(t, err)
	return dec.Decode(generic)
}

// TestLiveFixturesDecode runs every response this provider parses through the
// production decoder, against output captured from a real Arista device
// (CloudEOS 4.34.2F). A struct field whose type does not match what the device
// actually sends fails the whole command, so the resource returns "no data
// available" rather than a wrong value, and no unit test using encoding/json
// would notice.
func TestLiveFixturesDecode(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		target  func() any
	}{
		{"ip-bgp-summary.json", func() any { return &showIPBgpSummary{} }},
		{"ip-bgp-neighbors.json", func() any { return &showIPBgpNeighbors{} }},
		{"interfaces-status.json", func() any { return &showInterfacesStatus{} }},
		{"hostname.json", func() any { return &showHostname{} }},
		{"vlan.json", func() any { return &showVlan{} }},
		{"ip-route.json", func() any { return &showIPRoute{} }},
		{"inventory.json", func() any { return &showInventory{} }},
		{"system-environment-cooling.json", func() any { return &showEnvironmentCooling{} }},
		{"spanning-tree.json", func() any { return &showSpanningTree{} }},
		{"spanning-tree-mst-detail.json", func() any { return &showSpanningTreeMst{} }},
		{"extensions.json", func() any { return &showExtensions{} }},
		{"boot-config.json", func() any { return &showBootConfig{} }},
		{"snmp.json", func() any { return &showSnmp{} }},
		{"snmp-notification.json", func() any { return &showSnmpNotifications{} }},
		{"users-roles.json", func() any { return &showRoles{} }},
		{"vrrp-all.json", func() any { return &showVrrp{} }},
		{"management-api-http-commands.json", func() any { return &showManagementApiHttpCommands{} }},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			if err := decodeLikeEapi(t, tc.fixture, tc.target()); err != nil {
				t.Fatalf("%s does not decode the way goeapi decodes it, so the\nresource returns no data on a real device:\n  %v", tc.fixture, err)
			}
		})
	}
}
