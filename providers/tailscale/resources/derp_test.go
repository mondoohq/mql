// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

func TestFlattenDERPMap_NilYieldsEmptyList(t *testing.T) {
	// A policy with no custom relays must read as an empty list rather than
	// null, so that asserting no custom relay is configured compares against
	// a real value.
	regions, omitDefaults, err := flattenDERPMap(nil)
	require.NoError(t, err)
	assert.Equal(t, []any{}, regions)
	assert.False(t, omitDefaults)
}

func TestFlattenDERPMap_SortsByRegionID(t *testing.T) {
	derpMap := &tsclient.ACLDERPMap{
		OmitDefaultRegions: true,
		Regions: map[int]*tsclient.ACLDERPRegion{
			900: {RegionID: 900, RegionCode: "sfo", RegionName: "San Francisco"},
			100: {RegionID: 100, RegionCode: "ams", RegionName: "Amsterdam"},
			500: {RegionID: 500, RegionCode: "nyc", RegionName: "New York"},
		},
	}

	regions, omitDefaults, err := flattenDERPMap(derpMap)
	require.NoError(t, err)
	assert.True(t, omitDefaults)
	require.Len(t, regions, 3)

	// Go randomizes map iteration order, so without the sort two scans of an
	// unchanged policy would produce differently ordered lists.
	codes := make([]string, 0, len(regions))
	for _, region := range regions {
		entry, ok := region.(map[string]any)
		require.True(t, ok)
		codes = append(codes, entry["regionCode"].(string))
	}
	assert.Equal(t, []string{"ams", "nyc", "sfo"}, codes)
}

func TestFlattenDERPMap_SkipsNilRegions(t *testing.T) {
	derpMap := &tsclient.ACLDERPMap{
		Regions: map[int]*tsclient.ACLDERPRegion{
			100: {RegionID: 100, RegionCode: "ams"},
			200: nil,
		},
	}

	regions, _, err := flattenDERPMap(derpMap)
	require.NoError(t, err)
	assert.Len(t, regions, 1)
}

func TestFlattenDERPMap_CarriesNodeDetail(t *testing.T) {
	// The relay hosts are the security-relevant part: a custom DERP node is
	// a third-party server that tailnet traffic is relayed through.
	derpMap := &tsclient.ACLDERPMap{
		Regions: map[int]*tsclient.ACLDERPRegion{
			900: {
				RegionID:   900,
				RegionCode: "self",
				Nodes: []*tsclient.ACLDERPNode{
					{Name: "1", RegionID: 900, HostName: "derp.example.com", IPv4: "10.0.0.1", DERPPort: 8443},
				},
			},
		},
	}

	regions, _, err := flattenDERPMap(derpMap)
	require.NoError(t, err)
	require.Len(t, regions, 1)

	entry := regions[0].(map[string]any)
	nodes, ok := entry["nodes"].([]any)
	require.True(t, ok)
	require.Len(t, nodes, 1)

	node := nodes[0].(map[string]any)
	assert.Equal(t, "derp.example.com", node["hostName"])
	assert.Equal(t, float64(8443), node["derpPort"])
}

func TestStructMapToDictMap(t *testing.T) {
	in := map[string]tsclient.ACLAttrConfig{
		"custom:risk": {Type: "number", AllowSetByNode: true, BroadcastToPeers: []string{"tag:admin"}},
	}

	out, err := structMapToDictMap(in)
	require.NoError(t, err)
	require.Len(t, out, 1)

	entry, ok := out["custom:risk"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "number", entry["type"])
	// An attribute a node sets for itself is not a trustworthy posture
	// signal, so the flag has to survive the conversion.
	assert.Equal(t, true, entry["allowSetByNode"])
	assert.Equal(t, []any{"tag:admin"}, entry["broadcastToPeers"])
}

func TestStructMapToDictMap_Empty(t *testing.T) {
	out, err := structMapToDictMap(map[string]tsclient.ACLAttrConfig{})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{}, out)
}
