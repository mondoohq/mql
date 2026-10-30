// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBGPSummaryParsing(t *testing.T) {
	data, err := os.ReadFile("./testdata/bgp-summary.json")
	require.NoError(t, err)

	var summary showIPBgpSummary
	err = json.Unmarshal(data, &summary)
	require.NoError(t, err)

	// Verify VRF count
	assert.Len(t, summary.VRFs, 2)

	// Verify default VRF
	defaultVrf, ok := summary.VRFs["default"]
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1", defaultVrf.RouterID)
	assert.Equal(t, "65001", ASNString(defaultVrf.ASN))
	assert.Len(t, defaultVrf.Peers, 2)

	// Verify established peer
	peer1, ok := defaultVrf.Peers["10.0.0.2"]
	require.True(t, ok)
	assert.Equal(t, "Established", peer1.PeerState)
	assert.Equal(t, "65002", ASNString(peer1.ASN))
	assert.Equal(t, int64(150), peer1.PrefixAccepted)
	assert.Equal(t, int64(200), peer1.PrefixReceived)
	assert.InDelta(t, 86400.5, peer1.UpDownTime, 0.1)
	assert.False(t, peer1.UnderMaintenance)

	// Verify idle peer
	peer2, ok := defaultVrf.Peers["10.0.0.3"]
	require.True(t, ok)
	assert.Equal(t, "Idle", peer2.PeerState)
	assert.Equal(t, int64(0), peer2.PrefixAccepted)
	assert.Equal(t, int64(0), peer2.PrefixReceived)

	// Verify MGMT VRF
	mgmtVrf, ok := summary.VRFs["MGMT"]
	require.True(t, ok)
	assert.Equal(t, "172.16.0.1", mgmtVrf.RouterID)
	assert.Len(t, mgmtVrf.Peers, 1)

	mgmtPeer, ok := mgmtVrf.Peers["172.16.0.2"]
	require.True(t, ok)
	assert.True(t, mgmtPeer.UnderMaintenance)
	assert.Equal(t, int64(5), mgmtPeer.PrefixAccepted)
}

func TestBGPNeighborsParsing(t *testing.T) {
	data, err := os.ReadFile("./testdata/bgp-neighbors.json")
	require.NoError(t, err)

	var neighbors showIPBgpNeighbors
	err = json.Unmarshal(data, &neighbors)
	require.NoError(t, err)

	// Verify VRF count
	assert.Len(t, neighbors.VRFs, 2)

	// Verify default VRF peers
	defaultVrf, ok := neighbors.VRFs["default"]
	require.True(t, ok)
	assert.Len(t, defaultVrf.PeerList, 2)

	// Verify first peer details
	peer1 := defaultVrf.PeerList[0]
	assert.Equal(t, "10.0.0.2", peer1.PeerAddress)
	assert.Equal(t, "upstream-router", peer1.Description)
	assert.Equal(t, "65002", ASNString(peer1.ASN))
	assert.Equal(t, "IMPORT-FILTER", peer1.InboundRouteMap)
	assert.Equal(t, "EXPORT-FILTER", peer1.OutboundRouteMap)

	// Verify peer with no route maps
	peer2 := defaultVrf.PeerList[1]
	assert.Equal(t, "10.0.0.3", peer2.PeerAddress)
	assert.Equal(t, "backup-router", peer2.Description)
	assert.Empty(t, peer2.InboundRouteMap)
	assert.Empty(t, peer2.OutboundRouteMap)

	// Verify MGMT VRF
	mgmtVrf, ok := neighbors.VRFs["MGMT"]
	require.True(t, ok)
	assert.Len(t, mgmtVrf.PeerList, 1)
	assert.Equal(t, "172.16.0.2", mgmtVrf.PeerList[0].PeerAddress)
	assert.Equal(t, "MGMT-IN", mgmtVrf.PeerList[0].InboundRouteMap)
}

func TestBGPSummaryGetCmd(t *testing.T) {
	s := &showIPBgpSummary{}
	assert.Equal(t, "show ip bgp summary", s.GetCmd())
}

func TestBGPNeighborsGetCmd(t *testing.T) {
	s := &showIPBgpNeighbors{}
	assert.Equal(t, "show ip bgp neighbors", s.GetCmd())
}

func TestBGPSummaryEmptyVRFs(t *testing.T) {
	jsonData := `{"vrfs": {}}`
	var summary showIPBgpSummary
	err := json.Unmarshal([]byte(jsonData), &summary)
	require.NoError(t, err)
	assert.Empty(t, summary.VRFs)
}

func TestBGPSummaryEmptyPeers(t *testing.T) {
	jsonData := `{"vrfs": {"default": {"routerId": "1.2.3.4", "asn": 100, "peers": {}}}}`
	var summary showIPBgpSummary
	err := json.Unmarshal([]byte(jsonData), &summary)
	require.NoError(t, err)
	assert.Empty(t, summary.VRFs["default"].Peers)
	assert.Equal(t, "100", ASNString(summary.VRFs["default"].ASN))
}

// TestASNString covers both wire forms EOS has used for an AS number. The
// device sends it as a JSON string on 4.34 and as a number on older releases;
// goeapi decodes with weak typing off, so a concrete struct type fails the
// whole `show ip bgp summary` command on whichever release disagrees, and
// arista.eos.bgp.vrfs returns no data rather than a wrong number.
func TestASNString(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want string
	}{
		{"string, as EOS 4.34 sends it", "65001", "65001"},
		{"json number, as older releases send it", float64(65001), "65001"},
		{"int64", int64(65001), "65001"},
		{"int", 65001, "65001"},
		{"4-byte AS", "4200000000", "4200000000"},
		// Absent must not read as AS 0, which is a real reserved AS number.
		{"absent", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ASNString(tc.in))
		})
	}
}

// TestBGPNeighborsDecodesEitherAsnForm covers the third ASN field, on
// `show ip bgp neighbors`. Nothing reads it, but an unread field still gates
// the decode: mapstructure fills the whole struct, so the wrong type fails the
// entire command. That failure is quieter than the summary one, because
// bgpVrfs degrades to nil instead of erroring, and every peer silently loses
// its description and its inbound and outbound policies.
func TestBGPNeighborsDecodesEitherAsnForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		asn  any
	}{
		{"string, as EOS 4.34 sends it", "65002"},
		{"number, as older releases send it", float64(65002)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"vrfs": map[string]any{
					"default": map[string]any{
						"peerList": []any{map[string]any{
							"peerAddress":      "10.1.1.2",
							"description":      "EBGP-PEER",
							"asn":              tc.asn,
							"inboundRouteMap":  "IMPORT",
							"outboundRouteMap": "EXPORT",
						}},
					},
				},
			}
			out := &showIPBgpNeighbors{}
			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: out})
			require.NoError(t, err)
			require.NoError(t, dec.Decode(payload), "a peer's description and policies are lost if this fails")

			peer := out.VRFs["default"].PeerList[0]
			assert.Equal(t, "65002", ASNString(peer.ASN))
			assert.Equal(t, "EBGP-PEER", peer.Description)
			assert.Equal(t, "IMPORT", peer.InboundRouteMap)
		})
	}
}
