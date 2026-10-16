// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers/os/resources/frr"
)

func TestBFDPeerIDIncludesSessionIdentity(t *testing.T) {
	base := "frr/config"
	red := frr.BFDPeer{Kind: "peer", Name: "192.0.2.1", VRF: "RED", LocalAddress: "192.0.2.2", Interface: "eth0"}
	blue := red
	blue.VRF = "BLUE"
	if got, want := bfdPeerID(base, red), "frr/config/#bfd/peer/192.0.2.1/RED/192.0.2.2/eth0/false"; got != want {
		t.Fatalf("bfdPeerID() = %q, want %q", got, want)
	}
	if bfdPeerID(base, red) == bfdPeerID(base, blue) {
		t.Fatal("BFD peers in distinct VRFs must have distinct resource IDs")
	}
}
