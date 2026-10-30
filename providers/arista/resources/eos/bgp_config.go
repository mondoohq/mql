// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strings"
)

// BgpNeighborConfig is the configured security posture of one BGP neighbor.
//
//	router bgp 65001
//	   bgp log-neighbor-changes
//	   neighbor 10.1.1.2 remote-as 65002
//	   neighbor 10.1.1.2 password 7 042B0F1C
//	   neighbor 10.1.1.2 ttl maximum-hops 1
//	   neighbor 10.1.1.2 maximum-routes 12000
//	   vrf PROD
//	      neighbor 10.100.1.2 remote-as 65099
//
// The operational view of a session says whether it is up; it does not say
// whether it is protected. These are the three controls that decide that:
// a session password authenticates the peer, a TTL hop limit makes the
// session unreachable from more than that many hops away, and a route maximum
// bounds the damage a peer can do by announcing more prefixes than it should.
type BgpNeighborConfig struct {
	// VRF is the routing instance the neighbor is configured in. The
	// unnamed instance is reported as "default", matching how the device
	// names it operationally.
	VRF         string
	PeerAddress string
	// PasswordConfigured reports whether the session is authenticated. The
	// password itself is never captured.
	PasswordConfigured bool
	// PasswordEncryptionType is how the session password is stored, "0"
	// for cleartext or "7" for the reversible obfuscation. Empty when no
	// password is configured.
	PasswordEncryptionType string
	// TtlMaximumHops bounds how far away the peer may be (0 = unset).
	TtlMaximumHops int
	// MaximumRoutes caps the prefixes accepted from the peer (0 = unset,
	// meaning no limit).
	MaximumRoutes int
	// Shutdown reports a neighbor configured but administratively down.
	// Only the positive form is read, so this cannot distinguish a session
	// that says nothing from one explicitly brought up with `no shutdown`.
	Shutdown bool
	// UpdateSource is the interface sourcing the session.
	UpdateSource string
	// EbgpMultihop is the configured multihop limit (0 = unset).
	EbgpMultihop int
	// InboundRouteMap and OutboundRouteMap are the policies applied to
	// routes received from and advertised to the peer.
	InboundRouteMap  string
	OutboundRouteMap string
	// PeerGroup is the peer group the session takes its settings from, empty
	// when the session is configured on its own. A fabric is normally built
	// by configuring the controls once on a group and pointing every session
	// at it, so reading only the session's own lines reports every member as
	// unprotected.
	PeerGroup string
	// IsPeerGroup marks an entry that defines a group rather than a session.
	// It carries the group's settings and is not itself a peer.
	IsPeerGroup bool
}

// BgpGlobalConfig is the configured BGP state, keyed by neighbor.
type BgpGlobalConfig struct {
	// LogNeighborChanges reports whether session transitions are logged,
	// which is what makes a flapping or hijacked session visible after
	// the fact.
	LogNeighborChanges bool
	Neighbors          []BgpNeighborConfig
}

// ParseBgpConfig extracts the configured BGP neighbor settings from
// running-config, including those inside `vrf` sub-blocks.
func ParseBgpConfig(runningConfig string) *BgpGlobalConfig {
	cfg := &BgpGlobalConfig{Neighbors: []BgpNeighborConfig{}}

	// byKey lets the settings for one neighbor arrive across many lines.
	byKey := map[string]*BgpNeighborConfig{}
	order := []string{}

	inBgp := false
	vrf := "default"
	vrfIndent := -1

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		indent := CountLeadingSpace(raw)

		if indent == 0 {
			// Any other top-level line ends the router bgp block.
			inBgp = strings.HasPrefix(line, "router bgp ")
			vrf = "default"
			vrfIndent = -1
			continue
		}
		if !inBgp {
			continue
		}

		// A `vrf <name>` line opens a sub-block; anything at or above its
		// indentation closes it and returns to the unnamed instance.
		if vrfIndent >= 0 && indent <= vrfIndent {
			vrf = "default"
			vrfIndent = -1
		}
		if name, ok := strings.CutPrefix(line, "vrf "); ok {
			vrf = strings.TrimSpace(name)
			vrfIndent = indent
			continue
		}

		if line == "bgp log-neighbor-changes" {
			cfg.LogNeighborChanges = true
			continue
		}
		if line == "no bgp log-neighbor-changes" {
			cfg.LogNeighborChanges = false
			continue
		}

		rest, ok := strings.CutPrefix(line, "neighbor ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			continue
		}
		peer := fields[0]

		key := vrf + "/" + peer
		n, ok := byKey[key]
		if !ok {
			n = &BgpNeighborConfig{VRF: vrf, PeerAddress: peer}
			byKey[key] = n
			order = append(order, key)
		}
		applyBgpNeighborSetting(n, fields[1:])
	}

	for _, key := range order {
		n := byKey[key]
		if n.PeerGroup != "" {
			if group, ok := byKey[n.VRF+"/"+n.PeerGroup]; ok {
				inheritBgpGroupSettings(n, group)
			}
		}
		if n.IsPeerGroup {
			continue
		}
		cfg.Neighbors = append(cfg.Neighbors, *n)
	}
	return cfg
}

// inheritBgpGroupSettings folds a peer group's settings into one of its
// members. A setting written on the session itself wins; everything the
// session does not set comes from the group, which is where a fabric
// normally configures the controls exactly once.
func inheritBgpGroupSettings(n, group *BgpNeighborConfig) {
	if !n.PasswordConfigured && group.PasswordConfigured {
		n.PasswordConfigured = true
		n.PasswordEncryptionType = group.PasswordEncryptionType
	}
	if n.TtlMaximumHops == 0 {
		n.TtlMaximumHops = group.TtlMaximumHops
	}
	if n.MaximumRoutes == 0 {
		n.MaximumRoutes = group.MaximumRoutes
	}
	if n.EbgpMultihop == 0 {
		n.EbgpMultihop = group.EbgpMultihop
	}
	if n.UpdateSource == "" {
		n.UpdateSource = group.UpdateSource
	}
	if n.InboundRouteMap == "" {
		n.InboundRouteMap = group.InboundRouteMap
	}
	if n.OutboundRouteMap == "" {
		n.OutboundRouteMap = group.OutboundRouteMap
	}
	// Shutdown inherits one way only. `applyBgpNeighborSetting` recognizes
	// `shutdown` but not `no shutdown` — the parser skips `no ` lines
	// wholesale — so there is no value a member could carry that means
	// "explicitly up", and a member that re-enables itself under a
	// shut-down group is reported as down. That is a false "neighbor
	// administratively down", not a missed control, so it is the safe
	// direction to be wrong in. Teaching the parser `no ` prefixes would
	// make Shutdown tri-state, and this branch has to become "the member
	// said nothing" rather than "the member is not shut down".
	if !n.Shutdown && group.Shutdown {
		n.Shutdown = true
	}
}

// applyBgpNeighborSetting folds one `neighbor <peer> ...` line into the
// neighbor's configuration. Lines this does not recognize (activation,
// address-family settings, community propagation) are left alone.
func applyBgpNeighborSetting(n *BgpNeighborConfig, fields []string) {
	switch fields[0] {
	case "password":
		n.PasswordConfigured, n.PasswordEncryptionType = parseKeyClause(fields[1:])

	case "shutdown":
		n.Shutdown = true

	case "update-source":
		if len(fields) > 1 {
			n.UpdateSource = fields[1]
		}

	case "maximum-routes":
		if len(fields) > 1 {
			n.MaximumRoutes = atoiOrZero(fields[1])
		}

	case "ebgp-multihop":
		if len(fields) > 1 {
			n.EbgpMultihop = atoiOrZero(fields[1])
		}

	case "ttl":
		// `neighbor <peer> ttl maximum-hops <n>`
		if len(fields) > 2 && fields[1] == "maximum-hops" {
			n.TtlMaximumHops = atoiOrZero(fields[2])
		}

	case "peer", "peer-group":
		// `neighbor <name> peer group` (or `peer-group`) defines a group;
		// `neighbor <addr> peer group <name>` puts a session in one.
		rest := fields[1:]
		if fields[0] == "peer" {
			if len(rest) == 0 || rest[0] != "group" {
				return
			}
			rest = rest[1:]
		}
		if len(rest) == 0 {
			n.IsPeerGroup = true
			return
		}
		n.PeerGroup = rest[0]

	case "route-map":
		// `neighbor <peer> route-map <name> in|out`
		if len(fields) > 2 {
			switch fields[2] {
			case "in":
				n.InboundRouteMap = fields[1]
			case "out":
				n.OutboundRouteMap = fields[1]
			}
		}
	}
}
