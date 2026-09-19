// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// This file reads the configuration of the FRR daemons other than BGP: the
// interior gateway protocols OSPF, OSPFv3 and IS-IS, the BFD sessions that
// decide how fast a fabric reconverges, the policy based routing maps, and
// the segment routing and MPLS blocks.
//
// The authentication settings carry the security meaning here. An IGP
// without authentication accepts an adjacency from anything on the link,
// and a fabric that trusts its underlay trusts whatever the IGP installs.

package frr

import (
	"strings"
)

// OSPF is one `router ospf [vrf <name>]` or `router ospf6 [vrf <name>]`
// block.
type OSPF struct {
	// Version is 2 for `router ospf` and 3 for `router ospf6`.
	Version  int64
	VRF      string
	RouterID string
	// Areas holds one entry per area named by the block.
	Areas []OSPFArea
	// Networks holds `network <prefix> area <id>` statements.
	Networks []OSPFNetwork
	// PassiveInterfaceDefault reports `passive-interface default`, which
	// keeps the protocol quiet on every interface that does not opt in.
	PassiveInterfaceDefault bool
	// PassiveInterfaces holds the interfaces named by `passive-interface`.
	PassiveInterfaces []string
	// NoPassiveInterfaces holds the interfaces exempted with
	// `no passive-interface`, which matters when the default is passive.
	NoPassiveInterfaces []string
	// Redistribute holds every `redistribute <source>` statement.
	Redistribute []string
	// DefaultInformationOriginate reports whether the router originates a
	// default route into the protocol.
	DefaultInformationOriginate bool
	// LogAdjacencyChanges reports the logging of adjacency changes, which is
	// what makes a flapping neighbor visible.
	LogAdjacencyChanges bool
	// MaxMetricRouterLsa reports the stub router setting.
	MaxMetricRouterLsa string
	Params             map[string]string
	File               string
	StartLine          int
	Raw                string
}

// OSPFArea is one area of an OSPF instance.
type OSPFArea struct {
	// ID is the area identifier, in dotted or numeric form.
	ID string
	// Authentication is the area authentication mode, empty when the area
	// takes none. `message-digest` is the authenticated mode.
	Authentication string
	// Type is stub, nssa or empty for a normal area.
	Type string
	// NoSummary marks a totally stubby area.
	NoSummary bool
	// Ranges holds the `area <id> range <prefix>` statements.
	Ranges []string
	// FilterLists holds the `area <id> filter-list prefix <name> in|out`
	// statements, which is how an area boundary filters.
	FilterLists []string
	// VirtualLinks holds the `area <id> virtual-link <addr>` statements.
	VirtualLinks []string
}

// OSPFNetwork is one `network <prefix> area <id>` statement.
type OSPFNetwork struct {
	Prefix string
	Area   string
}

// ISIS is one `router isis <tag> [vrf <name>]` block.
type ISIS struct {
	// Tag is the instance tag, which the interfaces refer to.
	Tag string
	VRF string
	// Net is the network entity title of the instance.
	Net string
	// IsType is level-1, level-2-only or level-1-2.
	IsType string
	// MetricStyle is narrow, wide or transition.
	MetricStyle string
	// AreaPassword and DomainPassword report whether a password is set, and
	// how it is sent. The value itself is not exposed.
	AreaPasswordSet    bool
	AreaPasswordMode   string
	DomainPasswordSet  bool
	DomainPasswordMode string
	// AuthenticationMode is the `isis authentication` mode of the instance.
	AuthenticationMode string
	// Redistribute holds every `redistribute <source>` statement.
	Redistribute []string
	// LogAdjacencyChanges reports the logging of adjacency changes.
	LogAdjacencyChanges bool
	Params              map[string]string
	File                string
	StartLine           int
	Raw                 string
}

// BFDPeer is one `peer` or `profile` block of the `bfd` block. BFD decides
// how fast the fabric drops a dead neighbor, so its timers set the
// reconvergence time.
type BFDPeer struct {
	// Kind is peer or profile.
	Kind string
	// Name is the peer address or the profile name.
	Name string
	// Interface, LocalAddress, VRF and MultiHop qualify a peer.
	Interface    string
	LocalAddress string
	VRF          string
	MultiHop     bool
	Profile      string
	// DetectMultiplier, ReceiveInterval and TransmitInterval are the timers.
	// They are -1 when the block leaves them at the default.
	DetectMultiplier int64
	ReceiveInterval  int64
	TransmitInterval int64
	EchoMode         bool
	EchoInterval     int64
	PassiveMode      bool
	Shutdown         bool
	MinimumTTL       int64
	Params           map[string]string
	File             string
	StartLine        int
	Raw              string
}

// PBRMap is one `pbr-map <name> seq <n>` block. Policy based routing sends
// selected traffic to another table or VRF, so it can move traffic across a
// tenant boundary without a route.
type PBRMap struct {
	Name  string
	Rules []PBRRule
	File  string
	Line  int
}

// PBRRule is one sequence of a policy based routing map.
type PBRRule struct {
	Sequence int64
	// Matches holds the `match` statements without the leading keyword.
	Matches []string
	// SourcePrefix, DestPrefix, SourcePort, DestPort and Protocol are the
	// match statements read into fields.
	SourcePrefix string
	DestPrefix   string
	SourcePort   string
	DestPort     string
	Protocol     string
	DSCP         string
	// Nexthop, NexthopVRF and Table are the action of the rule.
	Nexthop    string
	NexthopVRF string
	Table      int64
	// VRFUnchanged marks a rule that keeps the VRF of the packet.
	VRFUnchanged bool
	File         string
	StartLine    int
	Raw          string
}

// SegmentRouting is the `segment-routing` block, which carries the SRv6
// locators of the node when the daemon set uses them.
type SegmentRouting struct {
	// SRv6Locators holds the locators declared under `srv6 locators`.
	SRv6Locators []SRv6Locator
	// MPLS reports whether the block enables the MPLS data plane.
	MPLSEnabled bool
	Params      map[string]string
	File        string
	StartLine   int
	Raw         string
}

// SRv6Locator is one locator of the segment routing block.
type SRv6Locator struct {
	Name   string
	Prefix string
	Params map[string]string
}

// OSPFInstances builds the typed view of every `router ospf` and
// `router ospf6` block.
func (c *Config) OSPFInstances() []OSPF {
	var out []OSPF
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		var version int64
		switch blk.Type {
		case "router ospf":
			version = 2
		case "router ospf6":
			version = 3
		default:
			continue
		}
		out = append(out, buildOSPF(blk, version))
	}
	return out
}

func buildOSPF(blk *Block, version int64) OSPF {
	o := OSPF{
		Version:   version,
		VRF:       argAfter(blk.Args, "vrf"),
		Params:    map[string]string{},
		File:      blk.File,
		StartLine: blk.StartLine,
		Raw:       blk.Raw,
	}

	areas := map[string]*OSPFArea{}
	var areaOrder []string
	area := func(id string) *OSPFArea {
		if a, ok := areas[id]; ok {
			return a
		}
		a := &OSPFArea{ID: id}
		areas[id] = a
		areaOrder = append(areaOrder, id)
		return a
	}

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "ospf", "ospf6":
			// `ospf router-id <id>` on both versions.
			if len(d.Args) >= 2 && d.Args[0] == "router-id" {
				o.RouterID = d.Args[1]
				continue
			}
			o.Params[directiveKey(d)] = directiveValue(d)
		case "router-id":
			if len(d.Args) > 0 {
				o.RouterID = d.Args[0]
			}
		case "network":
			// `network <prefix> area <id>`
			if len(d.Args) >= 3 && d.Args[1] == "area" {
				o.Networks = append(o.Networks, OSPFNetwork{Prefix: d.Args[0], Area: d.Args[2]})
				area(d.Args[2])
				continue
			}
			if len(d.Args) > 0 {
				o.Networks = append(o.Networks, OSPFNetwork{Prefix: d.Args[0]})
			}
		case "area":
			applyOSPFArea(area, d)
		case "passive-interface":
			if len(d.Args) == 0 {
				continue
			}
			if d.Args[0] == "default" {
				o.PassiveInterfaceDefault = !d.Negated
				continue
			}
			if d.Negated {
				o.NoPassiveInterfaces = append(o.NoPassiveInterfaces, d.Args[0])
			} else {
				o.PassiveInterfaces = append(o.PassiveInterfaces, d.Args[0])
			}
		case "redistribute":
			if len(d.Args) > 0 {
				o.Redistribute = append(o.Redistribute, strings.Join(d.Args, " "))
			}
		case "default-information":
			if len(d.Args) > 0 && d.Args[0] == "originate" {
				o.DefaultInformationOriginate = !d.Negated
			}
		case "log-adjacency-changes":
			o.LogAdjacencyChanges = !d.Negated
		case "max-metric":
			if len(d.Args) >= 2 && d.Args[0] == "router-lsa" {
				o.MaxMetricRouterLsa = strings.Join(d.Args[1:], " ")
			}
		default:
			o.Params[directiveKey(d)] = directiveValue(d)
		}
	}

	for _, id := range areaOrder {
		o.Areas = append(o.Areas, *areas[id])
	}
	return o
}

// applyOSPFArea folds one `area <id> ...` statement into its area.
func applyOSPFArea(area func(string) *OSPFArea, d *Directive) {
	if len(d.Args) < 2 {
		return
	}
	a := area(d.Args[0])
	rest := d.Args[1:]

	switch rest[0] {
	case "authentication":
		if len(rest) > 1 {
			a.Authentication = strings.Join(rest[1:], " ")
		} else {
			a.Authentication = "simple"
		}
	case "stub":
		a.Type = "stub"
		if len(rest) > 1 && rest[1] == "no-summary" {
			a.NoSummary = true
		}
	case "nssa":
		a.Type = "nssa"
		if len(rest) > 1 && rest[1] == "no-summary" {
			a.NoSummary = true
		}
	case "range":
		if len(rest) > 1 {
			a.Ranges = append(a.Ranges, strings.Join(rest[1:], " "))
		}
	case "filter-list":
		a.FilterLists = append(a.FilterLists, strings.Join(rest[1:], " "))
	case "virtual-link":
		if len(rest) > 1 {
			a.VirtualLinks = append(a.VirtualLinks, rest[1])
		}
	}
}

// ISISInstances builds the typed view of every `router isis` block.
func (c *Config) ISISInstances() []ISIS {
	var out []ISIS
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "router isis" {
			continue
		}
		out = append(out, buildISIS(blk))
	}
	return out
}

func buildISIS(blk *Block) ISIS {
	s := ISIS{
		Tag:       blk.Name,
		VRF:       argAfter(blk.Args, "vrf"),
		Params:    map[string]string{},
		File:      blk.File,
		StartLine: blk.StartLine,
		Raw:       blk.Raw,
	}

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "net":
			if len(d.Args) > 0 {
				s.Net = d.Args[0]
			}
		case "is-type":
			if len(d.Args) > 0 {
				s.IsType = d.Args[0]
			}
		case "metric-style":
			if len(d.Args) > 0 {
				s.MetricStyle = d.Args[0]
			}
		case "area-password":
			s.AreaPasswordSet = !d.Negated
			if len(d.Args) > 0 {
				s.AreaPasswordMode = d.Args[0]
			}
		case "domain-password":
			s.DomainPasswordSet = !d.Negated
			if len(d.Args) > 0 {
				s.DomainPasswordMode = d.Args[0]
			}
		case "isis":
			// `isis authentication <mode>` inside the instance.
			if len(d.Args) >= 2 && d.Args[0] == "authentication" {
				s.AuthenticationMode = strings.Join(d.Args[1:], " ")
				continue
			}
			s.Params[directiveKey(d)] = directiveValue(d)
		case "redistribute":
			if len(d.Args) > 0 {
				s.Redistribute = append(s.Redistribute, strings.Join(d.Args, " "))
			}
		case "log-adjacency-changes":
			s.LogAdjacencyChanges = !d.Negated
		default:
			s.Params[directiveKey(d)] = directiveValue(d)
		}
	}
	return s
}

// BFDPeers builds the typed view of the `bfd` block, with one entry per peer
// and per profile.
func (c *Config) BFDPeers() []BFDPeer {
	var out []BFDPeer
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "bfd" {
			continue
		}
		for j := range blk.Blocks {
			sub := &blk.Blocks[j]
			if sub.Type != "peer" && sub.Type != "profile" {
				continue
			}
			out = append(out, buildBFDPeer(sub))
		}
	}
	return out
}

func buildBFDPeer(blk *Block) BFDPeer {
	p := BFDPeer{
		Kind:             blk.Type,
		Name:             blk.Name,
		Interface:        argAfter(blk.Args, "interface"),
		LocalAddress:     argAfter(blk.Args, "local-address"),
		VRF:              argAfter(blk.Args, "vrf"),
		DetectMultiplier: -1,
		ReceiveInterval:  -1,
		TransmitInterval: -1,
		EchoInterval:     -1,
		MinimumTTL:       -1,
		Params:           map[string]string{},
		File:             blk.File,
		StartLine:        blk.StartLine,
		Raw:              blk.Raw,
	}
	for _, arg := range blk.Args {
		if arg == "multihop" {
			p.MultiHop = true
		}
	}

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "detect-multiplier":
			if len(d.Args) > 0 {
				p.DetectMultiplier = parseInt(d.Args[0], -1)
			}
		case "receive-interval":
			if len(d.Args) > 0 {
				p.ReceiveInterval = parseInt(d.Args[0], -1)
			}
		case "transmit-interval":
			if len(d.Args) > 0 {
				p.TransmitInterval = parseInt(d.Args[0], -1)
			}
		case "echo-interval", "echo":
			if len(d.Args) == 0 {
				p.EchoMode = !d.Negated
				continue
			}
			switch d.Args[0] {
			case "mode":
				p.EchoMode = !d.Negated
			case "receive-interval", "transmit-interval":
				if len(d.Args) > 1 {
					p.EchoInterval = parseInt(d.Args[1], -1)
				}
			default:
				p.EchoInterval = parseInt(d.Args[0], -1)
			}
		case "echo-mode":
			p.EchoMode = !d.Negated
		case "passive-mode":
			p.PassiveMode = !d.Negated
		case "shutdown":
			p.Shutdown = !d.Negated
		case "minimum-ttl":
			if len(d.Args) > 0 {
				p.MinimumTTL = parseInt(d.Args[0], -1)
			}
		case "profile":
			if len(d.Args) > 0 {
				p.Profile = d.Args[0]
			}
		default:
			p.Params[directiveKey(d)] = directiveValue(d)
		}
	}
	return p
}

// PBRMaps groups every `pbr-map <name> seq <n>` block by name, in first-seen
// order.
func (c *Config) PBRMaps() []PBRMap {
	var order []string
	byName := map[string]*PBRMap{}

	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "pbr-map" {
			continue
		}
		m, ok := byName[blk.Name]
		if !ok {
			m = &PBRMap{Name: blk.Name, File: blk.File, Line: blk.StartLine}
			byName[blk.Name] = m
			order = append(order, blk.Name)
		}
		m.Rules = append(m.Rules, buildPBRRule(blk))
	}

	out := make([]PBRMap, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

func buildPBRRule(blk *Block) PBRRule {
	r := PBRRule{
		Sequence:  parseInt(argAfter(blk.Args, "seq"), 0),
		Table:     -1,
		File:      blk.File,
		StartLine: blk.StartLine,
		Raw:       blk.Raw,
	}

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "match":
			if len(d.Args) == 0 {
				continue
			}
			r.Matches = append(r.Matches, strings.Join(d.Args, " "))
			if len(d.Args) < 2 {
				continue
			}
			switch d.Args[0] {
			case "src-ip":
				r.SourcePrefix = d.Args[1]
			case "dst-ip":
				r.DestPrefix = d.Args[1]
			case "src-port":
				r.SourcePort = d.Args[1]
			case "dst-port":
				r.DestPort = d.Args[1]
			case "ip-protocol":
				r.Protocol = d.Args[1]
			case "dscp", "mark":
				r.DSCP = d.Args[1]
			}
		case "set":
			if len(d.Args) < 2 {
				if len(d.Args) == 1 && d.Args[0] == "vrf-unchanged" {
					r.VRFUnchanged = true
				}
				continue
			}
			switch d.Args[0] {
			case "nexthop":
				r.Nexthop = d.Args[1]
				if v := argAfter(d.Args, "nexthop-vrf"); v != "" {
					r.NexthopVRF = v
				}
			case "vrf":
				if d.Args[1] == "unchanged" {
					r.VRFUnchanged = true
				} else {
					r.NexthopVRF = d.Args[1]
				}
			case "table":
				r.Table = parseInt(d.Args[1], -1)
			case "nexthop-group":
				r.Nexthop = d.Args[1]
			}
		}
	}
	return r
}

// SegmentRoutingBlock builds the typed view of the `segment-routing` block.
// It returns false when the configuration has none.
func (c *Config) SegmentRoutingBlock() (SegmentRouting, bool) {
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "segment-routing" {
			continue
		}
		return buildSegmentRouting(blk), true
	}
	return SegmentRouting{}, false
}

func buildSegmentRouting(blk *Block) SegmentRouting {
	sr := SegmentRouting{
		Params:    map[string]string{},
		File:      blk.File,
		StartLine: blk.StartLine,
		Raw:       blk.Raw,
	}

	for i := range blk.Directives {
		d := &blk.Directives[i]
		if d.Name == "mpls" || (d.Name == "srv6" && len(d.Args) == 0) {
			sr.MPLSEnabled = sr.MPLSEnabled || d.Name == "mpls"
			continue
		}
		sr.Params[directiveKey(d)] = directiveValue(d)
	}

	// The locators sit in nested blocks: `srv6` then `locators` then one
	// block per locator.
	var walk func(b *Block)
	walk = func(b *Block) {
		for i := range b.Blocks {
			sub := &b.Blocks[i]
			if sub.Type == "locator" {
				loc := SRv6Locator{Name: sub.Name, Params: map[string]string{}}
				for j := range sub.Directives {
					d := &sub.Directives[j]
					if d.Name == "prefix" && len(d.Args) > 0 {
						loc.Prefix = d.Args[0]
						continue
					}
					loc.Params[directiveKey(d)] = directiveValue(d)
				}
				sr.SRv6Locators = append(sr.SRv6Locators, loc)
				continue
			}
			walk(sub)
		}
	}
	walk(blk)

	return sr
}

// InterfaceProtocols holds the routing protocol settings of one interface
// block. An interface that carries an IGP without authentication accepts an
// adjacency from anything on the link.
type InterfaceProtocols struct {
	// OSPFArea is the area of `ip ospf area <id>`.
	OSPFArea string
	// OSPFAuthentication is the mode of `ip ospf authentication`, empty when
	// the interface takes none.
	OSPFAuthentication string
	// OSPFAuthenticationKeySet reports a configured key without exposing it.
	OSPFAuthenticationKeySet bool
	// OSPFMessageDigestKeySet reports a configured message digest key.
	OSPFMessageDigestKeySet bool
	// OSPFCost, OSPFPriority, OSPFHelloInterval and OSPFDeadInterval are the
	// timers and metrics. They are -1 when the interface leaves them at the
	// default.
	OSPFCost          int64
	OSPFPriority      int64
	OSPFHelloInterval int64
	OSPFDeadInterval  int64
	// OSPFNetworkType is the network type, for example point-to-point.
	OSPFNetworkType string
	// OSPFPassive reports `ip ospf passive`.
	OSPFPassive bool
	// ISISTag is the instance of `ip router isis <tag>`.
	ISISTag string
	// ISISPasswordSet and ISISAuthenticationMode report the link
	// authentication of IS-IS.
	ISISPasswordSet        bool
	ISISAuthenticationMode string
	// ISISNetworkType is the network type of the IS-IS link.
	ISISNetworkType string
	// ISISCircuitType is level-1, level-2-only or level-1-2.
	ISISCircuitType string
	// PIMEnabled and IGMPEnabled report multicast on the interface.
	PIMEnabled  bool
	IGMPEnabled bool
	// BFDEnabled reports a BFD session on the interface.
	BFDEnabled bool
}

// newInterfaceProtocols returns the settings with the numeric fields at -1.
func newInterfaceProtocols() InterfaceProtocols {
	return InterfaceProtocols{
		OSPFCost:          -1,
		OSPFPriority:      -1,
		OSPFHelloInterval: -1,
		OSPFDeadInterval:  -1,
	}
}

// parseInterfaceProtocols reads the protocol statements of one interface
// block.
func parseInterfaceProtocols(dirs []Directive) InterfaceProtocols {
	p := newInterfaceProtocols()

	for i := range dirs {
		d := &dirs[i]
		switch d.Name {
		case "ip", "ipv6":
			if len(d.Args) == 0 {
				continue
			}
			switch d.Args[0] {
			case "ospf", "ospf6":
				applyOSPFInterface(&p, d.Args[1:], d.Negated)
			case "router":
				// `ip router isis <tag>` or `ipv6 router isis <tag>`
				if len(d.Args) >= 3 && d.Args[1] == "isis" {
					p.ISISTag = d.Args[2]
				}
			case "pim":
				// `ip pim` on its own enables the protocol, and a following
				// word only tunes it.
				p.PIMEnabled = !d.Negated
			case "igmp":
				p.IGMPEnabled = !d.Negated
			}
		case "isis":
			applyISISInterface(&p, d.Args, d.Negated)
		case "bfd":
			p.BFDEnabled = !d.Negated
		}
	}
	return p
}

func applyOSPFInterface(p *InterfaceProtocols, args []string, negated bool) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "area":
		if len(args) > 1 {
			p.OSPFArea = args[1]
		}
	case "authentication":
		if len(args) > 1 {
			if args[1] == "key-chain" || args[1] == "null" {
				p.OSPFAuthentication = args[1]
			} else {
				p.OSPFAuthentication = strings.Join(args[1:], " ")
			}
		} else {
			p.OSPFAuthentication = "simple"
		}
	case "authentication-key":
		p.OSPFAuthenticationKeySet = !negated
	case "message-digest-key":
		p.OSPFMessageDigestKeySet = !negated
	case "cost":
		if len(args) > 1 {
			p.OSPFCost = parseInt(args[1], -1)
		}
	case "priority":
		if len(args) > 1 {
			p.OSPFPriority = parseInt(args[1], -1)
		}
	case "hello-interval":
		if len(args) > 1 {
			p.OSPFHelloInterval = parseInt(args[1], -1)
		}
	case "dead-interval":
		if len(args) > 1 {
			p.OSPFDeadInterval = parseInt(args[1], -1)
		}
	case "network":
		if len(args) > 1 {
			p.OSPFNetworkType = strings.Join(args[1:], " ")
		}
	case "passive":
		p.OSPFPassive = !negated
	}
}

func applyISISInterface(p *InterfaceProtocols, args []string, negated bool) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "password":
		p.ISISPasswordSet = !negated
	case "authentication":
		if len(args) > 1 {
			p.ISISAuthenticationMode = strings.Join(args[1:], " ")
		}
	case "network":
		if len(args) > 1 {
			p.ISISNetworkType = strings.Join(args[1:], " ")
		}
	case "circuit-type":
		if len(args) > 1 {
			p.ISISCircuitType = args[1]
		}
	}
}

// LogTarget is one `log <target>` line of the configuration.
type LogTarget struct {
	// Target is file, syslog, stdout, monitor or commands.
	Target string
	// Destination is the file path of a file target.
	Destination string
	// Level is the severity, empty when the line omits it.
	Level string
	Raw   string
}

// Service holds the daemon-wide settings that are not routing: the log
// targets, the shell passwords, and the SNMP agent.
type Service struct {
	LogTargets []LogTarget
	// PasswordSet and EnablePasswordSet report a configured shell password
	// without exposing it.
	PasswordSet       bool
	EnablePasswordSet bool
	// AgentxEnabled reports the SNMP AgentX socket, which exposes the
	// routing state to an SNMP master.
	AgentxEnabled bool
	// IntegratedVtyshConfig reports `service integrated-vtysh-config`.
	IntegratedVtyshConfig bool
	// AdvancedVty reports `service advanced-vty`, which drops the enable
	// mode barrier.
	AdvancedVty bool
	// LogCommands reports `log commands`, which records every command.
	LogCommands bool
	// Users holds the local shell users of the configuration.
	Users []VtyshUser
}

// ServiceSettings reads the daemon-wide settings of the configuration.
func (c *Config) ServiceSettings() Service {
	s := Service{Users: c.VtyshUsers()}

	for i := range c.Directives {
		d := &c.Directives[i]
		switch d.Name {
		case "log":
			if len(d.Args) == 0 {
				continue
			}
			t := LogTarget{Target: d.Args[0], Raw: d.Raw}
			switch d.Args[0] {
			case "file":
				if len(d.Args) > 1 {
					t.Destination = d.Args[1]
				}
				if len(d.Args) > 2 {
					t.Level = d.Args[2]
				}
			case "commands":
				// `log commands` records what an operator typed. It is a
				// setting, not a destination.
				s.LogCommands = !d.Negated
				continue
			default:
				if len(d.Args) > 1 {
					t.Level = d.Args[1]
				}
			}
			s.LogTargets = append(s.LogTargets, t)
		case "password":
			s.PasswordSet = !d.Negated
		case "enable":
			if len(d.Args) > 0 && d.Args[0] == "password" {
				s.EnablePasswordSet = !d.Negated
			}
		case "agentx":
			s.AgentxEnabled = !d.Negated
		case "service":
			if len(d.Args) == 0 {
				continue
			}
			switch d.Args[0] {
			case "integrated-vtysh-config":
				s.IntegratedVtyshConfig = !d.Negated
			case "advanced-vty":
				s.AdvancedVty = !d.Negated
			}
		}
	}
	return s
}

// LogTargetsAsDicts renders log targets as plain maps.
func LogTargetsAsDicts(targets []LogTarget) []any {
	out := make([]any, 0, len(targets))
	for i := range targets {
		t := &targets[i]
		out = append(out, map[string]any{
			"target":      t.Target,
			"destination": t.Destination,
			"level":       t.Level,
			"raw":         t.Raw,
		})
	}
	return out
}

// PBRRulesAsDicts renders the rules of a policy based routing map as plain
// maps.
func PBRRulesAsDicts(rules []PBRRule) []any {
	out := make([]any, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		out = append(out, map[string]any{
			"sequence":     r.Sequence,
			"matches":      toAnySlice(r.Matches),
			"sourcePrefix": r.SourcePrefix,
			"destPrefix":   r.DestPrefix,
			"sourcePort":   r.SourcePort,
			"destPort":     r.DestPort,
			"protocol":     r.Protocol,
			"dscp":         r.DSCP,
			"nexthop":      r.Nexthop,
			"nexthopVrf":   r.NexthopVRF,
			"table":        r.Table,
			"vrfUnchanged": r.VRFUnchanged,
			"startLine":    int64(r.StartLine),
			"raw":          r.Raw,
		})
	}
	return out
}

// OSPFAreasAsDicts renders the areas of an OSPF instance as plain maps.
func OSPFAreasAsDicts(areas []OSPFArea) []any {
	out := make([]any, 0, len(areas))
	for i := range areas {
		a := &areas[i]
		out = append(out, map[string]any{
			"id":             a.ID,
			"authentication": a.Authentication,
			"type":           a.Type,
			"noSummary":      a.NoSummary,
			"ranges":         toAnySlice(a.Ranges),
			"filterLists":    toAnySlice(a.FilterLists),
			"virtualLinks":   toAnySlice(a.VirtualLinks),
		})
	}
	return out
}

// OSPFNetworksAsDicts renders the networks of an OSPF instance as plain maps.
func OSPFNetworksAsDicts(networks []OSPFNetwork) []any {
	out := make([]any, 0, len(networks))
	for i := range networks {
		n := &networks[i]
		out = append(out, map[string]any{
			"prefix": n.Prefix,
			"area":   n.Area,
		})
	}
	return out
}

// SRv6LocatorsAsDicts renders the locators of the segment routing block as
// plain maps.
func SRv6LocatorsAsDicts(locators []SRv6Locator) []any {
	out := make([]any, 0, len(locators))
	for i := range locators {
		l := &locators[i]
		out = append(out, map[string]any{
			"name":   l.Name,
			"prefix": l.Prefix,
			"params": stringMapToAnyMap(l.Params),
		})
	}
	return out
}

func stringMapToAnyMap(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
