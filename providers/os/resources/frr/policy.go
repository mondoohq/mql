// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// This file reads the policy objects of a configuration: static routes,
// community lists, access lists, AS path access lists, and the match and set
// clauses of a route map.
//
// These objects are what a router enforces. A route map decides which routes
// a session accepts or announces, and it does so by naming a prefix list, a
// community list or an access list, so the objects have to be readable as
// data rather than as text.

package frr

import (
	"net"
	"strconv"
	"strings"
)

// StaticRoute is one `ip route` or `ipv6 route` line, from the top level or
// from inside a VRF block.
type StaticRoute struct {
	// AFI is ipv4 or ipv6.
	AFI    string
	Prefix string
	// Nexthop is the next hop address, empty for an interface route or a
	// discard route.
	Nexthop string
	// Interface is the outgoing interface, empty when the route has a next
	// hop address.
	Interface string
	// VRF is the VRF the route belongs to. It is the name of the enclosing
	// vrf block, or the `vrf` argument of a top-level line.
	VRF string
	// NexthopVRF is the VRF the next hop is resolved in, which is how a
	// route leaks between VRFs.
	NexthopVRF string
	// Blackhole and Reject mark a discard route.
	Blackhole bool
	Reject    bool
	// Distance is the administrative distance, 0 when the line omits it.
	Distance int64
	// Table is the routing table of the route, 0 when the line omits it.
	Table int64
	// Tag is the route tag, 0 when the line omits it.
	Tag   int64
	Label string
	File  string
	Line  int
	Raw   string
}

// CommunityList groups the lines of one community list. FRR keeps three
// kinds, and a route map matches on the name of one of them.
type CommunityList struct {
	// Kind is community, large-community or extcommunity.
	Kind string
	// Type is standard or expanded. A standard list holds values, an
	// expanded list holds a regular expression.
	Type    string
	Name    string
	Entries []PolicyEntry
	File    string
	Line    int
}

// AccessList groups the lines of one access list.
type AccessList struct {
	// AFI is ipv4 or ipv6.
	AFI     string
	Name    string
	Entries []PolicyEntry
	File    string
	Line    int
}

// ASPathAccessList groups the lines of one AS path access list, which filters
// on the AS path with a regular expression.
type ASPathAccessList struct {
	Name    string
	Entries []PolicyEntry
	File    string
	Line    int
}

// PolicyEntry is one line of a community list, an access list or an AS path
// access list.
type PolicyEntry struct {
	// Seq is the sequence number, 0 when the line omits it.
	Seq int64
	// Action is permit or deny.
	Action string
	// Value is the rest of the line: a community value, a prefix, or a
	// regular expression.
	Value string
	Line  int
	Raw   string
}

// StaticRoutes returns every static route of the configuration, from the top
// level and from inside the VRF blocks.
func (c *Config) StaticRoutes() []StaticRoute {
	var out []StaticRoute

	for i := range c.Directives {
		d := &c.Directives[i]
		if r, ok := parseStaticRoute(d, ""); ok {
			out = append(out, r)
		}
	}

	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "vrf" {
			continue
		}
		for j := range blk.Directives {
			d := &blk.Directives[j]
			if r, ok := parseStaticRoute(d, blk.Name); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// parseStaticRoute reads one `ip route` or `ipv6 route` line. The token after
// the prefix is the next hop, which is an address, an interface, or a discard
// keyword. The rest are keyword arguments.
func parseStaticRoute(d *Directive, vrf string) (StaticRoute, bool) {
	if d.Name != "ip" && d.Name != "ipv6" {
		return StaticRoute{}, false
	}
	if len(d.Args) < 2 || d.Args[0] != "route" {
		return StaticRoute{}, false
	}

	r := StaticRoute{
		AFI:    afiOf(d.Name),
		Prefix: d.Args[1],
		VRF:    vrf,
		File:   d.File,
		Line:   d.Line,
		Raw:    d.Raw,
	}

	args := d.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "blackhole":
			r.Blackhole = true
		case "reject":
			r.Reject = true
		case "Null0", "null0":
			r.Blackhole = true
		case "nexthop-vrf":
			if i+1 < len(args) {
				r.NexthopVRF = args[i+1]
				i++
			}
		case "vrf":
			if i+1 < len(args) {
				// A top-level line can name its VRF. Inside a vrf block the
				// enclosing block wins.
				if r.VRF == "" {
					r.VRF = args[i+1]
				}
				i++
			}
		case "table":
			if i+1 < len(args) {
				r.Table, _ = strconv.ParseInt(args[i+1], 10, 64)
				i++
			}
		case "tag":
			if i+1 < len(args) {
				r.Tag, _ = strconv.ParseInt(args[i+1], 10, 64)
				i++
			}
		case "label":
			if i+1 < len(args) {
				r.Label = args[i+1]
				i++
			}
		case "onlink":
			// A bare flag with no field of its own.
		case "color":
			// `color` takes a numeric argument. Skipping it keeps the value
			// from being read as the administrative distance.
			if i+1 < len(args) {
				i++
			}
		default:
			// The first free token is the next hop, and a later free number
			// is the administrative distance.
			if r.Nexthop == "" && r.Interface == "" && !r.Blackhole && !r.Reject {
				if net.ParseIP(args[i]) != nil {
					r.Nexthop = args[i]
				} else {
					r.Interface = args[i]
				}
				continue
			}
			if v, err := strconv.ParseInt(args[i], 10, 64); err == nil && r.Distance == 0 {
				r.Distance = v
			}
		}
	}
	return r, true
}

func afiOf(keyword string) string {
	if keyword == "ipv6" {
		return "ipv6"
	}
	return "ipv4"
}

// CommunityLists groups every community list line by kind and name, in
// first-seen order.
func (c *Config) CommunityLists() []CommunityList {
	var order []string
	byKey := map[string]*CommunityList{}

	for i := range c.Directives {
		d := &c.Directives[i]
		kind, args, ok := communityListArgs(d)
		if !ok {
			continue
		}

		// `<kind> [standard|expanded] <name> <permit|deny> <value...>`
		listType := "standard"
		if len(args) > 0 && (args[0] == "standard" || args[0] == "expanded") {
			listType = args[0]
			args = args[1:]
		}
		if len(args) < 2 {
			continue
		}
		name := args[0]
		entry, ok := policyEntry(d, args[1:])
		if !ok {
			continue
		}

		// FRR keeps a standard and an expanded list of the same name apart.
		// One matches values, the other matches a regular expression, so
		// the type belongs in the key.
		key := kind + "/" + listType + "/" + name
		list, ok := byKey[key]
		if !ok {
			list = &CommunityList{Kind: kind, Type: listType, Name: name, File: d.File, Line: d.Line}
			byKey[key] = list
			order = append(order, key)
		}
		list.Entries = append(list.Entries, entry)
	}

	out := make([]CommunityList, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}

// communityListArgs recognizes the three community list keywords, with the
// `bgp` prefix of modern FRR and the legacy `ip` prefix.
func communityListArgs(d *Directive) (string, []string, bool) {
	kinds := map[string]string{
		"community-list":       "community",
		"large-community-list": "large-community",
		"extcommunity-list":    "extcommunity",
	}

	switch d.Name {
	case "bgp", "ip":
		if len(d.Args) < 2 {
			return "", nil, false
		}
		if kind, ok := kinds[d.Args[0]]; ok {
			return kind, d.Args[1:], true
		}
	default:
		if kind, ok := kinds[d.Name]; ok {
			return kind, d.Args, true
		}
	}
	return "", nil, false
}

// AccessLists groups every `access-list` and `ipv6 access-list` line by
// address family and name, in first-seen order.
func (c *Config) AccessLists() []AccessList {
	var order []string
	byKey := map[string]*AccessList{}

	for i := range c.Directives {
		d := &c.Directives[i]

		var afi string
		var args []string
		switch {
		case d.Name == "access-list":
			afi, args = "ipv4", d.Args
		case (d.Name == "ip" || d.Name == "ipv6") && len(d.Args) > 1 && d.Args[0] == "access-list":
			afi, args = afiOf(d.Name), d.Args[1:]
		default:
			continue
		}
		if len(args) < 2 {
			continue
		}

		name := args[0]
		entry, ok := policyEntry(d, args[1:])
		if !ok {
			continue
		}

		key := afi + "/" + name
		list, ok := byKey[key]
		if !ok {
			list = &AccessList{AFI: afi, Name: name, File: d.File, Line: d.Line}
			byKey[key] = list
			order = append(order, key)
		}
		list.Entries = append(list.Entries, entry)
	}

	out := make([]AccessList, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}

// ASPathAccessLists groups every `bgp as-path access-list` line by name.
func (c *Config) ASPathAccessLists() []ASPathAccessList {
	var order []string
	byName := map[string]*ASPathAccessList{}

	for i := range c.Directives {
		d := &c.Directives[i]
		if d.Name != "bgp" && d.Name != "ip" {
			continue
		}
		if len(d.Args) < 4 || d.Args[0] != "as-path" || d.Args[1] != "access-list" {
			continue
		}

		name := d.Args[2]
		entry, ok := policyEntry(d, d.Args[3:])
		if !ok {
			continue
		}

		list, ok := byName[name]
		if !ok {
			list = &ASPathAccessList{Name: name, File: d.File, Line: d.Line}
			byName[name] = list
			order = append(order, name)
		}
		list.Entries = append(list.Entries, entry)
	}

	out := make([]ASPathAccessList, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// policyEntry reads the `[seq <n>] <permit|deny> <value...>` tail that every
// list line shares.
func policyEntry(d *Directive, args []string) (PolicyEntry, bool) {
	e := PolicyEntry{Line: d.Line, Raw: d.Raw}

	if len(args) >= 2 && args[0] == "seq" {
		e.Seq, _ = strconv.ParseInt(args[1], 10, 64)
		args = args[2:]
	}
	if len(args) == 0 {
		return e, false
	}
	if args[0] != "permit" && args[0] != "deny" {
		return e, false
	}
	e.Action = args[0]
	e.Value = strings.Join(args[1:], " ")
	return e, true
}

// RouteMapClauses holds the match and set statements of one route map clause,
// read into the fields a policy asks about. The raw statements stay on the
// entry, so a statement without a field of its own is still readable.
type RouteMapClauses struct {
	MatchPrefixLists      []string
	MatchAccessLists      []string
	MatchCommunityLists   []string
	MatchLargeCommunities []string
	MatchExtCommunities   []string
	MatchAsPathLists      []string
	MatchSourceVRF        string
	MatchInterface        string
	MatchPeer             string
	MatchEvpnRouteType    string
	MatchEvpnVNI          int64
	MatchTag              int64
	MatchMetric           int64
	MatchLocalPreference  int64

	SetCommunities       []string
	SetCommunityAdditive bool
	SetCommunityNone     bool
	SetLargeCommunities  []string
	SetExtCommunities    []string
	SetCommunityDelete   string
	SetLocalPreference   int64
	SetMetric            string
	SetWeight            int64
	SetOrigin            string
	SetAsPathPrepend     []string
	SetAsPathExclude     []string
	SetNextHop           string
	SetSourceAddress     string
	SetTag               int64
	SetTable             int64
	SetDistance          int64
	SetAtomicAggregate   bool
}

// newRouteMapClauses returns the clauses with the numeric fields at -1, which
// is how an unset number is told apart from a configured zero.
func newRouteMapClauses() RouteMapClauses {
	return RouteMapClauses{
		MatchEvpnVNI:         -1,
		MatchTag:             -1,
		MatchMetric:          -1,
		MatchLocalPreference: -1,
		SetLocalPreference:   -1,
		SetWeight:            -1,
		SetTag:               -1,
		SetTable:             -1,
		SetDistance:          -1,
	}
}

// parseRouteMapClauses reads the match and set statements of one clause.
func parseRouteMapClauses(dirs []Directive) RouteMapClauses {
	c := newRouteMapClauses()

	for i := range dirs {
		d := &dirs[i]
		switch d.Name {
		case "match":
			c.applyMatch(d.Args)
		case "set":
			c.applySet(d.Args)
		}
	}
	return c
}

func (c *RouteMapClauses) applyMatch(args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "ip", "ipv6":
		// `match ip address prefix-list <name>` or `match ip address <acl>`.
		if len(args) >= 3 && args[1] == "address" {
			if args[2] == "prefix-list" && len(args) >= 4 {
				c.MatchPrefixLists = append(c.MatchPrefixLists, args[3])
			} else {
				c.MatchAccessLists = append(c.MatchAccessLists, args[2])
			}
			return
		}
		if len(args) >= 4 && args[1] == "next-hop" && args[2] == "prefix-list" {
			c.MatchPrefixLists = append(c.MatchPrefixLists, args[3])
		}
	case "community":
		if len(args) > 1 {
			c.MatchCommunityLists = append(c.MatchCommunityLists, args[1])
		}
	case "large-community":
		if len(args) > 1 {
			c.MatchLargeCommunities = append(c.MatchLargeCommunities, args[1])
		}
	case "extcommunity":
		if len(args) > 1 {
			c.MatchExtCommunities = append(c.MatchExtCommunities, args[1])
		}
	case "as-path":
		if len(args) > 1 {
			c.MatchAsPathLists = append(c.MatchAsPathLists, args[1])
		}
	case "source-vrf":
		if len(args) > 1 {
			c.MatchSourceVRF = args[1]
		}
	case "interface":
		if len(args) > 1 {
			c.MatchInterface = args[1]
		}
	case "peer":
		if len(args) > 1 {
			c.MatchPeer = args[1]
		}
	case "tag":
		if len(args) > 1 {
			c.MatchTag = parseInt(args[1], -1)
		}
	case "metric":
		if len(args) > 1 {
			c.MatchMetric = parseInt(args[1], -1)
		}
	case "local-preference":
		if len(args) > 1 {
			c.MatchLocalPreference = parseInt(args[1], -1)
		}
	case "evpn":
		if len(args) < 3 {
			return
		}
		switch args[1] {
		case "route-type":
			c.MatchEvpnRouteType = args[2]
		case "vni":
			c.MatchEvpnVNI = parseInt(args[2], -1)
		}
	}
}

func (c *RouteMapClauses) applySet(args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "community":
		values := args[1:]
		for _, v := range values {
			switch v {
			case "additive":
				c.SetCommunityAdditive = true
			case "none":
				c.SetCommunityNone = true
			default:
				c.SetCommunities = append(c.SetCommunities, v)
			}
		}
	case "large-community":
		c.SetLargeCommunities = append(c.SetLargeCommunities, args[1:]...)
	case "extcommunity":
		c.SetExtCommunities = append(c.SetExtCommunities, strings.Join(args[1:], " "))
	case "comm-list":
		// `set comm-list <name> delete`
		if len(args) > 1 {
			c.SetCommunityDelete = args[1]
		}
	case "local-preference":
		if len(args) > 1 {
			c.SetLocalPreference = parseInt(args[1], -1)
		}
	case "metric":
		if len(args) > 1 {
			c.SetMetric = args[1]
		}
	case "weight":
		if len(args) > 1 {
			c.SetWeight = parseInt(args[1], -1)
		}
	case "origin":
		if len(args) > 1 {
			c.SetOrigin = args[1]
		}
	case "as-path":
		if len(args) < 3 {
			return
		}
		switch args[1] {
		case "prepend":
			c.SetAsPathPrepend = append(c.SetAsPathPrepend, args[2:]...)
		case "exclude":
			c.SetAsPathExclude = append(c.SetAsPathExclude, args[2:]...)
		}
	case "ip", "ipv6", "ipv4":
		// `set ip next-hop <addr>`, `set ipv6 next-hop global <addr>` and
		// `set ipv4 vpn next-hop <addr>` all name a next hop.
		for i := 1; i < len(args); i++ {
			if args[i] == "next-hop" && i+1 < len(args) {
				value := args[i+1]
				if value == "global" || value == "local" || value == "peer-address" {
					if i+2 < len(args) {
						value = args[i+2]
					}
				}
				c.SetNextHop = value
				return
			}
		}
	case "src":
		if len(args) > 1 {
			c.SetSourceAddress = args[1]
		}
	case "tag":
		if len(args) > 1 {
			c.SetTag = parseInt(args[1], -1)
		}
	case "table":
		if len(args) > 1 {
			c.SetTable = parseInt(args[1], -1)
		}
	case "distance":
		if len(args) > 1 {
			c.SetDistance = parseInt(args[1], -1)
		}
	case "atomic-aggregate":
		c.SetAtomicAggregate = true
	}
}

func parseInt(s string, fallback int64) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}
