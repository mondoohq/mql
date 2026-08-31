// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"sort"
	"strconv"
	"strings"
)

// BGP is one `router bgp <asn> [vrf <name>]` instance.
type BGP struct {
	ASN       int64
	VRF       string
	RouterID  string
	ClusterID string
	// EbgpRequiresPolicy reports whether eBGP sessions still need an inbound
	// and outbound policy. FRR enables it by default, so it is false only
	// when the config carries `no bgp ebgp-requires-policy`.
	EbgpRequiresPolicy bool
	// DefaultIPv4Unicast reports whether neighbors activate the IPv4 unicast
	// address family automatically. FRR enables it by default.
	DefaultIPv4Unicast bool
	Neighbors          []Neighbor
	AddressFamilies    []AddressFamily
	Params             map[string]string
	File               string
	StartLine          int
	Raw                string
}

// Neighbor is one BGP peer or peer group, merged from every `neighbor <name>
// ...` line in the router block and in its address families.
type Neighbor struct {
	Name string
	// Interface is true for an unnumbered peer configured with
	// `neighbor <ifname> interface remote-as <asn>`.
	Interface bool
	// IsPeerGroup is true when the name is declared with `neighbor <name>
	// peer-group`.
	IsPeerGroup bool
	// PeerGroup names the group this neighbor joins, if any.
	PeerGroup string
	// RemoteAs holds the raw value, which is a number or `internal` or
	// `external`.
	RemoteAs  string
	RemoteASN int64
	LocalASN  int64

	Description     string
	UpdateSource    string
	ListenRange     string
	BFD             bool
	Shutdown        bool
	PasswordSet     bool
	TTLSecurityHops int64
	KeepaliveTime   int64
	HoldTime        int64

	AddressFamilies []NeighborAddressFamily

	// The following lists roll up the per-address-family filters, so a policy
	// can ask whether a session is filtered at all without walking families.
	ActivatedAddressFamilies []string
	RouteMapsIn              []string
	RouteMapsOut             []string
	PrefixListsIn            []string
	PrefixListsOut           []string
	FilterListsIn            []string
	FilterListsOut           []string

	Params map[string]string
	File   string
	Line   int
}

// NeighborAddressFamily holds the settings a neighbor carries inside one
// address family of its router block.
type NeighborAddressFamily struct {
	AFI                  string
	SAFI                 string
	Activate             bool
	RouteMapIn           string
	RouteMapOut          string
	PrefixListIn         string
	PrefixListOut        string
	FilterListIn         string
	FilterListOut        string
	MaximumPrefix        int64
	RouteReflectorClient bool
	AllowasIn            bool
	NextHopSelf          bool
	SoftReconfiguration  bool
	DefaultOriginate     bool
	RemovePrivateAS      bool
}

// AddressFamily is one `address-family <afi> <safi>` block of a router.
type AddressFamily struct {
	AFI  string
	SAFI string
	// Networks holds every `network <prefix>` advertised in this family.
	Networks []string
	// Redistribute holds every `redistribute <source>` line.
	Redistribute []string
	// ImportVrfs holds the source VRFs of every `import vrf <name>` line.
	// `import vrf route-map <name>` goes to ImportVrfRouteMap instead.
	ImportVrfs        []string
	ImportVrfRouteMap string
	// RouteTargetsImport and RouteTargetsExport hold the EVPN route targets
	// of this family. They decide which VRF sees which routes, so they carry
	// the tenant separation of an EVPN fabric.
	RouteTargetsImport []string
	RouteTargetsExport []string
	// Advertise holds every `advertise <afi> <safi> [route-map <name>]` line.
	Advertise       []string
	AdvertiseAllVNI bool
	VNIs            []VNI
	Params          map[string]string
	File            string
	StartLine       int
	Raw             string
}

// VNI is a `vni <id>` block inside an EVPN address family.
type VNI struct {
	ID                 int64
	RouteTargetsImport []string
	RouteTargetsExport []string
}

// VRF is a `vrf <name>` block. RouteTargets, ImportedVrfs and RouterASN come
// from the `router bgp <asn> vrf <name>` instance that serves the VRF, so a
// single resource answers whether tenant VRFs stay separated.
type VRF struct {
	Name         string
	VNI          int64
	StaticRoutes []string
	Params       map[string]string
	File         string
	StartLine    int
	Raw          string

	RouterASN          int64
	RouteTargetsImport []string
	RouteTargetsExport []string
	ImportedVrfs       []string
}

// Interface is an `interface <name> [vrf <name>]` block.
type Interface struct {
	Name          string
	VRF           string
	Description   string
	IPAddresses   []string
	IPv6Addresses []string
	Shutdown      bool
	PBRPolicy     string
	// Protocols holds the routing protocol settings of the interface.
	Protocols InterfaceProtocols
	Params    map[string]string
	File      string
	StartLine int
	Raw       string
}

// PrefixList groups every `ip prefix-list <name> ...` line of one name.
type PrefixList struct {
	Name    string
	AFI     string
	Entries []PrefixListEntry
	File    string
	Line    int
}

// PrefixListEntry is one line of a prefix list.
type PrefixListEntry struct {
	Seq    int64
	Action string
	Prefix string
	Le     int64
	Ge     int64
	Line   int
	Raw    string
}

// RouteMap groups every `route-map <name> <action> <seq>` block of one name.
type RouteMap struct {
	Name    string
	Entries []RouteMapEntry
	File    string
	Line    int
}

// RouteMapEntry is one clause of a route map.
type RouteMapEntry struct {
	Name     string
	Action   string
	Sequence int64
	// Match and Set hold the raw statements, without the leading keyword.
	Match []string
	Set   []string
	// Clauses holds the same statements read into fields.
	Clauses   RouteMapClauses
	Call      string
	OnMatch   string
	File      string
	StartLine int
	Raw       string
}

// Hostname returns the `hostname` value of the config.
func (c *Config) Hostname() string { return c.firstArg("hostname") }

// Version returns the version from the `frr version <x>` line FRR writes at
// the top of a saved config.
func (c *Config) Version() string {
	for i := range c.Directives {
		d := c.Directives[i]
		if d.Name == "frr" && len(d.Args) >= 2 && d.Args[0] == "version" {
			return d.Args[1]
		}
	}
	return ""
}

// Defaults returns the profile from `frr defaults <traditional|datacenter>`.
func (c *Config) Defaults() string {
	for i := range c.Directives {
		d := c.Directives[i]
		if d.Name == "frr" && len(d.Args) >= 2 && d.Args[0] == "defaults" {
			return d.Args[1]
		}
	}
	return ""
}

// IntegratedVtyshConfig reports the `service integrated-vtysh-config` line.
func (c *Config) IntegratedVtyshConfig() bool {
	for i := range c.Directives {
		d := c.Directives[i]
		if d.Name == "service" && len(d.Args) >= 1 && d.Args[0] == "integrated-vtysh-config" {
			return !d.Negated
		}
	}
	return false
}

func (c *Config) firstArg(name string) string {
	for i := range c.Directives {
		if c.Directives[i].Name == name && len(c.Directives[i].Args) > 0 {
			return c.Directives[i].Args[0]
		}
	}
	return ""
}

// BGPInstances builds the typed view of every router bgp block.
func (c *Config) BGPInstances() []BGP {
	var out []BGP
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "router bgp" {
			continue
		}
		out = append(out, buildBGP(blk))
	}
	return out
}

func buildBGP(blk *Block) BGP {
	b := BGP{
		VRF: argAfter(blk.Args, "vrf"),
		// FRR turns both on by default. Only an explicit `no` clears them.
		EbgpRequiresPolicy: true,
		DefaultIPv4Unicast: true,
		Params:             map[string]string{},
		File:               blk.File,
		StartLine:          blk.StartLine,
		Raw:                blk.Raw,
	}
	if blk.Name != "" {
		b.ASN, _ = strconv.ParseInt(blk.Name, 10, 64)
	}

	neighbors := newNeighborSet()

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "bgp":
			if len(d.Args) == 0 {
				continue
			}
			switch {
			case d.Args[0] == "router-id" && len(d.Args) > 1:
				b.RouterID = d.Args[1]
			case d.Args[0] == "cluster-id" && len(d.Args) > 1:
				b.ClusterID = d.Args[1]
			case d.Args[0] == "ebgp-requires-policy":
				b.EbgpRequiresPolicy = !d.Negated
			case d.Args[0] == "default" && len(d.Args) > 1 && d.Args[1] == "ipv4-unicast":
				b.DefaultIPv4Unicast = !d.Negated
			case d.Args[0] == "listen" && len(d.Args) >= 4 && d.Args[1] == "range":
				// `bgp listen range <prefix> peer-group <name>`. A line
				// without the group names no peer, so it must not create
				// one under an empty name.
				group := argAfter(d.Args, "peer-group")
				if group == "" {
					break
				}
				n := neighbors.get(group, d)
				n.ListenRange = d.Args[2]
				n.IsPeerGroup = true
			}
			b.Params[strings.Join(d.Args, " ")] = boolParam(!d.Negated)
		case "neighbor":
			applyNeighborLine(neighbors, d)
		default:
			b.Params[directiveKey(d)] = directiveValue(d)
		}
	}

	for i := range blk.Blocks {
		sub := &blk.Blocks[i]
		if sub.Type != "address-family" {
			continue
		}
		af := buildAddressFamily(sub, neighbors)
		b.AddressFamilies = append(b.AddressFamilies, af)
	}

	b.Neighbors = neighbors.list()
	return b
}

// neighborSet keeps neighbors in first-seen order while merging the many
// lines that configure the same peer.
type neighborSet struct {
	order  []string
	byName map[string]*Neighbor
}

func newNeighborSet() *neighborSet {
	return &neighborSet{byName: map[string]*Neighbor{}}
}

func (s *neighborSet) get(name string, d *Directive) *Neighbor {
	if n, ok := s.byName[name]; ok {
		return n
	}
	n := &Neighbor{Name: name, Params: map[string]string{}}
	if d != nil {
		n.File = d.File
		n.Line = d.Line
	}
	s.byName[name] = n
	s.order = append(s.order, name)
	return n
}

func (s *neighborSet) list() []Neighbor {
	out := make([]Neighbor, 0, len(s.order))
	for _, name := range s.order {
		n := s.byName[name]
		sort.Strings(n.ActivatedAddressFamilies)
		out = append(out, *n)
	}
	return out
}

// applyNeighborLine folds one `neighbor <name> ...` line of a router block
// into the neighbor it configures.
func applyNeighborLine(set *neighborSet, d *Directive) {
	if len(d.Args) < 2 {
		return
	}
	n := set.get(d.Args[0], d)
	rest := d.Args[1:]

	switch rest[0] {
	case "interface":
		n.Interface = true
		// `neighbor <if> interface remote-as <asn>` and
		// `neighbor <if> interface peer-group <name>`.
		if v := argAfter(rest, "remote-as"); v != "" {
			n.setRemoteAs(v)
		}
		if v := argAfter(rest, "peer-group"); v != "" {
			n.PeerGroup = v
		}
	case "peer-group":
		if len(rest) == 1 {
			n.IsPeerGroup = true
		} else {
			n.PeerGroup = rest[1]
		}
	case "remote-as":
		if len(rest) > 1 {
			n.setRemoteAs(rest[1])
		}
	case "local-as":
		if len(rest) > 1 {
			n.LocalASN, _ = strconv.ParseInt(rest[1], 10, 64)
		}
	case "description":
		n.Description = strings.Join(rest[1:], " ")
	case "update-source":
		if len(rest) > 1 {
			n.UpdateSource = rest[1]
		}
	case "bfd":
		n.BFD = !d.Negated
	case "shutdown":
		n.Shutdown = !d.Negated
	case "password":
		n.PasswordSet = !d.Negated
	case "ttl-security":
		if v := argAfter(rest, "hops"); v != "" {
			n.TTLSecurityHops, _ = strconv.ParseInt(v, 10, 64)
		}
	case "timers":
		// `neighbor <n> timers <keepalive> <hold>`; the connect variant has
		// `connect` as its first argument and is kept in Params only.
		if len(rest) >= 3 && rest[1] != "connect" {
			n.KeepaliveTime, _ = strconv.ParseInt(rest[1], 10, 64)
			n.HoldTime, _ = strconv.ParseInt(rest[2], 10, 64)
		}
	}

	n.Params[strings.Join(rest, " ")] = boolParam(!d.Negated)
}

func (n *Neighbor) setRemoteAs(v string) {
	n.RemoteAs = v
	n.RemoteASN, _ = strconv.ParseInt(v, 10, 64)
}

func buildAddressFamily(blk *Block, neighbors *neighborSet) AddressFamily {
	af := AddressFamily{
		Params:    map[string]string{},
		File:      blk.File,
		StartLine: blk.StartLine,
		Raw:       blk.Raw,
	}
	if len(blk.Args) > 0 {
		af.AFI = blk.Args[0]
	}
	if len(blk.Args) > 1 {
		af.SAFI = blk.Args[1]
	}

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "network":
			if len(d.Args) > 0 {
				af.Networks = append(af.Networks, d.Args[0])
			}
		case "redistribute":
			if len(d.Args) > 0 {
				af.Redistribute = append(af.Redistribute, strings.Join(d.Args, " "))
			}
		case "import":
			// `import vrf <name>` or `import vrf route-map <name>`.
			if len(d.Args) >= 2 && d.Args[0] == "vrf" {
				if d.Args[1] == "route-map" && len(d.Args) > 2 {
					af.ImportVrfRouteMap = d.Args[2]
				} else {
					af.ImportVrfs = append(af.ImportVrfs, d.Args[1])
				}
			}
		case "route-target":
			// `route-target import|export|both <rt>`
			if len(d.Args) >= 2 {
				switch d.Args[0] {
				case "import":
					af.RouteTargetsImport = append(af.RouteTargetsImport, d.Args[1:]...)
				case "export":
					af.RouteTargetsExport = append(af.RouteTargetsExport, d.Args[1:]...)
				case "both":
					af.RouteTargetsImport = append(af.RouteTargetsImport, d.Args[1:]...)
					af.RouteTargetsExport = append(af.RouteTargetsExport, d.Args[1:]...)
				}
			}
		case "advertise":
			if len(d.Args) > 0 && d.Args[0] == "all-vni" {
				af.AdvertiseAllVNI = !d.Negated
				continue
			}
			af.Advertise = append(af.Advertise, strings.Join(d.Args, " "))
		case "advertise-all-vni":
			af.AdvertiseAllVNI = !d.Negated
		case "neighbor":
			applyNeighborAddressFamilyLine(neighbors, af.AFI, af.SAFI, d)
		default:
			af.Params[directiveKey(d)] = directiveValue(d)
		}
	}

	for i := range blk.Blocks {
		sub := &blk.Blocks[i]
		if sub.Type != "vni" {
			continue
		}
		v := VNI{}
		v.ID, _ = strconv.ParseInt(sub.Name, 10, 64)
		for j := range sub.Directives {
			d := &sub.Directives[j]
			if d.Name != "route-target" || len(d.Args) < 2 {
				continue
			}
			switch d.Args[0] {
			case "import":
				v.RouteTargetsImport = append(v.RouteTargetsImport, d.Args[1:]...)
			case "export":
				v.RouteTargetsExport = append(v.RouteTargetsExport, d.Args[1:]...)
			case "both":
				v.RouteTargetsImport = append(v.RouteTargetsImport, d.Args[1:]...)
				v.RouteTargetsExport = append(v.RouteTargetsExport, d.Args[1:]...)
			}
		}
		af.VNIs = append(af.VNIs, v)
	}

	return af
}

// applyNeighborAddressFamilyLine folds one `neighbor <name> ...` line of an
// address family into that neighbor's per-family settings.
func applyNeighborAddressFamilyLine(set *neighborSet, afi, safi string, d *Directive) {
	if len(d.Args) < 2 {
		return
	}
	n := set.get(d.Args[0], d)
	naf := n.addressFamily(afi, safi)
	rest := d.Args[1:]

	switch rest[0] {
	case "activate":
		naf.Activate = !d.Negated
	case "route-map":
		// `neighbor <n> route-map <name> in|out`
		if len(rest) >= 3 {
			if rest[2] == "in" {
				naf.RouteMapIn = rest[1]
			} else {
				naf.RouteMapOut = rest[1]
			}
		}
	case "prefix-list":
		if len(rest) >= 3 {
			if rest[2] == "in" {
				naf.PrefixListIn = rest[1]
			} else {
				naf.PrefixListOut = rest[1]
			}
		}
	case "filter-list":
		if len(rest) >= 3 {
			if rest[2] == "in" {
				naf.FilterListIn = rest[1]
			} else {
				naf.FilterListOut = rest[1]
			}
		}
	case "maximum-prefix":
		if len(rest) > 1 {
			naf.MaximumPrefix, _ = strconv.ParseInt(rest[1], 10, 64)
		}
	case "route-reflector-client":
		naf.RouteReflectorClient = !d.Negated
	case "allowas-in":
		naf.AllowasIn = !d.Negated
	case "next-hop-self":
		naf.NextHopSelf = !d.Negated
	case "soft-reconfiguration":
		naf.SoftReconfiguration = !d.Negated
	case "default-originate":
		naf.DefaultOriginate = !d.Negated
	case "remove-private-AS":
		naf.RemovePrivateAS = !d.Negated
	}

	n.Params[strings.Join(rest, " ")] = boolParam(!d.Negated)
	n.rollup()
}

// addressFamily returns the per-family settings of a neighbor, creating them
// on first use.
func (n *Neighbor) addressFamily(afi, safi string) *NeighborAddressFamily {
	for i := range n.AddressFamilies {
		if n.AddressFamilies[i].AFI == afi && n.AddressFamilies[i].SAFI == safi {
			return &n.AddressFamilies[i]
		}
	}
	n.AddressFamilies = append(n.AddressFamilies, NeighborAddressFamily{AFI: afi, SAFI: safi})
	return &n.AddressFamilies[len(n.AddressFamilies)-1]
}

// rollup recomputes the flat filter lists from the per-family settings.
func (n *Neighbor) rollup() {
	n.ActivatedAddressFamilies = nil
	n.RouteMapsIn = nil
	n.RouteMapsOut = nil
	n.PrefixListsIn = nil
	n.PrefixListsOut = nil
	n.FilterListsIn = nil
	n.FilterListsOut = nil

	for i := range n.AddressFamilies {
		af := &n.AddressFamilies[i]
		if af.Activate {
			n.ActivatedAddressFamilies = append(n.ActivatedAddressFamilies,
				strings.TrimSpace(af.AFI+" "+af.SAFI))
		}
		n.RouteMapsIn = appendNonEmpty(n.RouteMapsIn, af.RouteMapIn)
		n.RouteMapsOut = appendNonEmpty(n.RouteMapsOut, af.RouteMapOut)
		n.PrefixListsIn = appendNonEmpty(n.PrefixListsIn, af.PrefixListIn)
		n.PrefixListsOut = appendNonEmpty(n.PrefixListsOut, af.PrefixListOut)
		n.FilterListsIn = appendNonEmpty(n.FilterListsIn, af.FilterListIn)
		n.FilterListsOut = appendNonEmpty(n.FilterListsOut, af.FilterListOut)
	}
}

// VRFs builds the typed view of every `vrf <name>` block and links it to the
// BGP instance that serves the same VRF.
func (c *Config) VRFs() []VRF {
	instances := c.BGPInstances()

	var out []VRF
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "vrf" {
			continue
		}
		v := VRF{
			Name:      blk.Name,
			Params:    map[string]string{},
			File:      blk.File,
			StartLine: blk.StartLine,
			Raw:       blk.Raw,
		}
		for j := range blk.Directives {
			d := &blk.Directives[j]
			switch d.Name {
			case "vni":
				if len(d.Args) > 0 {
					v.VNI, _ = strconv.ParseInt(d.Args[0], 10, 64)
				}
			case "ip", "ipv6":
				if len(d.Args) > 0 && d.Args[0] == "route" {
					v.StaticRoutes = append(v.StaticRoutes, strings.Join(d.Args[1:], " "))
					continue
				}
				v.Params[directiveKey(d)] = directiveValue(d)
			default:
				v.Params[directiveKey(d)] = directiveValue(d)
			}
		}

		for j := range instances {
			if instances[j].VRF != v.Name {
				continue
			}
			v.RouterASN = instances[j].ASN
			for k := range instances[j].AddressFamilies {
				af := &instances[j].AddressFamilies[k]
				v.RouteTargetsImport = append(v.RouteTargetsImport, af.RouteTargetsImport...)
				v.RouteTargetsExport = append(v.RouteTargetsExport, af.RouteTargetsExport...)
				v.ImportedVrfs = append(v.ImportedVrfs, af.ImportVrfs...)
			}
		}
		v.RouteTargetsImport = dedupe(v.RouteTargetsImport)
		v.RouteTargetsExport = dedupe(v.RouteTargetsExport)
		v.ImportedVrfs = dedupe(v.ImportedVrfs)

		out = append(out, v)
	}
	return out
}

// Interfaces builds the typed view of every `interface <name>` block.
func (c *Config) Interfaces() []Interface {
	var out []Interface
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "interface" {
			continue
		}
		iface := Interface{
			Name:      blk.Name,
			VRF:       argAfter(blk.Args, "vrf"),
			Protocols: parseInterfaceProtocols(blk.Directives),
			Params:    map[string]string{},
			File:      blk.File,
			StartLine: blk.StartLine,
			Raw:       blk.Raw,
		}
		for j := range blk.Directives {
			d := &blk.Directives[j]
			switch {
			case d.Name == "description":
				iface.Description = strings.Join(d.Args, " ")
			case d.Name == "shutdown":
				iface.Shutdown = !d.Negated
			case d.Name == "pbr-policy" && len(d.Args) > 0:
				iface.PBRPolicy = d.Args[0]
			case d.Name == "ip" && len(d.Args) >= 2 && d.Args[0] == "address":
				iface.IPAddresses = append(iface.IPAddresses, d.Args[1])
			case d.Name == "ipv6" && len(d.Args) >= 2 && d.Args[0] == "address":
				iface.IPv6Addresses = append(iface.IPv6Addresses, d.Args[1])
			default:
				iface.Params[directiveKey(d)] = directiveValue(d)
			}
		}
		out = append(out, iface)
	}
	return out
}

// PrefixLists groups the top-level `ip prefix-list` and `ipv6 prefix-list`
// lines by address family and name, in first-seen order.
func (c *Config) PrefixLists() []PrefixList {
	var order []string
	byKey := map[string]*PrefixList{}

	for i := range c.Directives {
		d := &c.Directives[i]
		if d.Name != "ip" && d.Name != "ipv6" {
			continue
		}
		if len(d.Args) < 2 || d.Args[0] != "prefix-list" {
			continue
		}
		afi := d.Name
		name := d.Args[1]
		key := afi + " " + name
		pl, ok := byKey[key]
		if !ok {
			pl = &PrefixList{Name: name, AFI: afi, File: d.File, Line: d.Line}
			byKey[key] = pl
			order = append(order, key)
		}
		pl.Entries = append(pl.Entries, parsePrefixListEntry(d, d.Args[2:]))
	}

	out := make([]PrefixList, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}

func parsePrefixListEntry(d *Directive, args []string) PrefixListEntry {
	e := PrefixListEntry{Line: d.Line, Raw: d.Raw}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "seq":
			if i+1 < len(args) {
				e.Seq, _ = strconv.ParseInt(args[i+1], 10, 64)
				i++
			}
		case "permit", "deny":
			e.Action = args[i]
			if i+1 < len(args) {
				e.Prefix = args[i+1]
				i++
			}
		case "le":
			if i+1 < len(args) {
				e.Le, _ = strconv.ParseInt(args[i+1], 10, 64)
				i++
			}
		case "ge":
			if i+1 < len(args) {
				e.Ge, _ = strconv.ParseInt(args[i+1], 10, 64)
				i++
			}
		}
	}
	return e
}

// RouteMaps groups every `route-map <name> <action> <seq>` block by name, in
// first-seen order.
func (c *Config) RouteMaps() []RouteMap {
	var order []string
	byName := map[string]*RouteMap{}

	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "route-map" {
			continue
		}
		rm, ok := byName[blk.Name]
		if !ok {
			rm = &RouteMap{Name: blk.Name, File: blk.File, Line: blk.StartLine}
			byName[blk.Name] = rm
			order = append(order, blk.Name)
		}
		rm.Entries = append(rm.Entries, buildRouteMapEntry(blk))
	}

	out := make([]RouteMap, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

func buildRouteMapEntry(blk *Block) RouteMapEntry {
	e := RouteMapEntry{
		Name:      blk.Name,
		File:      blk.File,
		StartLine: blk.StartLine,
		Raw:       blk.Raw,
	}
	if len(blk.Args) > 1 {
		e.Action = blk.Args[1]
	}
	if len(blk.Args) > 2 {
		e.Sequence, _ = strconv.ParseInt(blk.Args[2], 10, 64)
	}
	e.Clauses = parseRouteMapClauses(blk.Directives)

	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "match":
			e.Match = append(e.Match, strings.Join(d.Args, " "))
		case "set":
			e.Set = append(e.Set, strings.Join(d.Args, " "))
		case "call":
			if len(d.Args) > 0 {
				e.Call = d.Args[0]
			}
		case "on-match":
			e.OnMatch = strings.Join(d.Args, " ")
		}
	}
	return e
}

// argAfter returns the token that follows key in args, or an empty string.
func argAfter(args []string, key string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func appendNonEmpty(list []string, v string) []string {
	if v == "" {
		return list
	}
	return append(list, v)
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// directiveKey is the map key a directive gets in a Params map. A directive
// with arguments keys on its name plus its first argument, so repeated
// keywords such as `redistribute` do not collapse into one entry.
func directiveKey(d *Directive) string {
	if len(d.Args) == 0 {
		return d.Name
	}
	return d.Name + " " + d.Args[0]
}

// directiveValue is the remaining text of a directive, or the negation state
// when the directive is a bare flag.
func directiveValue(d *Directive) string {
	if len(d.Args) <= 1 {
		return boolParam(!d.Negated)
	}
	return strings.Join(d.Args[1:], " ")
}

func boolParam(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// VtyshUser is a `username <name> ...` line of vtysh.conf.
type VtyshUser struct {
	Name       string
	NoPassword bool
	Privilege  int64
}

// VtyshUsers returns the local shell users declared in the config.
func (c *Config) VtyshUsers() []VtyshUser {
	var out []VtyshUser
	for i := range c.Directives {
		d := &c.Directives[i]
		if d.Name != "username" || len(d.Args) == 0 {
			continue
		}
		u := VtyshUser{Name: d.Args[0]}
		for j := 1; j < len(d.Args); j++ {
			switch d.Args[j] {
			case "nopassword":
				u.NoPassword = true
			case "privilege":
				if j+1 < len(d.Args) {
					u.Privilege, _ = strconv.ParseInt(d.Args[j+1], 10, 64)
					j++
				}
			}
		}
		out = append(out, u)
	}
	return out
}

// Params flattens the top-level directives into a name to value map. It is
// the flat view of a small config such as vtysh.conf.
func (c *Config) Params() map[string]string {
	out := make(map[string]string, len(c.Directives))
	for i := range c.Directives {
		d := &c.Directives[i]
		out[directiveKey(d)] = directiveValue(d)
	}
	return out
}
