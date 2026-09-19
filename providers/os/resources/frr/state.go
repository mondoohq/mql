// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// This file parses the runtime state of FRR, which comes from vtysh and from
// the kernel. Runtime state is time-varying. A prefix counter or a session
// state describes the moment of the scan, not a durable setting.
//
// Every parser here is a pure function over the recorded output of one
// command, so the resources stay testable without a live router.

package frr

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// reSafeName matches a VRF or table name that is safe to place in a command
// line. Names come from MQL queries, so they are validated before use.
//
// The dash is escaped so the class cannot be read as a range. It is the last
// character either way, which RE2 already takes literally, but the escape
// says so without the reader having to know that.
var reSafeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$`)

// ValidateName rejects a VRF or table name that could change the meaning of
// the command it is placed in.
func ValidateName(kind, name string) error {
	if !reSafeName.MatchString(name) {
		return fmt.Errorf("invalid %s name %q, expected letters, digits, dot, dash or underscore", kind, name)
	}
	return nil
}

// Refused reports whether vtysh printed an error instead of a result. vtysh
// answers `% Unknown command` or `% VRF <name> not found` with a leading
// percent sign and a zero exit status, so the text has to be read.
func Refused(data []byte) bool {
	trimmed := strings.TrimLeft(string(data), " \t\r\n")
	return strings.HasPrefix(trimmed, "%")
}

// ======================================================================
// BGP session state
// ======================================================================

// BGPPeer is one peer inside one address family, as reported by
// `show bgp [vrf <name>] summary json` and enriched from
// `show bgp [vrf <name>] neighbors json`.
type BGPPeer struct {
	VRF  string
	AFI  string
	SAFI string
	Name string
	// SummaryKey is the address family key FRR used in the summary, for
	// example `ipv4Unicast`. The neighbor detail keys its address families
	// the same way, so the key is kept instead of rebuilt.
	SummaryKey string

	RemoteAS int64
	LocalAS  int64
	Hostname string
	// State is the FSM state, for example Established or Idle.
	State       string
	Established bool
	// UptimeMsec is how long the session has held its current state.
	UptimeMsec             int64
	MessagesReceived       int64
	MessagesSent           int64
	ConnectionsEstablished int64
	ConnectionsDropped     int64
	// IDType is how the peer is addressed: ipv4, ipv6 or interface.
	IDType string

	// PrefixesReceived is the `pfxRcd` counter of the summary. FRR counts the
	// prefixes it kept from the peer, so an inbound policy has already run.
	PrefixesReceived int64
	// PrefixesSent is the `pfxSnt` counter of the summary.
	PrefixesSent int64
	// PrefixesAccepted is the accepted counter of the neighbor detail. It
	// falls back to PrefixesReceived when the FRR version does not report it.
	PrefixesAccepted int64
	// PrefixesFiltered is how many prefixes the inbound policy dropped. FRR
	// reports it directly in some versions. Otherwise it is derived from the
	// announced count minus the accepted count.
	PrefixesFiltered int64
	// PrefixesFilteredKnown is false when the FRR version reports neither the
	// filtered counter nor an announced count to derive it from.
	PrefixesFilteredKnown bool

	RouteMapIn    string
	RouteMapOut   string
	PrefixListIn  string
	PrefixListOut string

	// Details is the raw per address family object of the neighbor detail. It
	// keeps the fields that a given FRR version reports beyond the typed set.
	Details map[string]any
}

// bgpSummaryAF is one address family object of `show bgp summary json`.
type bgpSummaryAF struct {
	RouterID string                    `json:"routerId"`
	AS       int64                     `json:"as"`
	VRFName  string                    `json:"vrfName"`
	Peers    map[string]bgpSummaryPeer `json:"peers"`
}

type bgpSummaryPeer struct {
	Hostname               string `json:"hostname"`
	RemoteAS               int64  `json:"remoteAs"`
	LocalAS                int64  `json:"localAs"`
	MsgRcvd                int64  `json:"msgRcvd"`
	MsgSent                int64  `json:"msgSent"`
	PeerUptimeMsec         int64  `json:"peerUptimeMsec"`
	PfxRcd                 int64  `json:"pfxRcd"`
	PfxSnt                 int64  `json:"pfxSnt"`
	State                  string `json:"state"`
	PeerState              string `json:"peerState"`
	ConnectionsEstablished int64  `json:"connectionsEstablished"`
	ConnectionsDropped     int64  `json:"connectionsDropped"`
	IDType                 string `json:"idType"`
}

// afiSafiFromSummaryKey maps a key of `show bgp summary json` to the address
// family it describes. FRR writes the key in camel case, for example
// `ipv4Unicast` or `l2VpnEvpn`.
func afiSafiFromSummaryKey(key string) (string, string, bool) {
	switch key {
	case "ipv4Unicast":
		return "ipv4", "unicast", true
	case "ipv6Unicast":
		return "ipv6", "unicast", true
	case "ipv4Multicast":
		return "ipv4", "multicast", true
	case "ipv6Multicast":
		return "ipv6", "multicast", true
	case "ipv4Vpn":
		return "ipv4", "vpn", true
	case "ipv6Vpn":
		return "ipv6", "vpn", true
	case "ipv4Flowspec":
		return "ipv4", "flowspec", true
	case "ipv6Flowspec":
		return "ipv6", "flowspec", true
	case "ipv4Labeled-unicast", "ipv4LabeledUnicast":
		return "ipv4", "labeled-unicast", true
	case "ipv6Labeled-unicast", "ipv6LabeledUnicast":
		return "ipv6", "labeled-unicast", true
	case "l2VpnEvpn":
		return "l2vpn", "evpn", true
	case "l2VpnVpls":
		return "l2vpn", "vpls", true
	}
	return "", "", false
}

// ParseBGPSummary reads `show bgp [vrf <name>] summary json`. It returns one
// entry per peer and address family, in a stable order.
func ParseBGPSummary(vrf string, data []byte) ([]BGPPeer, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse bgp summary: %w", err)
	}

	var out []BGPPeer
	for _, key := range sortedKeys(raw) {
		afi, safi, ok := afiSafiFromSummaryKey(key)
		if !ok {
			// Keys such as `warning` or a version-specific extra object.
			continue
		}
		var af bgpSummaryAF
		if err := json.Unmarshal(raw[key], &af); err != nil {
			// One unreadable address family must not hide the others.
			continue
		}
		vrfName := vrf
		if af.VRFName != "" && af.VRFName != "default" {
			vrfName = af.VRFName
		}
		for _, name := range sortedKeysOf(af.Peers) {
			p := af.Peers[name]
			state := p.State
			if state == "" {
				state = p.PeerState
			}
			out = append(out, BGPPeer{
				VRF:                    vrfName,
				AFI:                    afi,
				SAFI:                   safi,
				Name:                   name,
				SummaryKey:             key,
				RemoteAS:               p.RemoteAS,
				LocalAS:                p.LocalAS,
				Hostname:               p.Hostname,
				State:                  state,
				Established:            strings.EqualFold(state, "Established"),
				UptimeMsec:             p.PeerUptimeMsec,
				MessagesReceived:       p.MsgRcvd,
				MessagesSent:           p.MsgSent,
				ConnectionsEstablished: p.ConnectionsEstablished,
				ConnectionsDropped:     p.ConnectionsDropped,
				IDType:                 p.IDType,
				PrefixesReceived:       p.PfxRcd,
				PrefixesSent:           p.PfxSnt,
				PrefixesAccepted:       p.PfxRcd,
			})
		}
	}
	return out, nil
}

// acceptedPrefixKeys, sentPrefixKeys and friends list the JSON keys that
// carry the same counter across FRR versions. The first key that is present
// wins, and anything not covered stays reachable through Details.
var (
	acceptedPrefixKeys = []string{"acceptedPrefixCounter", "acceptedPrefixes", "pfxRcd"}
	sentPrefixKeys     = []string{"sentPrefixCounter", "advertisedPrefixCounter", "pfxSnt"}
	announcedKeys      = []string{"announcedPrefixCounter", "receivedPrefixCounter", "prefixesReceived"}
	filteredKeys       = []string{"filteredPrefixCounter", "filteredPrefixes"}
	routeMapInKeys     = []string{"routeMapForIncomingAdvertisements", "routeMapIn"}
	routeMapOutKeys    = []string{"routeMapForOutgoingAdvertisements", "routeMapOut"}
	prefixListInKeys   = []string{"incomingUpdatePrefixFilterList", "prefixListIn"}
	prefixListOutKeys  = []string{"outgoingUpdatePrefixFilterList", "prefixListOut"}
)

// neighborDetail is the part of `show bgp neighbors json` that the resources
// use. Everything else stays in the raw per address family object.
type neighborDetail struct {
	AddressFamilyInfo map[string]map[string]any `json:"addressFamilyInfo"`
}

// EnrichBGPPeers folds `show bgp [vrf <name>] neighbors json` into the peers
// that came from the summary. Peers absent from the detail keep their summary
// values.
func EnrichBGPPeers(peers []BGPPeer, data []byte) error {
	var raw map[string]neighborDetail
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("cannot parse bgp neighbors: %w", err)
	}

	for i := range peers {
		p := &peers[i]
		detail, ok := raw[p.Name]
		if !ok {
			continue
		}
		af, ok := lookupAddressFamily(detail.AddressFamilyInfo, p)
		if !ok {
			continue
		}
		p.Details = af

		if v, ok := firstInt(af, acceptedPrefixKeys); ok {
			p.PrefixesAccepted = v
		}
		if v, ok := firstInt(af, sentPrefixKeys); ok {
			p.PrefixesSent = v
		}
		if v, ok := firstInt(af, filteredKeys); ok {
			p.PrefixesFiltered = v
			p.PrefixesFilteredKnown = true
		} else if announced, ok := firstInt(af, announcedKeys); ok {
			// FRR reports the accepted count in the summary. When it also
			// reports what the peer announced, the difference is what the
			// inbound policy dropped.
			if announced >= p.PrefixesAccepted {
				p.PrefixesFiltered = announced - p.PrefixesAccepted
				p.PrefixesFilteredKnown = true
			}
		}

		p.RouteMapIn = firstString(af, routeMapInKeys)
		p.RouteMapOut = firstString(af, routeMapOutKeys)
		p.PrefixListIn = firstString(af, prefixListInKeys)
		p.PrefixListOut = firstString(af, prefixListOutKeys)
	}
	return nil
}

// lookupAddressFamily finds the address family object of one peer in the
// neighbor detail. It uses the key FRR wrote in the summary first, so a
// spelling this code does not know still matches.
func lookupAddressFamily(info map[string]map[string]any, p *BGPPeer) (map[string]any, bool) {
	if p.SummaryKey != "" {
		if af, ok := info[p.SummaryKey]; ok {
			return af, true
		}
	}
	if af, ok := info[summaryKeyFor(p.AFI, p.SAFI)]; ok {
		return af, true
	}
	return nil, false
}

// summaryKeyFor rebuilds the camel case address family key that FRR uses in
// both the summary and the neighbor detail. It is the fallback for a peer
// that carries no summary key.
func summaryKeyFor(afi, safi string) string {
	switch {
	case afi == "l2vpn" && safi == "evpn":
		return "l2VpnEvpn"
	case afi == "l2vpn":
		return "l2Vpn" + camelSafi(safi)
	default:
		return afi + camelSafi(safi)
	}
}

// camelSafi renders a SAFI the way FRR writes it inside a key. A compound
// name keeps its word boundaries, so `labeled-unicast` becomes
// `LabeledUnicast`.
func camelSafi(safi string) string {
	parts := strings.Split(safi, "-")
	for i := range parts {
		parts[i] = title(parts[i])
	}
	return strings.Join(parts, "")
}

func title(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func firstInt(m map[string]any, keys []string) (int64, bool) {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int64(n), true
		case string:
			i, err := strconv.ParseInt(n, 10, 64)
			if err == nil {
				return i, true
			}
		}
	}
	return 0, false
}

func firstString(m map[string]any, keys []string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// ======================================================================
// Routing table state
// ======================================================================

// RouteEntry is one entry of `show ip route json` or `show ipv6 route json`.
type RouteEntry struct {
	Prefix    string
	PrefixLen int64
	Protocol  string
	VRF       string
	Table     int64
	Selected  bool
	Installed bool
	Distance  int64
	Metric    int64
	Uptime    string
	Nexthops  []RouteNexthop
}

// RouteNexthop is one next hop of a route entry.
type RouteNexthop struct {
	IP                string
	Interface         string
	VRF               string
	Active            bool
	FIB               bool
	DirectlyConnected bool
}

type routeJSON struct {
	Prefix    string         `json:"prefix"`
	PrefixLen int64          `json:"prefixLen"`
	Protocol  string         `json:"protocol"`
	VRFName   string         `json:"vrfName"`
	Table     int64          `json:"table"`
	Selected  bool           `json:"selected"`
	Installed bool           `json:"installed"`
	Distance  int64          `json:"distance"`
	Metric    int64          `json:"metric"`
	Uptime    string         `json:"uptime"`
	Nexthops  []routeHopJSON `json:"nexthops"`
}

type routeHopJSON struct {
	IP                string `json:"ip"`
	InterfaceName     string `json:"interfaceName"`
	VRF               string `json:"vrf"`
	Active            bool   `json:"active"`
	FIB               bool   `json:"fib"`
	DirectlyConnected bool   `json:"directlyConnected"`
}

// RouteTable is the bounded result of one route query.
type RouteTable struct {
	// Entries holds at most Limit routes.
	Entries []RouteEntry
	// Total is how many prefixes the command reported.
	Total int64
	// Truncated is true when the result does not hold everything the command
	// reported, either because the limit was reached or because a prefix
	// could not be read.
	Truncated bool
}

// DefaultRouteLimit bounds how many routes one query turns into resources.
// A fabric node that holds a full table has far more, and every entry costs
// far more as a resource than as JSON text.
const DefaultRouteLimit = 5000

// StreamRoutes decodes `show ip route json` and stops building entries after
// limit prefixes. It keeps counting the remaining prefixes with the token
// stream, so Total stays exact without holding the rest in memory.
//
// The output of the command is one object that maps a prefix to its list of
// route entries.
func StreamRoutes(r io.Reader, limit int) (*RouteTable, error) {
	if limit <= 0 {
		limit = DefaultRouteLimit
	}
	res := &RouteTable{}

	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			// An empty routing table prints nothing on some versions.
			return res, nil
		}
		return nil, fmt.Errorf("cannot read route output: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("unexpected route output, expected a JSON object")
	}

	for dec.More() {
		// The key is the prefix. The value is the list of entries for it.
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("cannot read route prefix: %w", err)
		}
		res.Total++

		if len(res.Entries) >= limit {
			res.Truncated = true
			// Skip the value without building any entry for it.
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}

		// The value is read as a raw message first, which always consumes
		// exactly one value. Decoding it afterwards can fail without
		// leaving the decoder in the middle of the table.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("cannot read the routes of a prefix: %w", err)
		}
		var entries []routeJSON
		if err := json.Unmarshal(raw, &entries); err != nil {
			// A single unreadable prefix must not drop the whole table, but
			// the result no longer holds everything FRR reported.
			res.Truncated = true
			continue
		}
		for i := range entries {
			// The check comes before the append, so a prefix with several
			// entries cannot push the result past the limit. Anything left
			// over marks the result as truncated.
			if len(res.Entries) >= limit {
				res.Truncated = true
				break
			}
			res.Entries = append(res.Entries, convertRoute(&entries[i]))
		}
	}

	return res, nil
}

// skipValue consumes one JSON value from the decoder without allocating it.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if _, ok := tok.(json.Delim); !ok {
		// A scalar value is already consumed by the token read.
		return nil
	}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func convertRoute(in *routeJSON) RouteEntry {
	out := RouteEntry{
		Prefix:    in.Prefix,
		PrefixLen: in.PrefixLen,
		Protocol:  in.Protocol,
		VRF:       in.VRFName,
		Table:     in.Table,
		Selected:  in.Selected,
		Installed: in.Installed,
		Distance:  in.Distance,
		Metric:    in.Metric,
		Uptime:    in.Uptime,
	}
	for i := range in.Nexthops {
		h := &in.Nexthops[i]
		out.Nexthops = append(out.Nexthops, RouteNexthop{
			IP:                h.IP,
			Interface:         h.InterfaceName,
			VRF:               h.VRF,
			Active:            h.Active,
			FIB:               h.FIB,
			DirectlyConnected: h.DirectlyConnected,
		})
	}
	return out
}

// ======================================================================
// EVPN state
// ======================================================================

// EVPNVNI is one entry of `show evpn vni json`.
type EVPNVNI struct {
	VNI  int64
	Type string
	// VRF is the tenant VRF of an L3 VNI, or the VRF an L2 VNI belongs to.
	VRF            string
	VxlanInterface string
	SVIInterface   string
	RouterMAC      string
	State          string
	NumMacs        int64
	NumArpNd       int64
	NumRemoteVteps int64
	RemoteVteps    []string
	Details        map[string]any
}

// ParseEVPNVNIs reads `show evpn vni json`, which maps the VNI to its state.
// L2 and L3 VNIs use slightly different keys across FRR versions, so both
// spellings are read and the raw object is kept.
func ParseEVPNVNIs(data []byte) ([]EVPNVNI, error) {
	var raw map[string]map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse evpn vni output: %w", err)
	}

	out := make([]EVPNVNI, 0, len(raw))
	for _, key := range sortedKeysOf(raw) {
		obj := raw[key]
		v := EVPNVNI{Details: obj}
		if n, ok := firstInt(obj, []string{"vni"}); ok {
			v.VNI = n
		} else if n, err := strconv.ParseInt(key, 10, 64); err == nil {
			v.VNI = n
		}
		v.Type = firstString(obj, []string{"type", "vniType"})
		v.VRF = firstString(obj, []string{"tenantVrf", "vrf"})
		v.VxlanInterface = firstString(obj, []string{"vxlanIf", "vxlanIntf", "vxlanInterface"})
		v.SVIInterface = firstString(obj, []string{"sviIntf", "sviInterface"})
		v.RouterMAC = firstString(obj, []string{"routerMac", "rmac"})
		v.State = firstString(obj, []string{"state"})
		if n, ok := firstInt(obj, []string{"numMacs"}); ok {
			v.NumMacs = n
		}
		if n, ok := firstInt(obj, []string{"numArpNd"}); ok {
			v.NumArpNd = n
		}
		if n, ok := firstInt(obj, []string{"numRemoteVteps"}); ok {
			v.NumRemoteVteps = n
		}
		if list, ok := obj["remoteVteps"].([]any); ok {
			for _, item := range list {
				switch t := item.(type) {
				case string:
					v.RemoteVteps = append(v.RemoteVteps, t)
				case map[string]any:
					if ip, ok := t["ip"].(string); ok {
						v.RemoteVteps = append(v.RemoteVteps, ip)
					}
				}
			}
			if v.NumRemoteVteps == 0 {
				v.NumRemoteVteps = int64(len(v.RemoteVteps))
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// ======================================================================
// VRF state, from FRR and from the kernel
// ======================================================================

// ZebraVRF is one line of `show vrf`.
type ZebraVRF struct {
	Name    string
	ID      int64
	TableID int64
}

// reShowVRF matches `vrf cluster id 5 table 1005`. FRR appends further words
// on some versions, which the pattern ignores.
var reShowVRF = regexp.MustCompile(`^\s*vrf\s+(\S+)\s+id\s+(\d+)(?:\s+table\s+(\d+))?`)

// ParseShowVRF reads the plain text of `show vrf`, which has no JSON form.
func ParseShowVRF(out string) []ZebraVRF {
	var res []ZebraVRF
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		m := reShowVRF.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		v := ZebraVRF{Name: m[1]}
		v.ID, _ = strconv.ParseInt(m[2], 10, 64)
		if m[3] != "" {
			v.TableID, _ = strconv.ParseInt(m[3], 10, 64)
		}
		res = append(res, v)
	}
	return res
}

// KernelVRF is one entry of `ip -j link show type vrf`.
type KernelVRF struct {
	Name      string
	Ifindex   int64
	MTU       int64
	OperState string
	Up        bool
	TableID   int64
}

type ipLinkJSON struct {
	Ifindex   int64    `json:"ifindex"`
	Ifname    string   `json:"ifname"`
	MTU       int64    `json:"mtu"`
	OperState string   `json:"operstate"`
	Flags     []string `json:"flags"`
	LinkInfo  struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			Table int64 `json:"table"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

// ParseIPLinkVRF reads `ip -j link show type vrf`.
func ParseIPLinkVRF(data []byte) ([]KernelVRF, error) {
	var raw []ipLinkJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse ip link output: %w", err)
	}
	out := make([]KernelVRF, 0, len(raw))
	for i := range raw {
		l := &raw[i]
		v := KernelVRF{
			Name:      l.Ifname,
			Ifindex:   l.Ifindex,
			MTU:       l.MTU,
			OperState: l.OperState,
			TableID:   l.LinkInfo.InfoData.Table,
		}
		v.Up = strings.EqualFold(l.OperState, "UP")
		if !v.Up {
			for _, f := range l.Flags {
				if f == "UP" {
					v.Up = true
					break
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// RoutingRule is one entry of `ip -j rule show`. The rules decide which
// routing table a packet uses, so they carry the separation between VRFs.
type RoutingRule struct {
	Priority             int64
	Source               string
	Dest                 string
	Table                string
	TableID              int64
	InputIf              string
	OutputIf             string
	L3mdev               bool
	Action               string
	Protocol             string
	FwMark               string
	Invert               bool
	SuppressPrefixLength int64
}

type ipRuleJSON struct {
	Priority             int64  `json:"priority"`
	Src                  string `json:"src"`
	SrcLen               *int64 `json:"srclen"`
	Dst                  string `json:"dst"`
	DstLen               *int64 `json:"dstlen"`
	Table                string `json:"table"`
	IIf                  string `json:"iif"`
	OIf                  string `json:"oif"`
	L3mdev               any    `json:"l3mdev"`
	Action               string `json:"action"`
	Protocol             string `json:"protocol"`
	FwMark               string `json:"fwmark"`
	Not                  any    `json:"not"`
	SuppressPrefixLength *int64 `json:"suppress_prefixlength"`
}

// ParseIPRules reads `ip -j rule show`. Table names are resolved with the
// tableNames map, which comes from /etc/iproute2/rt_tables.
func ParseIPRules(data []byte, tableNames map[int64]string) ([]RoutingRule, error) {
	var raw []ipRuleJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse ip rule output: %w", err)
	}

	out := make([]RoutingRule, 0, len(raw))
	for i := range raw {
		r := &raw[i]
		rule := RoutingRule{
			Priority: r.Priority,
			Source:   withPrefixLen(r.Src, r.SrcLen),
			Dest:     withPrefixLen(r.Dst, r.DstLen),
			Table:    r.Table,
			InputIf:  r.IIf,
			OutputIf: r.OIf,
			L3mdev:   truthy(r.L3mdev),
			Action:   r.Action,
			Protocol: r.Protocol,
			FwMark:   r.FwMark,
			Invert:   truthy(r.Not),
		}
		if r.SuppressPrefixLength != nil {
			rule.SuppressPrefixLength = *r.SuppressPrefixLength
		} else {
			rule.SuppressPrefixLength = -1
		}
		if rule.Table != "" {
			if id, err := strconv.ParseInt(rule.Table, 10, 64); err == nil {
				rule.TableID = id
				if name, ok := tableNames[id]; ok {
					rule.Table = name
				}
			} else {
				for id, name := range tableNames {
					if name == rule.Table {
						rule.TableID = id
						break
					}
				}
			}
		}
		out = append(out, rule)
	}
	return out, nil
}

func withPrefixLen(addr string, length *int64) string {
	if addr == "" || length == nil {
		return addr
	}
	return addr + "/" + strconv.FormatInt(*length, 10)
}

// truthy reads the flag keys of `ip -j`, which are `true` on new versions and
// an empty string or a missing key on older ones.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "" && !strings.EqualFold(t, "false")
	case float64:
		return t != 0
	}
	return false
}

// reRtTable matches an id and name line of /etc/iproute2/rt_tables.
var reRtTable = regexp.MustCompile(`^\s*(\d+)\s+(\S+)`)

// ParseRtTables reads /etc/iproute2/rt_tables, which names the numeric
// routing tables. A VRF table is often listed here by the operator.
func ParseRtTables(content string) map[int64]string {
	out := map[int64]string{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		m := reRtTable.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		out[id] = m[2]
	}
	return out
}

// VRFState merges what FRR knows about a VRF with what the kernel knows.
type VRFState struct {
	Name      string
	ID        int64
	TableID   int64
	TableName string
	Ifindex   int64
	MTU       int64
	OperState string
	Up        bool
	// InFRR is true when zebra reported the VRF.
	InFRR bool
	// InKernel is true when the VRF device exists on the asset.
	InKernel bool
}

// MergeVRFs joins the FRR view and the kernel view by name. A VRF that only
// one side knows is still returned, with the flag that says which side saw
// it, because that mismatch is itself a finding.
func MergeVRFs(zebra []ZebraVRF, kernel []KernelVRF, tableNames map[int64]string) []VRFState {
	var order []string
	byName := map[string]*VRFState{}

	get := func(name string) *VRFState {
		if v, ok := byName[name]; ok {
			return v
		}
		v := &VRFState{Name: name}
		byName[name] = v
		order = append(order, name)
		return v
	}

	for i := range zebra {
		v := get(zebra[i].Name)
		v.InFRR = true
		v.ID = zebra[i].ID
		if zebra[i].TableID != 0 {
			v.TableID = zebra[i].TableID
		}
	}
	for i := range kernel {
		v := get(kernel[i].Name)
		v.InKernel = true
		v.Ifindex = kernel[i].Ifindex
		v.MTU = kernel[i].MTU
		v.OperState = kernel[i].OperState
		v.Up = kernel[i].Up
		if kernel[i].TableID != 0 {
			v.TableID = kernel[i].TableID
		}
	}

	out := make([]VRFState, 0, len(order))
	for _, name := range order {
		v := byName[name]
		if n, ok := tableNames[v.TableID]; ok {
			v.TableName = n
		}
		out = append(out, *v)
	}
	return out
}

// ======================================================================
// helpers
// ======================================================================

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(in []string) {
	sort.Strings(in)
}
