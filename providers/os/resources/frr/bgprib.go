// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// This file reads the BGP routing information base: the EVPN table and the
// routes of one session. Both are unbounded on a real fabric, so both are
// decoded with the streaming pattern that stops building entries at a limit
// and keeps counting the rest.

package frr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// BGPRoute is one path of one prefix, from the EVPN table or from the
// advertised or received routes of a session.
type BGPRoute struct {
	// Prefix is the NLRI. For EVPN it is the bracketed form FRR prints, for
	// example `[2]:[0]:[48]:[aa:bb:cc:dd:ee:01]`.
	Prefix    string
	PrefixLen int64
	// Nexthop is the first next hop of the path.
	Nexthop string
	// Peer is the router the path was learned from, empty for a local path.
	Peer            string
	ASPath          string
	Origin          string
	Metric          int64
	LocalPreference int64
	Weight          int64
	Valid           bool
	BestPath        bool
	// Communities, LargeCommunities and ExtendedCommunities carry the tags a
	// policy matches on. Route targets are extended communities, so they
	// decide which VRF imports the route.
	Communities         []string
	LargeCommunities    []string
	ExtendedCommunities []string
	// RouteTargets holds the `RT:` extended communities, split out because
	// they are what separates one tenant from another.
	RouteTargets []string
}

// EVPNRoute is one prefix of the EVPN table, with the paths that carry it.
type EVPNRoute struct {
	// RD is the route distinguisher section the prefix was printed under.
	RD     string
	Prefix string
	// RouteType is the EVPN route type of the prefix, for example 2 for a
	// MAC/IP advertisement and 5 for an IP prefix route.
	RouteType     int64
	RouteTypeName string
	// EthernetTag, MACAddress and IP are read out of the bracketed prefix.
	EthernetTag int64
	MACAddress  string
	IP          string
	Paths       []BGPRoute
	// RouteTargets is the union of the route targets of every path.
	RouteTargets []string
}

// RouteSet is the bounded result of one RIB query.
type RouteSet struct {
	Routes []BGPRoute
	// Total counts every prefix the command reported, including the ones
	// past the limit.
	Total int64
	// Truncated is true when the result does not hold everything the command
	// reported, either because the limit was reached or because a prefix
	// could not be read.
	Truncated bool
	// FilteredCount is the `filteredPrefixCounter` of the command, which
	// says how many prefixes the policy dropped. It is -1 when the command
	// does not report it.
	FilteredCount int64
}

// EVPNRouteSet is the bounded result of one EVPN table query.
type EVPNRouteSet struct {
	Routes []EVPNRoute
	// Total counts every prefix the command reported.
	Total int64
	// Truncated is true when the result does not hold everything the command
	// reported, either because the limit was reached or because a prefix
	// could not be read.
	Truncated bool
}

// DefaultRIBLimit bounds how many prefixes one RIB query turns into
// resources. The EVPN table of a fabric holds one entry per MAC and per
// prefix of every tenant, so it grows with the fleet.
const DefaultRIBLimit = 5000

// evpnSummaryKeys are the scalar keys FRR prints next to the route data.
// They are counters and identifiers, not prefixes.
var evpnSummaryKeys = map[string]bool{
	"numPrefix":             true,
	"numPaths":              true,
	"totalPrefix":           true,
	"totalPaths":            true,
	"bgpTableVersion":       true,
	"bgpLocalRouterId":      true,
	"defaultLocPrf":         true,
	"localAS":               true,
	"vrfName":               true,
	"vrfId":                 true,
	"rd":                    true,
	"vni":                   true,
	"advertiseGatewayMacip": true,
	"advertiseSviMacIp":     true,
	"advertiseAllVnis":      true,
	"warning":               true,
}

// StreamEVPNRoutes decodes `show bgp l2vpn evpn json` and its per VNI form.
//
// FRR prints one section per route distinguisher, and each section holds the
// prefixes of that section. Both shapes are walked, so the per VNI output
// that prints prefixes at the top level is read as well.
//
// The decoder keeps one section in memory at a time and stops building
// entries at limit, while still counting the prefixes it skipped.
func StreamEVPNRoutes(r io.Reader, limit int) (*EVPNRouteSet, error) {
	if limit <= 0 {
		limit = DefaultRIBLimit
	}
	res := &EVPNRouteSet{}

	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		return nil, fmt.Errorf("cannot read evpn table: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("unexpected evpn output, expected a JSON object")
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("cannot read evpn key: %w", err)
		}
		key, _ := keyTok.(string)

		if evpnSummaryKeys[key] {
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}

		// The per VNI form prints prefixes at the top level, where the key
		// is the prefix rather than a route distinguisher.
		if isEVPNPrefix(key) {
			// The value is read as a raw message first, which always
			// consumes exactly one value, so a prefix that cannot be
			// decoded does not leave the decoder mid-table.
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, fmt.Errorf("cannot read the paths of a prefix: %w", err)
			}
			var entry map[string]json.RawMessage
			if err := json.Unmarshal(raw, &entry); err != nil {
				// The prefix was printed, so it counts even though its
				// paths cannot be read, and the result is not complete.
				res.Total++
				res.Truncated = true
				continue
			}
			res.addEVPNPrefix("", key, entry, limit)
			continue
		}

		// Anything else is a route distinguisher section. It is walked key
		// by key, so only one prefix is held at a time. A section of a busy
		// fabric holds tens of thousands of them.
		if err := res.streamEVPNSection(dec, key, limit); err != nil {
			return nil, err
		}
	}

	return res, nil
}

// streamEVPNSection walks one route distinguisher section. The section key
// is the route distinguisher, and an `rd` member overrides it when the
// version prints one.
func (s *EVPNRouteSet) streamEVPNSection(dec *json.Decoder, sectionKey string, limit int) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("cannot read evpn section: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		// A scalar at the top level is a counter this code does not know.
		return skipRemainder(dec, tok)
	}

	rd := sectionKey
	// The prefixes of a section are recorded first and their route
	// distinguisher is corrected afterwards, because `rd` can follow them.
	first := len(s.Routes)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("cannot read evpn prefix: %w", err)
		}
		key, _ := keyTok.(string)

		if key == "rd" {
			var v string
			if err := dec.Decode(&v); err == nil && v != "" {
				rd = v
			}
			continue
		}
		if evpnSummaryKeys[key] {
			if err := skipValue(dec); err != nil {
				return err
			}
			continue
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("cannot read the paths of a prefix: %w", err)
		}
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			// A single unreadable prefix must not drop the section. It was
			// printed, so it still counts, and the result is not complete.
			s.Total++
			s.Truncated = true
			continue
		}
		s.addEVPNPrefix(rd, key, entry, limit)
	}

	// Close the section object.
	if _, err := dec.Token(); err != nil {
		return err
	}

	for i := first; i < len(s.Routes); i++ {
		s.Routes[i].RD = rd
	}
	return nil
}

// skipRemainder consumes the value that starts with the token already read.
func skipRemainder(dec *json.Decoder, tok json.Token) error {
	if _, ok := tok.(json.Delim); !ok {
		return nil
	}
	depth := 1
	for depth > 0 {
		next, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := next.(json.Delim); ok {
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

// addEVPNPrefix records one prefix, or only counts it once the limit is
// reached.
func (s *EVPNRouteSet) addEVPNPrefix(rd, prefix string, entry map[string]json.RawMessage, limit int) {
	s.Total++
	if len(s.Routes) >= limit {
		s.Truncated = true
		return
	}

	route := EVPNRoute{RD: rd, Prefix: prefix}
	if raw, ok := entry["prefix"]; ok {
		var v string
		if json.Unmarshal(raw, &v) == nil && v != "" {
			route.Prefix = v
		}
	}
	fillEVPNPrefixParts(&route)

	if raw, ok := entry["paths"]; ok {
		var paths []map[string]any
		if json.Unmarshal(raw, &paths) == nil {
			for i := range paths {
				p := convertPath(paths[i])
				p.Prefix = route.Prefix
				route.Paths = append(route.Paths, p)
				route.RouteTargets = appendMissing(route.RouteTargets, p.RouteTargets)
			}
		}
	}
	s.Routes = append(s.Routes, route)
}

// reEVPNField matches one bracketed field of an EVPN prefix.
var reEVPNField = regexp.MustCompile(`\[([^\]]*)\]`)

// reMAC matches a MAC address in the prefix.
var reMAC = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)

func isEVPNPrefix(key string) bool {
	return strings.HasPrefix(key, "[")
}

// fillEVPNPrefixParts reads the bracketed fields FRR prints for an EVPN
// prefix. A type 2 route carries `[2]:[tag]:[48]:[mac]` and optionally an
// IP, a type 3 route carries the originator IP, and a type 5 route carries
// the IP prefix.
func fillEVPNPrefixParts(route *EVPNRoute) {
	fields := reEVPNField.FindAllStringSubmatch(route.Prefix, -1)
	if len(fields) == 0 {
		return
	}
	values := make([]string, 0, len(fields))
	for _, f := range fields {
		values = append(values, f[1])
	}

	if t, err := strconv.ParseInt(values[0], 10, 64); err == nil {
		route.RouteType = t
		route.RouteTypeName = evpnRouteTypeName(t)
	}
	if len(values) > 1 {
		if tag, err := strconv.ParseInt(values[1], 10, 64); err == nil {
			route.EthernetTag = tag
		}
	}
	ipIndex := -1
	for i := 2; i < len(values); i++ {
		v := values[i]
		switch {
		case reMAC.MatchString(v):
			route.MACAddress = v
		case strings.Contains(v, ".") || strings.Contains(v, ":"):
			// The IP field of a type 2, 3 or 5 route.
			if route.IP == "" {
				route.IP = v
				ipIndex = i
			}
		}
	}
	// A type 5 route prints the prefix length in the field right before the
	// IP, so the length is read from there rather than from the end. A
	// version that appends further fields does not move it.
	if route.RouteType == 5 && route.IP != "" && ipIndex > 0 {
		if plen, err := strconv.ParseInt(values[ipIndex-1], 10, 64); err == nil && plen <= 128 {
			route.IP += "/" + strconv.FormatInt(plen, 10)
		}
	}
}

// evpnRouteTypeName names the EVPN route types of RFC 7432 and RFC 9136.
func evpnRouteTypeName(t int64) string {
	switch t {
	case 1:
		return "ethernet-auto-discovery"
	case 2:
		return "mac-ip"
	case 3:
		return "inclusive-multicast"
	case 4:
		return "ethernet-segment"
	case 5:
		return "ip-prefix"
	}
	return ""
}

// StreamPeerRoutes decodes `show bgp neighbor <peer> advertised-routes json`
// and its received-routes form. Both print a `routes` object that maps a
// prefix to its path or paths.
func StreamPeerRoutes(r io.Reader, limit int) (*RouteSet, error) {
	if limit <= 0 {
		limit = DefaultRIBLimit
	}
	res := &RouteSet{FilteredCount: -1}

	// The wrapper is small, only `routes` is large, so the object is read
	// key by key and only `routes` is streamed.
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		return nil, fmt.Errorf("cannot read peer routes: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("unexpected peer route output, expected a JSON object")
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("cannot read peer route key: %w", err)
		}
		key, _ := keyTok.(string)

		switch key {
		case "routes":
			if err := streamRouteMap(dec, res, limit); err != nil {
				return nil, err
			}
		case "filteredPrefixCounter":
			var v int64
			if err := dec.Decode(&v); err == nil {
				res.FilteredCount = v
			}
		case "totalPrefixCounter":
			var v int64
			if err := dec.Decode(&v); err == nil && v > res.Total {
				// FRR counts the prefixes it walked, which includes the ones
				// this decoder skipped.
				res.Total = v
			}
		default:
			if err := skipValue(dec); err != nil {
				return nil, err
			}
		}
	}

	if int64(len(res.Routes)) < res.Total {
		res.Truncated = true
	}
	return res, nil
}

// streamRouteMap walks the `routes` object of a peer route query.
func streamRouteMap(dec *json.Decoder, res *RouteSet, limit int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("unexpected routes value, expected a JSON object")
	}

	var counted int64
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		prefix, _ := keyTok.(string)
		counted++

		if len(res.Routes) >= limit {
			res.Truncated = true
			if err := skipValue(dec); err != nil {
				return err
			}
			continue
		}

		// A prefix holds either one path object or a list of them.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("cannot read the paths of a prefix: %w", err)
		}
		paths := decodePaths(raw)
		if len(paths) == 0 {
			// The prefix was printed but nothing could be read from it.
			res.Truncated = true
			continue
		}
		for _, path := range paths {
			// A prefix with several paths must not push the result past the
			// limit, so the check comes before the append.
			if len(res.Routes) >= limit {
				res.Truncated = true
				break
			}
			route := convertPath(path)
			if route.Prefix == "" {
				route.Prefix = prefix
			}
			res.Routes = append(res.Routes, route)
		}
	}

	// Close the routes object.
	if _, err := dec.Token(); err != nil {
		return err
	}
	if counted > res.Total {
		res.Total = counted
	}
	return nil
}

// decodePaths reads the value of one prefix, which is a path object or a
// list of path objects depending on the command and the FRR version.
func decodePaths(raw json.RawMessage) []map[string]any {
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one map[string]any
	if err := json.Unmarshal(raw, &one); err == nil {
		// Some versions wrap the paths in a `paths` member.
		if inner, ok := one["paths"]; ok {
			if items, ok := inner.([]any); ok {
				var out []map[string]any
				for _, item := range items {
					if m, ok := item.(map[string]any); ok {
						out = append(out, m)
					}
				}
				return out
			}
		}
		return []map[string]any{one}
	}
	return nil
}

// convertPath reads the path object FRR prints for a route. Key names differ
// between versions and between commands, so every field is read from a list
// of candidates and an unknown spelling only leaves that field empty.
func convertPath(path map[string]any) BGPRoute {
	route := BGPRoute{}

	route.Prefix = firstString(path, []string{"prefix", "network"})
	if v, ok := firstInt(path, []string{"prefixLen", "prefixLength"}); ok {
		route.PrefixLen = v
	}
	route.ASPath = firstString(path, []string{"path", "aspath", "asPath"})
	route.Origin = firstString(path, []string{"origin"})
	route.Peer = pathPeer(path)
	if v, ok := firstInt(path, []string{"metric", "med"}); ok {
		route.Metric = v
	}
	if v, ok := firstInt(path, []string{"locPrf", "localpref", "localPreference"}); ok {
		route.LocalPreference = v
	}
	if v, ok := firstInt(path, []string{"weight"}); ok {
		route.Weight = v
	}
	route.Valid = firstBool(path, []string{"valid"})
	route.BestPath = pathIsBest(path)
	route.Nexthop = pathNexthop(path)

	route.Communities = communityStrings(path, "community")
	route.LargeCommunities = communityStrings(path, "largeCommunity")
	route.ExtendedCommunities = communityStrings(path, "extendedCommunity")
	for _, ec := range route.ExtendedCommunities {
		if rt, ok := routeTargetOf(ec); ok {
			route.RouteTargets = append(route.RouteTargets, rt)
		}
	}
	return route
}

func pathPeer(path map[string]any) string {
	if peer, ok := path["peer"].(map[string]any); ok {
		return firstString(peer, []string{"peerId", "routerId", "hostname"})
	}
	return firstString(path, []string{"peerId", "peer"})
}

// pathIsBest reads the best path marker, which is a boolean in some versions
// and an object in others.
func pathIsBest(path map[string]any) bool {
	switch v := path["bestpath"].(type) {
	case bool:
		return v
	case map[string]any:
		return true
	}
	return firstBool(path, []string{"bestPath", "best"})
}

// pathNexthop returns the first next hop of a path.
func pathNexthop(path map[string]any) string {
	list, ok := path["nexthops"].([]any)
	if !ok {
		return firstString(path, []string{"nexthop", "nextHop"})
	}
	for _, item := range list {
		hop, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if ip := firstString(hop, []string{"ip", "address"}); ip != "" {
			return ip
		}
	}
	return ""
}

// communityStrings reads a community member, which FRR prints either as an
// object with a `string` member and a `list`, or as a plain string.
func communityStrings(path map[string]any, key string) []string {
	switch v := path[key].(type) {
	case string:
		return splitCommunities(v)
	case map[string]any:
		if list, ok := v["list"].([]any); ok {
			var out []string
			for _, item := range list {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		if s, ok := v["string"].(string); ok {
			return splitCommunities(s)
		}
	}
	return nil
}

func splitCommunities(in string) []string {
	fields := strings.Fields(in)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// reRouteTarget matches the route target form of an extended community.
var reRouteTarget = regexp.MustCompile(`^(?i)RT:(.+)$`)

func routeTargetOf(ec string) (string, bool) {
	m := reRouteTarget.FindStringSubmatch(ec)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func firstBool(m map[string]any, keys []string) bool {
	for _, k := range keys {
		if v, ok := m[k].(bool); ok {
			return v
		}
	}
	return false
}

// appendMissing adds the values that are not in the list yet.
func appendMissing(list []string, values []string) []string {
	for _, v := range values {
		found := false
		for _, existing := range list {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}
