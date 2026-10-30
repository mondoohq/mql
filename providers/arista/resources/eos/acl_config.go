// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"math/bits"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// AccessList is one access-list block from running-config.
//
//	ip access-list standard MGMT-ACCESS
//	   10 permit 192.168.100.0/24
//	   20 deny any log
//	!
//	ip access-list extended UPLINK-IN
//	   10 permit tcp 10.0.0.0/8 any eq 443
//	   40 deny ip any any log
//	!
//	ipv6 access-list V6-MGMT
//	   10 permit ipv6 fc00::/7 any
//
// The device SDK only models standard IPv4 lists, so extended and IPv6 lists
// have to come from the configuration text. That matters more than it sounds:
// a real management filter is almost always extended, and an audit that could
// not see extended lists reported no filter rather than reporting a filter it
// could not read.
type AccessList struct {
	Name string
	// Family is "ipv4" or "ipv6".
	Family string
	// Type is "standard" or "extended".
	Type    string
	Entries []AccessListEntry
}

// AccessListEntry is one rule inside an access-list.
//
// Text carries the rule exactly as configured. The structured fields cover
// the forms EOS emits, but the rule grammar accepts qualifiers this parser
// does not break out (TTL and DSCP matching among them), so Text is what
// guarantees a rule is never silently reduced to less than it says.
type AccessListEntry struct {
	SequenceNumber int
	// Action is "permit", "deny", or "remark".
	Action string
	// Protocol is the matched protocol ("ip", "tcp", "udp", "icmp",
	// "ipv6", a protocol number). Empty on standard lists, which match on
	// source address alone.
	Protocol string
	// SrcAddress is "any" for a wildcard match, otherwise the network or
	// host address. SrcPrefixLen is its prefix length.
	SrcAddress   string
	SrcPrefixLen int
	// SrcPortOperator is "eq", "neq", "lt", "gt", or "range" when the rule
	// matches source ports. SrcPorts holds the operands.
	SrcPortOperator string
	SrcPorts        []string
	// DstAddress, DstPrefixLen, DstPortOperator and DstPorts mirror the
	// source fields for the destination. Empty on standard lists.
	DstAddress      string
	DstPrefixLen    int
	DstPortOperator string
	DstPorts        []string
	// Established matches only packets belonging to an existing TCP
	// session.
	Established bool
	// Log enables per-rule logging of matches.
	Log bool
	// Remark is the comment text on a `remark` entry.
	Remark string
	// Text is the rule as written, minus the sequence number.
	Text string
}

var (
	aclIPv4HeaderRe = regexp.MustCompile(`^ip access-list(?:\s+(standard|extended))?\s+(\S+)$`)
	aclIPv6HeaderRe = regexp.MustCompile(`^ipv6 access-list(?:\s+(standard|extended))?\s+(\S+)$`)
	dottedQuadRe    = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

// aclEntryFlags are the trailing qualifiers that end the address and port
// portion of a rule.
var aclEntryFlags = map[string]bool{
	"log": true, "established": true, "tracked": true, "fragments": true,
	"ttl": true, "dscp": true, "match-set": true,
}

// ParseAccessLists extracts every IPv4 and IPv6 access-list from
// running-config, covering the standard, extended, and IPv6 forms.
func ParseAccessLists(runningConfig string) []AccessList {
	res := []AccessList{}

	EachTopLevelBlock(runningConfig, func(header, body string) {
		var family, listType, name string
		switch {
		case strings.HasPrefix(header, "ip access-list"):
			m := aclIPv4HeaderRe.FindStringSubmatch(header)
			if m == nil {
				return
			}
			family, listType, name = "ipv4", m[1], m[2]
		case strings.HasPrefix(header, "ipv6 access-list"):
			m := aclIPv6HeaderRe.FindStringSubmatch(header)
			if m == nil {
				return
			}
			family, listType, name = "ipv6", m[1], m[2]
		default:
			return
		}

		// A list declared without an explicit keyword is extended, which is
		// what the device creates.
		if listType == "" {
			listType = "extended"
		}

		acl := AccessList{
			Name:    name,
			Family:  family,
			Type:    listType,
			Entries: []AccessListEntry{},
		}
		for line := range strings.SplitSeq(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if entry, ok := parseAccessListEntry(line, listType, family); ok {
				acl.Entries = append(acl.Entries, entry)
			}
		}
		sort.SliceStable(acl.Entries, func(i, j int) bool {
			return acl.Entries[i].SequenceNumber < acl.Entries[j].SequenceNumber
		})

		res = append(res, acl)
	})

	sort.SliceStable(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

// parseAccessListEntry reads one rule line. The boolean reports whether the
// line was a rule at all; block-level settings such as `statistics per-entry`
// are not.
func parseAccessListEntry(line, listType, family string) (AccessListEntry, bool) {
	toks := strings.Fields(line)
	if len(toks) == 0 {
		return AccessListEntry{}, false
	}

	entry := AccessListEntry{}
	i := 0
	// A leading number is the sequence number. EOS always renders one, but a
	// hand-written config can omit it.
	if n, err := strconv.Atoi(toks[0]); err == nil {
		entry.SequenceNumber = n
		i = 1
	}
	if i >= len(toks) {
		return AccessListEntry{}, false
	}

	entry.Action = toks[i]
	entry.Text = strings.Join(toks[i:], " ")
	switch entry.Action {
	case "remark":
		entry.Remark = strings.Join(toks[i+1:], " ")
		return entry, true
	case "permit", "deny":
	default:
		// Not a rule: block settings such as `statistics per-entry` or
		// `counters per-entry`.
		return AccessListEntry{}, false
	}
	i++

	hostBits := 32
	if family == "ipv6" {
		hostBits = 128
	}

	// A standard list matches on source address alone, with no protocol.
	if listType == "standard" {
		if i < len(toks) {
			entry.SrcAddress, entry.SrcPrefixLen, i = readAclAddress(toks, i, hostBits)
		}
		readAclFlags(toks, i, &entry)
		return entry, true
	}

	if i < len(toks) {
		entry.Protocol = toks[i]
		i++
	}
	if i < len(toks) && !aclEntryFlags[toks[i]] {
		entry.SrcAddress, entry.SrcPrefixLen, i = readAclAddress(toks, i, hostBits)
		entry.SrcPortOperator, entry.SrcPorts, i = readAclPorts(toks, i)
	}
	if i < len(toks) && !aclEntryFlags[toks[i]] {
		entry.DstAddress, entry.DstPrefixLen, i = readAclAddress(toks, i, hostBits)
		entry.DstPortOperator, entry.DstPorts, i = readAclPorts(toks, i)
	}
	readAclFlags(toks, i, &entry)

	return entry, true
}

// readAclAddress consumes one address operand and returns it with its prefix
// length and the index of the next unread token. EOS writes an address as
// `any`, `host <addr>`, `<prefix>/<len>`, or an address plus a wildcard mask.
func readAclAddress(toks []string, i, hostBits int) (string, int, int) {
	tok := toks[i]

	switch {
	case tok == "any":
		return "any", 0, i + 1

	case tok == "host" && i+1 < len(toks):
		return toks[i+1], hostBits, i + 2

	case strings.Contains(tok, "/"):
		addr, lenPart, _ := strings.Cut(tok, "/")
		n, err := strconv.Atoi(lenPart)
		if err != nil {
			return addr, hostBits, i + 1
		}
		return addr, n, i + 1

	case dottedQuadRe.MatchString(tok) && i+1 < len(toks) && dottedQuadRe.MatchString(toks[i+1]):
		// Address followed by a wildcard mask, the inverse-mask form.
		return tok, prefixLenFromWildcard(toks[i+1]), i + 2
	}

	// A bare address with no mask matches that host exactly.
	return tok, hostBits, i + 1
}

// readAclPorts consumes a port-match clause if one starts at i.
func readAclPorts(toks []string, i int) (string, []string, int) {
	if i >= len(toks) {
		return "", nil, i
	}

	switch toks[i] {
	case "range":
		if i+2 < len(toks) {
			return "range", []string{toks[i+1], toks[i+2]}, i + 3
		}
		return "", nil, i

	case "lt", "gt":
		// A threshold comparison takes exactly one operand.
		if i+1 < len(toks) && !aclEntryFlags[toks[i+1]] && !isAclAddressStart(toks[i+1]) {
			return toks[i], []string{toks[i+1]}, i + 2
		}
		return "", nil, i

	case "eq", "neq":
		op := toks[i]
		ports := []string{}
		j := i + 1
		// `eq` accepts a list of ports. The list ends at the next flag or at
		// the start of the destination address.
		for ; j < len(toks); j++ {
			if aclEntryFlags[toks[j]] || isAclAddressStart(toks[j]) {
				break
			}
			ports = append(ports, toks[j])
		}
		if len(ports) == 0 {
			return "", nil, i
		}
		return op, ports, j
	}

	return "", nil, i
}

// isAclAddressStart reports whether a token begins an address operand rather
// than continuing a port list.
func isAclAddressStart(tok string) bool {
	if tok == "any" || tok == "host" || strings.Contains(tok, "/") {
		return true
	}
	// A bare IP address also starts an operand; a port is never one.
	return net.ParseIP(tok) != nil
}

// readAclFlags reads the trailing qualifiers of a rule.
func readAclFlags(toks []string, i int, entry *AccessListEntry) {
	for ; i < len(toks); i++ {
		switch toks[i] {
		case "log":
			entry.Log = true
		case "established":
			entry.Established = true
		}
	}
}

// prefixLenFromWildcard converts an inverse mask such as 0.0.0.255 to the
// prefix length it represents (24). An unparseable mask yields 0, matching
// how a wildcard of all-ones behaves.
func prefixLenFromWildcard(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	// The wildcard is the bitwise inverse of the netmask, so the prefix
	// length is the number of zero bits in it.
	wildcard := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	return bits.OnesCount32(^wildcard)
}
