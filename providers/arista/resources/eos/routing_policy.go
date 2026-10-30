// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"regexp"
	"sort"
	"strings"
)

// RouteMapEntry is one clause of a route-map.
//
//	route-map IMPORT-FILTER permit 10
//	   description accept customer prefixes
//	   match ip address prefix-list CUSTOMER-PREFIXES
//	   set local-preference 200
//	!
//	route-map IMPORT-FILTER deny 20
//
// Match and Set carry the statements as written. Their grammar is wide and
// keeps growing, so structuring every variant would be a losing game and a
// lossy one; the statements stay readable and queryable as text.
//
// The final clause is what usually decides the posture: a route-map whose
// last clause is a bare `deny` rejects everything the earlier clauses did not
// explicitly accept, while a map with no deny clause accepts the remainder.
type RouteMapEntry struct {
	Name string
	// Action is "permit" or "deny".
	Action         string
	SequenceNumber int
	// Description is the clause's `description` text.
	Description string
	// Match holds the `match ...` statements, without the keyword.
	Match []string
	// Set holds the `set ...` statements, without the keyword.
	Set []string
	// MatchPrefixLists are the prefix-list names referenced by
	// `match ip address prefix-list` and its IPv6 form.
	MatchPrefixLists []string
	// Continue is the clause number processing continues at (0 = unset).
	Continue int
}

// RouteMap is a named routing policy made of ordered clauses.
type RouteMap struct {
	Name    string
	Entries []RouteMapEntry
}

// PrefixListEntry is one rule of a prefix-list.
//
//	ip prefix-list CUSTOMER-PREFIXES seq 10 permit 10.0.0.0/8 le 24
//
// Ge and Le bound the prefix lengths the rule accepts. A rule with a wide Le
// accepts far more than its prefix suggests: `permit 0.0.0.0/0 le 32` accepts
// every route there is.
type PrefixListEntry struct {
	SequenceNumber int
	// Action is "permit" or "deny".
	Action string
	// Prefix is the network in CIDR form.
	Prefix string
	// Eq, Ge and Le are the prefix-length qualifiers (0 = unset).
	Eq int
	Ge int
	Le int
}

// PrefixList is a named list of prefixes referenced by routing policy.
type PrefixList struct {
	Name string
	// Family is "ipv4" or "ipv6".
	Family  string
	Entries []PrefixListEntry
}

var (
	routeMapHeaderRe = regexp.MustCompile(`^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)$`)
	// A prefix-list is rendered either as a flat top-level line carrying the
	// name, or as a block header with the rules nested beneath it.
	prefixListFlatRe  = regexp.MustCompile(`^(ip|ipv6) prefix-list\s+(\S+)\s+(.*)$`)
	prefixListBlockRe = regexp.MustCompile(`^(ip|ipv6) prefix-list\s+(\S+)$`)
)

// ParseRouteMaps extracts the route-maps from running-config, grouping the
// clauses of each map under one entry.
func ParseRouteMaps(runningConfig string) []RouteMap {
	byName := map[string]*RouteMap{}
	order := []string{}

	EachTopLevelBlock(runningConfig, func(header, body string) {
		m := routeMapHeaderRe.FindStringSubmatch(header)
		if m == nil {
			return
		}
		name := m[1]

		entry := RouteMapEntry{
			Name:             name,
			Action:           m[2],
			SequenceNumber:   atoiOrZero(m[3]),
			Match:            []string{},
			Set:              []string{},
			MatchPrefixLists: []string{},
		}

		for line := range strings.SplitSeq(body, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case line == "":
			case strings.HasPrefix(line, "match "):
				stmt := strings.TrimPrefix(line, "match ")
				entry.Match = append(entry.Match, stmt)
				entry.MatchPrefixLists = append(entry.MatchPrefixLists, prefixListsFromMatch(stmt)...)
			case strings.HasPrefix(line, "set "):
				entry.Set = append(entry.Set, strings.TrimPrefix(line, "set "))
			case strings.HasPrefix(line, "description "):
				entry.Description = strings.TrimPrefix(line, "description ")
			case strings.HasPrefix(line, "continue "):
				entry.Continue = atoiOrZero(strings.TrimPrefix(line, "continue "))
			}
		}

		rm, ok := byName[name]
		if !ok {
			rm = &RouteMap{Name: name, Entries: []RouteMapEntry{}}
			byName[name] = rm
			order = append(order, name)
		}
		rm.Entries = append(rm.Entries, entry)
	})

	res := make([]RouteMap, 0, len(order))
	for _, name := range order {
		rm := byName[name]
		sort.SliceStable(rm.Entries, func(i, j int) bool {
			return rm.Entries[i].SequenceNumber < rm.Entries[j].SequenceNumber
		})
		res = append(res, *rm)
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

// prefixListsFromMatch reads the prefix-list names out of a match statement,
// returning nil when the statement matches on something else. EOS accepts more
// than one name per statement, as in `match ip address prefix-list A B C`, and
// the names are OR'd together.
func prefixListsFromMatch(stmt string) []string {
	fields := strings.Fields(stmt)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "prefix-list" {
			return fields[i+1:]
		}
	}
	return nil
}

// ParsePrefixLists extracts the IPv4 and IPv6 prefix-lists from
// running-config, handling both the flat one-line form and the block form.
func ParsePrefixLists(runningConfig string) []PrefixList {
	byKey := map[string]*PrefixList{}
	order := []string{}

	get := func(family, name string) *PrefixList {
		key := family + "/" + name
		pl, ok := byKey[key]
		if !ok {
			pl = &PrefixList{Name: name, Family: familyName(family), Entries: []PrefixListEntry{}}
			byKey[key] = pl
			order = append(order, key)
		}
		return pl
	}

	EachTopLevelBlock(runningConfig, func(header, body string) {
		if !strings.HasPrefix(header, "ip prefix-list") && !strings.HasPrefix(header, "ipv6 prefix-list") {
			return
		}

		// Block form: the header carries only the name and the rules are
		// nested beneath it.
		if m := prefixListBlockRe.FindStringSubmatch(header); m != nil {
			pl := get(m[1], m[2])
			for line := range strings.SplitSeq(body, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if entry, ok := parsePrefixListRule(line); ok {
					pl.Entries = append(pl.Entries, entry)
				}
			}
			return
		}

		// Flat form: the whole rule is on the header line.
		if m := prefixListFlatRe.FindStringSubmatch(header); m != nil {
			if entry, ok := parsePrefixListRule(m[3]); ok {
				pl := get(m[1], m[2])
				pl.Entries = append(pl.Entries, entry)
			}
		}
	})

	res := make([]PrefixList, 0, len(order))
	for _, key := range order {
		pl := byKey[key]
		sort.SliceStable(pl.Entries, func(i, j int) bool {
			return pl.Entries[i].SequenceNumber < pl.Entries[j].SequenceNumber
		})
		res = append(res, *pl)
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

// parsePrefixListRule reads the rule portion of a prefix-list line, which is
// everything after the list name: `[seq <n>] permit|deny <prefix> [eq|ge|le <n>]`.
func parsePrefixListRule(rule string) (PrefixListEntry, bool) {
	fields := strings.Fields(rule)
	i := 0
	entry := PrefixListEntry{}

	if i+1 < len(fields) && fields[i] == "seq" {
		entry.SequenceNumber = atoiOrZero(fields[i+1])
		i += 2
	}
	if i >= len(fields) {
		return PrefixListEntry{}, false
	}
	if fields[i] != "permit" && fields[i] != "deny" {
		return PrefixListEntry{}, false
	}
	entry.Action = fields[i]
	i++

	if i >= len(fields) {
		return PrefixListEntry{}, false
	}
	entry.Prefix = fields[i]
	i++

	for ; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "eq":
			entry.Eq = atoiOrZero(fields[i+1])
		case "ge":
			entry.Ge = atoiOrZero(fields[i+1])
		case "le":
			entry.Le = atoiOrZero(fields[i+1])
		}
	}

	return entry, true
}

// familyName maps the configuration keyword to the address family name used
// across the provider's resources.
func familyName(keyword string) string {
	if keyword == "ipv6" {
		return "ipv6"
	}
	return "ipv4"
}
