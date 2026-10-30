// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package snmpd

import "strings"

// Communities returns the community strings in content that grant read-only
// and read-write access, in file order.
//
// rocommunity, rocommunity6, rwcommunity, rwcommunity6, and authcommunity
// name the community as their first argument (after the type list for
// authcommunity). com2sec, com2sec6, and com2secunix map a community to a
// security name, which grants access only through a group line and an access
// line whose views are declared: snmpd answers such a community, but with an
// undeclared view or the view "none" it reaches no object. The access line
// must also match the context com2sec assigns with -Cn (none by default). A
// community reached through a write view is read-write, one reached only
// through a read view is read-only.
func Communities(content string) (ro []string, rw []string) {
	ro, rw = []string{}, []string{}
	directives := Parse(content)

	type com2sec struct {
		secName   string
		community string
		context   string
	}
	var mappings []com2sec
	// group name by security name, for community-based models only
	groups := map[string][]string{}
	type accessEntry struct {
		context     string
		prefix      bool
		read, write string
	}
	access := map[string][]accessEntry{}
	views := map[string]bool{}

	for _, d := range directives {
		args := d.Args
		switch strings.ToLower(d.Keyword) {
		case "rocommunity", "rocommunity6":
			if len(args) > 0 {
				ro = append(ro, args[0])
			}
		case "rwcommunity", "rwcommunity6":
			if len(args) > 0 {
				rw = append(rw, args[0])
			}
		case "authcommunity":
			if len(args) < 2 {
				continue
			}
			switch accessFromTypes(parseAccessTypes(args[0])) {
			case AccessReadWrite:
				rw = append(rw, args[1])
			case AccessReadOnly:
				ro = append(ro, args[1])
			}
		case "com2sec", "com2sec6", "com2secunix":
			// [-Cn CONTEXT] SECNAME SOURCE COMMUNITY
			context := ""
			if len(args) > 0 && args[0] == "-Cn" {
				if len(args) < 2 {
					continue
				}
				context = args[1]
				args = args[2:]
			}
			if len(args) < 3 {
				continue
			}
			mappings = append(mappings, com2sec{secName: args[0], community: args[2], context: context})
		case "group":
			// GROUP MODEL SECNAME
			if len(args) < 3 {
				continue
			}
			switch strings.ToLower(args[1]) {
			case "v1", "v2c":
				groups[args[2]] = append(groups[args[2]], args[0])
			}
		case "access":
			// GROUP CONTEXT MODEL LEVEL PREFX READ WRITE NOTIFY
			if len(args) < 7 {
				continue
			}
			switch strings.ToLower(args[2]) {
			case "any", "v1", "v2c":
			default:
				continue
			}
			// A community request is always noAuthNoPriv, so it only
			// matches access lines that require no more than that.
			if level, ok := securityLevels[strings.ToLower(args[3])]; !ok || level != LevelNoAuth {
				continue
			}
			access[args[0]] = append(access[args[0]], accessEntry{
				context: args[1],
				prefix:  strings.EqualFold(args[4], "prefix"),
				read:    args[5],
				write:   args[6],
			})
		case "view":
			// NAME TYPE SUBTREE [MASK]
			if len(args) >= 3 && strings.EqualFold(args[1], "included") {
				views[args[0]] = true
			}
		}
	}

	grants := func(view string) bool {
		return view != "" && view != "none" && views[view]
	}

	for _, m := range mappings {
		read, write := false, false
		for _, g := range groups[m.secName] {
			for _, a := range access[g] {
				// The com2sec context is the context of the request, so a
				// prefix access line matches when it starts with a.context.
				if a.context != m.context && (!a.prefix || !strings.HasPrefix(m.context, a.context)) {
					continue
				}
				read = read || grants(a.read)
				write = write || grants(a.write)
			}
		}
		switch {
		case write:
			rw = append(rw, m.community)
		case read:
			ro = append(ro, m.community)
		}
	}

	return ro, rw
}

// UserNames returns the security names declared by the given user directive
// (rouser or rwuser) in content, in file order. Lines snmpd rejects are
// skipped.
func UserNames(content string, directive string) []string {
	res := []string{}
	for _, u := range Users(content) {
		if u.Directive == directive {
			res = append(res, u.Name)
		}
	}
	return res
}
