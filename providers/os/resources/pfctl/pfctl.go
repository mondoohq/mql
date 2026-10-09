// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package pfctl parses the output of pfctl(8), the control program of the
// PF packet filter on FreeBSD, OpenBSD, macOS and Oracle Solaris 11.4.
package pfctl

import (
	"errors"
	"strings"
)

// Rule is one rule of the loaded ruleset as `pfctl -s rules` prints it.
// pfctl prints rules in a normalized form: lists in braces are expanded into
// one rule per element, `set block-policy` is folded into each block rule,
// and `from any to any` is printed as `all`.
type Rule struct {
	// Raw is the rule exactly as pfctl printed it.
	Raw string
	// Action is the leading keyword: pass, block, match, scrub, anchor,
	// "no scrub", and so on.
	Action string
	// BlockPolicy is how a block rule blocks: drop, return, return-rst,
	// return-icmp or return-icmp6. Empty for other actions.
	BlockPolicy string
	// Direction is in or out, empty when the rule applies to both.
	Direction string
	Quick     bool
	Log       bool
	// Interface is the interface or interface group after `on`, with a
	// leading "! " when negated.
	Interface string
	// AddressFamily is inet or inet6, empty for both.
	AddressFamily string
	Protocol      string
	From          string
	FromPort      string
	To            string
	ToPort        string
	// State is "keep state", "modulate state", "synproxy state" or
	// "no state" for pass rules, empty for other actions.
	State  string
	Label  string
	Anchor string
}

// ParseInfo reads the Status line of `pfctl -s info` and reports whether PF
// is enabled.
func ParseInfo(out string) (bool, error) {
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Status:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			break
		}
		switch fields[0] {
		case "Enabled":
			return true, nil
		case "Disabled":
			return false, nil
		}
		return false, errors.New("unexpected pfctl status " + fields[0])
	}
	return false, errors.New("pfctl -s info printed no Status line")
}

// ParseRules parses `pfctl -s rules`. Lines that start with whitespace are
// the counters `-v` adds below a rule and are skipped.
func ParseRules(out string, services Services) []Rule {
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rules = append(rules, ParseRule(line, services))
	}
	return rules
}

// ParseRule parses one rule as pfctl prints it. services resolves the port
// names pfctl prints (`port = ssh`) to numbers; it may be nil.
func ParseRule(line string, services Services) Rule {
	r := Rule{Raw: line}
	toks := tokenize(line)
	if len(toks) == 0 {
		return r
	}

	i := 0
	r.Action = toks[0]
	i++
	if r.Action == "no" && i < len(toks) {
		r.Action += " " + toks[i]
		i++
	}
	if strings.HasSuffix(r.Action, "anchor") && i < len(toks) && strings.HasPrefix(toks[i], `"`) {
		r.Anchor = unquote(toks[i])
		i++
	}

	next := func() string {
		if i+1 < len(toks) {
			i++
			return toks[i]
		}
		return ""
	}
	peek := func() string {
		if i+1 < len(toks) {
			return toks[i+1]
		}
		return ""
	}
	skipGroup := func() {
		if strings.HasPrefix(peek(), "(") {
			i++
		}
	}
	// address reads an address after from or to, and the port that may
	// follow it.
	address := func() (string, string) {
		addr := next()
		if addr == "!" {
			addr = "! " + next()
		}
		port := ""
		if peek() == "port" {
			i++
			port = readPort(toks, &i)
		}
		return addr, port
	}

	for ; i < len(toks); i++ {
		switch tok := toks[i]; tok {
		case "drop", "return", "return-rst", "return-icmp", "return-icmp6":
			if r.Action == "block" && r.BlockPolicy == "" {
				r.BlockPolicy = tok
				skipGroup()
			}
		case "port":
			// a port outside from and to, such as the target of rdr-to
			readPort(toks, &i)
		case "in", "out":
			if r.Direction == "" && r.From == "" {
				r.Direction = tok
			}
		case "log":
			r.Log = true
			skipGroup()
		case "quick":
			r.Quick = true
		case "on":
			iface := next()
			if iface == "!" {
				iface = "! " + next()
			}
			r.Interface = iface
		case "inet", "inet6":
			r.AddressFamily = tok
		case "proto":
			r.Protocol = next()
		case "all":
			r.From, r.To = "any", "any"
		case "from":
			r.From, r.FromPort = address()
		case "to":
			r.To, r.ToPort = address()
		case "keep", "modulate", "synproxy":
			if peek() == "state" {
				r.State = tok + " state"
				i++
			}
		case "no":
			if peek() == "state" {
				r.State = "no state"
				i++
			}
		case "label":
			r.Label = unquote(next())
		default:
			// return-icmp and return-icmp6 may carry their codes attached:
			// return-icmp(port-unr)
			if base, _, ok := strings.Cut(tok, "("); ok && r.Action == "block" && r.BlockPolicy == "" &&
				(base == "return-icmp" || base == "return-icmp6") {
				r.BlockPolicy = base
			}
		}
	}

	// Pass rules keep state unless they say otherwise. OpenBSD's pfctl, and
	// Solaris's, which derives from it, print `keep state` only when the
	// rule carries state options.
	if r.Action == "pass" && r.State == "" {
		r.State = "keep state"
	}
	r.FromPort = services.normalizePort(r.FromPort, r.Protocol)
	r.ToPort = services.normalizePort(r.ToPort, r.Protocol)
	return r
}

var portOps = map[string]bool{"=": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true}

// readPort reads the port expression after the `port` keyword at toks[*i]:
// `= ssh`, `> 1024`, `6000:6010`, or `1000 >< 2000`.
func readPort(toks []string, i *int) string {
	if *i+1 >= len(toks) {
		return ""
	}
	*i++
	first := toks[*i]
	if portOps[first] && *i+1 < len(toks) {
		*i++
		return first + " " + toks[*i]
	}
	if *i+2 < len(toks) && (toks[*i+1] == "><" || toks[*i+1] == "<>") {
		expr := first + " " + toks[*i+1] + " " + toks[*i+2]
		*i += 2
		return expr
	}
	return first
}

// tokenize splits a rule on whitespace, keeping a quoted string, a
// parenthesized group and a braced list as one token each.
func tokenize(line string) []string {
	var toks []string
	var cur strings.Builder
	depth := 0
	var closer byte
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for j := 0; j < len(line); j++ {
		c := line[j]
		switch {
		case inQuote:
			cur.WriteByte(c)
			if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
			cur.WriteByte(c)
		case depth > 0:
			cur.WriteByte(c)
			if c == closer {
				depth--
			} else if (c == '(' && closer == ')') || (c == '{' && closer == '}') {
				depth++
			}
		case c == '(' || c == '{':
			if c == '(' {
				closer = ')'
			} else {
				closer = '}'
			}
			depth = 1
			cur.WriteByte(c)
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ParseTables parses `pfctl -s Tables`, one table name per line.
func ParseTables(out string) []string {
	return nonEmptyLines(out)
}

// ParseTableAddresses parses `pfctl -t <table> -T show`, one address or
// network per indented line.
func ParseTableAddresses(out string) []string {
	return nonEmptyLines(out)
}

// ParseSkipInterfaces parses `pfctl -s Interfaces -v` and returns the
// interfaces marked `(skip)`, the ones `set skip on` excludes from filtering.
func ParseSkipInterfaces(out string) []string {
	res := []string{}
	for _, line := range strings.Split(out, "\n") {
		name, flags, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if strings.Contains(flags, "(skip)") {
			res = append(res, name)
		}
	}
	return res
}

func nonEmptyLines(out string) []string {
	res := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			res = append(res, line)
		}
	}
	return res
}

// ErrorKind tells why pfctl failed.
type ErrorKind int

const (
	// ErrorOther is any failure not listed below.
	ErrorOther ErrorKind = iota
	// ErrorRefused is a caller without the privileges to open /dev/pf.
	ErrorRefused
	// ErrorNotLoaded is a kernel without PF: /dev/pf does not exist, as on
	// FreeBSD before pf.ko is loaded.
	ErrorNotLoaded
)

// ClassifyError reads what pfctl printed to stderr when it failed.
func ClassifyError(stderr string) ErrorKind {
	switch {
	case strings.Contains(stderr, "Permission denied"), strings.Contains(stderr, "Operation not permitted"):
		return ErrorRefused
	case strings.Contains(stderr, "/dev/pf: No such file or directory"):
		return ErrorNotLoaded
	}
	return ErrorOther
}
