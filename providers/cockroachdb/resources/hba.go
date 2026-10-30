// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"strings"
)

// hbaRule is one rule of server.host_based_authentication.configuration.
type hbaRule struct {
	position       int
	connectionType string
	databases      []string
	users          []string
	address        string
	method         string
	options        map[string]string
	line           string
}

func (r hbaRule) optionsAny() map[string]any {
	out := make(map[string]any, len(r.options))
	for k, v := range r.options {
		out[k] = v
	}
	return out
}

// parseHBA parses the host-based authentication configuration, which uses the
// pg_hba.conf syntax: one rule per line, "TYPE DATABASE USER [ADDRESS] METHOD
// [OPTION=VALUE ...]", where local rules have no address, databases and users
// are comma-separated lists, a token may be double-quoted, and "#" starts a
// comment. Lines CockroachDB would reject are skipped; the setting cannot hold
// them, because CockroachDB validates it when it is set.
func parseHBA(conf string) []hbaRule {
	rules := []hbaRule{}
	for raw := range strings.SplitSeq(conf, "\n") {
		tokens := hbaTokens(raw)
		if len(tokens) < 4 {
			continue
		}
		rule := hbaRule{
			position:       len(rules) + 1,
			connectionType: tokens[0],
			databases:      splitList(tokens[1]),
			users:          splitList(tokens[2]),
			options:        map[string]string{},
			line:           strings.TrimSpace(stripComment(raw)),
		}
		rest := tokens[3:]
		if rule.connectionType != "local" {
			if len(rest) < 2 {
				continue
			}
			rule.address = rest[0]
			rest = rest[1:]
			// An address may be an IP followed by a separate netmask.
			if !strings.Contains(rule.address, "/") && net.ParseIP(rule.address) != nil &&
				len(rest) > 1 && net.ParseIP(rest[0]) != nil {
				rule.address += " " + rest[0]
				rest = rest[1:]
			}
		}
		rule.method = rest[0]
		for _, opt := range rest[1:] {
			k, v, _ := strings.Cut(opt, "=")
			rule.options[k] = v
		}
		rules = append(rules, rule)
	}
	return rules
}

// stripComment removes a "#" comment that is not inside double quotes.
func stripComment(line string) string {
	inQuote := false
	for i, c := range line {
		switch c {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

// hbaTokens splits a line into whitespace-separated tokens, keeping
// double-quoted runs together and dropping the quotes.
func hbaTokens(line string) []string {
	line = stripComment(line)
	var tokens []string
	var cur strings.Builder
	inQuote, inToken := false, false
	for _, c := range line {
		switch {
		case c == '"':
			inQuote = !inQuote
			inToken = true
		case !inQuote && (c == ' ' || c == '\t' || c == '\r'):
			if inToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(c)
			inToken = true
		}
	}
	if inToken {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// splitList splits a comma-separated database or user list.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
