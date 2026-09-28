// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package inetd parses classic inetd super-server configuration files.
package inetd

import "strings"

// Entry is a single active inetd service line. The columns follow the classic
// inetd.conf layout shared by the FreeBSD, OpenBSD-derived, GNU inetutils, and
// BusyBox daemons:
//
//	[address:]service-name  socket-type  protocol  wait|nowait[.max]  user[.group]  server-program  server-arguments
//
// FreeBSD writes the suffixes as wait|nowait[/max-child[/...]] and
// user[:group][/login-class]. Both forms are kept verbatim.
type Entry struct {
	// Address is the local address the service binds to, empty when it
	// listens on all addresses.
	Address    string
	Name       string
	SocketType string
	Protocol   string
	Wait       string
	User       string
	Server     string
	Arguments  string
	// Line is the 1-based line number where this entry starts within its file.
	Line int
}

// fixedFields is the number of columns every entry must have before the
// optional server arguments.
const fixedFields = 6

// Parse reads inetd.conf content and returns the active service entries.
//
//   - Blank lines and comment lines (those whose first non-whitespace
//     character is #) are skipped, so disabled entries never show up. That
//     includes FreeBSD's #@ IPsec policy lines.
//   - A service name may carry a local address prefix (127.0.0.1:ftp,
//     [::1]:ftp). A line holding only an address and a colon (127.0.0.1:)
//     sets the address for the entries after it, and *: resets it.
//   - A line that starts with a space or tab continues an entry that doesn't
//     yet have all six fixed columns. The BSD daemons read any indented line
//     as a continuation while GNU inetutils and BusyBox don't, so joining is
//     limited to the case where both agree the previous line is incomplete.
//   - A token that starts with a double or single quote runs to the matching
//     quote and may contain spaces.
//
// Entries with fewer than the six fixed columns are treated as malformed and
// ignored.
func Parse(content string) []Entry {
	return (&Parser{}).Parse(content)
}

// Parser reads the files of one inetd configuration in order. The address set
// by an address-only line carries over into the files after it, the way GNU
// inetutils applies it to its drop-in directory.
type Parser struct {
	defaultAddress string
}

// Parse reads one file of the configuration. See the package-level Parse for
// the syntax.
func (p *Parser) Parse(content string) []Entry {
	entries := []Entry{}

	var fields []string
	start := 0
	flush := func() {
		defer func() { fields = nil }()

		if len(fields) == 1 && strings.HasSuffix(fields[0], ":") {
			p.defaultAddress = normalizeAddress(strings.TrimSuffix(fields[0], ":"))
			return
		}
		if len(fields) < fixedFields {
			return
		}

		e := Entry{
			Name:       fields[0],
			SocketType: fields[1],
			Protocol:   fields[2],
			Wait:       fields[3],
			User:       fields[4],
			Server:     fields[5],
			Line:       start,
		}
		if len(fields) > fixedFields {
			e.Arguments = strings.Join(fields[fixedFields:], " ")
		}

		idx := strings.LastIndexByte(e.Name, ':')
		switch {
		case e.Protocol == "unix":
			// Unix-domain services are named by a socket path. FreeBSD lets
			// the path carry a :user:group:mode: ownership prefix, which is
			// not an address.
			if idx >= 0 {
				e.Name = e.Name[idx+1:]
			}
		case idx >= 0:
			e.Address = normalizeAddress(e.Name[:idx])
			e.Name = e.Name[idx+1:]
		default:
			e.Address = p.defaultAddress
		}

		entries = append(entries, e)
	}

	for i, raw := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(raw)

		if strings.HasPrefix(trimmed, "#") {
			flush()
			continue
		}

		indented := raw != "" && (raw[0] == ' ' || raw[0] == '\t')
		if indented && fields != nil && len(fields) < fixedFields {
			fields = append(fields, tokenize(trimmed)...)
			continue
		}

		flush()
		if trimmed == "" {
			continue
		}
		fields = tokenize(trimmed)
		start = i + 1
	}
	flush()

	return entries
}

// normalizeAddress strips IPv6 brackets and maps the wildcard address to an
// empty string.
func normalizeAddress(addr string) string {
	if len(addr) >= 2 && addr[0] == '[' && addr[len(addr)-1] == ']' {
		addr = addr[1 : len(addr)-1]
	}
	if addr == "*" {
		return ""
	}
	return addr
}

// tokenize splits one line into whitespace-separated tokens. A token that
// starts with a quote extends to the matching quote, which is dropped, and the
// next token begins right after it.
func tokenize(line string) []string {
	tokens := []string{}
	for {
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			return tokens
		}

		if q := line[0]; q == '"' || q == '\'' {
			line = line[1:]
			end := strings.IndexByte(line, q)
			if end < 0 {
				return append(tokens, line)
			}
			tokens = append(tokens, line[:end])
			line = line[end+1:]
			continue
		}

		end := strings.IndexAny(line, " \t")
		if end < 0 {
			return append(tokens, line)
		}
		tokens = append(tokens, line[:end])
		line = line[end+1:]
	}
}
