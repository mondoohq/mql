// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ports

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// AixPort is one socket row from the "Active Internet connections" section of
// AIX `netstat -an`. State is the raw AIX token ("LISTEN", "ESTABLISHED", ...)
// and is empty for UDP, which AIX reports without a state column because UDP is
// stateless. The caller maps it onto the canonical state vocabulary.
type AixPort struct {
	// Protocol as AIX reports it, normalised to an address family suffix:
	// tcp4 | tcp6 | udp4 | udp6.
	Protocol      string
	LocalAddress  string
	LocalPort     int64
	RemoteAddress string
	RemotePort    int64
	State         string
}

// AIX writes the protocol as tcp/tcp4/tcp6/udp/udp4/udp6. tcp4 and udp4 are
// IPv4 sockets and tcp6 and udp6 IPv6 sockets that take IPv6 only. A bare tcp
// or udp is an IPv6 socket that takes IPv4 as well: on AIX 7.3 httpd's *.80
// and portmap's *.111 answer on both ::1 and 127.0.0.1, where the tcp4
// listeners refuse ::1. Bound to the wildcard it is a dual-stack listener,
// which Linux reports as tcp6 on [::]; bound to an IPv4 address it takes that
// address only.
var reAixProto = regexp.MustCompile(`^(tcp|udp)([46])?$`)

// ParseAixNetstat reads the "Active Internet connections" section of AIX
// `netstat -an`.
//
// The row shape is BSD-style, so a socket reads `10.10.20.15.32790`: the port is
// appended to the address with a dot rather than a colon, and `*` stands for a
// wildcard. Both `netstat -an` and `netstat -Aan` are accepted; the latter
// prefixes every row with a PCB address, so the protocol column is located by
// pattern rather than by index.
//
// Everything after the "Active UNIX domain sockets" header is ignored: those are
// filesystem sockets with an unrelated column layout and no IP semantics.
func ParseAixNetstat(r io.Reader) ([]AixPort, error) {
	res := []AixPort{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// Unix domain sockets are listed after the internet connections and
		// share none of the columns. Nothing below this header is a socket we
		// can describe as an IP endpoint.
		if strings.HasPrefix(line, "Active UNIX domain sockets") {
			break
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		protoIdx, proto, ok := findAixProto(fields)
		if !ok {
			continue
		}

		// proto Recv-Q Send-Q Local Foreign [state]
		if len(fields) < protoIdx+5 {
			continue
		}

		if proto == "tcp" || proto == "udp" {
			proto += aixBareSocketFamily(fields[protoIdx+3])
		}
		v6 := strings.HasSuffix(proto, "6")
		localAddr, localPort := splitDottedEndpoint(fields[protoIdx+3], v6)
		remoteAddr, remotePort := splitDottedEndpoint(fields[protoIdx+4], v6)

		state := ""
		if len(fields) > protoIdx+5 {
			state = fields[protoIdx+5]
		}

		res = append(res, AixPort{
			Protocol:      proto,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			State:         state,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

// findAixProto locates the protocol column in a netstat row and returns the
// protocol as written; a bare tcp or udp gets its family from the local
// endpoint (see aixBareSocketFamily). The column is found by pattern rather
// than by index because `netstat -Aan` prefixes every row with a PCB address
// while `netstat -an` does not.
//
// ok is false when the row carries no protocol column, which is how header
// lines are skipped.
func findAixProto(fields []string) (int, string, bool) {
	for i, f := range fields {
		m := reAixProto.FindStringSubmatch(f)
		if m == nil {
			continue
		}

		return i, m[1] + m[2], true
	}
	return 0, "", false
}

// aixBareSocketFamily returns the address family suffix of a bare tcp or udp
// row from its local endpoint: 6 for the wildcard, which takes both families,
// and for an IPv6 address, 4 for an IPv4 address.
func aixBareSocketFamily(local string) string {
	addr := local
	if i := strings.LastIndex(local, "."); i >= 0 {
		addr = local[:i]
	}
	if addr == "*" || strings.Contains(addr, ":") {
		return "6"
	}
	return "4"
}

// splitDottedEndpoint splits a BSD-style `address.port` endpoint, the form both
// AIX and Solaris netstat write. `v6` is the row's address family, needed
// because both write the wildcard as a bare `*` on v6 rows too, where it means
// every v6 interface rather than every v4 one.
//
// The separator is the LAST dot, so IPv4 (`10.10.20.15.22`) and IPv6
// (`2001:db8::15.443`) both split correctly. Wildcards are normalised to the
// forms the other platforms emit, so a consumer comparing addresses across
// platforms does not have to special-case AIX or Solaris:
//
//	*.22 (v4) -> 0.0.0.0, port 22 — bound to every interface
//	*.25 (v6) -> [::],    port 25 — same, v6
//	*.*       -> "",      port 0  — no endpoint (an unconnected socket's peer)
//
// An IPv6 literal is bracketed to match the Windows rows.
func splitDottedEndpoint(s string, v6 bool) (string, int64) {
	if s == "" || s == "*.*" {
		return "", 0
	}

	addr, portStr := s, ""
	if i := strings.LastIndex(s, "."); i >= 0 {
		addr, portStr = s[:i], s[i+1:]
	}

	var port int64
	if portStr != "" && portStr != "*" {
		if p, err := strconv.ParseInt(portStr, 10, 64); err == nil {
			port = p
		}
	}

	switch {
	case addr == "*" && v6:
		addr = "[::]"
	case addr == "*":
		addr = "0.0.0.0"
	case strings.Contains(addr, ":"):
		addr = "[" + addr + "]"
	}

	return addr, port
}
