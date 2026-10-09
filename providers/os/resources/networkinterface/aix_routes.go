// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"bufio"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// aixRouteDetector detects network routes on AIX.
type aixRouteDetector struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (d *aixRouteDetector) List() ([]Route, error) {
	// netstat -rnv on AIX prints adapter statistics, not more route columns
	output, err := runCommand(d.conn, d.platform, "netstat -rn")
	if err != nil {
		return nil, errors.Wrap(err, "failed to run netstat")
	}
	return parseAixNetstatRoutes(output), nil
}

// The flag letters of AIX netstat -r, named the way bsdRouteFlagsMap names
// the same RTF_* bits.
var aixRouteFlags = map[rune]string{
	'U': "UP",
	'G': "GATEWAY",
	'H': "HOST",
	'D': "DYNAMIC",
	'M': "MODIFIED",
	'C': "CLONING",
	'c': "PRCLONING",
	'X': "XRESOLVE",
	'L': "LLINFO",
	'S': "STATIC",
	'B': "BLACKHOLE",
	'R': "REJECT",
	'W': "WASCLONED",
	'P': "PINNED",
	'l': "LOCAL",
	'b': "BROADCAST",
}

// parseAixNetstatRoutes reads AIX `netstat -rn`, which prints one route tree
// per address family:
//
//	Route tree for Protocol Family 2 (Internet):
//	default            192.168.234.33    UG        4         0 en0      -      -
//	127/8              127.0.0.1         U        11         0 lo0      -      -
//	198.51.100/24      192.168.234.33    UG        0         0 en0      -      -
//
//	Route tree for Protocol Family 24 (Internet v6):
//	::1%1              ::1%1             UH        0         0 lo0      -      -
//	fe80::80de:eff:fe65:c1a                   UHXLWl    2         0 lo0      -      -
//
// IPv4 network destinations leave out trailing zero octets, and a route to a
// local address can leave the gateway column empty. Destinations are written
// the way the other platforms report them: default as 0.0.0.0/0 or ::/0, and
// every destination with its prefix length. Reject and blackhole routes are
// left out, as on Linux, Solaris and FreeBSD, as are IPv6 multicast
// destinations and the neighbor entries the link layer adds to the IPv6 tree.
// A route to one of the host's own addresses is kept, as for IPv4.
func parseAixNetstatRoutes(output string) []Route {
	routes := []Route{}
	family := ""

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Route tree for Protocol Family 2 "):
			family = "ipv4"
			continue
		case strings.HasPrefix(line, "Route tree for Protocol Family 24 "):
			family = "ipv6"
			continue
		case strings.HasPrefix(line, "Route tree for"):
			family = ""
			continue
		}

		fields := strings.Fields(line)
		if family == "" || len(fields) < 5 || fields[0] == "Destination" {
			continue
		}

		// Destination [Gateway] Flags Refs Use If ...: the flags are the
		// column the two counters follow.
		flagIdx := -1
		for i := 1; i+3 < len(fields) && i <= 2; i++ {
			if isAixCounter(fields[i+1]) && isAixCounter(fields[i+2]) {
				flagIdx = i
				break
			}
		}
		if flagIdx < 0 {
			continue
		}
		gateway := ""
		if flagIdx == 2 {
			gateway = fields[1]
		}
		iface := fields[flagIdx+3]

		var dest string
		if family == "ipv4" {
			dest = aixIPv4Destination(fields[0])
		} else {
			dest = aixIPv6Destination(fields[0])
			gateway = stripZone(gateway)
		}
		if dest == "" {
			continue
		}
		if family == "ipv6" && strings.HasPrefix(dest, "ff") {
			continue
		}

		flags := parseAixRouteFlags(fields[flagIdx])
		// a neighbor entry carries link-layer information and is not one of
		// the host's own addresses
		if routeFlagsRejected(flags) || (hasFlag(flags, "LLINFO") && !hasFlag(flags, "LOCAL")) {
			continue
		}

		routes = append(routes, Route{
			Destination: dest,
			Gateway:     gateway,
			Flags:       flags,
			Interface:   iface,
		})
	}

	return routes
}

func isAixCounter(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// aixIPv4Destination expands a destination of AIX netstat. Networks leave out
// their trailing zero octets (127/8, 198.51.100/24); a destination without a
// prefix length is a host.
func aixIPv4Destination(dest string) string {
	if dest == "default" {
		return "0.0.0.0/0"
	}
	addr, prefix, hasPrefix := strings.Cut(dest, "/")
	octets := strings.Split(addr, ".")
	if len(octets) > 4 {
		return ""
	}
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	ip := net.ParseIP(strings.Join(octets, ".")).To4()
	if ip == nil {
		return ""
	}
	if !hasPrefix {
		return ip.String() + "/32"
	}
	if n, err := strconv.Atoi(prefix); err != nil || n < 0 || n > 32 {
		return ""
	}
	return ip.String() + "/" + prefix
}

func aixIPv6Destination(dest string) string {
	if dest == "default" {
		return "::/0"
	}
	addr, prefix, hasPrefix := strings.Cut(dest, "/")
	addr = stripZone(addr)
	if net.ParseIP(addr) == nil {
		return ""
	}
	if !hasPrefix {
		return addr + "/128"
	}
	if n, err := strconv.Atoi(prefix); err != nil || n < 0 || n > 128 {
		return ""
	}
	return addr + "/" + prefix
}

// stripZone drops the zone of an IPv6 address: ::1%1 is ::1 on interface 1.
func stripZone(addr string) string {
	addr, _, _ = strings.Cut(addr, "%")
	return addr
}

func parseAixRouteFlags(col string) []string {
	flags := []string{}
	for _, r := range col {
		if name, ok := aixRouteFlags[r]; ok {
			flags = append(flags, name)
		}
	}
	sort.Strings(flags)
	return flags
}

func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}
