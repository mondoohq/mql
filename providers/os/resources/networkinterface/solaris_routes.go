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

// solarisRouteDetector detects network routes on Solaris and illumos.
type solarisRouteDetector struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (d *solarisRouteDetector) List() ([]Route, error) {
	output, err := runCommand(d.conn, d.platform, "netstat -rnv")
	if err != nil {
		return nil, errors.Wrap(err, "failed to run netstat")
	}
	return parseSolarisNetstatRoutes(output), nil
}

// The flag letters of Solaris netstat -r, named the way bsdRouteFlagsMap names
// the same RTF_* bits.
var solarisRouteFlags = map[rune]string{
	'U': "UP",
	'G': "GATEWAY",
	'H': "HOST",
	'D': "DYNAMIC",
	'M': "MODIFIED",
	'A': "ADDRCONF",
	'B': "BROADCAST",
	'L': "LOCAL",
	'R': "REJECT",
	'b': "BLACKHOLE",
	'S': "STATIC",
	'P': "PINNED",
}

// parseSolarisNetstatRoutes reads Solaris `netstat -rnv`, which prints an IPv4
// and an IPv6 table. -v adds the IPv4 mask, which plain -r leaves out, so a
// network route can be told from a host route:
//
//	IRE Table: IPv4
//	  Destination             Mask           Gateway          Device  MTU  Ref Flg  Out  In/Fwd
//	default              0.0.0.0         10.77.1.1            net0    9000   3 UG   77522      0
//
//	IRE Table: IPv6
//	  Destination/Mask            Gateway                    If    MTU  Ref Flags  Out   In/Fwd
//	fe80::/10                   fe80::17ff:fe04:b9e2        net0   9000   2 U          0      0
//
// Destinations are written the way the other platforms report them: default
// as 0.0.0.0/0 or ::/0, and every destination with its prefix length. Reject
// and blackhole routes are left out, as on Linux and FreeBSD, as are IPv6
// multicast destinations.
func parseSolarisNetstatRoutes(output string) []Route {
	routes := []Route{}
	family := ""

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "IRE Table: IPv4"), strings.HasPrefix(line, "Routing Table: IPv4"):
			family = "ipv4"
			continue
		case strings.HasPrefix(line, "IRE Table: IPv6"), strings.HasPrefix(line, "Routing Table: IPv6"):
			family = "ipv6"
			continue
		}

		fields := strings.Fields(line)
		if family == "" || len(fields) < 6 || strings.HasPrefix(fields[0], "-") || fields[0] == "Destination" || fields[0] == "Destination/Mask" {
			continue
		}

		// A route bound to no interface leaves the device column blank, which
		// shifts the MTU into its place.
		devIdx := 3
		if family == "ipv6" {
			devIdx = 2
		}
		if _, err := strconv.Atoi(fields[devIdx]); err == nil {
			fields = append(fields[:devIdx], append([]string{""}, fields[devIdx:]...)...)
		}

		var dest, gateway, iface, flagCol string
		if family == "ipv4" {
			// Destination Mask Gateway Device MTU Ref Flg Out In/Fwd
			if len(fields) < 9 {
				continue
			}
			dest = solarisIPv4Destination(fields[0], fields[1])
			gateway, iface, flagCol = fields[2], fields[3], fields[6]
		} else {
			// Destination/Mask Gateway If MTU Ref Flags Out In/Fwd
			if len(fields) < 8 {
				continue
			}
			dest = solarisIPv6Destination(fields[0])
			gateway, iface, flagCol = fields[1], fields[2], fields[5]
		}
		if dest == "" {
			continue
		}
		if family == "ipv6" && strings.HasPrefix(dest, "ff") {
			continue
		}

		flags := parseSolarisRouteFlags(flagCol)
		if routeFlagsRejected(flags) {
			continue
		}

		// a route through a logical interface names it net0:1
		iface, _, _ = strings.Cut(iface, ":")

		routes = append(routes, Route{
			Destination: dest,
			Gateway:     gateway,
			Flags:       flags,
			Interface:   iface,
		})
	}

	return routes
}

func solarisIPv4Destination(dest string, mask string) string {
	if dest == "default" {
		return "0.0.0.0/0"
	}
	if net.ParseIP(dest) == nil {
		return ""
	}
	m := net.ParseIP(mask).To4()
	if m == nil {
		return dest + "/32"
	}
	ones, _ := net.IPv4Mask(m[0], m[1], m[2], m[3]).Size()
	return dest + "/" + strconv.Itoa(ones)
}

func solarisIPv6Destination(dest string) string {
	if dest == "default" {
		return "::/0"
	}
	addr, _, hasPrefix := strings.Cut(dest, "/")
	if net.ParseIP(addr) == nil {
		return ""
	}
	if !hasPrefix {
		return dest + "/128"
	}
	return dest
}

func parseSolarisRouteFlags(col string) []string {
	flags := []string{}
	for _, r := range col {
		name, ok := solarisRouteFlags[r]
		if !ok {
			name = string(r)
		}
		flags = append(flags, name)
	}
	sort.Strings(flags)
	return flags
}
