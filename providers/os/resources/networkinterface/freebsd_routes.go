// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"encoding/json"
	"net"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// freebsdRouteDetector detects network routes on FreeBSD. It reads the table
// with netstat through the connection, so it answers for the scanned host
// whether mql runs on it or reaches it over SSH.
type freebsdRouteDetector struct {
	conn     shared.Connection
	platform *inventory.Platform
}

// netstatRoutesJSON is the shape of `netstat -rnW --libxo json`, which every
// supported FreeBSD release ships with.
type netstatRoutesJSON struct {
	Statistics struct {
		RouteInformation struct {
			RouteTable struct {
				Families []netstatRouteFamily `json:"rt-family"`
			} `json:"route-table"`
		} `json:"route-information"`
	} `json:"statistics"`
}

type netstatRouteFamily struct {
	// "Internet" or "Internet6"
	AddressFamily string              `json:"address-family"`
	Entries       []netstatRouteEntry `json:"rt-entry"`
}

type netstatRouteEntry struct {
	Destination string   `json:"destination"`
	Gateway     string   `json:"gateway"`
	Flags       string   `json:"flags"`
	FlagsPretty []string `json:"flags_pretty"`
	Interface   string   `json:"interface-name"`
}

// List detects network routes on FreeBSD.
func (d *freebsdRouteDetector) List() ([]Route, error) {
	output, err := runCommand(d.conn, d.platform, "netstat -rnW --libxo json")
	if err != nil {
		return nil, errors.Wrap(err, "failed to run netstat")
	}
	return parseFreebsdNetstatRoutes(output)
}

// parseFreebsdNetstatRoutes converts `netstat -rnW --libxo json` into routes,
// in the formats the Darwin detector reports for the same BSD routing table:
//
//   - a default route reads 0.0.0.0/0 or ::/0 rather than netstat's "default",
//     which it prints for both families
//   - a host route without a prefix gains /32 or /128
//   - a link-level gateway stays link#N and a scoped destination keeps its
//     %ifname zone (fe80::%ena0/64)
//   - flags use the bsdRouteFlagsMap names (UP, GATEWAY, STATIC, ...)
//
// Reject and blackhole routes are left out, as on Linux: FreeBSD installs
// them for ::/96, ::ffff:0.0.0.0/96, fe80::/10 and ff02::/16 on every host,
// and they discard traffic rather than carry it. IPv6 multicast destinations
// are left out as on Linux and Darwin.
func parseFreebsdNetstatRoutes(output string) ([]Route, error) {
	var parsed netstatRoutesJSON
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil, errors.Wrap(err, "failed to parse netstat JSON output")
	}

	routes := []Route{}
	for _, family := range parsed.Statistics.RouteInformation.RouteTable.Families {
		var ipv6 bool
		switch family.AddressFamily {
		case "Internet":
			ipv6 = false
		case "Internet6":
			ipv6 = true
		default:
			// netstat -rn lists only inet and inet6 without -f, but skip
			// anything else rather than mislabel it.
			continue
		}

		for _, entry := range family.Entries {
			flags := freebsdRouteFlags(entry.FlagsPretty)
			if routeFlagsRejected(flags) {
				continue
			}

			dest := freebsdRouteDestination(entry.Destination, ipv6, flags)
			if dest == "" {
				continue
			}
			if ipv6 && strings.HasPrefix(dest, "ff") {
				continue
			}

			routes = append(routes, Route{
				Destination: dest,
				Gateway:     entry.Gateway,
				Flags:       flags,
				Interface:   entry.Interface,
			})
		}
	}

	return routes, nil
}

// freebsdRouteFlags turns netstat's flags_pretty names ("up", "gateway",
// "static") into the names bsdRouteFlagsMap uses for the same RTF_* bits,
// which are the upper-cased netstat names.
func freebsdRouteFlags(pretty []string) []string {
	flags := make([]string, 0, len(pretty))
	seen := make(map[string]struct{}, len(pretty))
	for _, f := range pretty {
		name := strings.ToUpper(strings.TrimSpace(f))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		flags = append(flags, name)
	}
	sort.Strings(flags)
	return flags
}

// freebsdRouteDestination normalizes a netstat destination.
func freebsdRouteDestination(dest string, ipv6 bool, flags []string) string {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return ""
	}

	if dest == "default" {
		if ipv6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}

	if strings.Contains(dest, "/") {
		return dest
	}

	// A host route carries no prefix in netstat's output. The route matches
	// the one address exactly, so spell out the full-length prefix the way
	// the other detectors report every destination.
	isHost := false
	for _, f := range flags {
		if f == "HOST" {
			isHost = true
			break
		}
	}
	if !isHost {
		return dest
	}

	addr := dest
	if pct := strings.Index(addr, "%"); pct != -1 {
		addr = addr[:pct]
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return dest
	}
	if ip.To4() != nil && !ipv6 {
		return dest + "/32"
	}
	return dest + "/128"
}
