// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// ipRouteJSON represents a route entry from 'ip -json route show table all'
type ipRouteJSON struct {
	Dst      string   `json:"dst"`
	Gateway  string   `json:"gateway,omitempty"`
	Dev      string   `json:"dev"`
	Type     string   `json:"type,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Table    string   `json:"table,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	Prefsrc  string   `json:"prefsrc,omitempty"`
	Metric   int      `json:"metric,omitempty"`
	Pref     string   `json:"pref,omitempty"`
	Flags    []string `json:"flags,omitempty"`
}

// List detects network routes on Linux
func (l *linuxRouteDetector) List() ([]Route, error) {
	routes, err := l.getRoutesFromProcFs()
	if err == nil {
		return routes, nil
	}
	log.Debug().Err(err).Msg("Failed to get routes from proc fs, falling back to ip route show table all")

	// use ip route command as fallback in case the proc fs doesn't work for some reason
	output, err := runCommand(l.conn, l.platform, "ip -json route show table all")
	if err == nil {
		routes, err := l.parseIpRouteJSON(output)
		if err == nil {
			return routes, nil
		}
		log.Debug().Err(err).Msg("Failed to parse ip route JSON output")
	}

	return nil, errors.New("failed to get network routes")
}

func (l *linuxRouteDetector) getRoutesFromProcFs() ([]Route, error) {
	ipv4Data, err := afero.ReadFile(l.conn.FileSystem(), "/proc/net/route")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read /proc/net/route")
	}

	ipv4Routes, err := l.parseLinuxRoutesFromProc(string(ipv4Data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse IPv4 routes from /proc/net/route")
	}

	ipv6Data, err := afero.ReadFile(l.conn.FileSystem(), "/proc/net/ipv6_route")
	var ipv6Routes []Route
	if err == nil {
		ipv6Routes, err = l.parseLinuxIPv6RoutesFromProc(string(ipv6Data))
		if err != nil {
			// Some alpine systems may not have IPv6 enabled
			log.Debug().Err(err).Msg("Failed to parse IPv6 routes from /proc/net/ipv6_route")
			ipv6Routes = []Route{}
		}
	}
	return append(ipv4Routes, ipv6Routes...), nil
}

// parseIpRouteJSON parses JSON output from 'ip -json route show table all'
func (l *linuxRouteDetector) parseIpRouteJSON(output string) ([]Route, error) {
	var jsonRoutes []ipRouteJSON
	if err := json.Unmarshal([]byte(output), &jsonRoutes); err != nil {
		return nil, errors.Wrap(err, "failed to parse ip route JSON output")
	}

	var routes []Route
	for _, jsonRoute := range jsonRoutes {
		route := l.convertJSONRouteToRoute(jsonRoute)
		if route != nil {
			routes = append(routes, *route)
		}
	}

	return routes, nil
}

// convertJSONRouteToRoute converts an ipRouteJSON to a Route
func (l *linuxRouteDetector) convertJSONRouteToRoute(jsonRoute ipRouteJSON) *Route {
	// `ip route show table all` includes the entries the kernel installs to
	// discard traffic. They are not paths anything travels over, and counting
	// an unreachable ::/0 as a default route makes a host without IPv6
	// connectivity look like it has some.
	switch jsonRoute.Type {
	case "unreachable", "blackhole", "prohibit", "throw":
		return nil
	}

	route := &Route{
		Interface: jsonRoute.Dev,
		Gateway:   jsonRoute.Gateway,
		Table:     jsonRoute.Table,
		Protocol:  jsonRoute.Protocol,
		Scope:     jsonRoute.Scope,
		Metric:    int64(jsonRoute.Metric),
		Source:    jsonRoute.Prefsrc,
		Type:      jsonRoute.Type,
	}

	dest := jsonRoute.Dst
	if dest == "default" {
		var family string
		if ip := net.ParseIP(jsonRoute.Gateway); ip != nil {
			if ip.To4() != nil {
				family = "v4"
			} else {
				family = "v6"
			}
		} else if ip := net.ParseIP(jsonRoute.Prefsrc); ip != nil {
			if ip.To4() != nil {
				family = "v4"
			} else {
				family = "v6"
			}
		}

		if family == "v6" {
			dest = "::"
		} else {
			dest = "0.0.0.0"
		}
	}
	route.Destination = dest
	route.Flags = jsonRoute.Flags

	return route
}

// parseLinuxRoutesFromProc parses IPv4 routes from /proc/net/route output
// Format: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
func (l *linuxRouteDetector) parseLinuxRoutesFromProc(output string) ([]Route, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return nil, errors.New("invalid /proc/net/route format")
	}

	// Skip header line
	var routes []Route
	for i := 1; i < len(lines); i++ {
		line := strings.Fields(lines[i])
		if len(line) < 11 {
			continue
		}

		iface := line[0]
		destHex := line[1]
		gatewayHex := line[2]
		flagsHex := line[3]
		maskHex := line[7]

		// Parse hex values
		dest, err := hexToIP(destHex)
		if err != nil {
			continue
		}
		gateway, err := hexToIP(gatewayHex)
		if err != nil {
			continue
		}
		mask, err := hexToIP(maskHex)
		if err != nil {
			continue
		}

		destStr := dest.String()
		// Calculate CIDR from netmask
		if mask.To4() != nil {
			ones, _ := net.IPMask(mask.To4()).Size()
			destStr = fmt.Sprintf("%s/%d", dest.String(), ones)
		}

		// Handle default route
		if dest.Equal(net.IPv4zero) {
			destStr = "0.0.0.0/0"
		}

		// Parse flags (hex to int)
		flagsInt, err := strconv.ParseUint(flagsHex, 16, 32)
		if err != nil {
			flagsInt = 0
		}

		flags := parseLinuxRouteFlags(int64(flagsInt))
		var metric int64
		if v, err := strconv.ParseInt(line[6], 10, 64); err == nil {
			metric = v
		}

		// Same discard entries the IPv6 table and `ip route` paths drop. The
		// kernel's fib_flag_trans sets RTF_REJECT for unreachable and prohibit
		// routes; blackhole carries no flag of its own here, so only the JSON
		// path can tell that one apart.
		if routeFlagsRejected(flags) {
			continue
		}

		// Handle gateway
		gatewayStr := gateway.String()
		if gateway.Equal(net.IPv4zero) {
			gatewayStr = ""
		}

		routes = append(routes, Route{
			Destination: destStr,
			Gateway:     gatewayStr,
			Flags:       flags,
			Interface:   iface,
			Table:       "main",
			Metric:      metric,
		})
	}

	return routes, nil
}

// parseLinuxIPv6RoutesFromProc parses IPv6 routes from /proc/net/ipv6_route output
// Format: destination dest_prefix_len source src_prefix_len next_hop metric ref use flags device
func (l *linuxRouteDetector) parseLinuxIPv6RoutesFromProc(output string) ([]Route, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return []Route{}, nil
	}

	var routes []Route
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		destHex := fields[0]
		prefixLenHex := fields[1] // Destination prefix length (stored as hex string representing decimal)
		nextHopHex := fields[4]   // Next hop is at index 4
		flagsHex := fields[8]
		device := fields[9]

		// Parse destination IPv6 address (32 hex chars = 128 bits)
		dest, err := hexToIPv6(destHex)
		if err != nil {
			continue
		}

		// Parse prefix length (hex string representing decimal value)
		// "00" = 0, "80" = 128 (hex 0x80 = decimal 128)
		prefixLen, err := strconv.ParseInt(prefixLenHex, 16, 32)
		if err != nil {
			continue
		}

		// Format destination with CIDR
		destStr := fmt.Sprintf("%s/%d", dest.String(), int(prefixLen))

		// Handle default route
		if dest.Equal(net.IPv6zero) {
			destStr = "::/0"
		}

		// Parse next hop
		nextHop, err := hexToIPv6(nextHopHex)
		var gatewayStr string
		if err == nil && !nextHop.Equal(net.IPv6zero) {
			gatewayStr = nextHop.String()
		} else {
			gatewayStr = "::"
		}

		// Filter out IPv6 multicast routes (ff00::/8) to match osquery results
		if strings.HasPrefix(destStr, "ff00::") || strings.HasPrefix(destStr, "ff") {
			continue
		}

		flagsInt, err := strconv.ParseUint(flagsHex, 16, 64)
		if err != nil {
			flagsInt = 0
		}
		flags := parseLinuxIPv6RouteFlags(int64(flagsInt))

		// The kernel installs a reject route for every destination it knows is
		// unreachable, including a ::/0 one on hosts with no IPv6 default
		// route. Those discard traffic rather than carry it, so reporting them
		// makes a host look like it has a default route when it does not.
		if routeFlagsRejected(flags) {
			continue
		}

		// The metric sits in the sixth column as a hex value.
		var metric int64
		if v, err := strconv.ParseInt(fields[5], 16, 64); err == nil {
			metric = v
		}

		// /proc/net/ipv6_route holds the routes of every table and names
		// none of them, so the table stays empty rather than claiming main.
		routes = append(routes, Route{
			Destination: destStr,
			Gateway:     gatewayStr,
			Flags:       flags,
			Interface:   device,
			Metric:      metric,
		})
	}

	return routes, nil
}

// hexToIP converts a hex string (little-endian) to net.IP (IPv4)
func hexToIP(hexStr string) (net.IP, error) {
	val, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return nil, err
	}
	// Convert from little-endian to IP
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, uint32(val))
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]), nil
}

// hexToIPv6 converts a hex string (32 hex chars) to net.IP (IPv6)
func hexToIPv6(hexStr string) (net.IP, error) {
	if len(hexStr) != 32 {
		return nil, fmt.Errorf("invalid IPv6 hex string length: %d", len(hexStr))
	}

	ip := make(net.IP, 16)
	_, err := hex.Decode(ip, []byte(hexStr))
	if err != nil {
		return nil, err
	}

	return ip, nil
}
