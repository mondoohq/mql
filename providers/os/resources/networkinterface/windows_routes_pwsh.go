// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

const (
	// Windows AddressFamily constants from Get-NetRoute
	addressFamilyIPv4 = 2  // AF_INET
	addressFamilyIPv6 = 23 // AF_INET6
)

// listViaCommands asks the target for its routes: Get-NetRoute, then netstat.
// It is the path for every connection except a local one on Windows.
func (w *windowsRouteDetector) listViaCommands() ([]Route, error) {
	routes, err := w.detectWindowsRoutesViaPowerShell()
	if err == nil && len(routes) > 0 {
		return routes, nil
	}
	log.Debug().Err(err).Int("routeCount", len(routes)).Msg("PowerShell Get-NetRoute failed or returned no routes, trying netstat")
	return w.detectWindowsRoutesViaNetstat()
}

// getNetRouteScript lists the routes with the first address of each route's
// interface and address family. The addresses are read once into a table: a
// Get-NetIPAddress per route (a CIM query each) made the script about 18x
// slower on a host with 26 routes. The list is passed with -InputObject so a
// host with one route still gets an array. Both cmdlets key the table with
// [int]$_.AddressFamily, so the keys match whether a PowerShell version
// returns the family as the CIM enum or as its number.
const getNetRouteScript = `$addrs = @{}
Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object {
	$key = "$($_.InterfaceIndex)|$([int]$_.AddressFamily)"
	if (-not $addrs.ContainsKey($key)) { $addrs[$key] = $_.IPAddress }
}
$routes = @(Get-NetRoute | ForEach-Object {
	[PSCustomObject]@{
		DestinationPrefix = $_.DestinationPrefix
		NextHop = $_.NextHop
		InterfaceIndex = $_.InterfaceIndex
		InterfaceAlias = $_.InterfaceAlias
		RouteMetric = $_.RouteMetric
		AddressFamily = [int]$_.AddressFamily
		InterfaceIP = $addrs["$($_.InterfaceIndex)|$([int]$_.AddressFamily)"]
	}
})
ConvertTo-Json -InputObject $routes`

// detectWindowsRoutesViaPowerShell uses PowerShell Get-NetRoute command
func (w *windowsRouteDetector) detectWindowsRoutesViaPowerShell() ([]Route, error) {
	cmd := getNetRouteScript
	// runCommand encodes the script for a Windows target; encoding it here
	// too sent a PowerShell that only started another encoded PowerShell,
	// which failed over SSH.
	output, err := runCommand(w.conn, w.platform, cmd)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get routes via PowerShell Get-NetRoute")
	}

	return w.parsePowerShellGetNetRouteOutput(output)
}

// WindowsNetRoute represents a route from Get-NetRoute PowerShell command
type WindowsNetRoute struct {
	DestinationPrefix string `json:"DestinationPrefix"`
	NextHop           string `json:"NextHop"`
	InterfaceIndex    int    `json:"InterfaceIndex"`
	InterfaceAlias    string `json:"InterfaceAlias"`
	RouteMetric       int    `json:"RouteMetric"`
	AddressFamily     int    `json:"AddressFamily"`
	InterfaceIP       string `json:"InterfaceIP"`
}

// parsePowerShellGetNetRouteOutput parses JSON output from Get-NetRoute PowerShell command
func (w *windowsRouteDetector) parsePowerShellGetNetRouteOutput(output string) ([]Route, error) {
	var routes []Route

	// Trim whitespace from output
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, errors.New("Get-NetRoute output is empty")
	}

	// PowerShell may return a single object or an array
	var netRoutes []WindowsNetRoute
	err := json.Unmarshal([]byte(output), &netRoutes)
	if err != nil {
		var singleRoute WindowsNetRoute
		err2 := json.Unmarshal([]byte(output), &singleRoute)
		if err2 != nil {
			return nil, errors.Wrap(err, "failed to parse Get-NetRoute output")
		}
		netRoutes = []WindowsNetRoute{singleRoute}
	}

	for _, netRoute := range netRoutes {
		destination := netRoute.DestinationPrefix
		if destination == "" {
			continue
		}

		// osquery shows "::" for IPv6 local routes
		gateway := netRoute.NextHop
		if gateway == "" || gateway == "0.0.0.0" {
			// Empty or 0.0.0.0 gateway means on-link route

			if netRoute.AddressFamily == addressFamilyIPv4 {
				if netRoute.InterfaceIP != "" {
					gateway = netRoute.InterfaceIP
				} else {
					gateway = "0.0.0.0"
				}
			}
		}

		var iface string
		iface = netRoute.InterfaceAlias
		if iface == "" {
			iface = fmt.Sprintf("%d", netRoute.InterfaceIndex)
		}
		routes = append(routes, Route{
			Destination: destination,
			Gateway:     gateway,
			Flags:       []string{},
			Interface:   iface,
		})
	}

	return routes, nil
}

// detectWindowsRoutesViaNetstat uses netstat -rn with PowerShell ConvertFrom-String
// Uses: $a = netstat -rn; $a[8..$a.count] | ConvertFrom-String | select p1,p2,p3,p4,p5,p6
func (w *windowsRouteDetector) detectWindowsRoutesViaNetstat() ([]Route, error) {
	// Get IP -> Interface Name lookup map using PowerShell Get-NetIPAddress
	ipToNameMap, err := w.getWindowsIPToInterfaceMap()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get IP to interface mapping")
	}

	cmd := `$a = netstat -rn; $a[8..$a.count] | ConvertFrom-String | select p1,p2,p3,p4,p5,p6 | ConvertTo-Json`
	// runCommand encodes the script for a Windows target; encoding it here
	// too sent a PowerShell that only started another encoded PowerShell,
	// which failed over SSH.
	output, err := runCommand(w.conn, w.platform, cmd)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get routes via netstat")
	}

	return w.parseNetstatPowerShellOutput(output, ipToNameMap)
}

// getWindowsIPToInterfaceMap uses PowerShell Get-NetIPAddress to create an IP -> Interface Name mapping
func (w *windowsRouteDetector) getWindowsIPToInterfaceMap() (map[string]string, error) {
	cmd := `Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias | ConvertTo-Json`
	// runCommand encodes the script for a Windows target; encoding it here
	// too sent a PowerShell that only started another encoded PowerShell,
	// which failed over SSH.
	output, err := runCommand(w.conn, w.platform, cmd)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get IP addresses via Get-NetIPAddress")
	}

	// Parse JSON output
	var ipAddresses []struct {
		IPAddress      string `json:"IPAddress"`
		InterfaceAlias string `json:"InterfaceAlias"`
	}

	output = strings.TrimSpace(output)
	if output == "" {
		return make(map[string]string), nil
	}

	err = json.Unmarshal([]byte(output), &ipAddresses)
	if err != nil {
		// Try parsing as a single object
		var singleAddr struct {
			IPAddress      string `json:"IPAddress"`
			InterfaceAlias string `json:"InterfaceAlias"`
		}
		err2 := json.Unmarshal([]byte(output), &singleAddr)
		if err2 != nil {
			return nil, errors.Wrap(err, "failed to parse Get-NetIPAddress output")
		}
		ipAddresses = []struct {
			IPAddress      string `json:"IPAddress"`
			InterfaceAlias string `json:"InterfaceAlias"`
		}{singleAddr}
	}

	ipToNameMap := make(map[string]string)
	for _, addr := range ipAddresses {
		if addr.IPAddress != "" && addr.InterfaceAlias != "" {
			ipToNameMap[addr.IPAddress] = addr.InterfaceAlias
		}
	}

	return ipToNameMap, nil
}

// NetstatRoute represents a route parsed from netstat -rn via ConvertFrom-String
// IPv4 format: P1=empty, P2=Destination, P3=Netmask, P4=Gateway, P5=Interface, P6=Metric
// IPv6 format: P1=empty, P2=If, P3=Metric, P4=Network Destination, P5=Gateway, P6=Gateway
type NetstatRoute struct {
	P1 string `json:"P1"` // Empty (leading spaces) or header text
	P2 string `json:"P2"` // Destination (IPv4) or If (IPv6)
	P3 string `json:"P3"` // Netmask (IPv4) or Metric (IPv6)
	P4 string `json:"P4"` // Gateway (IPv4) or Network Destination (IPv6)
	P5 string `json:"P5"` // Interface (IPv4) or Gateway (IPv6)
	P6 string `json:"P6"` // Metric (IPv4) or Gateway (IPv6, when "On-link" appears)
}

// UnmarshalJSON handles unstable fields where type and field name is inconsistent
func (n *NetstatRoute) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	// Handle both uppercase and lowercase field names, and convert numbers to strings
	getString := func(key string) string {
		// Try uppercase first
		if val, ok := m[key]; ok && val != nil {
			if s, ok := val.(string); ok {
				return s
			}
			// Convert number to string
			if num, ok := val.(float64); ok {
				return fmt.Sprintf("%.0f", num)
			}
		}
		// Try lowercase version
		lowerKey := strings.ToLower(key)
		if val, ok := m[lowerKey]; ok && val != nil {
			if s, ok := val.(string); ok {
				return s
			}
			// Convert number to string
			if num, ok := val.(float64); ok {
				return fmt.Sprintf("%.0f", num)
			}
		}
		return ""
	}

	n.P1 = getString("P1")
	n.P2 = getString("P2")
	n.P3 = getString("P3")
	n.P4 = getString("P4")
	n.P5 = getString("P5")
	n.P6 = getString("P6")

	return nil
}

// parseNetstatPowerShellOutput parses JSON output from netstat -rn via ConvertFrom-String
func (w *windowsRouteDetector) parseNetstatPowerShellOutput(output string, ipToNameMap map[string]string) ([]Route, error) {
	var routes []Route

	// PowerShell may return a single object or an array
	var netstatRoutes []NetstatRoute
	err := json.Unmarshal([]byte(output), &netstatRoutes)
	if err != nil {
		// try parsing as a single object
		var singleRoute NetstatRoute
		err = json.Unmarshal([]byte(output), &singleRoute)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse netstat output")
		}
		netstatRoutes = []NetstatRoute{singleRoute}
	}

	var inIPv4Table, inIPv6Table bool
	var pendingIPv6Route *Route

	for i, route := range netstatRoutes {
		if w.isHeaderRow(route) {
			if strings.Contains(route.P1, "IPv6") || strings.Contains(route.P2, "IPv6") {
				inIPv6Table = true
				inIPv4Table = false
			} else if route.P1 == "Network" && route.P2 == "Destination" {
				inIPv4Table = true
				inIPv6Table = false
			} else if route.P2 == "If" && route.P3 == "Metric" {
				inIPv6Table = true
				inIPv4Table = false
			}
			continue
		}

		// Skip empty rows and non-route rows
		if route.P1 == "" && route.P2 == "" && route.P3 == "" && route.P4 == "" {
			continue
		}
		if route.P2 == "None" {
			continue
		}

		if inIPv4Table && !inIPv6Table {
			if route.P2 != "" && strings.Contains(route.P2, ".") {
				r := w.parseIPv4NetstatRoute(route, ipToNameMap)
				if r != nil {
					routes = append(routes, *r)
				}
			}
			continue
		}

		if inIPv6Table {
			if strings.TrimSpace(route.P2) == "On-link" && pendingIPv6Route != nil {
				pendingIPv6Route.Gateway = "::"
				routes = append(routes, *pendingIPv6Route)
				pendingIPv6Route = nil
				continue
			}
			if route.P4 != "" && (strings.Contains(route.P4, ":") || strings.Contains(route.P4, "::")) {
				r := w.parseIPv6NetstatRoute(route)
				if r != nil {
					if r.Gateway == "" {
						// Check next row for "On-link"
						if i+1 < len(netstatRoutes) && strings.TrimSpace(netstatRoutes[i+1].P2) == "On-link" {
							pendingIPv6Route = r
							continue
						}
						r.Gateway = "::"
					}
					routes = append(routes, *r)
				}
			}
		}
	}

	if pendingIPv6Route != nil {
		pendingIPv6Route.Gateway = "::"
		routes = append(routes, *pendingIPv6Route)
	}

	return routes, nil
}

// isHeaderRow checks if a row is a header that should be skipped
func (w *windowsRouteDetector) isHeaderRow(route NetstatRoute) bool {
	p1 := strings.TrimSpace(route.P1)
	p2 := strings.TrimSpace(route.P2)
	p3 := strings.TrimSpace(route.P3)

	if (p1 == "Network" && p2 == "Destination") ||
		(p2 == "If" && p3 == "Metric") ||
		(p1 == "Active" && p2 == "Routes:") ||
		(p1 == "Persistent" && p2 == "Routes:") ||
		(p1 == "IPv6" && p2 == "Route" && p3 == "Table") {
		return true
	}

	return false
}

// parseIPv4NetstatRoute parses an IPv4 route from netstat output
func (w *windowsRouteDetector) parseIPv4NetstatRoute(route NetstatRoute, ipToNameMap map[string]string) *Route {
	if route.P2 == "" || route.P3 == "" {
		return nil
	}

	destination := strings.TrimSpace(route.P2)
	netmask := strings.TrimSpace(route.P3)
	gateway := strings.TrimSpace(route.P4)
	ifaceIP := strings.TrimSpace(route.P5)

	if gateway == "On-link" {
		gateway = ifaceIP
	}

	destIP := net.ParseIP(destination)
	if destIP == nil {
		return nil
	}

	maskIP := net.ParseIP(netmask)
	if maskIP == nil {
		return nil
	}

	mask := net.IPMask(maskIP.To4())
	if mask == nil {
		return nil
	}

	ones, bits := mask.Size()
	if bits != 32 {
		return nil
	}

	var dest string
	if destIP.Equal(net.IPv4zero) {
		dest = "0.0.0.0"
	} else {
		dest = fmt.Sprintf("%s/%d", destination, ones)
	}

	iface := ifaceIP
	if name, ok := ipToNameMap[ifaceIP]; ok {
		iface = name
	}

	return &Route{
		Destination: dest,
		Gateway:     gateway,
		Flags:       []string{},
		Interface:   iface,
	}
}

// parseIPv6NetstatRoute parses an IPv6 route from netstat output
func (w *windowsRouteDetector) parseIPv6NetstatRoute(route NetstatRoute) *Route {
	dest := strings.TrimSpace(route.P4)
	if dest == "" {
		return nil
	}

	gateway := strings.TrimSpace(route.P5)

	if gateway == "On-link" {
		gateway = "::"
	}
	if !strings.Contains(dest, "/") {
		// Try to parse as IP and add /128 for host routes
		if ip := net.ParseIP(dest); ip != nil {
			if ip.Equal(net.IPv6zero) {
				dest = "::"
			} else {
				dest = fmt.Sprintf("%s/128", dest)
			}
		}
	}

	return &Route{
		Destination: dest,
		Gateway:     gateway,
		Flags:       []string{},
		Interface:   "",
	}
}
