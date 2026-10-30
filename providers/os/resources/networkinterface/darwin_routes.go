// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package networkinterface

import (
	"fmt"
	"net"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// List detects network routes on macOS using golang.org/x/net/route
func (d *darwinRouteDetector) List() ([]Route, error) {
	ipv4Routes, err := d.fetchDarwinRoutes(unix.AF_INET)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get IPv4 routes")
	}

	ipv6Routes, err := d.fetchDarwinRoutes(unix.AF_INET6)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get IPv6 routes")
	}
	routes := append(ipv4Routes, ipv6Routes...)

	return routes, nil
}

// fetchDarwinRoutes fetches routes for a ipv4 or ipv6 address family
func (d *darwinRouteDetector) fetchDarwinRoutes(af int) ([]Route, error) {
	rib, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch RIB")
	}

	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse RIB")
	}

	// Get interface map to resolve interface indices to names
	interfaceMap, err := d.getDarwinInterfaceMap()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get interface map")
	}

	var routes []Route
	for _, msg := range messages {
		routeMsg, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		dest, gateway, iface, err := d.parseRouteMessage(routeMsg, interfaceMap)
		if err != nil {
			log.Debug().Err(err).Msg("failed to parse route message")
			continue
		}

		if dest == "" {
			continue
		}

		// Filter out IPv6 multicast routes (ff00::/8) to match osquery results
		if strings.Contains(dest, ":") && strings.HasPrefix(dest, "ff") {
			continue
		}

		routes = append(routes, Route{
			Destination: dest,
			Gateway:     gateway,
			Flags:       parseBSDRouteFlags(int64(routeMsg.Flags)),
			Interface:   iface,
		})
	}

	return routes, nil
}

// getDarwinInterfaceMap creates a map of interface index to interface name
func (d *darwinRouteDetector) getDarwinInterfaceMap() (map[int]string, error) {
	interfaceMap := make(map[int]string)

	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		return nil, err
	}

	messages, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return nil, err
	}

	for _, msg := range messages {
		if ifMsg, ok := msg.(*route.InterfaceMessage); ok {
			interfaceMap[ifMsg.Index] = ifMsg.Name
		}
	}

	return interfaceMap, nil
}

// parseRouteMessage extracts destination, gateway, and interface from a RouteMessage
// RouteMessage.Addrs contains addresses in this order on macOS:
// Index 0: Destination (Inet4Addr/Inet6Addr)
// Index 1: Gateway (Inet4Addr/Inet6Addr or LinkAddr)
// Index 2: Netmask (Inet4Addr/Inet6Addr, if present)
// Index 3: Interface (LinkAddr, if present)
func (d *darwinRouteDetector) parseRouteMessage(routeMsg *route.RouteMessage, interfaceMap map[int]string) (dest, gateway, iface string, err error) {
	// Get destination (index 0)
	if len(routeMsg.Addrs) > 0 && routeMsg.Addrs[0] != nil {
		dest = d.addrToString(routeMsg.Addrs[0], interfaceMap)
	}

	// Get gateway (index 1) - can be Inet4Addr, Inet6Addr, or LinkAddr
	if len(routeMsg.Addrs) > 1 && routeMsg.Addrs[1] != nil {
		switch a := routeMsg.Addrs[1].(type) {
		case *route.LinkAddr:
			gateway = fmt.Sprintf("link#%d", a.Index)
		default:
			gateway = d.addrToString(routeMsg.Addrs[1], interfaceMap)
		}
	}

	// Get netmask (index 2) and convert to CIDR if present
	if len(routeMsg.Addrs) > 2 && routeMsg.Addrs[2] != nil && dest != "" {
		var maskBytes []byte
		switch a := routeMsg.Addrs[2].(type) {
		case *route.Inet4Addr:
			maskBytes = a.IP[:]
		case *route.Inet6Addr:
			maskBytes = a.IP[:]
		}
		if maskBytes != nil {
			ones, bits := net.IPMask(maskBytes).Size()
			if bits > 0 {
				dest = fmt.Sprintf("%s/%d", dest, ones)
			}
		}
	}

	if routeMsg.Index > 0 {
		if name, ok := interfaceMap[routeMsg.Index]; ok {
			iface = name
		} else {
			iface = fmt.Sprintf("%d", routeMsg.Index)
		}
	} else if len(routeMsg.Addrs) > 3 {
		if linkAddr, ok := routeMsg.Addrs[3].(*route.LinkAddr); ok && linkAddr.Name != "" {
			iface = linkAddr.Name
		}
	}

	return dest, gateway, iface, nil
}

// addrToString converts a route.Addr to a string IP address
// For IPv6 addresses with zone IDs, converts the zone ID to interface name to match osquery format (e.g., %16 -> %utun1)
func (d *darwinRouteDetector) addrToString(addr route.Addr, interfaceMap map[int]string) string {
	switch a := addr.(type) {
	case *route.Inet4Addr:
		return net.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3]).String()
	case *route.Inet6Addr:
		ip := make(net.IP, 16)
		copy(ip, a.IP[:])
		if a.ZoneID > 0 {
			if ifaceName, ok := interfaceMap[a.ZoneID]; ok {
				return fmt.Sprintf("%s%%%s", ip.String(), ifaceName)
			}
			return fmt.Sprintf("%s%%%d", ip.String(), a.ZoneID)
		}
		return ip.String()
	default:
		return ""
	}
}
