// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shadowscatcher/shodan/search"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/shodan/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// maxCIDRHosts caps how many addresses a single CIDR may expand to during
// discovery. Each address costs one Shodan host lookup (and its query credit),
// so we refuse to enumerate a range larger than a /16 rather than exhausting
// memory and API credits. This also rejects IPv6 CIDRs, whose ranges are
// astronomically large.
const maxCIDRHosts = 1 << 16 // 65536, a /16 worth of IPv4 addresses

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.ShodanConnection)
	if conn == nil || conn.Asset() == nil || len(conn.Asset().Connections) == 0 {
		return nil, nil
	}

	conf := conn.Asset().Connections[0]
	targets := handleTargets(conf.Discover.Targets)
	if !stringx.ContainsAnyOf(targets, connection.DiscoveryHosts, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return nil, nil
	}

	// we only need to discover when networks are specified
	networkValue, ok := conf.Options["networks"]
	if !ok || networkValue == "" {
		return nil, nil
	}
	networks := strings.Split(networkValue, ",")
	assetList := []*inventory.Asset{}

	addrs := resolveNetworks(networks)

	for i := range addrs {
		addr := addrs[i]

		// if the host is not found, we skip it
		// TODO: optimize this by using the bulk search so we save some API calls
		_, err := conn.Client().Host(context.Background(), search.HostParams{
			IP: addr.String(),
		})
		if err != nil {
			continue
		}

		a := &inventory.Asset{
			Name: addr.String(),
			Connections: []*inventory.Config{
				{
					Type: "shodan",
					Host: addr.String(),
					Options: map[string]string{
						"search": "host",
					},
					Credentials: conf.Credentials,
				},
			},
		}

		assetList = append(assetList, a)
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: assetList,
	}}
	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) {
		return []string{
			connection.DiscoveryHosts,
		}
	}
	return targets
}

// resolve all IPs in the CIDR range
func resolveNetworks(networks []string) []netip.Addr {
	addresses := []netip.Addr{}
	for i := range networks {
		network := networks[i]
		// check if network is a CIDR range
		if strings.Contains(network, "/") {
			ips, err := cidrIPs(network)
			if err != nil {
				log.Warn().Err(err).Str("network", network).Msg("skipping network during Shodan discovery")
			} else {
				addresses = append(addresses, ips...)
			}
		} else {
			// we assume a single IP address
			addr, err := netip.ParseAddr(network)
			if err == nil {
				addresses = append(addresses, addr)
			}
		}
	}
	return addresses
}

// cidrIPs determines the ips from a CIDR range
func cidrIPs(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	// Mask to the network address so enumeration covers the whole range even
	// when the caller passed a host address (e.g. "10.0.0.5/24").
	prefix = prefix.Masked()

	// hostBits is the number of variable bits in the range; 2^hostBits is the
	// range size. Reject anything larger than maxCIDRHosts before enumerating,
	// which also rejects any non-trivial IPv6 CIDR (128-bit addresses).
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR range %q is too large to enumerate (limit is %d addresses)", cidr, maxCIDRHosts)
	}

	var ips []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	if len(ips) < 2 {
		return ips, nil
	}

	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}
