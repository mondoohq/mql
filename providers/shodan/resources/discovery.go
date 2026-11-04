// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shadowscatcher/shodan/models"
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

	addrs := discoverAddrs(context.Background(), conn.Client(), networks)

	for i := range addrs {
		addr := addrs[i]

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

// shodanClient is the part of the Shodan API discovery uses.
type shodanClient interface {
	Host(ctx context.Context, params search.HostParams) (models.Host, error)
	Count(ctx context.Context, params search.Params) (models.SearchResult, error)
}

// maxIPFacet caps how many distinct IPs one Count call asks Shodan to list.
// Shodan rejects a facet larger than the plan allows (5120 on the basic API
// plan), and a rejected call costs the range its fast path.
const maxIPFacet = 5000

// discoverAddrs returns the addresses Shodan has data for. A CIDR range is
// listed with one Count call per range instead of one host lookup per
// address: API calls are rate limited to about one per second, so a /22 is
// ~17 minutes of lookups, most of them for addresses Shodan has no data on. Count
// does not use query credits. A range falls back to per-address lookups when
// Count fails (e.g. a plan without search filters) or returns a partial list.
func discoverAddrs(ctx context.Context, client shodanClient, networks []string) []netip.Addr {
	addrs := []netip.Addr{}
	for _, network := range networks {
		if strings.Contains(network, "/") {
			found, err := indexedAddrs(ctx, client, network)
			if err == nil {
				addrs = append(addrs, found...)
				continue
			}
			log.Debug().Err(err).Str("network", network).Msg("Shodan range listing unavailable, looking up each address")
		}
		for _, addr := range resolveNetworks([]string{network}) {
			// if the host is not found, we skip it
			if _, err := client.Host(ctx, search.HostParams{IP: addr.String()}); err == nil {
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs
}

// indexedAddrs lists the addresses in cidr that Shodan has banners for.
func indexedAddrs(ctx context.Context, client shodanClient, cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	// Same cap as cidrIPs, so a range too large to enumerate stays skipped.
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR range %q is too large to enumerate (limit is %d addresses)", cidr, maxCIDRHosts)
	}

	res, err := client.Count(ctx, search.Params{
		Query:  search.Query{Net: prefix.String()},
		Facets: []string{fmt.Sprintf("ip:%d", min(1<<hostBits, maxIPFacet))},
	})
	if err != nil {
		return nil, err
	}

	// Total counts banners; every banner belongs to one IP. If the per-IP
	// counts don't add up to it, Shodan cut the facet list short.
	sum := 0
	addrs := []netip.Addr{}
	for _, f := range res.Facets["ip"] {
		sum += f.Count
		s, _ := f.Value.(string)
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("unexpected ip facet value %v", f.Value)
		}
		// cidrIPs never looked up a range's network and broadcast address,
		// so neither does this.
		if prefix.Contains(addr) && (hostBits < 2 || (addr != prefix.Addr() && addr != lastAddr(prefix))) {
			addrs = append(addrs, addr)
		}
	}
	if sum != res.Total {
		return nil, fmt.Errorf("ip facet is partial: %d of %d banners", sum, res.Total)
	}
	return addrs, nil
}

// lastAddr returns the highest address in a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < p.Addr().BitLen(); i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
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
