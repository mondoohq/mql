// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "strings"

// internetGatewayIdPrefix identifies an internet gateway in a route's
// polymorphic gatewayId. Egress-only internet gateways use "eigw-" and are
// deliberately not matched: they carry outbound IPv6 traffic only, so a subnet
// whose default route points at one is not reachable from the internet.
const internetGatewayIdPrefix = "igw-"

// routeIsDefault reports whether a single route's destination matches every
// address, for either address family. A default route is what carries traffic
// with no more specific match, so it is the one that decides internet
// reachability.
//
// A route table can also cover every address with a pair of half-routes rather
// than one default route, which no single destination identifies. That case is
// routesReachInternet's, not this function's.
func routeIsDefault(ipv4Cidr, ipv6Cidr string) bool {
	return ipv4Cidr == "0.0.0.0/0" || ipv6Cidr == "::/0"
}

// The two halves of the split default, per address family. A pair of them
// covers the whole address space between them and carries traffic with no more
// specific match, exactly as a default route does, because either half is more
// specific than the /0 it is deployed to override. Appliance vendors and VPN
// setups use the pair for precisely that reason, so a route table that has one
// usually has no /0 at all.
const (
	splitDefaultIpv4LowerHalf = "0.0.0.0/1"
	splitDefaultIpv4UpperHalf = "128.0.0.0/1"
	splitDefaultIpv6LowerHalf = "::/1"
	splitDefaultIpv6UpperHalf = "8000::/1"
)

// internetRoute is one active route reduced to what reachability depends on:
// where it sends traffic, and which destinations it sends there.
type internetRoute struct {
	ipv4Cidr  string
	ipv6Cidr  string
	gatewayId string
}

// routesReachInternet reports whether a set of active routes sends
// unmatched traffic to an internet gateway, by a default route or by both
// halves of a split default. Only routes that already point at an internet
// gateway are considered, so two halves pointing at different targets do not
// combine into one.
func routesReachInternet(routes []internetRoute) bool {
	var ipv4Lower, ipv4Upper, ipv6Lower, ipv6Upper bool

	for _, route := range routes {
		if !hasInternetGatewayPrefix(route.gatewayId) {
			continue
		}
		if routeIsDefault(route.ipv4Cidr, route.ipv6Cidr) {
			return true
		}
		switch route.ipv4Cidr {
		case splitDefaultIpv4LowerHalf:
			ipv4Lower = true
		case splitDefaultIpv4UpperHalf:
			ipv4Upper = true
		}
		switch route.ipv6Cidr {
		case splitDefaultIpv6LowerHalf:
			ipv6Lower = true
		case splitDefaultIpv6UpperHalf:
			ipv6Upper = true
		}
	}

	return (ipv4Lower && ipv4Upper) || (ipv6Lower && ipv6Upper)
}

// hasInternetGatewayPrefix reports whether a route's polymorphic gatewayId names
// an internet gateway. An egress-only internet gateway ("eigw-") does not match:
// its ID does not carry the "igw-" prefix, and it only carries outbound traffic.
func hasInternetGatewayPrefix(gatewayId string) bool {
	return strings.HasPrefix(gatewayId, internetGatewayIdPrefix)
}

// blockModeStopsIngress reports whether a subnet's internet gateway block mode
// prevents inbound internet traffic. Both block-bidirectional and block-ingress
// stop traffic arriving from an internet gateway; only "off" (and an empty
// value, for a subnet the API reported no mode for) leaves it flowing.
func blockModeStopsIngress(mode string) bool {
	return mode == "block-bidirectional" || mode == "block-ingress"
}

// isPublic reports whether the subnet is a public subnet: one whose effective
// route table sends unmatched traffic to an internet gateway, by a default
// route or by both halves of a split default.
//
// The route table comes from routeTable(), which already resolves the subnet's
// explicit association and falls back to the VPC main route table, so this
// matches what AWS actually applies to traffic. A blackholed route is skipped:
// it matches traffic and then discards it, which is the opposite of reachable.
func (a *mqlAwsVpcSubnet) isPublic() (bool, error) {
	blockMode := a.GetInternetGatewayBlockMode()
	if blockMode.Error != nil {
		return false, blockMode.Error
	}
	if blockModeStopsIngress(blockMode.Data) {
		return false, nil
	}

	routeTable := a.GetRouteTable()
	if routeTable.Error != nil {
		return false, routeTable.Error
	}
	if routeTable.Data == nil {
		return false, nil
	}

	routes := routeTable.Data.GetRouteEntries()
	if routes.Error != nil {
		return false, routes.Error
	}

	active := make([]internetRoute, 0, len(routes.Data))
	for _, r := range routes.Data {
		route, ok := r.(*mqlAwsVpcRoutetableRoute)
		if !ok {
			continue
		}
		state := route.GetState()
		if state.Error != nil {
			return false, state.Error
		}
		if !strings.EqualFold(state.Data, "active") {
			continue
		}

		ipv4 := route.GetDestinationCidrBlock()
		if ipv4.Error != nil {
			return false, ipv4.Error
		}
		ipv6 := route.GetDestinationIpv6CidrBlock()
		if ipv6.Error != nil {
			return false, ipv6.Error
		}
		gatewayId := route.GetGatewayId()
		if gatewayId.Error != nil {
			return false, gatewayId.Error
		}

		active = append(active, internetRoute{
			ipv4Cidr:  ipv4.Data,
			ipv6Cidr:  ipv6.Data,
			gatewayId: gatewayId.Data,
		})
	}

	return routesReachInternet(active), nil
}
