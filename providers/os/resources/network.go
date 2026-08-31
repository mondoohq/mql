// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/machineid"
	"go.mondoo.com/mql/providers/os/id/networki"
	"go.mondoo.com/mql/providers/os/resources/networkinterface"
	"go.mondoo.com/mql/types"
)

func (c *mqlNetwork) interfaces() ([]any, error) {
	log.Debug().Msg("os.network> interfaces")
	conn := c.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	interfaces, err := networki.Interfaces(conn, platform)
	if err != nil {
		log.Error().Err(err).Msg("unable to detect network interfaces")
		c.Interfaces = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	var resources []any
	if interfaces != nil {
		var resource plugin.Resource
		for _, neti := range interfaces {
			log.Debug().Interface("interface", neti).Msg("os.network> adding interface")

			ipaddresses := []any{}
			for _, ipaddress := range neti.IPAddresses {
				resource, err = NewResource(c.MqlRuntime, "ipAddress", map[string]*llx.RawData{
					"__id":      llx.StringData(ipaddress.IP.String()),
					"ip":        llx.IPData(llx.ParseIP(ipaddress.IP.String())),
					"cidr":      llx.IPData(llx.ParseIP(ipaddress.CIDR)),
					"broadcast": llx.IPData(llx.ParseIP(ipaddress.Broadcast)),
					"gateway":   llx.IPData(llx.ParseIP(ipaddress.Gateway)),
					"subnet":    llx.IPData(llx.ParseIP(ipaddress.Subnet)),
				})
				if err != nil { // non-critical error
					log.Error().Err(err).Msg("unable to create ipaddress resource")
					continue
				}
				ipaddresses = append(ipaddresses, resource)
			}

			resource, err = NewResource(c.MqlRuntime, "networkInterface", map[string]*llx.RawData{
				"__id":    llx.StringData(neti.Name + "/" + neti.MACAddress),
				"name":    llx.StringData(neti.Name),
				"mac":     llx.StringData(neti.MACAddress),
				"mtu":     llx.IntData(neti.MTU),
				"active":  llx.BoolDataPtr(neti.Active),
				"virtual": llx.BoolDataPtr(neti.Virtual),
				"vendor":  llx.StringData(neti.Vendor),
				"flags":   llx.ArrayData(convert.SliceAnyToInterface(neti.Flags), types.String),
				"ips":     llx.ArrayData(ipaddresses, types.Resource("ipAddress")),
			})
			if err != nil {
				return resources, nil
			}
			resources = append(resources, resource)
		}
	}
	return resources, nil
}

// ipsByVersion collects all IP addresses from all interfaces matching the given IP version (4 or 6).
func (c *mqlNetwork) ipsByVersion(version uint8) ([]any, error) {
	interfaces := c.GetInterfaces()
	if interfaces.Error != nil {
		return nil, interfaces.Error
	}

	var result []any
	for _, ifaceRes := range interfaces.Data {
		iface, ok := ifaceRes.(*mqlNetworkInterface)
		if !ok {
			continue
		}
		ips := iface.GetIps()
		if ips.Error != nil {
			continue
		}
		for _, ipRes := range ips.Data {
			ipAddr, ok := ipRes.(*mqlIpAddress)
			if !ok {
				continue
			}
			ip := ipAddr.GetIp()
			if ip.Error != nil {
				continue
			}
			if ip.Data.Version == version {
				result = append(result, ip.Data)
			}
		}
	}
	return result, nil
}

func (c *mqlNetwork) ipv4() ([]any, error) {
	return c.ipsByVersion(4)
}

func (c *mqlNetwork) ipv6() ([]any, error) {
	return c.ipsByVersion(6)
}

// primaryIPByDefaultRoute finds the first IP of the given version on the interface
// associated with the default route for that IP version.
func (c *mqlNetwork) primaryIPByDefaultRoute(version uint8, defaultDests []string) (llx.RawIP, error) {
	routes := c.GetRoutes()
	if routes.Error != nil {
		return llx.RawIP{}, routes.Error
	}

	defaults := routes.Data.GetDefaults()
	if defaults.Error != nil {
		return llx.RawIP{}, defaults.Error
	}

	destSet := make(map[string]bool, len(defaultDests))
	for _, d := range defaultDests {
		destSet[d] = true
	}

	for _, routeRes := range defaults.Data {
		route, ok := routeRes.(*mqlNetworkRoute)
		if !ok {
			continue
		}

		dest := route.GetDestination()
		if dest.Error != nil {
			continue
		}
		if !destSet[dest.Data] {
			continue
		}

		iface := route.GetIface()
		if iface.Error != nil || iface.Data == nil {
			continue
		}

		ips := iface.Data.GetIps()
		if ips.Error != nil {
			continue
		}

		for _, ipRes := range ips.Data {
			ipAddr, ok := ipRes.(*mqlIpAddress)
			if !ok {
				continue
			}
			ip := ipAddr.GetIp()
			if ip.Error != nil {
				continue
			}
			if ip.Data.Version == version {
				return ip.Data, nil
			}
		}
	}

	return llx.RawIP{}, nil
}

func (c *mqlNetwork) primaryIPv4() (llx.RawIP, error) {
	res, err := c.primaryIPByDefaultRoute(4, []string{"0.0.0.0/0", "0.0.0.0", "default"})
	if err != nil {
		return llx.RawIP{}, err
	}
	if res.IP == nil {
		c.PrimaryIPv4.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return res, nil
}

func (c *mqlNetwork) primaryIPv6() (llx.RawIP, error) {
	res, err := c.primaryIPByDefaultRoute(6, []string{"::/0", "::"})
	if err != nil {
		return llx.RawIP{}, err
	}
	if res.IP == nil {
		c.PrimaryIPv6.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return res, nil
}

func (c *mqlNetwork) neighbors() ([]any, error) {
	log.Debug().Msg("os.network> neighbors")
	conn := c.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	neighbors, err := networki.Neighbors(conn, platform)
	if err != nil {
		log.Error().Err(err).Msg("unable to detect network neighbors")
		c.Neighbors = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	resources := make([]any, 0, len(neighbors))
	for _, nb := range neighbors {
		if nb.IP == "" {
			continue
		}
		resource, err := CreateResource(c.MqlRuntime, "networkNeighbor", map[string]*llx.RawData{
			"__id":      llx.StringData(nb.Interface + "/" + nb.IP),
			"ip":        llx.IPData(llx.ParseIP(nb.IP)),
			"mac":       llx.StringData(nb.MAC),
			"interface": llx.StringData(nb.Interface),
			"state":     llx.StringData(nb.State),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (c *mqlNetwork) routes() (*mqlNetworkRoutes, error) {
	log.Debug().Msg("os.network> routes")
	conn := c.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	routes, err := networkinterface.Routes(conn, platform)
	if err != nil {
		log.Error().Err(err).Msg("unable to detect network routes")
		return nil, err
	}

	interfaces, err := networki.Interfaces(conn, platform)
	if err != nil {
		log.Error().Err(err).Msg("unable to get interfaces for routes")
		interfaces = []networki.Interface{}
	}

	// Map interfaces by name
	interfaceMap := make(map[string]networki.Interface)
	for _, iface := range interfaces {
		interfaceMap[iface.Name] = iface
	}

	routeResources := []any{}
	for _, route := range routes {
		var ifaceResource plugin.Resource
		if iface, ok := interfaceMap[route.Interface]; ok {
			ipaddresses := []any{}
			for _, ipaddress := range iface.IPAddresses {
				ipRes, err := NewResource(c.MqlRuntime, "ipAddress", map[string]*llx.RawData{
					"__id":      llx.StringData(ipaddress.IP.String()),
					"ip":        llx.IPData(llx.ParseIP(ipaddress.IP.String())),
					"cidr":      llx.IPData(llx.ParseIP(ipaddress.CIDR)),
					"broadcast": llx.IPData(llx.ParseIP(ipaddress.Broadcast)),
					"gateway":   llx.IPData(llx.ParseIP(ipaddress.Gateway)),
					"subnet":    llx.IPData(llx.ParseIP(ipaddress.Subnet)),
				})
				if err != nil {
					continue
				}
				ipaddresses = append(ipaddresses, ipRes)
			}

			ifaceResource, err = NewResource(c.MqlRuntime, "networkInterface", map[string]*llx.RawData{
				"__id":    llx.StringData(iface.Name + "/" + iface.MACAddress),
				"name":    llx.StringData(iface.Name),
				"mac":     llx.StringData(iface.MACAddress),
				"mtu":     llx.IntData(iface.MTU),
				"active":  llx.BoolDataPtr(iface.Active),
				"virtual": llx.BoolDataPtr(iface.Virtual),
				"vendor":  llx.StringData(iface.Vendor),
				"flags":   llx.ArrayData(convert.SliceAnyToInterface(iface.Flags), types.String),
				"ips":     llx.ArrayData(ipaddresses, types.Resource("ipAddress")),
			})
			if err != nil {
				log.Debug().Err(err).Str("iface", route.Interface).Msg("unable to create networkInterface resource")
				return nil, err
			}
		}

		// The table belongs in the id. A host with VRFs holds the same
		// prefix in several tables, and those routes are not the same route.
		id := route.Destination + "/" + route.Gateway + "/" + route.Interface
		if route.Table != "" {
			id += "/" + route.Table
		}

		routeRes, err := NewResource(c.MqlRuntime, "networkRoute", map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"destination": llx.StringData(route.Destination),
			"gateway":     llx.StringData(route.Gateway),
			"flags":       llx.ArrayData(convert.SliceAnyToInterface(route.Flags), types.String),
			"iface":       llx.ResourceData(ifaceResource, "networkInterface"),
			"table":       llx.StringData(route.Table),
			"protocol":    llx.StringData(route.Protocol),
			"scope":       llx.StringData(route.Scope),
			"metric":      llx.IntData(route.Metric),
			"source":      llx.StringData(route.Source),
			"type":        llx.StringData(route.Type),
			"device":      llx.StringData(route.Interface),
		})
		if err != nil {
			log.Debug().Err(err).Msg("unable to create networkRoute resource")
			return nil, err
		}
		routeResources = append(routeResources, routeRes)
	}

	machineID, err := machineid.MachineId(conn, platform)
	if err != nil || machineID == "" {
		// Fallback to asset MRN if machine ID is not available
		assetID := conn.Asset().GetMrn()
		if assetID == "" {
			assetID = "default"
		}
		machineID = assetID
	}

	routesRes, err := NewResource(c.MqlRuntime, "networkRoutes", map[string]*llx.RawData{
		"__id": llx.StringData(fmt.Sprintf("networkRoutes(%s)", machineID)),
		"list": llx.ArrayData(routeResources, types.Resource("networkRoute")),
	})
	if err != nil {
		return nil, err
	}

	return routesRes.(*mqlNetworkRoutes), nil
}

func (c *mqlNetworkRoutes) list() ([]any, error) {
	return c.List.Data, c.List.Error
}

func (c *mqlNetworkRoutes) defaults() ([]any, error) {
	log.Debug().Msg("os.network.routes> defaults")

	// Get all routes from the list
	allRoutes := c.GetList()
	if allRoutes.Error != nil {
		return nil, allRoutes.Error
	}

	// Filter to only default routes
	var defaultRoutes []any
	for _, routeRes := range allRoutes.Data {
		route, ok := routeRes.(*mqlNetworkRoute)
		if !ok {
			continue
		}

		dest := route.GetDestination()
		if dest.Error != nil {
			continue
		}

		// Check if it's a default route
		destStr := dest.Data
		if destStr == "0.0.0.0/0" || destStr == "::/0" || destStr == "default" ||
			destStr == "0.0.0.0" || destStr == "::" {
			defaultRoutes = append(defaultRoutes, routeRes)
		}
	}

	return defaultRoutes, nil
}

func (c *mqlNetworkRoute) iface() (*mqlNetworkInterface, error) {
	return c.Iface.Data, c.Iface.Error
}
