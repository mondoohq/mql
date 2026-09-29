// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// detectSolarisInterfaces detects network interfaces on Solaris and illumos.
// ifconfig lists the addresses; dladm adds the MAC address of every datalink,
// which ifconfig only prints for root, and whether a link is physical.
func (n *neti) detectSolarisInterfaces() ([]Interface, error) {
	detectors := []func() ([]Interface, error){
		n.getSolarisIfconfigInterfaces,
		n.getSolarisDatalinks,
		n.getSolarisGatewayDetails,
	}

	var errs []error
	interfaces := []Interface{}
	for _, detectFn := range detectors {
		detected, err := detectFn()
		if err != nil {
			log.Debug().Err(err).Msg("os.network.interface> unable to detect network interfaces")
			errs = append(errs, err)
			continue
		}
		interfaces = AddOrUpdateInterfaces(interfaces, detected)
	}

	if len(interfaces) == 0 {
		return interfaces, errors.Join(errs...)
	}
	return interfaces, nil
}

// solarisIfconfigHeader matches the first line of a Solaris ifconfig stanza.
// A logical interface carries its instance after a colon (net0:1), and the
// flags value is bare hex:
//
//	net0:1: flags=100001000843<UP,BROADCAST,RUNNING,MULTICAST,IPv4> mtu 9000 index 3
var solarisIfconfigHeader = regexp.MustCompile(`^([a-zA-Z0-9._]+)(?::\d+)?:\s+flags=[0-9a-fA-F]+<([^>]*)>`)

func (n *neti) getSolarisIfconfigInterfaces() ([]Interface, error) {
	output, err := n.RunCommand("ifconfig -a")
	if err != nil {
		return nil, err
	}
	return parseSolarisIfconfig(output), nil
}

// parseSolarisIfconfig reads Solaris `ifconfig -a`. Solaris prints an
// interface once per address family and once per logical interface, so the
// IPv4 stanza of net0, its IPv6 stanza, and net0:1 all describe one interface
// and are merged into it.
//
// An IPv6 stanza for an interface with no IPv6 address configured shows the
// unspecified address (inet6 ::/0), which is left out.
func parseSolarisIfconfig(output string) []Interface {
	var interfaces []Interface
	var current *Interface

	find := func(name string) *Interface {
		for i := range interfaces {
			if interfaces[i].Name == name {
				return &interfaces[i]
			}
		}
		interfaces = append(interfaces, Interface{Name: name})
		return &interfaces[len(interfaces)-1]
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" {
			continue
		}

		if m := solarisIfconfigHeader.FindStringSubmatch(raw); len(m) > 0 {
			current = find(m[1])
			for _, flag := range strings.Split(m[2], ",") {
				if flag != "" && !slices.Contains(current.Flags, flag) {
					current.Flags = append(current.Flags, flag)
				}
			}
			tokens := strings.Fields(raw)
			for i, t := range tokens {
				if t == "mtu" && i+1 < len(tokens) && current.MTU == 0 {
					current.MTU = parseInt(tokens[i+1])
				}
			}
			continue
		}

		if current == nil {
			continue
		}

		fields := strings.Fields(raw)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "ether":
			current.SetMAC(normalizeSolarisMAC(fields[1]))

		case "inet":
			// inet 10.77.1.190 netmask ffffff00 broadcast 10.77.1.255
			if len(fields) >= 4 && fields[2] == "netmask" {
				current.AddOrUpdateIP(NewIPv4WithMask(fields[1], "0x"+fields[3]))
			} else if ip, ok := NewIPAddress(fields[1]); ok {
				current.AddOrUpdateIP(ip)
			}

		case "inet6":
			// inet6 fe80::17ff:fe04:b9e2/10
			addr, prefix, hasPrefix := strings.Cut(fields[1], "/")
			if pct := strings.Index(addr, "%"); pct != -1 {
				addr = addr[:pct]
			}
			if ip := net.ParseIP(addr); ip == nil || ip.IsUnspecified() {
				continue
			}
			if hasPrefix {
				current.AddOrUpdateIP(NewIPv6WithPrefixLength(addr, parseInt(prefix)))
			} else if ip, ok := NewIPAddress(addr); ok {
				current.AddOrUpdateIP(ip)
			}
		}
	}

	for i := range interfaces {
		iface := &interfaces[i]
		// RUNNING is the link-up flag on Solaris
		iface.Active = convert.ToPtr(slices.Contains(iface.Flags, "RUNNING"))
		// the loopback and other interfaces with no datalink under them
		if slices.Contains(iface.Flags, "VIRTUAL") {
			iface.Virtual = convert.ToPtr(true)
		}
	}

	return interfaces
}

// normalizeSolarisMAC pads the octets Solaris writes without a leading zero
// (2:0:17:4:b9:e2) to the two-digit form every other platform reports.
func normalizeSolarisMAC(mac string) string {
	octets := strings.Split(mac, ":")
	for i, o := range octets {
		if len(o) == 1 {
			octets[i] = "0" + o
		}
	}
	return strings.ToLower(strings.Join(octets, ":"))
}

func (n *neti) getSolarisDatalinks() ([]Interface, error) {
	macs, err := n.RunCommand("dladm show-linkprop -c -o link,value -p mac-address")
	if err != nil {
		return nil, err
	}
	classes, err := n.RunCommand("dladm show-link -p -o link,class")
	if err != nil {
		return nil, err
	}
	return parseSolarisDatalinks(macs, classes), nil
}

// parseSolarisDatalinks reads the MAC address and class of every datalink from
// the parseable output of dladm, which escapes the colons inside a value:
//
//	net0:2\:0\:17\:4\:b9\:e2      (show-linkprop -c -o link,value -p mac-address)
//	net0:phys                     (show-link -p -o link,class)
//
// A datalink with no IP interface on it (an etherstub) is reported too, the
// way Linux lists a link that carries no address.
func parseSolarisDatalinks(macs string, classes string) []Interface {
	byName := map[string]*Interface{}
	var order []string
	get := func(name string) *Interface {
		if iface, ok := byName[name]; ok {
			return iface
		}
		byName[name] = &Interface{Name: name}
		order = append(order, name)
		return byName[name]
	}

	for line := range strings.SplitSeq(macs, "\n") {
		link, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		mac := normalizeSolarisMAC(strings.ReplaceAll(value, `\:`, ":"))
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		get(link).SetMAC(mac)
	}

	for line := range strings.SplitSeq(classes, "\n") {
		link, class, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || class == "" {
			continue
		}
		get(link).Virtual = convert.ToPtr(class != "phys")
	}

	res := make([]Interface, 0, len(order))
	for _, name := range order {
		res = append(res, *byName[name])
	}
	return res
}

func (n *neti) getSolarisGatewayDetails() ([]Interface, error) {
	output, err := n.RunCommand("netstat -rn")
	if err != nil {
		return nil, err
	}
	return parseSolarisGateways(output), nil
}

// parseSolarisGateways reads the default routes from Solaris `netstat -rn`:
//
//	default              10.77.1.1            UG        3      77348 net0
//
// The interface is the last column in both the IPv4 and the IPv6 table.
func parseSolarisGateways(output string) []Interface {
	var interfaces []Interface
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || !isDefaultRoute(fields[0]) {
			continue
		}
		gw := fields[1]
		if pct := strings.Index(gw, "%"); pct != -1 {
			gw = gw[:pct]
		}
		ip := net.ParseIP(gw)
		if ip == nil {
			continue
		}
		ver := IPv4
		if ip.To4() == nil {
			ver = IPv6
		}
		// a logical interface's route names it net0:1
		name, _, _ := strings.Cut(fields[len(fields)-1], ":")
		interfaces = append(interfaces, Interface{
			Name: name,
			enrichments: func(in *Interface) {
				for i := range in.IPAddresses {
					v, ok := in.IPAddresses[i].Version()
					if !ok || v != ver {
						continue
					}
					in.IPAddresses[i].Gateway = gw
				}
			},
		})
	}
	return interfaces
}
