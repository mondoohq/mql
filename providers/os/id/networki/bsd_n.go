// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

// detectBSDInterfaces detects network interfaces on FreeBSD, NetBSD,
// OpenBSD, and DragonFly. (Darwin/macOS uses detectDarwinInterfaces.)
func (n *neti) detectBSDInterfaces() ([]Interface, error) {
	detectors := []func() ([]Interface, error){
		n.getBSDIfconfigInterfaces,
		n.getBSDGatewayDetails,
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

// bsdIfconfigHeader matches the first line of an ifconfig stanza. NetBSD
// prefixes the flags value with "0x"; the others use a bare hex/decimal
// number. Both forms are accepted, as is the second flags word AIX prints:
// en0: flags=1e084863,81cc0<UP,BROADCAST,...>
var bsdIfconfigHeader = regexp.MustCompile(`^([a-zA-Z0-9._]+):\s+flags=(?:0x)?[0-9a-fA-F]+(?:,[0-9a-fA-F]+)?<([^>]*)>`)

func (n *neti) getBSDIfconfigInterfaces() (interfaces []Interface, err error) {
	output, err := n.RunCommand("ifconfig -a")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	var current *Interface
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" {
			continue
		}

		if m := bsdIfconfigHeader.FindStringSubmatch(raw); len(m) > 0 {
			if current != nil {
				interfaces = append(interfaces, *current)
			}
			current = &Interface{
				Name:    m[1],
				Virtual: bsdVirtualByName(m[1]),
			}
			if m[2] != "" {
				current.Flags = strings.Split(m[2], ",")
			}
			tokens := strings.Fields(raw)
			for i, t := range tokens {
				if t == "mtu" && i+1 < len(tokens) {
					current.MTU = parseInt(tokens[i+1])
				}
			}
			continue
		}

		if current == nil {
			continue
		}

		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		// MAC: "ether AA:..." (FreeBSD/DragonFly), "lladdr AA:..." (OpenBSD),
		// "address: AA:..." (NetBSD)
		case "ether", "lladdr", "address:":
			current.SetMAC(fields[1])

		case "inet":
			// Two formats:
			//   FreeBSD/OpenBSD/DragonFly: inet 1.2.3.4 netmask 0xffffff00 broadcast 1.2.3.255
			//   NetBSD:                    inet 1.2.3.4/24 broadcast 1.2.3.255 flags 0x0
			ipField := fields[1]
			if slash := strings.Index(ipField, "/"); slash != -1 {
				current.AddOrUpdateIP(NewIPv4WithPrefixLength(
					ipField[:slash],
					parseInt(ipField[slash+1:]),
				))
			} else if len(fields) >= 4 && fields[2] == "netmask" {
				current.AddOrUpdateIP(NewIPv4WithMask(ipField, fields[3]))
			} else if ip, ok := NewIPAddress(ipField); ok {
				current.AddOrUpdateIP(ip)
			}

		case "inet6":
			// FreeBSD/OpenBSD/DragonFly: inet6 fe80::1%em0 prefixlen 64 scopeid 0x1
			// NetBSD:                    inet6 fe80::1%wm0/64 flags 0x0 scopeid 0x1
			ipField := fields[1]
			prefix := -1
			if slash := strings.Index(ipField, "/"); slash != -1 {
				prefix = parseInt(ipField[slash+1:])
				ipField = ipField[:slash]
			}
			if pct := strings.Index(ipField, "%"); pct != -1 {
				if pct < len(ipField) {
					ipField = ipField[:pct]
				}
			}
			if prefix < 0 {
				for i, t := range fields {
					if t == "prefixlen" && i+1 < len(fields) {
						prefix = parseInt(fields[i+1])
						break
					}
				}
			}
			if prefix >= 0 {
				current.AddOrUpdateIP(NewIPv6WithPrefixLength(ipField, prefix))
			} else if ip, ok := NewIPAddress(ipField); ok {
				current.AddOrUpdateIP(ip)
			}

		case "status:":
			switch fields[1] {
			case "active":
				current.Active = convert.ToPtr(true)
			case "inactive", "no":
				current.Active = convert.ToPtr(false)
			}
		}
	}

	if current != nil {
		interfaces = append(interfaces, *current)
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "cmd.ifconfig").
		Msg("os.network.interfaces> discovered")
	return interfaces, nil
}

// getBSDGatewayDetails extracts default-gateway info from `netstat -rn`.
// netstat prints both the Internet (IPv4) and Internet6 sections in one
// pass, so a single command covers both address families on all four
// non-Darwin BSDs.
func (n *neti) getBSDGatewayDetails() (interfaces []Interface, err error) {
	output, err := n.RunCommand("netstat -rn")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 4 || !isDefaultRoute(fields[0]) {
			continue
		}

		gateway := fields[1]
		// Strip "%ifname" zone suffix from link-local IPv6 gateways
		if pct := strings.Index(gateway, "%"); pct != -1 {
			gateway = gateway[:pct]
		}

		version := IPv4
		if strings.Contains(gateway, ":") {
			version = IPv6
		}

		// The Netif column position varies (Expire may or may not be
		// populated), so pick the rightmost token that looks like an
		// interface name.
		netif := ""
		for i := len(fields) - 1; i >= 2; i-- {
			if isLikelyBSDIfname(fields[i]) {
				netif = fields[i]
				break
			}
		}
		if netif == "" {
			continue
		}

		gw := gateway
		ver := version
		interfaces = append(interfaces, Interface{
			Name: netif,
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
	return
}

// bsdIfnamePattern matches typical BSD interface names like em0, wm0,
// vlan100, gif0, lo0, em0.5 (vlan sub-interface).
var bsdIfnamePattern = regexp.MustCompile(`^[a-zA-Z]+\d+(\.\d+)?$`)

func isLikelyBSDIfname(s string) bool {
	return bsdIfnamePattern.MatchString(s)
}

// bsdVirtualByName flags interfaces as virtual based on common BSD
// naming conventions. Only well-known virtual prefixes are reported as
// true; everything else stays nil ("unknown") rather than asserting
// physical, since BSD has no /sys/class/net to inspect.
func bsdVirtualByName(name string) *bool {
	prefixes := []string{
		"tap", "tun",
		"bridge", "vether", "veb",
		"epair",
		"vlan",
		"gif",
		"vxlan",
		"wg",
		"enc",
		"pflog", "pfsync",
		"vmnet",
		"ipsec",
		"ovpnc", "ovpns",
		"carp",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return convert.ToPtr(true)
		}
	}
	return nil
}
