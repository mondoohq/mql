// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"howett.net/plist"
)

// Compiled once: this is matched against every line of ifconfig output.
var darwinFlagsRegex = regexp.MustCompile(`flags=([0-9]+)<([^>]+)>`)

// darwinInterfaceHeaderRegex matches the line that starts an interface block in
// ifconfig output. Anchored at column 0 on purpose: a bridge's `member: en1
// flags=3<...>` line is indented and must not be read as an interface.
var darwinInterfaceHeaderRegex = regexp.MustCompile(`^([a-zA-Z0-9_.-]+): flags=`)

// detectDarwinInterfaces detects network interfaces on Darwin.
func (n *neti) detectDarwinInterfaces() ([]Interface, error) {
	var errs []error
	interfaces := []Interface{}

	// ifconfig describes the interfaces that exist now, and the plist is a
	// fallback for a scan that cannot run it -- a mounted image or disk --
	// rather than a second opinion to merge in. The two answer different
	// questions: NetworkInterfaces.plist is macOS's record of every interface
	// the machine has ever seen, so adding its entries to a live enumeration
	// reported adapters that are not plugged in, as names with no mac, no mtu
	// and no address. Only one detector runs, the way the Linux path already
	// works.
	//
	// Nothing is lost on a live scan: the plist contributes a name and Active,
	// and ifconfig's own `status:` line already carries the latter.
	detectors := []func() ([]Interface, error){
		n.getMacIfconfigInterfaces,
		n.getMacSystemConfigInterfaces,
		// Detector via: `networksetup -listallhardwareports`
		// Detector via: `netstat -I <interface_name>`
	}
	for _, detectFn := range detectors {
		detectedInterfaces, err := detectFn()
		if err == nil && len(detectedInterfaces) != 0 {
			interfaces = AddOrUpdateInterfaces(interfaces, detectedInterfaces)
			break
		}
		log.Debug().Err(err).Msg("os.network.interface> unable to detect network interfaces")
		errs = append(errs, err)
	}

	// Enrichments describe interfaces the detector already found; the gateway
	// comes from the routing table, which names interfaces rather than
	// introducing them.
	enrichments := []func() ([]Interface, error){
		n.getMacGatewayDetails,
	}
	for _, detectFn := range enrichments {
		detectedInterfaces, err := detectFn()
		if err != nil {
			log.Debug().Err(err).Msg("os.network.interface> unable to enrich network interfaces")
			errs = append(errs, err)
			continue
		}
		interfaces = AddOrUpdateInterfaces(interfaces, detectedInterfaces)
	}

	if len(interfaces) == 0 {
		return interfaces, errors.Join(errs...)
	}

	return interfaces, nil
}

func (n *neti) getMacSystemConfigInterfaces() ([]Interface, error) {
	var interfaces []Interface
	content, err := afero.ReadFile(
		n.connection.FileSystem(),
		"/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist",
	)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if _, err := plist.Unmarshal(content, &result); err != nil {
		return nil, err
	}

	if entries, ok := result["Interfaces"].([]any); ok {
		for _, entry := range entries {
			if iface, ok := entry.(map[string]any); ok {
				iName, ok := iface["BSD Name"].(string)
				if !ok {
					log.Trace().
						Interface("interface", iface).
						Str("detector", "SystemConfiguration").
						Msg("os.network.interface> unable to detect network interface")
					continue
				}

				// Check if the interface is hidden, if so, don't add it
				if hidden, ok := iface["HiddenInterface"].(bool); ok && hidden {
					log.Debug().
						Interface("interface", iface).
						Str("detector", "SystemConfiguration").
						Msg("os.network.interface> found hidden network interface, skipping")
					continue
				}

				intf := Interface{
					Name: iName,
				}

				if active, ok := iface["Active"].(bool); ok {
					intf.Active = &active
				}

				interfaces = append(interfaces, intf)
			}
		}
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "SystemConfiguration").
		Msg("os.network.interfaces> discovered")
	return interfaces, nil
}

func (n *neti) getMacGatewayDetails() (interfaces []Interface, err error) {
	output, err := n.RunCommand("netstat -rn")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		// we are looking for lines like this one
		//
		// Destination        Gateway            Flags               Netif
		// default            192.168.86.1       UGScg                en0
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) > 3 && isDefaultRoute(fields[0]) {

			gatewayVersion := IPv4
			if strings.Contains(fields[1], ":") {
				gatewayVersion = IPv6
			}

			interfaces = append(interfaces, Interface{
				Name: fields[3],
				enrichments: func(in *Interface) {
					for i := range in.IPAddresses {
						version, ok := in.IPAddresses[i].Version()
						if !ok {
							continue
						}
						if version == gatewayVersion {
							in.IPAddresses[i].Gateway = fields[1]
						}
					}
				},
			})
		}
	}
	return
}

func (n *neti) getMacIfconfigInterfaces() (interfaces []Interface, err error) {
	output, err := n.RunCommand("ifconfig")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentInterface *Interface
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		// An interface starts at column 0 and everything belonging to it is
		// indented. That indentation is the only thing separating an interface
		// from a bridge's membership line, which has the same shape:
		//
		//	bridge0: flags=8863<UP,BROADCAST,...> mtu 1500
		//	        member: en1 flags=3<LEARNING,DISCOVER>
		//
		// Matching on flags= anywhere in a trimmed line made `member` an
		// interface of its own -- with no mac, no mtu and no address -- on
		// every host that has a bridge, which on macOS includes any machine
		// running Internet Sharing, a hypervisor or Thunderbolt Bridge.
		if header := darwinInterfaceHeaderRegex.FindStringSubmatch(raw); header != nil {
			if currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
			}
			currentInterface = &Interface{Name: header[1]}
			if strings.HasPrefix(currentInterface.Name, "vmnet") {
				currentInterface.Virtual = convert.ToPtr(true)
			}

			// Flags and MTU are only ever on this line, and reading them here
			// rather than from any line carrying them keeps a membership line
			// from overwriting the bridge's own flags with LEARNING,DISCOVER.
			if flagsMatch := darwinFlagsRegex.FindStringSubmatch(raw); len(flagsMatch) > 2 {
				currentInterface.Flags = strings.Split(flagsMatch[2], ",")
			}
			fields := strings.Fields(raw)
			for i, f := range fields {
				if f == "mtu" && i+1 < len(fields) {
					currentInterface.MTU = parseInt(fields[i+1])
				}
			}
			continue
		}

		if currentInterface != nil {
			// Match MAC address
			if strings.Contains(line, "ether") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					currentInterface.SetMAC(fields[1])
				}
			}

			// Match IPv4 address, CIDR, and netmask
			if strings.HasPrefix(line, "inet ") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					ip := fields[1]
					ipv4, ok := NewIPAddress(ip)
					if !ok {
						log.Trace().Str("ip", ip).Msg("not a valid ipaddress, skipping")
						continue
					}
					if len(fields) > 3 {
						// netmask found
						netmask := fields[3]
						ipv4 = NewIPv4WithMask(ip, netmask)
					}
					currentInterface.AddOrUpdateIP(ipv4)
				}
			}

			// Match IPv6 address, CIDR, and netmask
			if strings.HasPrefix(line, "inet6 ") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					ip := fields[1]
					// Check if the ip address has a scope id like "fe80::1%lo0"
					if strings.Contains(ip, "%") {
						ipWithScope := strings.Split(ip, "%")
						ip = ipWithScope[0]
						if ipWithScope[1] != currentInterface.Name {
							log.Debug().
								Str("scope_id", ipWithScope[1]).
								Str("interface_name", currentInterface.Name).
								Msg("ipv6 scope id and interface name mismatched")
						}
					}
					ipv6, ok := NewIPAddress(ip)
					if !ok {
						log.Trace().Str("ip", ip).Msg("not a valid ipaddress, skipping")
						continue
					}
					if len(fields) > 3 {
						// prefix length found
						prefixLength := parseInt(fields[3])
						ipv6 = NewIPv6WithPrefixLength(ip, prefixLength)
					}
					currentInterface.AddOrUpdateIP(ipv6)
				}
			}

			// Match status [active/inactive]
			if strings.Contains(line, "status:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					switch fields[1] {
					case "active":
						currentInterface.Active = convert.ToPtr(true)
					case "inactive":
						currentInterface.Active = convert.ToPtr(false)
					}
				}
			}

		}
	}

	if currentInterface != nil {
		interfaces = append(interfaces, *currentInterface)
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "cmd.ifconfig").
		Msg("os.network.interfaces> discovered")
	return interfaces, nil
}

func parseInt(s string) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return val
}
