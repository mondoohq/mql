// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"errors"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/networki/oui"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// neti is a helper struct to avoid passing the connection and platform
// as function arguments.
type neti struct {
	connection shared.Connection
	platform   *inventory.Platform
}

// Interfaces returns the network interfaces of the system.
//
// NOTE we are not using `net.Interfaces()` since the implementation use syscall's
// which do not work for SSH connection types.
func Interfaces(conn shared.Connection, pf *inventory.Platform) ([]Interface, error) {
	n := &neti{conn, pf}

	// Solaris 11.4 ships /etc/os-release and is detected into the linux
	// family, so it is matched by name first.
	if pf.Name == "solaris" {
		return n.detectSolarisInterfaces()
	}
	if pf.IsFamily(inventory.FAMILY_LINUX) {
		return n.detectLinuxInterfaces()
	}
	if pf.IsFamily(inventory.FAMILY_DARWIN) {
		return n.detectDarwinInterfaces()
	}
	if pf.IsFamily(inventory.FAMILY_BSD) {
		return n.detectBSDInterfaces()
	}
	if pf.IsFamily(inventory.FAMILY_WINDOWS) && conn.Capabilities().Has(shared.Capability_File) {
		return n.detectWindowsInterfaces()
	}

	return nil, errors.New("your platform is not supported for the detection of network interfaces")
}

// runCommand is a wrapper around connection.RunCommand that helps execute commands
// and read the standard output for unix and windows systems.
func (n *neti) RunCommand(commandString string) (string, error) {
	if n.platform.IsFamily(inventory.FAMILY_WINDOWS) {
		commandString = powershell.Encode(commandString)
	}
	cmd, err := n.connection.RunCommand(commandString)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

type Interface struct {
	Name        string      `json:"name"`
	MACAddress  string      `json:"mac_address"`
	Vendor      string      `json:"vendor"`
	IPAddresses []IPAddress `json:"ip_addresses"`
	MTU         int         `json:"mtu"`
	Flags       []string    `json:"flags"`
	Active      *bool       `json:"active"`
	Virtual     *bool       `json:"virtual"`

	enrichments enrichmentFn
}
type enrichmentFn func(in *Interface)

// SetMAC is the recommended way to configure the MAC address of
// the interface since it uses it to populate the Vendor field.
func (i *Interface) SetMAC(mac string) {
	if mac != "" {
		i.MACAddress = strings.ReplaceAll(mac, "-", ":")
		// An all-zero address (loopback, tunnels) is no address, and its
		// 00:00:00 prefix would otherwise read as XEROX's OUI.
		if !isZeroMAC(i.MACAddress) {
			i.Vendor = oui.Vendor(i.MACAddress)
		}
	}
}

// isZeroMAC reports whether every hex digit of a colon-separated hardware
// address is zero.
func isZeroMAC(mac string) bool {
	return strings.Trim(mac, "0:") == ""
}

// AddOrUpdateInterfaces adds or updates one or many network interfaces
func AddOrUpdateInterfaces(interfaces1, interfaces2 []Interface) (interfaces []Interface) {
	interfaces = interfaces1
	for _, iinterface := range interfaces2 {
		index := FindInterface(interfaces, iinterface)

		if index < 0 {
			// not found, add
			log.Trace().Str("name", iinterface.Name).Msg("os.network.interface> add interface")
			interfaces = append(interfaces, iinterface)
			index = len(interfaces) - 1
		} else {
			// found, update
			log.Trace().Str("name", iinterface.Name).Msg("os.network.interface> update interface")
			merged := mergeInterfaces(interfaces[index], iinterface)
			interfaces[index] = merged
		}

		// enritchments function
		if iinterface.enrichments != nil {
			log.Trace().Str("name", iinterface.Name).Msg("os.network.interface> enrichments")
			iinterface.enrichments(&interfaces[index])
		}
	}
	return
}

// mergeInterfaces merges two interfaces giving precedence to the first interface (i1).
func mergeInterfaces(i1, i2 Interface) Interface {
	log.Trace().
		Interface("i1", i1).
		Interface("i2", i2).
		Msg("os.network.interface> merging interfaces")

	if i1.Name == "" {
		i1.Name = i2.Name
	}
	if i1.MACAddress == "" {
		i1.SetMAC(i2.MACAddress)
	}
	if i1.Vendor == "" {
		i1.Vendor = i2.Vendor
	}
	if i1.MTU == 0 {
		i1.MTU = i2.MTU
	}
	if i1.Active == nil {
		i1.Active = i2.Active
	}
	if i1.Virtual == nil {
		i1.Virtual = i2.Virtual
	}

	for _, flag := range i2.Flags {
		if !slices.Contains(i1.Flags, flag) {
			i1.Flags = append(i1.Flags, flag)
		}
	}

	i1.AddOrUpdateIP(i2.IPAddresses...)

	return i1
}

// FindInterface finds an interface from a list of interfaces.
// It first tries an exact name match, then falls back to matching
// by base interface name to handle peer interfaces (e.g. eth0@if103).
func FindInterface(interfaces []Interface, iinterface Interface) int {
	// Try exact match first
	idx := slices.IndexFunc(interfaces, func(i Interface) bool {
		return i.Name == iinterface.Name
	})
	if idx >= 0 {
		return idx
	}

	// Fall back to base name match (handles peer interfaces like eth0@if103)
	base := baseInterfaceName(iinterface.Name)
	return slices.IndexFunc(interfaces, func(i Interface) bool {
		return baseInterfaceName(i.Name) == base
	})
}

// baseInterfaceName strips the peer suffix (@ifN) from interface names.
// For example, "eth0@if103" returns "eth0", while "enX0" returns "enX0".
func baseInterfaceName(name string) string {
	if i := strings.Index(name, "@"); i != -1 {
		return name[:i]
	}
	return name
}

// AddOrUpdateIP adds or updates one or many IPAddresses
func (i *Interface) AddOrUpdateIP(ips ...IPAddress) {
	if i.IPAddresses == nil {
		i.IPAddresses = make([]IPAddress, 0)
	}

	for _, ip := range ips {
		if ip.IP == nil {
			continue
		}

		index := i.FindIP(ip.IP)
		if index < 0 {
			// not found, add
			log.Trace().Str("ip", ip.IP.String()).Msg("os.network.interface> add ip")
			i.IPAddresses = append(i.IPAddresses, ip)
			continue
		}

		// found, update
		log.Trace().Str("ip", ip.IP.String()).Msg("os.network.interface> update ip")
		i.mergeIP(index, ip)
	}
}

// mergeIP merges the ip address into the provided index.
func (i *Interface) mergeIP(index int, ip IPAddress) {
	merged := mergeIPs(i.IPAddresses[index], ip)
	i.IPAddresses[index] = merged
}

// FindIP finds an ip address inside a network interface.
func (i *Interface) FindIP(ip net.IP) int {
	return slices.IndexFunc(i.IPAddresses, func(address IPAddress) bool {
		return address.IP.Equal(ip)
	})
}

// mergeIPs merges two ip addresses giving precedence to the first address (ip1).
func mergeIPs(ip1, ip2 IPAddress) IPAddress {
	log.Trace().
		Interface("ip1", ip1).
		Interface("ip2", ip2).
		Msg("os.network.interface> merging ip addresses")

	if ip1.Subnet == "" {
		ip1.Subnet = ip2.Subnet
	}
	if ip1.Gateway == "" {
		ip1.Gateway = ip2.Gateway
	}
	if ip1.CIDR == "" {
		ip1.CIDR = ip2.CIDR
	}
	if ip1.Broadcast == "" {
		ip1.Broadcast = ip2.Broadcast
	}
	return ip1
}

// isDefaultRoute returns true if the provided field matches one of the
// possible default route formats.
func isDefaultRoute(field string) bool {
	// human readable
	return field == "default" ||
		// IPv4
		field == "0.0.0.0" ||
		field == "0.0.0.0/0" ||
		// IPv6
		field == "::/0" ||
		field == "::"
}
