// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// Compiled once: these are matched against every line of `ip addr` output.
var (
	interfaceRegex = regexp.MustCompile(`^\d+: ([^:]+): <([^>]+)> mtu (\d+)`)
	macRegex       = regexp.MustCompile(`link/ether ([0-9a-fA-F:]+) `)
	ipRegex        = regexp.MustCompile(`inet ([0-9\.]+)/([0-9]+)`)
	ip6Regex       = regexp.MustCompile(`inet6 ([0-9a-fA-F:]+)/([0-9]+) scope (global|link|host)`)
)

// detectLinuxInterfaces detects network interfaces on Linux.
func (n *neti) detectLinuxInterfaces() ([]Interface, error) {
	var errs []error
	interfaces := []Interface{}

	// List of detectors that collect network interfaces, we stop executing them as
	// soon as one of them succeeds collecting all the information
	detectors := []func() ([]Interface, error){
		n.getLinuxCmdInterfaces,
		n.getLinuxSysfsInterfaces,
	}
	for _, detectFn := range detectors {
		detectedInterfaces, err := detectFn()
		if err == nil && len(detectedInterfaces) != 0 {
			interfaces = AddOrUpdateInterfaces(interfaces, detectedInterfaces)
			break
		}
		log.Debug().Err(err).
			Msg("os.network.interface> unable to detect network interfaces")
		errs = append(errs, err)
	}

	// List of enrichment functions that collect additional information that we
	// couldn't gather in the detectors.
	enrichments := []func() ([]Interface, error){}

	// Addresses are the one thing the sysfs detector cannot answer, because the
	// kernel does not publish them under /sys/class/net. Where iproute2 is not
	// installed that left every interface with none, and network.ipv4,
	// network.ipv6, network.primaryIPv4 and ipAddress empty with it. procfs has
	// them on every Linux kernel.
	//
	// The test is whether anything was found rather than which detector ran:
	// `ip addr` reports at least the loopback address on any running host, so
	// no addresses at all means the walk that cannot see them is what answered.
	// It runs before the gateway enrichments so those have addresses to attach
	// a gateway to.
	if interfacesHaveNoIPs(interfaces) {
		known := interfaceNames(interfaces)
		enrichments = append(enrichments, func() ([]Interface, error) {
			return n.getLinuxProcfsIPs(known)
		})
	}

	enrichments = append(enrichments,
		n.getLinuxIPv4GatewayDetails,
		n.getLinuxIPv6GatewayDetails,
	)

	// The sysfs detector already answers Virtual for every interface it walks,
	// so the enrichment has something to add only when the command detector
	// won. Asking anyway costs a second walk of /sys/class/net plus a few
	// probes per interface, and over a remote connection each of those is a
	// round trip.
	//
	// The test is whether any interface still lacks a verdict rather than
	// which detector ran: linuxInterfaceVirtual can decline to answer for a
	// single interface, and that one should still get its chance here.
	if slices.ContainsFunc(interfaces, func(i Interface) bool { return i.Virtual == nil }) {
		enrichments = append(enrichments, n.getLinuxSysfsVirtual)
	}

	for _, detectFn := range enrichments {
		detectedInterfaces, err := detectFn()
		if err != nil {
			log.Debug().Err(err).
				Msg("os.network.interface> unable to detect network interfaces")
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

func (n *neti) getLinuxIPv4GatewayDetails() (interfaces []Interface, err error) {
	output, err := n.RunCommand("ip route show")
	log.Debug().Msg("os.network.interface> run command ip route show")
	if err != nil {
		log.Debug().Msg("os.network.interface> failed running ip route show")
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		// we are looking for lines like this one
		//
		// default via 172.31.16.1 dev enX0
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) > 4 && isDefaultRoute(fields[0]) {
			interfaces = append(interfaces, Interface{
				Name: fields[4],
				enrichments: func(in *Interface) {
					for i := range in.IPAddresses {
						if version, ok := in.IPAddresses[i].Version(); ok && version == IPv4 {
							in.IPAddresses[i].Gateway = fields[2]
						}
					}
				},
			})
		}
	}
	return
}

func (n *neti) getLinuxIPv6GatewayDetails() (interfaces []Interface, err error) {
	output, err := n.RunCommand("ip -6 route show")
	log.Debug().Msg("os.network.interface> run command ip -6 route show")
	if err != nil {
		log.Debug().Msg("os.network.interface> failed running ip -6 route show")
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		// we are looking for lines like this one
		//
		// default via 2001:db8::1 dev enX1
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) > 4 && isDefaultRoute(fields[0]) {
			interfaces = append(interfaces, Interface{
				Name: fields[4],
				enrichments: func(in *Interface) {
					for i := range in.IPAddresses {
						if version, ok := in.IPAddresses[i].Version(); ok && version == IPv6 {
							in.IPAddresses[i].Gateway = fields[2]
						}
					}
				},
			})
		}
	}
	return
}

func (n *neti) getLinuxSysfsInterfaces() (interfaces []Interface, err error) {
	log.Debug().Msg("os.network.interface> detecting interfaces via sysfs")

	dirEntries, err := afero.ReadDir(n.connection.FileSystem(), "/sys/class/net")
	if err != nil {
		log.Debug().Msg("os.network.interface> could not read /sys/class/net")
		return nil, err
	}

	log.Debug().Int("dir_entries", len(dirEntries)).Msg("os.network.interface> read /sys/class/net")

	for _, entry := range dirEntries {
		ifaceName := entry.Name()

		// /sys/class/net holds more than interfaces. The bonding driver keeps
		// its control file bonding_masters there, and reporting it as an
		// interface invents one with no mac, no mtu and no flags -- which it
		// did on every distribution scanned without `ip` installed, and in the
		// host namespace of a machine with the bonding module loaded.
		//
		// Filtering on IsDir cannot do this: these entries are symlinks, and
		// over SFTP IsDir is false for all of them, which is what
		// linux_sys_class_net_symlinks.toml exists to pin. So require a marker
		// every real interface carries instead.
		if !isLinuxNetworkInterface(n.connection.FileSystem(), ifaceName) {
			log.Debug().Str("entry", ifaceName).
				Msg("os.network.interface> skipping /sys/class/net entry that is not an interface")
			continue
		}

		iinterface := Interface{Name: ifaceName}

		// Read MAC Address
		macAddress, err := afero.ReadFile(
			n.connection.FileSystem(),
			filepath.Join("/sys/class/net/", ifaceName, "address"),
		)
		if err == nil {
			iinterface.SetMAC(strings.TrimSpace(string(macAddress)))
		}

		// Read MTU
		mtu, err := afero.ReadFile(
			n.connection.FileSystem(),
			filepath.Join("/sys/class/net/", ifaceName, "mtu"),
		)
		if err == nil {
			iinterface.MTU = parseInt(strings.TrimSpace(string(mtu)))
		}

		iinterface.Virtual = linuxInterfaceVirtual(n.connection.FileSystem(), ifaceName)

		// Read Flags
		flags, err := afero.ReadFile(
			n.connection.FileSystem(),
			filepath.Join("/sys/class/net/", ifaceName, "flags"),
		)
		if err == nil {
			iinterface.Flags = parseHexFlags(strings.TrimPrefix(string(flags), "0x"))
		}

		// Read Status
		operstate, err := afero.ReadFile(
			n.connection.FileSystem(),
			filepath.Join("/sys/class/net/", ifaceName, "operstate"),
		)
		if err == nil {
			switch strings.TrimSpace(strings.ToLower(string(operstate))) {
			case "up":
				iinterface.Active = convert.ToPtr(true)
			case "down":
				iinterface.Active = convert.ToPtr(false)
			}
		}

		// TODO we could fetch statistics from here, like `tx_queue_len` or `rx_bytes` and `tx_bytes`
		// iinterface.Statistics = getLinuxInterfaceStats(ifaceName)

		interfaces = append(interfaces, iinterface)
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "cmd.sys_class_net_fs").
		Msg("os.network.interfaces> discovered")

	return
}

func parseHexFlags(hexStr string) []string {
	flagsMap := map[int]string{
		0x1:    "UP",
		0x2:    "BROADCAST",
		0x4:    "DEBUG",
		0x8:    "LOOPBACK",
		0x10:   "POINTOPOINT",
		0x20:   "NOTRAILERS",
		0x40:   "RUNNING",
		0x80:   "NOARP",
		0x100:  "PROMISC",
		0x200:  "ALLMULTI",
		0x400:  "MASTER",
		0x800:  "SLAVE",
		0x1000: "MULTICAST",
		0x2000: "PORTSEL",
		0x4000: "AUTOMEDIA",
		0x8000: "DYNAMIC",
	}
	flagsInt, err := strconv.ParseInt(hexStr, 16, 32)
	if err != nil {
		return []string{}
	}
	var flags []string
	for bit, name := range flagsMap {
		if int(flagsInt)&bit != 0 {
			flags = append(flags, name)
		}
	}
	return flags
}

func (n *neti) getLinuxCmdInterfaces() ([]Interface, error) {
	log.Debug().Msg("os.network.interface> detecting interfaces via command line")

	output, err := n.RunCommand("ip addr show")
	log.Debug().Msg("os.network.interface> run command ip addr show")
	if err != nil {
		log.Debug().Msg("os.network.interface> failed running ip addr show")
		return nil, err
	}

	var (
		interfaces = []Interface{}
		scanner    = bufio.NewScanner(strings.NewReader(string(output)))
		// TODO @afiune we could add additional information to the interface struct like
		//  * `altname` (alternative name)
		//  * `metric` (priority or cost of a network interface)
	)

	var currentInterface *Interface
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if matches := interfaceRegex.FindStringSubmatch(line); matches != nil {
			if currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
			}
			mtu := parseInt(matches[3])
			flags := strings.Split(matches[2], ",")
			active := strings.Contains(matches[2], "UP")
			// Virtual is deliberately left unset. `ip addr` does not report
			// it, and the name it prints does not imply it, so it is filled
			// from sysfs by getLinuxSysfsVirtual below -- one source of truth
			// for the field however the interfaces were discovered.
			currentInterface = &Interface{
				Name:        matches[1],
				MTU:         mtu,
				Flags:       flags,
				Active:      &active,
				IPAddresses: []IPAddress{},
			}
		} else if currentInterface != nil {
			if matches := macRegex.FindStringSubmatch(line); matches != nil {
				// Match MAC address
				currentInterface.SetMAC(matches[1])
			} else if matches := ipRegex.FindStringSubmatch(line); matches != nil {
				// Match IPv4 address
				currentInterface.AddOrUpdateIP(NewIPv4WithPrefixLength(
					matches[1],
					parseInt(matches[2]),
				))
			} else if matches := ip6Regex.FindStringSubmatch(line); matches != nil {
				// Match IPv6 address
				ip := NewIPv6WithPrefixLength(matches[1], parseInt(matches[2]))
				currentInterface.AddOrUpdateIP(ip)
			}
		}
	}

	if currentInterface != nil {
		interfaces = append(interfaces, *currentInterface)
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "cmd.ip_addr_show").
		Msg("os.network.interfaces> discovered")
	return interfaces, nil
}

// getLinuxSysfsVirtual reports which interfaces are virtual, for the
// interfaces sysfs knows about.
//
// It runs as an enrichment rather than inside a detector because only one
// detector runs -- `ip addr` wins where iproute2 is installed, the sysfs walk
// answers otherwise -- and the field has to mean the same thing either way.
// Before this, whether an interface was virtual depended on whether iproute2
// happened to be installed on the host being scanned.
func (n *neti) getLinuxSysfsVirtual() ([]Interface, error) {
	dirEntries, err := afero.ReadDir(n.connection.FileSystem(), "/sys/class/net")
	if err != nil {
		return nil, err
	}

	interfaces := []Interface{}
	for _, entry := range dirEntries {
		name := entry.Name()
		if !isLinuxNetworkInterface(n.connection.FileSystem(), name) {
			continue
		}
		virtual := linuxInterfaceVirtual(n.connection.FileSystem(), name)
		if virtual == nil {
			continue
		}
		interfaces = append(interfaces, Interface{Name: name, Virtual: virtual})
	}

	log.Debug().Int("interfaces", len(interfaces)).
		Msg("os.network.interface> read virtual from sysfs")
	return interfaces, nil
}

// isLinuxNetworkInterface reports whether an entry of /sys/class/net is an
// interface. Every interface carries an ifindex and an address; nothing else
// the directory holds carries either, because nothing else is a directory.
func isLinuxNetworkInterface(fs afero.Fs, name string) bool {
	for _, marker := range []string{"ifindex", "address"} {
		if ok, err := afero.Exists(fs, filepath.Join("/sys/class/net", name, marker)); err == nil && ok {
			return true
		}
	}
	return false
}

// linuxInterfaceVirtual reports whether an interface is synthesized by the
// kernel rather than backed by hardware, reading the only source that knows.
//
// `ip addr` cannot answer it. The command detector used to guess from the name,
// treating a veth or virbr prefix as virtual and everything else as physical,
// which missed loopback, bridges, bonds, dummies, every tunnel, and a veth
// renamed to eth0 -- which is what a veth is called inside a container, so the
// guess was wrong for both interfaces of every container scanned.
//
// Two facts, in order. A devtype names a virtual kind outright, and some of
// those still sit on a bus and so have a device link of their own (a Xen vif).
// Where there is no devtype, the device link is the test: an interface backed
// by hardware has one, and everything the kernel synthesizes does not. That
// was checked both ways against sysfs on real systems -- lo, a container veth,
// docker0, bond0 and dummy0 have no device link and resolve under
// /sys/devices/virtual, while a virtio NIC has one and resolves under
// /sys/devices/platform.
func linuxInterfaceVirtual(fs afero.Fs, name string) *bool {
	base := filepath.Join("/sys/class/net", name)

	// TrimSpace matters: sysfs ends the value with a newline, so an untrimmed
	// read matched no case at all and every devtype fell through to nil.
	if devtype, err := afero.ReadFile(fs, filepath.Join(base, "device/devtype")); err == nil {
		if virtual := isVirtualDevice(strings.TrimSpace(string(devtype))); virtual != nil {
			return virtual
		}
	}

	hasDevice, err := afero.Exists(fs, filepath.Join(base, "device"))
	if err != nil {
		return nil
	}
	return convert.ToPtr(!hasDevice)
}

func isVirtualDevice(deviceType string) *bool {
	switch deviceType {
	// The device is a VIF (Xen virtual interface).
	case "vif":
		return convert.ToPtr(true)

	// The device is a TUN (network layer) virtual network interface.
	case "tun":
		return convert.ToPtr(true)

	// The device is a TAP (data link layer) virtual network interface.
	case "tap":
		return convert.ToPtr(true)

	// The device is a MACVLAN virtual network interface.
	case "macvlan":
		return convert.ToPtr(true)

	// The device is an IPVLan virtual network interface.
	case "ipvlan":
		return convert.ToPtr(true)

	// The device is a Virtual Ethernet (veth) interface.
	case "veth":
		return convert.ToPtr(true)

	// The device is a network bridge.
	case "bridge":
		return convert.ToPtr(true)

	// The device is a bonded network interface (multiple NICs bonded together).
	case "bond":
		return convert.ToPtr(true)

	// The device is a VXLAN virtual network tunnel interface.
	case "vxlan":
		return convert.ToPtr(true)

	// The device is a GRE (Generic Routing Encapsulation) tunnel interface.
	case "gre":
		return convert.ToPtr(true)

	// The device is a GRE TAP (Layer 2 GRE) tunnel interface.
	case "gretap":
		return convert.ToPtr(true)

	// The device is an IPv6 GRE tunnel interface.
	case "ip6gre":
		return convert.ToPtr(true)

	// The device is an IPv6 GRE TAP tunnel interface.
	case "ip6gretap":
		return convert.ToPtr(true)

	// The device is an IPv6-in-IPv4 tunnel.
	case "sit":
		return convert.ToPtr(true)

	// The device is an IPv4-in-IPv4 tunnel.
	case "ipip":
		return convert.ToPtr(true)

	// The device is a WireGuard VPN interface.
	case "wireguard":
		return convert.ToPtr(true)

	// The device is a Point-to-Point Protocol (PPP) interface.
	case "ppp":
		return convert.ToPtr(true)

	// The device is an XFRM (IPsec transform) interface.
	case "xfrm":
		return convert.ToPtr(true)

	}
	return nil
}
