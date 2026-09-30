// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

var errNoSuchInterface = errors.New("no such network interface")

// Compiled once: matched against every line of `ip addr` output.
var ipaddrParse = regexp.MustCompile(`^(\d+):\s([\w\d\./\:]+)\s*(inet|inet6)\s([\w\d\./\:]+)\s(.*)$`)

// mimics https://go.dev/src/net/interface.go to provide a similar api
type Interface struct {
	Index          int              // positive integer that starts at one, zero is never used
	MTU            int              // maximum transmission unit
	Name           string           // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr   net.HardwareAddr // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags          net.Flags        // e.g., FlagUp, FlagLoopback, FlagMulticast
	Addrs          []net.Addr
	MulticastAddrs []net.Addr
}

func New(conn shared.Connection) *InterfaceResource {
	return &InterfaceResource{
		conn: conn,
	}
}

type InterfaceResource struct {
	conn shared.Connection
}

func (r *InterfaceResource) Interfaces() ([]Interface, error) {
	asset := r.conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("cannot find OS information for interface detection")
	}

	log.Debug().Strs("families", asset.Platform.Family).Msg("check if platform is supported for network interface")
	if r.conn.Type() == shared.Type_Local {
		handler := &GoNativeInterfaceHandler{}
		return handler.Interfaces()
	} else if asset.Platform.Name == "macos" {
		log.Debug().Msg("detected macos platform")
		handler := &MacOSInterfaceHandler{
			conn: r.conn,
		}
		return handler.Interfaces()
	} else if asset.Platform.IsFamily(inventory.FAMILY_LINUX) {
		log.Debug().Msg("detected linux platform")
		handler := &LinuxInterfaceHandler{
			conn: r.conn,
		}
		return handler.Interfaces()
	} else if asset.Platform.IsFamily(inventory.FAMILY_BSD) && !asset.Platform.IsFamily(inventory.FAMILY_DARWIN) {
		log.Debug().Msg("detected bsd platform")
		handler := &BSDInterfaceHandler{
			conn: r.conn,
		}
		return handler.Interfaces()
	} else if asset.Platform.Name == "windows" {
		log.Debug().Msg("detected windows platform")
		handler := &WindowsInterfaceHandler{
			conn: r.conn,
		}
		return handler.Interfaces()
	}

	return nil, errors.New("interfaces does not yet support platform: " + asset.Platform.Name)
}

func (r *InterfaceResource) InterfaceByName(name string) (*Interface, error) {
	ifaces, err := r.Interfaces()
	if err != nil {
		return nil, err
	}

	for i := range ifaces {
		if ifaces[i].Name == name {
			return &ifaces[i], nil
		}
	}
	return nil, errNoSuchInterface
}

type GoNativeInterfaceHandler struct{}

func (i *GoNativeInterfaceHandler) Interfaces() ([]Interface, error) {
	var goInterfaces []net.Interface
	var err error
	if goInterfaces, err = net.Interfaces(); err != nil {
		return nil, errors.Wrap(err, "failed to load network interfaces")
	}

	ifaces := make([]Interface, len(goInterfaces))
	for i := range goInterfaces {

		addrs, err := goInterfaces[i].Addrs()
		if err != nil {
			log.Debug().Err(err).Str("iface", goInterfaces[i].Name).Msg("could not retrieve ip addresses")
		}
		multicastAddrs, err := goInterfaces[i].MulticastAddrs()
		if err != nil {
			log.Debug().Err(err).Str("iface", goInterfaces[i].Name).Msg("could not retrieve multicast addresses")
		}

		ifaces[i] = Interface{
			Name:           goInterfaces[i].Name,
			Index:          goInterfaces[i].Index,
			MTU:            goInterfaces[i].MTU,
			HardwareAddr:   goInterfaces[i].HardwareAddr,
			Flags:          goInterfaces[i].Flags,
			Addrs:          addrs,
			MulticastAddrs: multicastAddrs,
		}
	}

	return ifaces, nil
}

type LinuxInterfaceHandler struct {
	conn shared.Connection
}

func (i *LinuxInterfaceHandler) Interfaces() ([]Interface, error) {
	// TODO: support extracting the information via /sys/class/net/, /proc/net/fib_trie
	// fetch all network adapter via ip addr show
	cmd, err := i.conn.RunCommand("ip -o addr show")
	if err != nil {
		return nil, errors.Wrap(err, "could not run 'ip -o addr show' to fetch network interfaces")
	}

	return i.ParseIpAddr(cmd.Stdout)
}

func (i *LinuxInterfaceHandler) ParseIpAddr(r io.Reader) ([]Interface, error) {
	interfaces := map[string]Interface{}

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		m := ipaddrParse.FindStringSubmatch(line)

		// check that we have a match
		if len(m) < 4 {
			return nil, fmt.Errorf("cannot parse ip: %s", line)
		}

		name := m[2]

		idx, err := strconv.Atoi(strings.TrimSpace(m[1]))
		if err != nil {
			log.Warn().Err(err).Msg("could not parse ip addr idx")
			continue
		}

		inet, ok := interfaces[name]
		if !ok {
			inet = Interface{
				Index: idx,
				Name:  name,
			}
		}

		var ip net.IP
		switch m[3] {
		case "inet":
			ipv4Addr, _, err := net.ParseCIDR(m[4])
			if err != nil {
				log.Error().Err(err).Msg("could not parse ipv4")
			}

			ip = ipv4Addr
		case "inet6":
			ipv6Addr, _, err := net.ParseCIDR(m[4])
			if err != nil {
				log.Error().Err(err).Msg("could not parse ipv6")
			}
			ip = ipv6Addr
		}

		inet.Addrs = append(inet.Addrs, &ipAddr{IP: ip})

		var flags net.Flags
		flags |= net.FlagUp

		if strings.Contains(m[5], "host") {
			flags |= net.FlagLoopback
		} else {
			flags |= net.FlagBroadcast
		}

		inet.Flags = flags

		interfaces[name] = inet
	}

	res := []Interface{}
	for i := range interfaces {
		res = append(res, interfaces[i])
	}

	return res, nil
}

type MacOSInterfaceHandler struct {
	conn shared.Connection
}

func (i *MacOSInterfaceHandler) Interfaces() ([]Interface, error) {
	// fetch all network adapter
	cmd, err := i.conn.RunCommand("ifconfig")
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch macos network adapter")
	}

	return i.ParseMacOS(cmd.Stdout)
}

var (
	IfconfigInterfaceLine = regexp.MustCompile(`^(.*):\ flags=(\d*)\<(.*)>\smtu\s(\d*)$`)
	IfconfigInetLine      = regexp.MustCompile(`^\s+inet(\d*)\s([\w\d.:%]+)\s`)
)

func (i *MacOSInterfaceHandler) ParseMacOS(r io.Reader) ([]Interface, error) {
	interfaces := []Interface{}
	ifIndex := -1
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		// new interface
		m := IfconfigInterfaceLine.FindStringSubmatch(line)
		if len(m) > 0 {
			var mtu int
			var err error
			mtu, err = strconv.Atoi(strings.TrimSpace(m[4]))
			if err != nil {
				return nil, errors.Wrap(err, "cannot parse macos ifconfig mtu")
			}

			var flags net.Flags
			if len(m[3]) > 0 {
				ifConfigFlags := strings.Split(m[3], ",")
				for i := range ifConfigFlags {
					switch strings.ToLower(ifConfigFlags[i]) {
					case "up":
						flags |= net.FlagUp
					case "broadcast":
						flags |= net.FlagBroadcast
					case "multicast":
						flags |= net.FlagMulticast
					case "loopback":
						flags |= net.FlagLoopback
					case "pointtopoint":
						flags |= net.FlagPointToPoint
					}
				}
			}

			i := Interface{
				Index: ifIndex + 2,
				Name:  m[1],
				MTU:   mtu,
				Flags: flags,
			}

			interfaces = append(interfaces, i)
			ifIndex++
		}

		// parse mac address
		if strings.HasPrefix(line, "	ether") {
			macaddress := strings.TrimSpace(strings.TrimPrefix(line, "	ether"))
			mac, err := net.ParseMAC(macaddress)
			if err != nil {
				return nil, err
			}
			interfaces[ifIndex].HardwareAddr = mac
		}

		m = IfconfigInetLine.FindStringSubmatch(line)
		if len(m) > 0 {
			ip := parseIpAddr(m[2])
			if ip != nil {
				interfaces[ifIndex].Addrs = append(interfaces[ifIndex].Addrs, &ipAddr{IP: ip})
			}
		}

	}
	return interfaces, nil
}

type BSDInterfaceHandler struct {
	conn shared.Connection
}

func (i *BSDInterfaceHandler) Interfaces() ([]Interface, error) {
	cmd, err := i.conn.RunCommand("ifconfig -a")
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch bsd network adapter")
	}
	return i.ParseBSD(cmd.Stdout)
}

// BSDIfconfigHeader matches the first line of an ifconfig stanza on
// FreeBSD, OpenBSD, NetBSD, and DragonFly. Note that NetBSD prefixes
// the flags value with "0x", which differs from the other three.
var BSDIfconfigHeader = regexp.MustCompile(`^([a-zA-Z0-9._]+):\s+flags=(?:0x)?[0-9a-fA-F]+<([^>]*)>`)

func (i *BSDInterfaceHandler) ParseBSD(r io.Reader) ([]Interface, error) {
	interfaces := []Interface{}
	ifIndex := -1
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// New interface stanza
		if m := BSDIfconfigHeader.FindStringSubmatch(line); len(m) > 0 {
			var flags net.Flags
			if m[2] != "" {
				for _, f := range strings.Split(m[2], ",") {
					switch strings.ToLower(f) {
					case "up":
						flags |= net.FlagUp
					case "broadcast":
						flags |= net.FlagBroadcast
					case "multicast":
						flags |= net.FlagMulticast
					case "loopback":
						flags |= net.FlagLoopback
					case "pointopoint", "pointtopoint":
						flags |= net.FlagPointToPoint
					}
				}
			}

			mtu := 0
			tokens := strings.Fields(line)
			for j, t := range tokens {
				if t == "mtu" && j+1 < len(tokens) {
					if v, err := strconv.Atoi(tokens[j+1]); err == nil {
						mtu = v
					}
				}
			}

			ifIndex++
			interfaces = append(interfaces, Interface{
				Index: ifIndex + 1,
				Name:  m[1],
				MTU:   mtu,
				Flags: flags,
			})
			continue
		}

		if ifIndex < 0 {
			continue
		}
		cur := &interfaces[ifIndex]

		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		// MAC: "ether AA:..." (FreeBSD/DragonFly), "lladdr AA:..." (OpenBSD),
		// "address: AA:..." (NetBSD)
		case "ether", "lladdr", "address:":
			if mac, err := net.ParseMAC(fields[1]); err == nil {
				cur.HardwareAddr = mac
			}

		case "inet", "inet6":
			addr := fields[1]
			// strip CIDR suffix (NetBSD: "inet 1.2.3.4/24")
			if k := strings.Index(addr, "/"); k != -1 {
				addr = addr[:k]
			}
			// strip IPv6 link-local zone suffix (e.g. "fe80::1%em0")
			if k := strings.Index(addr, "%"); k != -1 {
				addr = addr[:k]
			}
			if ip := net.ParseIP(addr); ip != nil {
				cur.Addrs = append(cur.Addrs, &ipAddr{IP: ip})
			}
		}
	}

	return interfaces, nil
}

type WindowsInterface struct {
	Name          string `json:"Name"`
	IfIndex       int    `json:"ifIndex"`
	InterfaceType int    `json:"InterfaceType"`
	Status        string `json:"Status"`
	MacAddress    string `json:"MacAddress"`
}

type WindowsNetIp struct {
	InterfaceAlias string  `json:"InterfaceAlias"`
	IPv4Address    *string `json:"IPv4Address"`
	IPv6Address    *string `json:"IPv6Address"`
}

const (
	WinGetNetAdapter   = "Get-NetAdapter | Select-Object -Property Name, ifIndex, InterfaceType, InterfaceDescription, Status, State, MacAddress, LinkSpeed, ReceiveLinkSpeed, TransmitLinkSpeed, Virtual | ConvertTo-Json"
	WinGetNetIPAddress = "Get-NetIPAddress | Select-Object -Property IPv6Address, IPv4Address, InterfaceAlias | ConvertTo-Json"
)

const (
	IF_TYPE_OTHER              = 1
	IF_TYPE_ETHERNET_CSMACD    = 6
	IF_TYPE_ISO88025_TOKENRING = 9
	IF_TYPE_PPP                = 23
	IF_TYPE_SOFTWARE_LOOPBACK  = 24
	IF_TYPE_ATM                = 37
	IF_TYPE_IEEE80211          = 71
	IF_TYPE_TUNNEL             = 131
	IF_TYPE_IEEE1394           = 144
)

// derived from https://go.dev/src/net/interface_windows.go
func windowsInterfaceFlags(status string, ifType int) net.Flags {
	var flags net.Flags
	if status == "Up" {
		flags |= net.FlagUp
	}

	switch ifType {
	case IF_TYPE_ETHERNET_CSMACD, IF_TYPE_ISO88025_TOKENRING, IF_TYPE_IEEE80211, IF_TYPE_IEEE1394:
		flags |= net.FlagBroadcast | net.FlagMulticast
	case IF_TYPE_PPP, IF_TYPE_TUNNEL:
		flags |= net.FlagPointToPoint | net.FlagMulticast
	case IF_TYPE_SOFTWARE_LOOPBACK:
		flags |= net.FlagLoopback | net.FlagMulticast
	case IF_TYPE_ATM:
		flags |= net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast
	}
	return flags
}

type ipAddr struct {
	IP net.IP
}

// name of the network (for example, "tcp", "udp")
func (a *ipAddr) Network() string {
	return "tcp"
}

// string form of address (for example, "192.0.2.1:25", "[2001:db8::1]:80")
func (a *ipAddr) String() string {
	return a.IP.String()
}

func parseIpAddr(ip string) net.IP {
	// filter network id https://sid-500.com/2017/01/10/cisco-ipv6-link-local-adressen-und-router-advertisements/
	// "fe80::ed94:1267:afb5:bb7%6" becomes "fe80::ed94:1267:afb5:bb7"
	m := strings.Split(ip, "%")
	return net.ParseIP(m[0])
}

func filterWinIpByInterface(iName string, ips []WindowsNetIp) []net.Addr {
	addrs := []net.Addr{}

	for i := range ips {
		if ips[i].InterfaceAlias == iName {
			var ip net.IP
			if ips[i].IPv4Address != nil {
				ip = parseIpAddr(*ips[i].IPv4Address)
			} else if ips[i].IPv6Address != nil {
				ip = parseIpAddr(*ips[i].IPv6Address)
			}
			if ip != nil {
				addrs = append(addrs, &ipAddr{IP: ip})
			}
		}
	}

	return addrs
}

type WindowsInterfaceHandler struct {
	conn shared.Connection
}

func (i *WindowsInterfaceHandler) Interfaces() ([]Interface, error) {
	// fetch all network adapter
	cmd, err := i.conn.RunCommand(powershell.Wrap(WinGetNetAdapter))
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch windows network adapter")
	}
	winAdapter, err := i.ParseNetAdapter(cmd.Stdout)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse windows network adapter list")
	}

	// fetch all ip addresses
	cmd, err = i.conn.RunCommand(powershell.Wrap(WinGetNetIPAddress))
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch windows ip addresses")
	}
	winIpAddresses, err := i.ParseNetIpAddresses(cmd.Stdout)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse windows ip addresses")
	}

	// map information together
	interfaces := make([]Interface, len(winAdapter))
	for i := range winAdapter {
		mac, err := net.ParseMAC(winAdapter[i].MacAddress)
		if err != nil {
			return nil, err
		}

		interfaces[i] = Interface{
			Name:         winAdapter[i].Name,
			Index:        winAdapter[i].IfIndex,
			HardwareAddr: mac,
			Flags:        windowsInterfaceFlags(winAdapter[i].Status, winAdapter[i].InterfaceType),
			Addrs:        filterWinIpByInterface(winAdapter[i].Name, winIpAddresses),
		}
	}

	return interfaces, nil
}

func (i *WindowsInterfaceHandler) ParseNetAdapter(r io.Reader) ([]WindowsInterface, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return powershell.UnmarshalList[WindowsInterface](data)
}

func (i *WindowsInterfaceHandler) ParseNetIpAddresses(r io.Reader) ([]WindowsNetIp, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	winNetIps, err := powershell.UnmarshalList[WindowsNetIp](data)
	if err != nil {
		return nil, err
	}
	return winNetIps, nil
}
