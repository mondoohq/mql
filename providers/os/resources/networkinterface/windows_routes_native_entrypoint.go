// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package networkinterface

import (
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows"
)

const (
	AF_INET  = 2  // IPv4
	AF_INET6 = 23 // IPv6

	// Windows error codes for GetAdaptersAddresses
	ERROR_NO_DATA             = 232
	ERROR_BUFFER_OVERFLOW     = 122
	ERROR_INSUFFICIENT_BUFFER = 111

	// GAA_FLAG_* are used as filter for the Windows GetAdaptersAddresses API call
	GAA_FLAG_INCLUDE_PREFIX  = 0x0010
	GAA_FLAG_SKIP_ANYCAST    = 0x0002
	GAA_FLAG_SKIP_MULTICAST  = 0x0004
	GAA_FLAG_SKIP_DNS_SERVER = 0x0008
)

var (
	iphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable2   = iphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable         = iphlpapi.NewProc("FreeMibTable")
	procGetAdaptersAddresses = iphlpapi.NewProc("GetAdaptersAddresses")
)

// nativeRoutes reads the routing table of the machine the provider runs on;
// tests replace it.
var nativeRoutes = (*windowsRouteDetector).detectWindowsRoutesViaGetIpForwardTable

// List detects network routes on Windows. The IP Helper API reads the routing
// table of the machine this process runs on, so it answers only for a local
// connection: a Windows scanner scanning another host over SSH or WinRM must
// report the target's routes, not its own. Everything else, and a native
// read that fails, goes through PowerShell and netstat on the target.
func (w *windowsRouteDetector) List() ([]Route, error) {
	if w.conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		routes, err := nativeRoutes(w)
		if err == nil && len(routes) > 0 {
			return routes, nil
		}
		log.Debug().Err(err).Msg("native Windows API failed")
	}
	return w.listViaCommands()
}

// ipv4Address represents an IPv4 socket address
type ipv4Address struct {
	SinFamily uint16
	SinPort   [2]byte
	SinAddr   [4]byte
	SinZero   [8]byte
}

// ipv6Address represents an IPv6 socket address
type ipv6Address struct {
	Sin6Family   uint16
	Sin6Port     [2]byte
	Sin6Flowinfo uint32
	Sin6Addr     [16]byte
	Sin6ScopeId  uint32
}

// socketInetAddress can represent either IPv4 or IPv6 address
type socketInetAddress struct {
	Data [28]byte
}

// ipAddressPrefix is IP_ADDRESS_PREFIX: a SOCKADDR_INET and its prefix
// length, padded to 32 bytes.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
type ipAddressPrefix struct {
	Prefix       socketInetAddress
	PrefixLength uint8
	_            [3]byte
}

// mibIpForwardRow2 is MIB_IPFORWARD_ROW2, declared field for field so that
// every value is read by name. The layout (104 bytes, InterfaceIndex at 8,
// DestinationPrefix at 12, NextHop at 44) is asserted in
// windows_routes_layout_windows_test.go.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type mibIpForwardRow2 struct {
	InterfaceLuid        uint64 // NET_LUID; its 8-byte alignment places the rows at offset 8 of the table
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              socketInetAddress
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

// mibIpForwardTable2 is MIB_IPFORWARD_TABLE2: the entry count, then the rows.
type mibIpForwardTable2 struct {
	NumEntries uint32
	Table      [1]mibIpForwardRow2
}

// interfaceIPv4s maps each local interface index to its first IPv4 address.
func interfaceIPv4s() map[uint32]string {
	res := map[uint32]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Debug().Err(err).Msg("could not list interfaces for on-link gateways")
		return res
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				res[uint32(iface.Index)] = ipnet.IP.String()
				break
			}
		}
	}
	return res
}

// family returns the address family of a SOCKADDR_INET, its first two bytes.
func (a socketInetAddress) family() uint16 {
	return uint16(a.Data[0]) | uint16(a.Data[1])<<8
}

// detectWindowsRoutesViaGetIpForwardTable uses GetIpForwardTable2 to get routes (IPv4 + IPv6)
func (w *windowsRouteDetector) detectWindowsRoutesViaGetIpForwardTable() ([]Route, error) {
	interfaceMap, err := w.getWindowsInterfaceMap()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get interface map, continuing without interface names")
		interfaceMap = make(map[uint32]string)
	}

	var table *mibIpForwardTable2
	ret, _, _ := procGetIpForwardTable2.Call(
		uintptr(0), // AddressFamily: 0 = both IPv4 and IPv6
		uintptr(unsafe.Pointer(&table)),
	)
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	if ret != 0 {
		return nil, errors.Errorf("GetIpForwardTable2 failed with error code: %d", ret)
	}
	if table == nil || table.NumEntries == 0 {
		return []Route{}, nil
	}

	// An on-link IPv4 route (next hop 0.0.0.0) reports the interface's own
	// address as its gateway, as Get-NetRoute and netstat do on the command
	// path, so a local scan and a remote one agree.
	ifIPv4 := interfaceIPv4s()

	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	var routes []Route

	for i := range rows {
		row := &rows[i]
		interfaceIndex := row.InterfaceIndex
		actualFamily := row.DestinationPrefix.Prefix.family()
		destPrefix := row.DestinationPrefix.Prefix
		prefixLength := uint32(row.DestinationPrefix.PrefixLength)
		nextHop := row.NextHop

		if actualFamily != AF_INET && actualFamily != AF_INET6 {
			continue
		}

		destIP, _, err := w.parseSockaddrInet(destPrefix, actualFamily)
		if err != nil {
			continue
		}

		gatewayIP, _, err := w.parseSockaddrInet(nextHop, actualFamily)
		if err != nil {
			gatewayIP = nil
		}

		dest := w.formatDestination(destIP, int(prefixLength))
		if dest == "" {
			continue
		}

		gateway := w.formatGateway(gatewayIP, actualFamily)
		if actualFamily == AF_INET && gateway == "0.0.0.0" {
			if ip, ok := ifIPv4[interfaceIndex]; ok {
				gateway = ip
			}
		}
		iface := w.getInterfaceName(interfaceIndex, interfaceMap)

		routes = append(routes, Route{
			Destination: dest,
			Gateway:     gateway,
			Flags:       []string{},
			Interface:   iface,
		})
	}

	return routes, nil
}

// formatDestination formats a destination IP address with prefix length
func (w *windowsRouteDetector) formatDestination(destIP net.IP, prefixLen int) string {
	if destIP == nil {
		return ""
	}
	if destIP.To4() != nil {
		if destIP.Equal(net.IPv4zero) {
			return "0.0.0.0/0"
		}
		return fmt.Sprintf("%s/%d", destIP.String(), prefixLen)
	}

	if destIP.Equal(net.IPv6unspecified) {
		return "::/0"
	}
	return fmt.Sprintf("%s/%d", destIP.String(), prefixLen)
}

func (w *windowsRouteDetector) formatGateway(gatewayIP net.IP, family uint16) string {
	if gatewayIP == nil {
		if family == AF_INET {
			return "0.0.0.0"
		}
		return "::"
	}
	if gatewayIP.To4() != nil {
		if gatewayIP.IsUnspecified() {
			return "0.0.0.0"
		}
		return gatewayIP.String()
	}
	if gatewayIP.Equal(net.IPv6unspecified) {
		return "::"
	}
	return gatewayIP.String()
}

// getInterfaceName returns the interface name from the map, or the index as string if not found
func (w *windowsRouteDetector) getInterfaceName(interfaceIndex uint32, interfaceMap map[uint32]string) string {
	if name, ok := interfaceMap[interfaceIndex]; ok {
		return name
	}
	return fmt.Sprintf("%d", interfaceIndex)
}

// parseSockaddrInet parses a SOCKADDR_INET union into a net.IP
func (w *windowsRouteDetector) parseSockaddrInet(addr socketInetAddress, family uint16) (net.IP, int, error) {
	switch family {
	case AF_INET:
		sa := (*ipv4Address)(unsafe.Pointer(&addr.Data[0]))
		return net.IPv4(sa.SinAddr[0], sa.SinAddr[1], sa.SinAddr[2], sa.SinAddr[3]), 0, nil
	case AF_INET6:
		sa6 := (*ipv6Address)(unsafe.Pointer(&addr.Data[0]))
		ip := make(net.IP, 16)
		copy(ip, sa6.Sin6Addr[:])
		return ip, 0, nil
	default:
		return nil, 0, errors.Errorf("unsupported address family: %d", family)
	}
}

// https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
type ipAdapterAddresses struct {
	Length                uint32
	IfIndex               uint32
	Next                  *ipAdapterAddresses
	AdapterName           *byte
	FirstUnicastAddress   uintptr
	FirstAnycastAddress   uintptr
	FirstMulticastAddress uintptr
	FirstDnsServerAddress uintptr
	DnsSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	Mtu                   uint32
	IfType                uint32
	OperStatus            uint32
	Ipv6IfIndex           uint32
	ZoneIndices           [16]uint32
	FirstPrefix           uintptr
}

// getWindowsInterfaceMap creates a map of interface index to interface name
// Uses native Windows GetAdaptersAddresses API https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
// getAdaptersAddresses calls GetAdaptersAddresses into buf, updating size;
// tests replace it. It returns the API's own result code. The error that
// LazyProc.Call returns is the thread's last error (GetLastError), which the
// API does not set on success and a goroutine can inherit stale from an
// unrelated call, so it is never used to decide the outcome.
var getAdaptersAddresses = func(buf *byte, size *uint32) uintptr {
	ret, _, _ := procGetAdaptersAddresses.Call(
		uintptr(syscall.AF_UNSPEC), // Family: AF_UNSPEC = both IPv4 and IPv6
		uintptr(GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER),
		0,
		uintptr(unsafe.Pointer(buf)),
		uintptr(unsafe.Pointer(size)),
	)
	return ret
}

// adapterAddressesBuffer returns the buffer GetAdaptersAddresses filled, or
// nil when the host has no adapters. It starts with the 15 KB Microsoft
// recommends and retries with the size the API asks for, since adapters can
// appear between two calls.
func adapterAddressesBuffer() ([]byte, error) {
	size := uint32(15 * 1024)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		switch ret := getAdaptersAddresses(&buf[0], &size); ret {
		case 0: // ERROR_SUCCESS
			return buf, nil
		case ERROR_NO_DATA:
			return nil, nil
		case ERROR_BUFFER_OVERFLOW:
			continue // size now holds what the API needs
		default:
			return nil, errors.Errorf("GetAdaptersAddresses failed with error code: %d", ret)
		}
	}
	return nil, errors.New("GetAdaptersAddresses: the buffer size kept changing")
}

func (w *windowsRouteDetector) getWindowsInterfaceMap() (map[uint32]string, error) {
	interfaceMap := make(map[uint32]string)

	buf, err := adapterAddressesBuffer()
	if err != nil {
		return nil, err
	}
	if buf == nil {
		return interfaceMap, nil
	}
	adapter := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))

	for adapter != nil {
		if adapter.IfIndex != 0 {
			if name := w.getAdapterName(adapter); name != "" {
				interfaceMap[adapter.IfIndex] = name
			}
		}
		if adapter.Next == nil {
			break
		}
		adapter = adapter.Next
	}

	return interfaceMap, nil
}

// getAdapterName extracts the adapter name from IP_ADAPTER_ADDRESSES structure
func (w *windowsRouteDetector) getAdapterName(adapter *ipAdapterAddresses) string {
	if adapter.FriendlyName != nil {
		return windows.UTF16PtrToString(adapter.FriendlyName)
	}
	if adapter.AdapterName != nil {
		return windows.BytePtrToString(adapter.AdapterName)
	}
	return ""
}
