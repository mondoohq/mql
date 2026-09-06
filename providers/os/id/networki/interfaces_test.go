// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki_test

import (
	"net"
	"testing"

	subject "go.mondoo.com/mql/providers/os/id/networki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestInterfacesDarwin(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/macos.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 26)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "en0"})
	if assert.NotEqual(t, -1, index) {
		en0 := interfaces[index]
		assert.Equal(t, "en0", en0.Name)
		assert.Equal(t, "80:a9:97:40:12:53", en0.MACAddress)
		assert.Equal(t, "Apple", en0.Vendor)
		assert.Equal(t, 1500, en0.MTU)
		if assert.NotNil(t, en0.Active) {
			assert.True(t, *en0.Active)
		}
		assert.Nil(t, en0.Virtual)
		assert.ElementsMatch(t, []string{"UP", "BROADCAST", "SMART", "RUNNING", "SIMPLEX", "MULTICAST"}, en0.Flags)
		if assert.NotEmpty(t, en0.IPAddresses) {
			i4 := en0.FindIP(net.ParseIP("192.168.86.36"))
			if assert.NotEqual(t, -1, i4) {
				ipv4 := en0.IPAddresses[i4]
				assert.Equal(t, "192.168.86.36", ipv4.IP.String())
				assert.Equal(t, "192.168.86.36/24", ipv4.CIDR)
				assert.Equal(t, "192.168.86.0/24", ipv4.Subnet)
				assert.Equal(t, "192.168.86.255", ipv4.Broadcast)
				assert.Equal(t, "192.168.86.1", ipv4.Gateway)
			}
			i6 := en0.FindIP(net.ParseIP("fd19:f27d:7e31:1af4:1cd0:9dc4:e6b0:ab13"))
			if assert.NotEqual(t, -1, i6) {
				ipv6 := en0.IPAddresses[i6]
				assert.Equal(t, "fd19:f27d:7e31:1af4:1cd0:9dc4:e6b0:ab13", ipv6.IP.String())
				assert.Equal(t, "fd19:f27d:7e31:1af4:1cd0:9dc4:e6b0:ab13/64", ipv6.CIDR)
				assert.Equal(t, "fd19:f27d:7e31:1af4::/64", ipv6.Subnet)
				assert.Equal(t, "", ipv6.Broadcast)
				assert.Equal(t, "", ipv6.Gateway)
			}
		}
	}
}

func TestInterfacesFreeBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	assert.Equal(t, "freebsd", platform.Name)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "em0"})
	if assert.NotEqual(t, -1, index) {
		em0 := interfaces[index]
		assert.Equal(t, "em0", em0.Name)
		assert.Equal(t, "08:00:27:6c:1a:0e", em0.MACAddress)
		assert.Equal(t, "PCS Systemtechnik", em0.Vendor)
		assert.Equal(t, 1500, em0.MTU)
		if assert.NotNil(t, em0.Active) {
			assert.True(t, *em0.Active)
		}
		assert.Nil(t, em0.Virtual)
		assert.ElementsMatch(t,
			[]string{"UP", "BROADCAST", "RUNNING", "SIMPLEX", "MULTICAST"},
			em0.Flags,
		)

		i4 := em0.FindIP(net.ParseIP("192.168.1.50"))
		if assert.NotEqual(t, -1, i4) {
			ipv4 := em0.IPAddresses[i4]
			assert.Equal(t, "192.168.1.50/24", ipv4.CIDR)
			assert.Equal(t, "192.168.1.0/24", ipv4.Subnet)
			assert.Equal(t, "192.168.1.255", ipv4.Broadcast)
			assert.Equal(t, "192.168.1.1", ipv4.Gateway)
		}
		i6 := em0.FindIP(net.ParseIP("fe80::a00:27ff:fe6c:1a0e"))
		if assert.NotEqual(t, -1, i6) {
			ipv6 := em0.IPAddresses[i6]
			assert.Equal(t, "fe80::a00:27ff:fe6c:1a0e/64", ipv6.CIDR)
			assert.Equal(t, "fe80::/64", ipv6.Subnet)
			assert.Equal(t, "fe80::1", ipv6.Gateway)
		}
	}
}

func TestInterfacesOpenBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/openbsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	assert.Equal(t, "openbsd", platform.Name)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	// OpenBSD uses "lladdr" instead of "ether" for MAC.
	index := subject.FindInterface(interfaces, subject.Interface{Name: "em0"})
	if assert.NotEqual(t, -1, index) {
		em0 := interfaces[index]
		assert.Equal(t, "em0", em0.Name)
		assert.Equal(t, "08:00:27:6c:1a:0e", em0.MACAddress)
		assert.Equal(t, 1500, em0.MTU)
		if assert.NotNil(t, em0.Active) {
			assert.True(t, *em0.Active)
		}
		assert.Nil(t, em0.Virtual)
		assert.ElementsMatch(t,
			[]string{"UP", "BROADCAST", "RUNNING", "SIMPLEX", "MULTICAST"},
			em0.Flags,
		)

		i4 := em0.FindIP(net.ParseIP("192.168.1.51"))
		if assert.NotEqual(t, -1, i4) {
			ipv4 := em0.IPAddresses[i4]
			assert.Equal(t, "192.168.1.51/24", ipv4.CIDR)
			assert.Equal(t, "192.168.1.0/24", ipv4.Subnet)
			assert.Equal(t, "192.168.1.255", ipv4.Broadcast)
			assert.Equal(t, "192.168.1.1", ipv4.Gateway)
		}
		i6 := em0.FindIP(net.ParseIP("fe80::a00:27ff:fe6c:1a0e"))
		if assert.NotEqual(t, -1, i6) {
			ipv6 := em0.IPAddresses[i6]
			assert.Equal(t, "fe80::a00:27ff:fe6c:1a0e/64", ipv6.CIDR)
			assert.Equal(t, "fe80::1", ipv6.Gateway)
		}
	}
}

func TestInterfacesNetBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/netbsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	assert.Equal(t, "netbsd", platform.Name)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	// NetBSD has "0x" hex flag prefix, "address:" MAC keyword, and CIDR
	// suffixes on inet/inet6 instead of separate netmask/prefixlen tokens.
	index := subject.FindInterface(interfaces, subject.Interface{Name: "wm0"})
	if assert.NotEqual(t, -1, index) {
		wm0 := interfaces[index]
		assert.Equal(t, "wm0", wm0.Name)
		assert.Equal(t, "08:00:27:6c:1a:0e", wm0.MACAddress)
		assert.Equal(t, 1500, wm0.MTU)
		if assert.NotNil(t, wm0.Active) {
			assert.True(t, *wm0.Active)
		}
		assert.Nil(t, wm0.Virtual)
		assert.ElementsMatch(t,
			[]string{"UP", "BROADCAST", "RUNNING", "SIMPLEX", "MULTICAST"},
			wm0.Flags,
		)

		i4 := wm0.FindIP(net.ParseIP("192.168.1.52"))
		if assert.NotEqual(t, -1, i4) {
			ipv4 := wm0.IPAddresses[i4]
			assert.Equal(t, "192.168.1.52/24", ipv4.CIDR)
			assert.Equal(t, "192.168.1.0/24", ipv4.Subnet)
			assert.Equal(t, "192.168.1.255", ipv4.Broadcast)
			assert.Equal(t, "192.168.1.1", ipv4.Gateway)
		}
		i6 := wm0.FindIP(net.ParseIP("fe80::a00:27ff:fe6c:1a0e"))
		if assert.NotEqual(t, -1, i6) {
			ipv6 := wm0.IPAddresses[i6]
			assert.Equal(t, "fe80::a00:27ff:fe6c:1a0e/64", ipv6.CIDR)
			assert.Equal(t, "fe80::1", ipv6.Gateway)
		}
	}
}

func TestInterfacesDragonFlyBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/dragonflybsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	assert.Equal(t, "dragonflybsd", platform.Name)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "em0"})
	if assert.NotEqual(t, -1, index) {
		em0 := interfaces[index]
		assert.Equal(t, "em0", em0.Name)
		assert.Equal(t, "08:00:27:6c:1a:0e", em0.MACAddress)
		assert.Equal(t, 1500, em0.MTU)
		if assert.NotNil(t, em0.Active) {
			assert.True(t, *em0.Active)
		}
		assert.Nil(t, em0.Virtual)

		i4 := em0.FindIP(net.ParseIP("192.168.1.53"))
		if assert.NotEqual(t, -1, i4) {
			ipv4 := em0.IPAddresses[i4]
			assert.Equal(t, "192.168.1.53/24", ipv4.CIDR)
			assert.Equal(t, "192.168.1.0/24", ipv4.Subnet)
			assert.Equal(t, "192.168.1.1", ipv4.Gateway)
		}
		i6 := em0.FindIP(net.ParseIP("fe80::a00:27ff:fe6c:1a0e"))
		if assert.NotEqual(t, -1, i6) {
			ipv6 := em0.IPAddresses[i6]
			assert.Equal(t, "fe80::1", ipv6.Gateway)
		}
	}
}

func TestInterfacesLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_ip_addr_show_cmd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "enX0"})
	if assert.NotEqual(t, -1, index) {
		enX0 := interfaces[index]
		assert.Equal(t, "enX0", enX0.Name)
		assert.Equal(t, "0a:ff:de:6b:e3:19", enX0.MACAddress)
		assert.Equal(t, "", enX0.Vendor)
		assert.Equal(t, 9001, enX0.MTU)
		if assert.NotNil(t, enX0.Active) {
			assert.True(t, *enX0.Active)
		}
		if assert.NotNil(t, enX0.Virtual) {
			assert.False(t, *enX0.Virtual)
		}
		assert.ElementsMatch(t, []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}, enX0.Flags)
		if assert.NotEmpty(t, enX0.IPAddresses) {
			i4 := enX0.FindIP(net.ParseIP("172.31.24.71"))
			if assert.NotEqual(t, -1, i4) {
				ipv4 := enX0.IPAddresses[i4]
				assert.Equal(t, "172.31.24.71", ipv4.IP.String())
				assert.Equal(t, "172.31.24.71/20", ipv4.CIDR)
				assert.Equal(t, "172.31.16.0/20", ipv4.Subnet)
				assert.Equal(t, "172.31.31.255", ipv4.Broadcast)
				assert.Equal(t, "172.31.16.1", ipv4.Gateway)
			}
			i6 := enX0.FindIP(net.ParseIP("fe80::8ff:deff:fe6b:e319"))
			if assert.NotEqual(t, -1, i6) {
				ipv6 := enX0.IPAddresses[i6]
				assert.Equal(t, "fe80::8ff:deff:fe6b:e319", ipv6.IP.String())
				assert.Equal(t, "fe80::8ff:deff:fe6b:e319/64", ipv6.CIDR)
				assert.Equal(t, "fe80::/64", ipv6.Subnet)
				assert.Equal(t, "", ipv6.Broadcast)
				assert.Equal(t, "", ipv6.Gateway)
			}
		}
	}
}

func TestInterfacesLinuxPeerInterface(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_peer_interface.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	// The interface is named eth0@if104 (peer interface) but the routing table
	// uses the base name eth0. Verify that the gateway is correctly assigned.
	index := subject.FindInterface(interfaces, subject.Interface{Name: "eth0@if104"})
	if assert.NotEqual(t, -1, index) {
		eth0 := interfaces[index]
		assert.Equal(t, "eth0@if104", eth0.Name)
		assert.Equal(t, "02:42:ac:11:00:04", eth0.MACAddress)
		assert.Equal(t, 1500, eth0.MTU)
		if assert.NotNil(t, eth0.Active) {
			assert.True(t, *eth0.Active)
		}
		if assert.NotEmpty(t, eth0.IPAddresses) {
			i4 := eth0.FindIP(net.ParseIP("172.17.0.4"))
			if assert.NotEqual(t, -1, i4) {
				ipv4 := eth0.IPAddresses[i4]
				assert.Equal(t, "172.17.0.4", ipv4.IP.String())
				assert.Equal(t, "172.17.0.4/16", ipv4.CIDR)
				assert.Equal(t, "172.17.0.0/16", ipv4.Subnet)
				assert.Equal(t, "172.17.255.255", ipv4.Broadcast)
				assert.Equal(t, "172.17.0.1", ipv4.Gateway)
			}
		}
	}

	// Also verify that FindInterface can locate the peer interface by its base name
	index = subject.FindInterface(interfaces, subject.Interface{Name: "eth0"})
	assert.NotEqual(t, -1, index)
}

func TestInterfacesLinuxFallbackSysNetFilesystem(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_sys_class_net_fs.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "enX0"})
	if assert.NotEqual(t, -1, index) {
		enX0 := interfaces[index]
		assert.Equal(t, "enX0", enX0.Name)
		assert.Equal(t, "0a:ff:de:6b:e3:19", enX0.MACAddress)
		assert.Equal(t, "", enX0.Vendor)
		assert.Equal(t, 9001, enX0.MTU)
		if assert.NotNil(t, enX0.Active) {
			assert.True(t, *enX0.Active)
		}
		if assert.NotNil(t, enX0.Virtual) {
			assert.True(t, *enX0.Virtual)
		}
		assert.ElementsMatch(t, []string{"MULTICAST", "BROADCAST", "UP"}, enX0.Flags)
		// Note that this method lacks implementation for gathering ip addresses
		// configured in the network interfaces, maybe we can look at two files to
		// get them `/proc/net/fib_trie` and `/proc/net/if_inet6`
		assert.Empty(t, enX0.IPAddresses)
	}
}

func TestInterfacesLinuxSysfsSymlinks(t *testing.T) {
	// On real Linux over SFTP, /sys/class/net/ entries are symlinks
	// and IsDir() returns false. This test verifies sysfs detection
	// still works when entries are not directories (i.e. symlinks).
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_sys_class_net_symlinks.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	assert.Len(t, interfaces, 2)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "enp0s3"})
	if assert.NotEqual(t, -1, index) {
		enp0s3 := interfaces[index]
		assert.Equal(t, "enp0s3", enp0s3.Name)
		assert.Equal(t, "08:00:27:ac:25:39", enp0s3.MACAddress)
		assert.Equal(t, 1500, enp0s3.MTU)
		if assert.NotNil(t, enp0s3.Active) {
			assert.True(t, *enp0s3.Active)
		}
		assert.ElementsMatch(t, []string{"MULTICAST", "BROADCAST", "UP"}, enp0s3.Flags)
	}
}

func TestInterfacesWindows(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows_get_net_ip_cmd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	// The fixture includes an adapter with a null InterfaceAlias, which is skipped.
	assert.Len(t, interfaces, 4)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "Ethernet0"})
	if assert.NotEqual(t, -1, index) {
		ethernet0 := interfaces[index]
		assert.Equal(t, "Ethernet0", ethernet0.Name)
		assert.Equal(t, "00:50:56:B0:9A:A5", ethernet0.MACAddress)
		assert.Equal(t, "VMware", ethernet0.Vendor)
		assert.Equal(t, 1500, ethernet0.MTU)
		if assert.NotNil(t, ethernet0.Active) {
			assert.True(t, *ethernet0.Active)
		}
		if assert.NotNil(t, ethernet0.Virtual) {
			assert.False(t, *ethernet0.Virtual)

		}
		assert.Empty(t, ethernet0.Flags)
		if assert.NotEmpty(t, ethernet0.IPAddresses) {
			i4 := ethernet0.FindIP(net.ParseIP("192.168.5.38"))
			if assert.NotEqual(t, -1, i4) {
				ipv4 := ethernet0.IPAddresses[i4]
				assert.Equal(t, "192.168.5.38", ipv4.IP.String())
				assert.Equal(t, "192.168.5.38/24", ipv4.CIDR)
				assert.Equal(t, "192.168.5.0/24", ipv4.Subnet)
				assert.Equal(t, "192.168.5.255", ipv4.Broadcast)
				assert.Equal(t, "192.168.5.1", ipv4.Gateway)
			}
		}
	}

	index = subject.FindInterface(interfaces, subject.Interface{Name: "Teredo Tunneling Pseudo-Interface"})
	if assert.NotEqual(t, -1, index) {
		teredoTunneling := interfaces[index]
		if assert.NotEmpty(t, teredoTunneling.IPAddresses) {
			i6 := teredoTunneling.FindIP(net.ParseIP("2001:0:2851:782c:869:1f7d:a331:f3e1"))
			if assert.NotEqual(t, -1, i6) {
				ipv6 := teredoTunneling.IPAddresses[i6]
				assert.Equal(t, "2001:0:2851:782c:869:1f7d:a331:f3e1", ipv6.IP.String())
				assert.Equal(t, "2001:0:2851:782c:869:1f7d:a331:f3e1/64", ipv6.CIDR)
				assert.Equal(t, "2001:0:2851:782c::/64", ipv6.Subnet)
				assert.Equal(t, "", ipv6.Broadcast)
				assert.Equal(t, "::", ipv6.Gateway)
			}
		}

		// The link-local address carries a `%N` zone index that has to be
		// stripped before it parses.
		assert.NotEqual(t, -1, teredoTunneling.FindIP(net.ParseIP("fe80::869:1f7d:a331:f3e1")))
	}

	// This adapter has a single IP address, so `ConvertTo-Json` reports a bare
	// object rather than a one-element array.
	index = subject.FindInterface(interfaces, subject.Interface{Name: "isatap.localdomain"})
	if assert.NotEqual(t, -1, index) {
		isatap := interfaces[index]
		if assert.Len(t, isatap.IPAddresses, 1) {
			assert.True(t, net.ParseIP("fe80::5efe:192.168.5.38").Equal(isatap.IPAddresses[0].IP))
		}
	}
}

func TestInterfacesWindowsSingleInterface(t *testing.T) {
	// A host with one network interface makes `ConvertTo-Json` report a bare
	// object rather than a one-element array.
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows_get_net_ip_cmd_single.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	require.Len(t, interfaces, 1)

	ethernet0 := interfaces[0]
	assert.Equal(t, "Ethernet0", ethernet0.Name)
	assert.Equal(t, "00:50:56:B0:9A:A5", ethernet0.MACAddress)
	assert.Equal(t, 1500, ethernet0.MTU)
	if assert.Len(t, ethernet0.IPAddresses, 1) {
		ipv4 := ethernet0.IPAddresses[0]
		assert.Equal(t, "192.168.5.38", ipv4.IP.String())
		assert.Equal(t, "192.168.5.38/24", ipv4.CIDR)
		assert.Equal(t, "192.168.5.0/24", ipv4.Subnet)
		assert.Equal(t, "192.168.5.1", ipv4.Gateway)
	}
}

func TestInterfacesWindowsFallbackIpconfigCmd(t *testing.T) {
	// Note that ipconfig command doesn't have as much information as Get-NetIPAddress
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows_ipconfig.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	interfaces, err := subject.Interfaces(conn, platform)
	require.NoError(t, err)
	// less interfaces, we don't have lo
	assert.Len(t, interfaces, 3)

	index := subject.FindInterface(interfaces, subject.Interface{Name: "Ethernet0"})
	if assert.NotEqual(t, -1, index) {
		ethernet0 := interfaces[index]
		assert.Equal(t, "Ethernet0", ethernet0.Name)
		assert.Equal(t, "00:50:56:B0:9A:A5", ethernet0.MACAddress)
		assert.Equal(t, "VMware", ethernet0.Vendor)
		// can't get these fields
		assert.Equal(t, 0, ethernet0.MTU)
		assert.Nil(t, ethernet0.Active)
		assert.Nil(t, ethernet0.Virtual)
		assert.Empty(t, ethernet0.Flags)
		// ^^^^
		if assert.NotEmpty(t, ethernet0.IPAddresses) {
			i4 := ethernet0.FindIP(net.ParseIP("192.168.5.38"))
			if assert.NotEqual(t, -1, i4) {
				ipv4 := ethernet0.IPAddresses[i4]
				assert.Equal(t, "192.168.5.38", ipv4.IP.String())
				assert.Equal(t, "192.168.5.38/24", ipv4.CIDR)
				assert.Equal(t, "192.168.5.0/24", ipv4.Subnet)
				assert.Equal(t, "192.168.5.255", ipv4.Broadcast)
				assert.Equal(t, "192.168.5.1", ipv4.Gateway)
			}
		}
	}

	index = subject.FindInterface(interfaces, subject.Interface{Name: "Teredo Tunneling Pseudo-Interface"})
	if assert.NotEqual(t, -1, index) {
		teredoTunneling := interfaces[index]
		if assert.NotEmpty(t, teredoTunneling.IPAddresses) {
			i6 := teredoTunneling.FindIP(net.ParseIP("2001:0:2851:782c:869:1f7d:a331:f3e1"))
			if assert.NotEqual(t, -1, i6) {
				ipv6 := teredoTunneling.IPAddresses[i6]
				assert.Equal(t, "2001:0:2851:782c:869:1f7d:a331:f3e1", ipv6.IP.String())
				assert.Equal(t, "::", ipv6.Gateway)
				assert.Equal(t, "", ipv6.CIDR)   // can't get this
				assert.Equal(t, "", ipv6.Subnet) // can't get this
				assert.Equal(t, "", ipv6.Broadcast)
			}
		}
	}
}
