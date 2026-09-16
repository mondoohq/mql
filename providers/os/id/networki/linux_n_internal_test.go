// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHexFlags(t *testing.T) {
	tests := []struct {
		hexStr   string
		expected []string
	}{
		{"1", []string{"UP"}},
		{"2", []string{"BROADCAST"}},
		{"3", []string{"UP", "BROADCAST"}},
		{"8", []string{"LOOPBACK"}},
		{"10", []string{"POINTOPOINT"}},
		{"40", []string{"RUNNING"}},
		{"100", []string{"PROMISC"}},
		{"400", []string{"MASTER"}},
		{"1003", []string{"BROADCAST", "MULTICAST", "UP"}},
		{"8000", []string{"DYNAMIC"}},
		{"8001", []string{"UP", "DYNAMIC"}},
		{"FFFF", []string{"UP", "BROADCAST", "DEBUG", "LOOPBACK", "POINTOPOINT", "NOTRAILERS", "RUNNING", "NOARP", "PROMISC", "ALLMULTI", "MASTER", "SLAVE", "MULTICAST", "PORTSEL", "AUTOMEDIA", "DYNAMIC"}},
		{"0", []string{}},       // No flags set
		{"invalid", []string{}}, // Invalid hex input
	}

	for _, test := range tests {
		t.Run("hexStr="+test.hexStr, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, parseHexFlags(test.hexStr))
		})
	}
}

// Every devtype the kernel reports here names a device it synthesized, so
// every one of them is virtual. Six used to answer false -- gre, ip6gre, sit,
// ipip, ppp and xfrm -- while their own siblings (gretap, ip6gretap) answered
// true, which is what gives the slip away: a GRE tunnel is no less virtual
// than a GRE tap.
func TestIsVirtualDeviceAllKnownTypesAreVirtual(t *testing.T) {
	virtual := []string{
		"vif", "tun", "tap", "macvlan", "ipvlan", "veth", "bridge", "bond",
		"vxlan", "gre", "gretap", "ip6gre", "ip6gretap", "sit", "ipip",
		"wireguard", "ppp", "xfrm",
	}
	for _, devtype := range virtual {
		got := isVirtualDevice(devtype)
		if assert.NotNil(t, got, "devtype %q has no verdict", devtype) {
			assert.True(t, *got, "devtype %q is a virtual device", devtype)
		}
	}
}

// A devtype nobody has taught this function about is unknown rather than
// physical, so the caller can fall back to the device link instead of
// reporting a guess.
func TestIsVirtualDeviceUnknownTypeHasNoVerdict(t *testing.T) {
	assert.Nil(t, isVirtualDevice("something-new"))
	assert.Nil(t, isVirtualDevice(""))
}

// sysfs terminates the value with a newline. Reading it untrimmed matched no
// case at all, so every devtype on every real host fell through to "unknown"
// and the file might as well not have been read.
func TestLinuxInterfaceVirtualTrimsDevtype(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/sys/class/net/eth0/device", 0o755))
	require.NoError(t, afero.WriteFile(fs, "/sys/class/net/eth0/device/devtype", []byte("veth\n"), 0o444))

	got := linuxInterfaceVirtual(fs, "eth0")
	if assert.NotNil(t, got) {
		assert.True(t, *got, "a veth is virtual even though sysfs wrote a newline after it")
	}
}

// Where sysfs names no devtype -- which is every bridge, bond, dummy, veth and
// the loopback -- the device link is the test. Values taken from sysfs on real
// systems: a virtio NIC has the link and resolves under /sys/devices/platform,
// while lo, a container veth, docker0, bond0 and dummy0 have none and resolve
// under /sys/devices/virtual.
func TestLinuxInterfaceVirtualFromDeviceLink(t *testing.T) {
	fs := afero.NewMemMapFs()

	// backed by hardware
	require.NoError(t, fs.MkdirAll("/sys/class/net/eth0/device", 0o755))
	require.NoError(t, afero.WriteFile(fs, "/sys/class/net/eth0/ifindex", []byte("2\n"), 0o444))

	// synthesized by the kernel
	for _, name := range []string{"lo", "docker0", "bond0", "dummy0", "veth1a2b3c"} {
		require.NoError(t, fs.MkdirAll("/sys/class/net/"+name, 0o755))
		require.NoError(t, afero.WriteFile(fs, "/sys/class/net/"+name+"/ifindex", []byte("1\n"), 0o444))
	}

	got := linuxInterfaceVirtual(fs, "eth0")
	if assert.NotNil(t, got) {
		assert.False(t, *got, "an interface with a device link is backed by hardware")
	}

	for _, name := range []string{"lo", "docker0", "bond0", "dummy0", "veth1a2b3c"} {
		got := linuxInterfaceVirtual(fs, name)
		if assert.NotNil(t, got, "%s has no verdict", name) {
			assert.True(t, *got, "%s has no device link, so it is virtual", name)
		}
	}
}

// /sys/class/net is not a directory of interfaces alone. The bonding driver
// keeps bonding_masters there as a plain file, and it has no children.
func TestIsLinuxNetworkInterface(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/sys/class/net/eth0", 0o755))
	require.NoError(t, afero.WriteFile(fs, "/sys/class/net/eth0/ifindex", []byte("2\n"), 0o444))
	require.NoError(t, fs.MkdirAll("/sys/class/net/lo", 0o755))
	require.NoError(t, afero.WriteFile(fs, "/sys/class/net/lo/address", []byte("00:00:00:00:00:00\n"), 0o444))
	require.NoError(t, afero.WriteFile(fs, "/sys/class/net/bonding_masters", []byte(""), 0o444))

	assert.True(t, isLinuxNetworkInterface(fs, "eth0"), "an ifindex marks an interface")
	assert.True(t, isLinuxNetworkInterface(fs, "lo"), "an address marks an interface")
	assert.False(t, isLinuxNetworkInterface(fs, "bonding_masters"),
		"the bonding control file is not an interface")
	assert.False(t, isLinuxNetworkInterface(fs, "does-not-exist"))
}
