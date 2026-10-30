// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// Solaris 11.4 is detected into the linux family, so the platform here carries
// it too: the dispatch must still pick the Solaris detector.
var solaris114 = &inventory.Platform{Name: "solaris", Family: []string{"linux", "unix", "os"}}

func TestInterfacesSolaris(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{Platform: solaris114}, mock.WithPath("./testdata/solaris114.toml"))
	require.NoError(t, err)

	interfaces, err := Interfaces(conn, solaris114)
	require.NoError(t, err)

	names := []string{}
	for _, i := range interfaces {
		names = append(names, i.Name)
	}
	// one entry per interface, not per ifconfig stanza; the etherstub has no
	// IP interface but is a datalink
	assert.ElementsMatch(t, []string{"lo0", "net0", "vnic0", "stub0"}, names)

	net0 := interfaces[FindInterface(interfaces, Interface{Name: "net0"})]
	// unprivileged ifconfig prints no MAC; dladm does
	assert.Equal(t, "02:00:17:04:b9:e2", net0.MACAddress)
	assert.Equal(t, 9000, net0.MTU)
	require.NotNil(t, net0.Active)
	assert.True(t, *net0.Active)
	require.NotNil(t, net0.Virtual)
	assert.False(t, *net0.Virtual)
	assert.Contains(t, net0.Flags, "IPv4")
	assert.Contains(t, net0.Flags, "IPv6")

	i4 := net0.FindIP(net.ParseIP("10.77.1.190"))
	require.NotEqual(t, -1, i4)
	assert.Equal(t, "10.77.1.190/24", net0.IPAddresses[i4].CIDR)
	assert.Equal(t, "10.77.1.0/24", net0.IPAddresses[i4].Subnet)
	assert.Equal(t, "10.77.1.1", net0.IPAddresses[i4].Gateway)

	i6 := net0.FindIP(net.ParseIP("fe80::17ff:fe04:b9e2"))
	require.NotEqual(t, -1, i6)
	assert.Equal(t, "fe80::17ff:fe04:b9e2/10", net0.IPAddresses[i6].CIDR)
	assert.Len(t, net0.IPAddresses, 2)

	vnic0 := interfaces[FindInterface(interfaces, Interface{Name: "vnic0"})]
	assert.Equal(t, "02:08:20:f5:36:67", vnic0.MACAddress)
	require.NotNil(t, vnic0.Virtual)
	assert.True(t, *vnic0.Virtual)
	// vnic0:1 is a second address on vnic0; the unconfigured IPv6 stanza's
	// ::/0 is not an address
	assert.Len(t, vnic0.IPAddresses, 2)
	assert.NotEqual(t, -1, vnic0.FindIP(net.ParseIP("192.168.77.6")))
	assert.Equal(t, -1, vnic0.FindIP(net.ParseIP("::")))

	lo0 := interfaces[FindInterface(interfaces, Interface{Name: "lo0"})]
	require.NotNil(t, lo0.Virtual)
	assert.True(t, *lo0.Virtual)
	assert.Equal(t, 8232, lo0.MTU)
	assert.Len(t, lo0.IPAddresses, 2)
}

func TestParseSolarisIfconfigRoot(t *testing.T) {
	data, err := os.ReadFile("./testdata/solaris114_ifconfig_root.txt")
	require.NoError(t, err)

	interfaces := parseSolarisIfconfig(string(data))
	require.Len(t, interfaces, 3)
	for _, i := range interfaces {
		switch i.Name {
		case "net0":
			assert.Equal(t, "02:00:17:04:b9:e2", i.MACAddress)
		case "vnic0":
			assert.Equal(t, "02:08:20:f5:36:67", i.MACAddress)
		case "lo0":
			assert.Equal(t, "", i.MACAddress)
		default:
			t.Errorf("unexpected interface %q", i.Name)
		}
	}
}

func TestNormalizeSolarisMAC(t *testing.T) {
	assert.Equal(t, "02:00:17:04:b9:e2", normalizeSolarisMAC("2:0:17:4:b9:e2"))
	assert.Equal(t, "00:14:4f:ab:cd:ef", normalizeSolarisMAC("0:14:4F:AB:CD:EF"))
}
