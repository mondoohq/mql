// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// iproute2 prints a link's parent or peer after "@": a veth as eth0@if29
// (captured in a ubi9 container on Docker Desktop), a VLAN as eth0.100@eth0,
// a tunnel without one as gre0@NONE. The interface is the part before it, as
// sysfs and the routing table name it.
func TestLinuxCmdInterfacesDropLinkSuffix(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"ip addr show": {Stdout: `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
3: gre0@NONE: <NOARP> mtu 1476 qdisc noop state DOWN group default qlen 1000
    link/gre 0.0.0.0 brd 0.0.0.0
5: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
29: eth0@if30: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 6a:3b:0e:51:9c:2f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
`},
		},
	}))
	require.NoError(t, err)
	n := &neti{connection: conn}
	interfaces, err := n.getLinuxCmdInterfaces()
	require.NoError(t, err)
	names := []string{}
	for _, i := range interfaces {
		names = append(names, i.Name)
	}
	assert.Equal(t, []string{"lo", "gre0", "eth0.100", "eth0"}, names)
}
