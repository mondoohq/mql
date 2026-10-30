// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/cloud"
)

func TestMqlID(t *testing.T) {
	cases := []struct {
		name     string
		input    cloud.InstanceMetadata
		expected string
	}{
		{"Public Hostname",
			cloud.InstanceMetadata{PublicHostname: "public.example.com"},
			"cloud.instance/public/public.example.com"},
		{"Private Hostname",
			cloud.InstanceMetadata{PrivateHostname: "private.example.com"},
			"cloud.instance/private/private.example.com"},
		{"Public IP",
			cloud.InstanceMetadata{PublicIpv4: []cloud.Ipv4Address{{IP: "192.168.1.1"}}},
			"cloud.instance/public/192.168.1.1"},
		{"Private IP",
			cloud.InstanceMetadata{PrivateIpv4: []cloud.Ipv4Address{{IP: "10.0.0.1"}}},
			"cloud.instance/private/10.0.0.1"},
		{"Unknown",
			cloud.InstanceMetadata{},
			"cloud.instance/unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.input.MqlID())
		})
	}
}

func TestAddOrUpdatePublicIP(t *testing.T) {
	meta := cloud.InstanceMetadata{}
	ip1 := cloud.Ipv4Address{IP: "192.168.1.1", CIDR: "192.168.1.1/24"}
	ip2 := cloud.Ipv4Address{IP: "192.168.1.1", Gateway: "192.168.1.254"}
	ip3 := cloud.Ipv4Address{IP: "192.168.1.2"}

	meta.AddOrUpdatePublicIP(ip1)
	assert.Equal(t, 1, len(meta.PublicIpv4))
	assert.Equal(t, "192.168.1.1", meta.PublicIpv4[0].IP)

	meta.AddOrUpdatePublicIP(ip2)
	assert.Equal(t, "192.168.1.1/24", meta.PublicIpv4[0].CIDR)
	assert.Equal(t, "192.168.1.254", meta.PublicIpv4[0].Gateway)

	meta.AddOrUpdatePublicIP(ip3)
	assert.Equal(t, 2, len(meta.PublicIpv4))
}

func TestAddOrUpdatePrivateIP(t *testing.T) {
	meta := cloud.InstanceMetadata{}
	ip1 := cloud.Ipv4Address{IP: "10.0.0.1", Subnet: "255.255.255.0"}
	ip2 := cloud.Ipv4Address{IP: "10.0.0.1", Broadcast: "10.0.0.255"}
	ip3 := cloud.Ipv4Address{IP: "10.0.0.2"}
	ip4 := cloud.Ipv4Address{IP: "10.0.0.2"}

	meta.AddOrUpdatePrivateIP(ip1)
	assert.Equal(t, 1, len(meta.PrivateIpv4))
	assert.Equal(t, "10.0.0.1", meta.PrivateIpv4[0].IP)

	meta.AddOrUpdatePrivateIP(ip2)
	assert.Equal(t, 1, len(meta.PrivateIpv4))
	assert.Equal(t, "255.255.255.0", meta.PrivateIpv4[0].Subnet)
	assert.Equal(t, "10.0.0.255", meta.PrivateIpv4[0].Broadcast)

	meta.AddOrUpdatePrivateIP(ip3)
	assert.Equal(t, 2, len(meta.PrivateIpv4))

	meta.AddOrUpdatePrivateIP(ip4)
	assert.Equal(t, 2, len(meta.PrivateIpv4))
}
