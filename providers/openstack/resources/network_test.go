// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceOwnerIsRouter(t *testing.T) {
	tests := []struct {
		name        string
		deviceOwner string
		want        bool
	}{
		{"empty", "", false},
		{"legacy router interface", "network:router_interface", true},
		{"distributed router interface", "network:router_interface_distributed", true},
		{"HA/DVR replicated interface", "network:ha_router_replicated_interface", true},
		{"external gateway", "network:router_gateway", true},
		{"HA keepalived interface", "network:router_ha_interface", true},
		{"centralized SNAT", "network:router_centralized_snat", true},
		{"DHCP agent port is not a router", "network:dhcp", false},
		{"floating IP port is not a router", "network:floatingip", false},
		{"floating IP agent gateway is not a router", "network:floatingip_agent_gateway", false},
		{"compute port is not a router", "compute:nova", false},
		{"load balancer port is not a router", "Octavia", false},
		{"unowned port", "network:", false},
		{"bare router word without namespace", "router_interface", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deviceOwnerIsRouter(tt.deviceOwner))
		})
	}
}

func TestParseSegmentationID(t *testing.T) {
	t.Run("empty string returns 0", func(t *testing.T) {
		assert.Equal(t, int64(0), parseSegmentationID(""))
	})
	t.Run("decimal digits parse normally", func(t *testing.T) {
		assert.Equal(t, int64(0), parseSegmentationID("0"))
		assert.Equal(t, int64(1), parseSegmentationID("1"))
		assert.Equal(t, int64(100), parseSegmentationID("100"))
		assert.Equal(t, int64(4094), parseSegmentationID("4094"))
		assert.Equal(t, int64(16777215), parseSegmentationID("16777215"))
	})
	t.Run("non-digit characters return 0", func(t *testing.T) {
		assert.Equal(t, int64(0), parseSegmentationID("vlan-100"))
		assert.Equal(t, int64(0), parseSegmentationID("100x"))
		assert.Equal(t, int64(0), parseSegmentationID("+100"))
		assert.Equal(t, int64(0), parseSegmentationID("-100"))
		assert.Equal(t, int64(0), parseSegmentationID(" 100"))
	})
}
