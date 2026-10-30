// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "testing"

func TestDetectVendor(t *testing.T) {
	tests := []struct {
		name         string
		manufacturer string
		wantPlatform string
	}{
		{"hpe", "HPE", "bmc-hpe-ilo"},
		{"hpe lowercase", "hpe", "bmc-hpe-ilo"},
		{"hewlett packard", "Hewlett Packard Enterprise", "bmc-hpe-ilo"},
		{"dell", "Dell Inc.", "bmc-dell-idrac"},
		{"dell mixed case", "DELL", "bmc-dell-idrac"},
		{"supermicro one word", "Supermicro", "bmc-supermicro"},
		{"supermicro two words", "Super Micro Computer, Inc.", "bmc-supermicro"},
		{"unknown vendor", "Lenovo", "bmc-redfish"},
		{"empty", "", "bmc-redfish"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectVendor(tt.manufacturer)
			if got.Platform != tt.wantPlatform {
				t.Errorf("DetectVendor(%q).Platform = %q, want %q", tt.manufacturer, got.Platform, tt.wantPlatform)
			}
		})
	}
}
