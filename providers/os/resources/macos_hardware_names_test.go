// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMacosFullDisplayName(t *testing.T) {
	tests := []struct {
		name         string
		machineModel string
		want         string
	}{
		// Measured: MacBook Pro 14-inch M4 Pro, 2026-11-19. system_profiler
		// reports machine_model "Mac16,8" and machine_name "MacBook Pro".
		{"apple silicon", "Mac16,8", "MacBook Pro (14-inch, M4 Pro, Nov 2024)"},
		// Synthetic: an Intel-era identifier; no target showed this.
		{"intel", "MacBookPro16,1", "MacBook Pro (16-inch, 2019)"},
		// Synthetic: one identifier shared by two Mac Pro generations; no target showed this.
		{"shared identifier", "MacPro5,1", "Mac Pro (Late 2010/Mid 2012)"},
		// Synthetic: iMacPro starts with iMac, the lookup must not match on prefix.
		{"iMac Pro", "iMacPro1,1", "iMac Pro (Retina 5K, 27-inch, Late 2017)"},
		// Synthetic: a model newer than the table is returned unchanged.
		{"unknown model", "Mac99,1", "Mac99,1"},
		// Synthetic: an Apple virtual machine is not a sold product. The
		// identifier comes from the VM fixture in macos_hardware_test.go.
		{"virtual machine", "VirtualMac2,1", "VirtualMac2,1"},
		// Synthetic: system_profiler reported no model.
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, macosFullDisplayName(tt.machineModel))
		})
	}
}

// Every key must look like an identifier system_profiler reports, so a
// suffixed key such as "MacPro5,1-2010", which no Mac can match, fails here.
func TestMacosFullDisplayNamesKeys(t *testing.T) {
	identifier := regexp.MustCompile(`^(Mac|MacBook|MacBookAir|MacBookPro|MacPro|Macmini|iMac|iMacPro)\d+,\d+$`)
	for model, name := range macosFullDisplayNames {
		assert.Regexp(t, identifier, model)
		assert.NotEmpty(t, name, model)
	}
}
