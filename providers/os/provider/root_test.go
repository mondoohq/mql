// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// The connection reports which root it exposed, and that is what bounds the
// query: rooting a Linux host at os.linux is what makes `_.registrykey` fail to
// compile instead of answering with an unset field. See ADR 031.
func TestAssetRoot(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		expected string
	}{
		{"linux", &inventory.Platform{Name: "arch", Family: []string{"arch", "linux", "unix", "os"}}, "os.linux"},
		{"debian", &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}, "os.linux"},
		{"windows", &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}, "os.windows"},
		{"macos", &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}, "os.macos"},
		{"freebsd", &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}}, "os.unix"},

		// A container image of a Linux distro is still that distro's family, so
		// it roots there. Bounding it further - an image has no uptime or
		// processes - needs asset-kind roots, which do not exist yet.
		{"linux container image", &inventory.Platform{Name: "alpine", Kind: "container-image", Family: []string{"linux", "unix", "os"}}, "os.linux"},

		// Claiming a family we did not detect would bound the query by a guess,
		// so an unplaceable platform gets the universal root instead.
		{"unknown family", &inventory.Platform{Name: "something", Family: []string{"os"}}, "os.base"},
		{"no family", &inventory.Platform{Name: "something"}, "os.base"},
		{"no platform", nil, "os.base"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, assetRoot(test.platform))
		})
	}
}
