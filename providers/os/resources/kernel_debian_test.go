// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDebianImageKernelName(t *testing.T) {
	tests := []struct {
		pkg      string
		wantName string
		wantOK   bool
		why      string
	}{
		// Real image packages, as installed on the live hosts these cases came from.
		{"linux-image-6.17.0-1019-aws", "6.17.0-1019-aws", true, "ubuntu 24.04"},
		{"linux-image-5.4.0-1156-aws", "5.4.0-1156-aws", true, "ubuntu 18.04"},
		{"linux-image-5.10.0-46-cloud-amd64", "5.10.0-46-cloud-amd64", true, "debian 11"},
		{"linux-image-6.12.101+deb13-cloud-amd64", "6.12.101+deb13-cloud-amd64", true, "debian 13"},

		// The metapackages. These are the regression: each one used to be
		// reported as an installed kernel named after the flavour.
		{"linux-image-aws", "", false, "ubuntu metapackage"},
		{"linux-image-cloud-amd64", "", false, "debian metapackage"},
		{"linux-image-amd64", "", false, "debian generic metapackage"},
		{"linux-image-generic", "", false, "ubuntu generic metapackage"},
		{"linux-image-virtual", "", false, "ubuntu virtual metapackage"},

		// Bare name, no release and no trailing dash.
		{"linux-image", "", false, "bare metapackage"},

		// Unsigned builds: ubuntu puts the marker in front of the release,
		// debian appends it, so only ubuntu needs the prefix stripped.
		{"linux-image-unsigned-6.17.0-1019-aws", "6.17.0-1019-aws", true, "ubuntu unsigned"},
		{"linux-image-5.10.0-46-cloud-amd64-unsigned", "5.10.0-46-cloud-amd64-unsigned", true, "debian unsigned"},

		// Neighbours that share the prefix but hold no kernel.
		{"linux-image-extra-virtual", "", false, "extra metapackage"},
		{"linux-headers-6.17.0-1019-aws", "", false, "headers, not an image"},
		{"linux-modules-6.17.0-1019-aws", "", false, "modules, not an image"},
		{"", "", false, "empty"},
	}

	for _, tc := range tests {
		t.Run(tc.pkg, func(t *testing.T) {
			name, ok := debianImageKernelName(tc.pkg)
			assert.Equal(t, tc.wantOK, ok, tc.why)
			assert.Equal(t, tc.wantName, name, tc.why)
		})
	}
}

// The running kernel must still be matched after the metapackage is dropped.
func TestDebianImageKernelNameMatchesRunning(t *testing.T) {
	running := "6.12.101+deb13-cloud-amd64"

	name, ok := debianImageKernelName("linux-image-" + running)
	assert.True(t, ok)
	assert.Equal(t, running, name, "the versioned image is the running kernel")

	// The metapackage carries the same version string in dpkg, which is exactly
	// why it looked like a second kernel. It must not be considered at all.
	_, ok = debianImageKernelName("linux-image-cloud-amd64")
	assert.False(t, ok, "the metapackage is never a kernel, matching or not")
}
