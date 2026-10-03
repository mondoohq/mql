// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// An amd64 image running under emulation on an arm64 Docker Desktop reported
// the daemon's arm64, so its packages got arm64 purls and matched the wrong
// advisories. The image's architecture wins.
func TestContainerArchitecture(t *testing.T) {
	assert.Equal(t, "amd64", containerArchitecture("amd64", "", "arm64"),
		"a multi-platform image inspects with no architecture; the manifest names it")
	assert.Equal(t, "amd64", containerArchitecture("", "amd64", "arm64"))
	assert.Equal(t, "arm64", containerArchitecture("", "", "arm64"), "the daemon's is the fallback")
	assert.Equal(t, "", containerArchitecture("", "", ""))
}
