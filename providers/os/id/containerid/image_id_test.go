// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package containerid

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerIDFromPlatformID(t *testing.T) {
	id, ok := ContainerIDFromPlatformID(MondooContainerID("93a5a846c3e5"))
	assert.True(t, ok)
	assert.Equal(t, "93a5a846c3e5", id)

	_, ok = ContainerIDFromPlatformID(MondooContainerImageID("sha256:0f9a2e1c7b3d"))
	assert.False(t, ok)
	_, ok = ContainerIDFromPlatformID(MondooContainerID(""))
	assert.False(t, ok)
}
