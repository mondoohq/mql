// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker_engine

import (
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"
)

func TestDockerContainerImageName(t *testing.T) {
	// Inspect of a container started from alpine/socat:1.8.0.3.
	c := container.InspectResponse{
		Image:  "sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e",
		Config: &container.Config{Image: "alpine/socat:1.8.0.3"},
	}
	assert.Equal(t, "alpine/socat:1.8.0.3", dockerContainerImageName(c))

	c.Config = nil
	assert.Equal(t, "sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e", dockerContainerImageName(c))
}
