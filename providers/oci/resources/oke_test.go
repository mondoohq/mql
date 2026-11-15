// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"github.com/stretchr/testify/assert"
)

func TestOkeSupportedKubernetesVersions(t *testing.T) {
	out := okeSupportedKubernetesVersions(&containerengine.ClusterOptions{
		KubernetesVersions: []string{"v1.34.2", "v1.35.0"},
	})

	assert.Equal(t, []any{"v1.34.2", "v1.35.0"}, out)
}

// A missing options document must read as "nothing supported" rather than
// null, so a version check against it fails instead of erroring or passing.
func TestOkeSupportedKubernetesVersionsNil(t *testing.T) {
	assert.Equal(t, []any{}, okeSupportedKubernetesVersions(nil))
	assert.Equal(t, []any{}, okeSupportedKubernetesVersions(&containerengine.ClusterOptions{}))
}
