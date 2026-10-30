// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestAdmissionProvider(t *testing.T) {
	manifestFile := "../shared/resources/testdata/admission-review.json"
	data, err := os.ReadFile(manifestFile)
	require.NoError(t, err)

	c, err := NewConnection(1, &inventory.Asset{Name: "K8s Admission review test-dep-5f65697f8d-fxclr", Connections: []*inventory.Config{{Options: map[string]string{}}}}, base64.StdEncoding.EncodeToString(data))
	require.NoError(t, err)
	require.NotNil(t, c)
	res, err := c.AdmissionReviews()
	require.NoError(t, err)
	assert.Len(t, res, 1)
	platform := c.Platform()
	require.NotNil(t, platform)
	assert.Equal(t, "Kubernetes Admission", platform.Title)
	assert.Equal(t, "k8s-admission", platform.Runtime)
	name := c.Name()
	require.NoError(t, err)
	assert.Equal(t, "K8s Admission review "+res[0].Request.Name, name)
}
