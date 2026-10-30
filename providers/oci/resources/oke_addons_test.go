// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"github.com/stretchr/testify/assert"
)

func TestCompareOkeVersions(t *testing.T) {
	assert.Equal(t, 0, compareOkeVersions("v1.34.1", "v1.34.1"))
	assert.Equal(t, 0, compareOkeVersions("v1.34.1", "1.34.1"))
	// Numeric, not lexical: 10 is after 2.
	assert.Equal(t, 1, compareOkeVersions("v1.34.10", "v1.34.2"))
	assert.Equal(t, -1, compareOkeVersions("v1.34.2", "v1.34.10"))
	assert.Equal(t, -1, compareOkeVersions("v1.33.9", "v1.34.0"))
	// A missing part is older.
	assert.Equal(t, -1, compareOkeVersions("v1.34", "v1.34.0"))
}

func TestOkeKubernetesVersionAdmitted(t *testing.T) {
	// No filter: offered for every version.
	assert.True(t, okeKubernetesVersionAdmitted(nil, "v1.36.4"))
	assert.True(t, okeKubernetesVersionAdmitted(&containerengine.KubernetesVersionsFilters{}, "v1.36.4"))

	minOnly := &containerengine.KubernetesVersionsFilters{MinimalVersion: new("v1.34.1")}
	assert.True(t, okeKubernetesVersionAdmitted(minOnly, "v1.34.1"))
	assert.True(t, okeKubernetesVersionAdmitted(minOnly, "v1.36.4"))
	assert.False(t, okeKubernetesVersionAdmitted(minOnly, "v1.34.0"))

	bounded := &containerengine.KubernetesVersionsFilters{
		MinimalVersion: new("v1.30.1"),
		MaximumVersion: new("v1.34.10"),
	}
	assert.True(t, okeKubernetesVersionAdmitted(bounded, "v1.34.2"))
	assert.False(t, okeKubernetesVersionAdmitted(bounded, "v1.35.0"))

	// Exact versions win over the range.
	exact := &containerengine.KubernetesVersionsFilters{
		MinimalVersion:          new("v1.20.0"),
		ExactKubernetesVersions: []string{"v1.34.1"},
	}
	assert.True(t, okeKubernetesVersionAdmitted(exact, "v1.34.1"))
	assert.False(t, okeKubernetesVersionAdmitted(exact, "v1.34.2"))
}

// The versions offered for a cluster are those its Kubernetes version is in
// range of, whatever their status: a deprecated version stays in the list
// with its status, so a check can tell it from a supported one.
func TestOkeAddonVersionsFor(t *testing.T) {
	versions := []containerengine.AddonVersions{
		{
			VersionNumber:            new("v0.27.3-34af5f87b0d-1"),
			Status:                   containerengine.AddonVersionsStatusActive,
			KubernetesVersionFilters: &containerengine.KubernetesVersionsFilters{MinimalVersion: new("v1.31.10")},
		},
		{
			VersionNumber:            new("v0.20.2-e48ab53decf-8"),
			Status:                   containerengine.AddonVersionsStatusDeprecated,
			KubernetesVersionFilters: &containerengine.KubernetesVersionsFilters{MinimalVersion: new("v1.26.2")},
		},
		{
			VersionNumber:            new("v9.9.9"),
			Status:                   containerengine.AddonVersionsStatusActive,
			KubernetesVersionFilters: &containerengine.KubernetesVersionsFilters{MinimalVersion: new("v1.40.0")},
		},
	}
	got := okeAddonVersionsFor(versions, "v1.36.4")
	numbers := make([]string, 0, len(got))
	for _, v := range got {
		numbers = append(numbers, *v.VersionNumber)
	}
	assert.Equal(t, []string{"v0.27.3-34af5f87b0d-1", "v0.20.2-e48ab53decf-8"}, numbers)
	assert.Equal(t, containerengine.AddonVersionsStatusDeprecated, got[1].Status)

	assert.Empty(t, okeAddonVersionsFor(nil, "v1.36.4"))
}
