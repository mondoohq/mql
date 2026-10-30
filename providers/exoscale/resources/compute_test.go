// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeInstanceTypes(t *testing.T) {
	small := v3.InstanceType{ID: "t1", Family: "standard", Size: "small"}
	gpu := v3.InstanceType{ID: "t2", Family: "gpu", Size: "large"}
	merged := mergeInstanceTypes([]zoned[v3.InstanceType]{
		{zone: "de-fra-1", item: small},
		{zone: "ch-gva-2", item: small},
		{zone: "ch-gva-2", item: gpu},
	})
	require.Len(t, merged, 2)
	assert.Equal(t, v3.UUID("t1"), merged[0].ID)
	assert.Equal(t, []v3.ZoneName{"ch-gva-2", "de-fra-1"}, merged[0].Zones)
	assert.Equal(t, []v3.ZoneName{"ch-gva-2"}, merged[1].Zones)
	// The input's zone slice must not be aliased and grown.
	assert.Empty(t, small.Zones)
}

func TestInstanceTypeName(t *testing.T) {
	assert.Equal(t, "standard.medium", instanceTypeName(&v3.InstanceType{Family: "standard", Size: "medium"}))
	assert.Equal(t, "", instanceTypeName(&v3.InstanceType{ID: "t1"}))
}

func TestTemplateArgsKeyedByZone(t *testing.T) {
	a := templateArgs("ch-gva-2", v3.Template{ID: "t1"})
	b := templateArgs("de-fra-1", v3.Template{ID: "t1"})
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
	// Absent optional flags stay null.
	assert.Nil(t, a["passwordEnabled"].Value)
	assert.Nil(t, a["created"].Value)
}
