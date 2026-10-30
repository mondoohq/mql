// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func strVal(s string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: s, State: plugin.StateIsSet}
}

// TestResourceIDsAreUniquePerInstance guards against the __id-collision class:
// a list-created resource with no id() method and no explicit "__id" arg gets
// the empty cache key "<name>\x00", so every instance aliases to the first.
// Each resource below previously lacked an id() method; this test asserts the
// id() exists, embeds the resource's own id, and differs across two instances.
func TestResourceIDsAreUniquePerInstance(t *testing.T) {
	type idFn func() (string, error)
	tests := []struct {
		name string
		a    idFn
		b    idFn
	}{
		{
			name: "digitalocean.nfs",
			a:    (&mqlDigitaloceanNfs{Id: strVal("nfs-a")}).id,
			b:    (&mqlDigitaloceanNfs{Id: strVal("nfs-b")}).id,
		},
		{
			name: "digitalocean.vpcNatGateway",
			a:    (&mqlDigitaloceanVpcNatGateway{Id: strVal("gw-a")}).id,
			b:    (&mqlDigitaloceanVpcNatGateway{Id: strVal("gw-b")}).id,
		},
		{
			name: "digitalocean.dropletAutoscalePool",
			a:    (&mqlDigitaloceanDropletAutoscalePool{Id: strVal("pool-a")}).id,
			b:    (&mqlDigitaloceanDropletAutoscalePool{Id: strVal("pool-b")}).id,
		},
		{
			name: "digitalocean.vectorDatabase",
			a:    (&mqlDigitaloceanVectorDatabase{Id: strVal("vdb-a")}).id,
			b:    (&mqlDigitaloceanVectorDatabase{Id: strVal("vdb-b")}).id,
		},
		{
			name: "digitalocean.gradientai.dedicatedInferenceEndpoint",
			a:    (&mqlDigitaloceanGradientaiDedicatedInferenceEndpoint{Id: strVal("ep-a")}).id,
			b:    (&mqlDigitaloceanGradientaiDedicatedInferenceEndpoint{Id: strVal("ep-b")}).id,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idA, err := tt.a()
			require.NoError(t, err)
			idB, err := tt.b()
			require.NoError(t, err)

			assert.NotEmpty(t, idA, "id() must not be empty (empty => cache collision)")
			assert.NotEqual(t, idA, idB, "distinct instances must get distinct __ids")
			assert.Contains(t, idA, tt.name+"/", "id() should be namespaced by resource type")
			assert.Contains(t, idA, "-a", "id() must embed the instance's own id")
		})
	}
}
