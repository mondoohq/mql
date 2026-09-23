// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// TestExpressRoutePortLinksDict guards the assumption behind
// expressRoutePort.links: converting []*ExpressRouteLink through
// JsonToDictSlice preserves the link name and its nested property fields
// (admin state, interface name, patch panel, rack). If the SDK's MarshalJSON
// ever changes those keys, the links dict silently loses its shape.
func TestExpressRoutePortLinksDict(t *testing.T) {
	adminState := network.ExpressRouteLinkAdminStateEnabled
	links := []*network.ExpressRouteLink{
		{
			Name: strPtr("link1"),
			Properties: &network.ExpressRouteLinkPropertiesFormat{
				AdminState:    &adminState,
				InterfaceName: strPtr("HundredGigE0/0/0/0"),
				PatchPanelID:  strPtr("PP-42"),
				RackID:        strPtr("RACK-7"),
			},
		},
	}

	dicts, err := convert.JsonToDictSlice(links)
	require.NoError(t, err)
	require.Len(t, dicts, 1)

	link, ok := dicts[0].(map[string]any)
	require.True(t, ok, "link should serialize to an object")
	assert.Equal(t, "link1", link["name"])

	props, ok := link["properties"].(map[string]any)
	require.True(t, ok, "link should carry its properties object")
	assert.Equal(t, "Enabled", props["adminState"])
	assert.Equal(t, "HundredGigE0/0/0/0", props["interfaceName"])
	assert.Equal(t, "PP-42", props["patchPanelId"])
	assert.Equal(t, "RACK-7", props["rackId"])
}

func TestExpressRouteGatewayScaleBounds(t *testing.T) {
	i32 := func(i int32) *int32 { return &i }

	t.Run("nil config yields zero bounds", func(t *testing.T) {
		min, max := expressRouteGatewayScaleBounds(nil)
		assert.Equal(t, int64(0), min)
		assert.Equal(t, int64(0), max)
	})

	t.Run("nil bounds yields zero bounds", func(t *testing.T) {
		min, max := expressRouteGatewayScaleBounds(&network.ExpressRouteGatewayPropertiesAutoScaleConfiguration{})
		assert.Equal(t, int64(0), min)
		assert.Equal(t, int64(0), max)
	})

	t.Run("nil min or max defaults that side to zero", func(t *testing.T) {
		cfg := &network.ExpressRouteGatewayPropertiesAutoScaleConfiguration{
			Bounds: &network.ExpressRouteGatewayPropertiesAutoScaleConfigurationBounds{Max: i32(10)},
		}
		min, max := expressRouteGatewayScaleBounds(cfg)
		assert.Equal(t, int64(0), min)
		assert.Equal(t, int64(10), max)
	})

	t.Run("populated bounds", func(t *testing.T) {
		cfg := &network.ExpressRouteGatewayPropertiesAutoScaleConfiguration{
			Bounds: &network.ExpressRouteGatewayPropertiesAutoScaleConfigurationBounds{Min: i32(1), Max: i32(4)},
		}
		min, max := expressRouteGatewayScaleBounds(cfg)
		assert.Equal(t, int64(1), min)
		assert.Equal(t, int64(4), max)
	})
}
