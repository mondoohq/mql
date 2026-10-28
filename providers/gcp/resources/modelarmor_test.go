// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/modelarmor/apiv1/modelarmorpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelArmorFloorSettingName(t *testing.T) {
	// Synthetic: the three parents a floor setting can live on. The name is
	// the resource's __id, so the three must stay distinct.
	assert.Equal(t, "projects/p1/locations/global/floorSetting", modelArmorFloorSettingName("projects/p1"))
	assert.Equal(t, "folders/123/locations/global/floorSetting", modelArmorFloorSettingName(folderResourceName("123")))
	assert.Equal(t, "folders/123/locations/global/floorSetting", modelArmorFloorSettingName(folderResourceName("folders/123")))
	assert.Equal(t, "organizations/456/locations/global/floorSetting", modelArmorFloorSettingName("organizations/456"))
}

func TestModelArmorFloorSettingDictShapes(t *testing.T) {
	t.Run("MCP server floor setting in inspect-and-block mode", func(t *testing.T) {
		// Synthetic: the documented keys of googleMcpServerFloorSetting. The
		// enforcement oneof appears as its member's name, not as
		// enforcementType.
		d, err := protoToDict(&modelarmorpb.McpServerFloorSetting{
			EnforcementType:    &modelarmorpb.McpServerFloorSetting_InspectAndBlock{InspectAndBlock: true},
			EnableCloudLogging: true,
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"inspectAndBlock": true, "enableCloudLogging": true}, d)
	})

	t.Run("MCP server floor setting absent", func(t *testing.T) {
		// Synthetic: no MCP floor setting configured reads as null.
		var fs modelarmorpb.FloorSetting
		d, err := protoToDict(fs.GoogleMcpServerFloorSetting)
		require.NoError(t, err)
		assert.Nil(t, d)
	})

	t.Run("multi-language detection enabled", func(t *testing.T) {
		// Synthetic: the documented keys of floorSettingMetadata.
		d, err := protoToDict(&modelarmorpb.FloorSetting_FloorSettingMetadata{
			MultiLanguageDetection: &modelarmorpb.FloorSetting_FloorSettingMetadata_MultiLanguageDetection{
				EnableMultiLanguageDetection: true,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{
			"multiLanguageDetection": map[string]any{"enableMultiLanguageDetection": true},
		}, d)
	})
}
