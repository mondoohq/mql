// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"cloud.google.com/go/modelarmor/apiv1/modelarmorpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestModelArmorTemplateConfigOf(t *testing.T) {
	t.Run("all filters configured", func(t *testing.T) {
		// Synthetic: a template that blocks with every filter on, advanced
		// SDP and two RAI filters.
		c := modelArmorTemplateConfigOf(&modelarmorpb.Template{
			FilterConfig: &modelarmorpb.FilterConfig{
				SdpSettings: &modelarmorpb.SdpFilterSettings{SdpConfiguration: &modelarmorpb.SdpFilterSettings_AdvancedConfig{
					AdvancedConfig: &modelarmorpb.SdpAdvancedConfig{
						InspectTemplate:    "projects/p/locations/us/inspectTemplates/it",
						DeidentifyTemplate: "projects/p/locations/us/deidentifyTemplates/dt",
					},
				}},
				PiAndJailbreakFilterSettings: &modelarmorpb.PiAndJailbreakFilterSettings{
					FilterEnforcement: modelarmorpb.PiAndJailbreakFilterSettings_ENABLED,
					ConfidenceLevel:   modelarmorpb.DetectionConfidenceLevel_MEDIUM_AND_ABOVE,
				},
				MaliciousUriFilterSettings: &modelarmorpb.MaliciousUriFilterSettings{FilterEnforcement: modelarmorpb.MaliciousUriFilterSettings_ENABLED},
				CsamFilterSettings:         &modelarmorpb.CsamFilterSettings{FilterEnforcement: modelarmorpb.CsamFilterSettings_ENABLED},
				RaiSettings: &modelarmorpb.RaiFilterSettings{RaiFilters: []*modelarmorpb.RaiFilterSettings_RaiFilter{
					{FilterType: modelarmorpb.RaiFilterType_HATE_SPEECH, ConfidenceLevel: modelarmorpb.DetectionConfidenceLevel_HIGH},
					{FilterType: modelarmorpb.RaiFilterType_DANGEROUS},
				}},
			},
			TemplateMetadata: &modelarmorpb.Template_TemplateMetadata{EnforcementType: modelarmorpb.Template_TemplateMetadata_INSPECT_AND_BLOCK},
		})
		assert.False(t, c.sdpBasicEnabled)
		assert.Equal(t, "projects/p/locations/us/inspectTemplates/it", c.inspectTemplate)
		assert.Equal(t, "projects/p/locations/us/deidentifyTemplates/dt", c.deidentifyTemplate)
		assert.True(t, c.piAndJailbreakEnabled)
		assert.Equal(t, "MEDIUM_AND_ABOVE", c.piAndJailbreakConfidence)
		assert.True(t, c.maliciousUriEnabled)
		assert.True(t, c.csamEnabled)
		assert.Equal(t, []modelArmorRaiFilter{
			{filterType: "HATE_SPEECH", confidenceLevel: "HIGH"},
			{filterType: "DANGEROUS"},
		}, c.raiFilters)
		assert.Equal(t, "INSPECT_AND_BLOCK", c.enforcementType)
	})

	t.Run("basic SDP and filters turned off", func(t *testing.T) {
		// Synthetic: basic SDP on, the other filters explicitly disabled.
		c := modelArmorTemplateConfigOf(&modelarmorpb.Template{
			FilterConfig: &modelarmorpb.FilterConfig{
				SdpSettings: &modelarmorpb.SdpFilterSettings{SdpConfiguration: &modelarmorpb.SdpFilterSettings_BasicConfig{
					BasicConfig: &modelarmorpb.SdpBasicConfig{FilterEnforcement: modelarmorpb.SdpBasicConfig_ENABLED},
				}},
				PiAndJailbreakFilterSettings: &modelarmorpb.PiAndJailbreakFilterSettings{FilterEnforcement: modelarmorpb.PiAndJailbreakFilterSettings_DISABLED},
				MaliciousUriFilterSettings:   &modelarmorpb.MaliciousUriFilterSettings{FilterEnforcement: modelarmorpb.MaliciousUriFilterSettings_DISABLED},
			},
		})
		assert.True(t, c.sdpBasicEnabled)
		assert.Empty(t, c.inspectTemplate)
		assert.False(t, c.piAndJailbreakEnabled)
		assert.False(t, c.maliciousUriEnabled)
	})

	t.Run("empty template", func(t *testing.T) {
		// Synthetic: no filter config or metadata at all.
		c := modelArmorTemplateConfigOf(&modelarmorpb.Template{})
		assert.False(t, c.sdpBasicEnabled)
		assert.False(t, c.piAndJailbreakEnabled)
		assert.False(t, c.csamEnabled)
		assert.Empty(t, c.piAndJailbreakConfidence)
		assert.Empty(t, c.enforcementType)
		assert.Equal(t, []modelArmorRaiFilter{}, c.raiFilters)
	})
}

func TestModelArmorLocations(t *testing.T) {
	// Synthetic: the global location serves floor settings only.
	assert.Equal(t, []string{"us", "europe-west4"}, modelArmorTemplateLocations([]string{"global", "us", "europe-west4", "us", ""}))
	assert.Equal(t, "modelarmor.us.rep.googleapis.com:443", modelArmorEndpoint("us"))
	assert.Equal(t, "us-central1", modelArmorLocationFromName("projects/p/locations/us-central1/templates/t"))
	assert.Empty(t, modelArmorLocationFromName("t"))
}

func TestListAcrossModelArmorLocations(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	locations := []string{"us", "eu"}

	// Synthetic: one location refuses, the other reports.
	got, err := listAcrossModelArmorLocations(locations, func(l string) ([]any, error) {
		if l == "eu" {
			return nil, status.Error(codes.PermissionDenied, "denied")
		}
		return []any{"t1"}, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []any{"t1"}, got)

	// Synthetic: locations run concurrently but results keep location order.
	got, err = listAcrossModelArmorLocations([]string{"us", "eu", "us-central1"}, func(l string) ([]any, error) {
		return []any{l}, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []any{"us", "eu", "us-central1"}, got)

	// Synthetic: every location refuses; Forbidden under structured errors.
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	_, err = listAcrossModelArmorLocations(locations, func(string) ([]any, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))
}
