// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// projectConfigFlags lists every boolean field of mongodbatlas.projectConfig
// alongside the GroupSettings pointer it is read from.
var projectConfigFlags = []struct {
	field string
	set   func(s *admin.GroupSettings, v *bool)
}{
	{"isDataExplorerEnabled", func(s *admin.GroupSettings, v *bool) { s.IsDataExplorerEnabled = v }},
	{"isDataExplorerGenAIFeaturesEnabled", func(s *admin.GroupSettings, v *bool) { s.IsDataExplorerGenAIFeaturesEnabled = v }},
	{"isExtendedStorageSizesEnabled", func(s *admin.GroupSettings, v *bool) { s.IsExtendedStorageSizesEnabled = v }},
	{"isPerformanceAdvisorEnabled", func(s *admin.GroupSettings, v *bool) { s.IsPerformanceAdvisorEnabled = v }},
	{"isRealtimePerformancePanelEnabled", func(s *admin.GroupSettings, v *bool) { s.IsRealtimePerformancePanelEnabled = v }},
	{"isSchemaAdvisorEnabled", func(s *admin.GroupSettings, v *bool) { s.IsSchemaAdvisorEnabled = v }},
	{"isCollectDatabaseSpecificsStatisticsEnabled", func(s *admin.GroupSettings, v *bool) {
		s.IsCollectDatabaseSpecificsStatisticsEnabled = v
	}},
	{"isDataExplorerGenAISampleDocumentPassingEnabled", func(s *admin.GroupSettings, v *bool) {
		s.IsDataExplorerGenAISampleDocumentPassingEnabled = v
	}},
	{"isClusterAiAssistantEnabled", func(s *admin.GroupSettings, v *bool) { s.IsClusterAiAssistantEnabled = v }},
	{"isNativeRerankingEnabled", func(s *admin.GroupSettings, v *bool) { s.IsNativeRerankingEnabled = v }},
	{"isDataValidationEnabled", func(s *admin.GroupSettings, v *bool) { s.IsDataValidationEnabled = v }},
}

func TestProjectConfigFieldsID(t *testing.T) {
	got := projectConfigFields("p1", &admin.GroupSettings{})
	require.Contains(t, got, "__id")
	assert.Equal(t, "mongodbatlas.projectConfig/p1", got["__id"].Value)
}

// TestProjectConfigFieldsUnreported pins the behaviour that a flag Atlas did not
// report stays null instead of becoming a fabricated false. Reading the flags
// through the SDK's Get accessors instead of the pointer fields regresses this:
// the accessors dereference a *bool and return the zero value when it is nil, so
// an unreported flag would read as false. Because `null && null` evaluates to
// true in MQL, a fabricated false on a flag whose secure reading is false makes
// a "must be disabled" assertion pass on a project where nothing was read.
func TestProjectConfigFieldsUnreported(t *testing.T) {
	// An empty payload: the API reported none of the flags.
	got := projectConfigFields("p1", &admin.GroupSettings{})

	for _, f := range projectConfigFlags {
		t.Run(f.field, func(t *testing.T) {
			raw, ok := got[f.field]
			require.True(t, ok, "field is mapped")
			assert.Equal(t, types.Nil, raw.Type, "an unreported flag stays null, never a fabricated false")
			assert.Nil(t, raw.Value)
			assert.NotEqual(t, llx.BoolData(false), raw, "must not report false for a flag the API did not return")
		})
	}
}

func TestProjectConfigFieldsReported(t *testing.T) {
	for _, want := range []bool{false, true} {
		for _, f := range projectConfigFlags {
			t.Run(f.field, func(t *testing.T) {
				s := &admin.GroupSettings{}
				f.set(s, admin.PtrBool(want))

				raw, ok := projectConfigFields("p1", s)[f.field]
				require.True(t, ok, "field is mapped")
				assert.Equal(t, types.Bool, raw.Type)
				assert.Equal(t, want, raw.Value, "a reported flag keeps its value")
			})
		}
	}
}

// TestProjectConfigFieldsPartial covers the mixed payload: the flags Atlas
// reported keep their values while the rest stay null. Atlas gates several of
// these settings on the cluster tier and the organization's feature flags, so a
// partial payload is the normal case, not an edge case.
func TestProjectConfigFieldsPartial(t *testing.T) {
	got := projectConfigFields("p1", &admin.GroupSettings{
		IsDataExplorerEnabled:       admin.PtrBool(true),
		IsPerformanceAdvisorEnabled: admin.PtrBool(false),
	})

	assert.Equal(t, true, got["isDataExplorerEnabled"].Value)
	assert.Equal(t, false, got["isPerformanceAdvisorEnabled"].Value)
	assert.Equal(t, types.Nil, got["isDataExplorerGenAIFeaturesEnabled"].Type)
	assert.Equal(t, types.Nil, got["isSchemaAdvisorEnabled"].Type)
	assert.Equal(t, types.Nil, got["isDataValidationEnabled"].Type)
}
