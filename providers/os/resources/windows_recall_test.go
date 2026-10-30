// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/registry"
)

func TestComputeRecallPolicy(t *testing.T) {
	t.Run("not configured yields every value nil", func(t *testing.T) {
		// Synthetic: a host without the WindowsAI policy key; no target showed this.
		v := computeRecallPolicy(map[string]registry.RegistryKeyItem{})
		assert.Nil(t, v.enablementAllowed)
		assert.Nil(t, v.exportAllowed)
		assert.Nil(t, v.snapshotsDisabled)
		assert.Nil(t, v.clickToDoDisabled)
		assert.Nil(t, v.filteredApps)
		assert.Nil(t, v.filteredUris)
		assert.Nil(t, v.maxSnapshotRetentionDays)
		assert.Nil(t, v.maxSnapshotStorageMB)
	})

	t.Run("Recall disallowed and snapshots off", func(t *testing.T) {
		// Synthetic: values from the Policy CSP - WindowsAI allowed-values tables; no target showed this.
		v := computeRecallPolicy(dwordItems(map[string]int64{
			"allowrecallenablement": 0,
			"allowrecallexport":     0,
			"disableaidataanalysis": 1,
			"disableclicktodo":      1,
		}))
		require.NotNil(t, v.enablementAllowed)
		assert.False(t, *v.enablementAllowed)
		require.NotNil(t, v.exportAllowed)
		assert.False(t, *v.exportAllowed)
		require.NotNil(t, v.snapshotsDisabled)
		assert.True(t, *v.snapshotsDisabled)
		require.NotNil(t, v.clickToDoDisabled)
		assert.True(t, *v.clickToDoDisabled)
	})

	t.Run("Recall allowed and snapshots left to the user", func(t *testing.T) {
		// Synthetic: the opposite toggles; no target showed this.
		v := computeRecallPolicy(dwordItems(map[string]int64{
			"allowrecallenablement": 1,
			"allowrecallexport":     1,
			"disableaidataanalysis": 0,
			"disableclicktodo":      0,
		}))
		require.NotNil(t, v.enablementAllowed)
		assert.True(t, *v.enablementAllowed)
		require.NotNil(t, v.exportAllowed)
		assert.True(t, *v.exportAllowed)
		require.NotNil(t, v.snapshotsDisabled)
		assert.False(t, *v.snapshotsDisabled)
		require.NotNil(t, v.clickToDoDisabled)
		assert.False(t, *v.clickToDoDisabled)
	})

	t.Run("storage limits keep explicit zero apart from not configured", func(t *testing.T) {
		// Synthetic: 0 means "let Windows decide" per the CSP docs; no target showed this.
		v := computeRecallPolicy(dwordItems(map[string]int64{
			"setmaximumstoragedurationforrecallsnapshots": 0,
			"setmaximumstoragespaceforrecallsnapshots":    51200,
		}))
		require.NotNil(t, v.maxSnapshotRetentionDays)
		assert.Equal(t, int64(0), *v.maxSnapshotRetentionDays)
		require.NotNil(t, v.maxSnapshotStorageMB)
		assert.Equal(t, int64(51200), *v.maxSnapshotStorageMB)
		assert.Nil(t, v.enablementAllowed)
	})

	t.Run("filter lists split on semicolons", func(t *testing.T) {
		// Synthetic: the examples from the SetDenyAppListForRecall and SetDenyUriListForRecall docs,
		// with stray whitespace and an empty entry added; no target showed this.
		v := computeRecallPolicy(stringItems(map[string]string{
			"setdenyapplistforrecall": "code.exe;Microsoft.WindowsNotepad_8wekyb3d8bbwe!App; ms-teams.exe;",
			"setdenyurilistforrecall": "https://www.Contoso.com;;https://www.WoodgroveBank.com",
		}))
		assert.Equal(t, []string{"code.exe", "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App", "ms-teams.exe"}, v.filteredApps)
		assert.Equal(t, []string{"https://www.Contoso.com", "https://www.WoodgroveBank.com"}, v.filteredUris)
	})
}

func TestRegSemicolonList(t *testing.T) {
	t.Run("absent is nil", func(t *testing.T) {
		// Synthetic: policy not configured; no target showed this.
		assert.Nil(t, regSemicolonList(stringItems(map[string]string{}), "SetDenyAppListForRecall"))
	})

	t.Run("present but empty is an empty list, not nil", func(t *testing.T) {
		// Synthetic: policy configured with an empty string; no target showed this.
		got := regSemicolonList(stringItems(map[string]string{"setdenyapplistforrecall": " ; "}), "SetDenyAppListForRecall")
		require.NotNil(t, got)
		assert.Empty(t, got)
	})
}

func TestStringListField(t *testing.T) {
	t.Run("nil is a null field", func(t *testing.T) {
		// Synthetic: not configured; no target showed this.
		f := stringListField(nil)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, f.State)
	})

	t.Run("values are carried over", func(t *testing.T) {
		// Synthetic: a configured list; no target showed this.
		f := stringListField([]string{"a.exe", "b.exe"})
		assert.Equal(t, plugin.StateIsSet, f.State)
		assert.Equal(t, []any{"a.exe", "b.exe"}, f.Data)
	})
}
