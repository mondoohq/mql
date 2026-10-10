// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsFeatures(t *testing.T) {
	r, err := os.Open("./testdata/features.json")
	require.NoError(t, err)

	items, err := ParseWindowsFeatures(r)
	assert.Nil(t, err)
	assert.Equal(t, 5, len(items))
}

// A localized description with typographic quotes parses when the output is
// UTF-8, which QUERY_FEATURES pins. Under the ibm850 code page of an SSH
// session on a German Windows, „ and “ arrive as plain quotes, and the JSON
// no longer parses.
func TestWindowsFeatures_LocalizedQuotes(t *testing.T) {
	assert.True(t, strings.HasPrefix(QUERY_FEATURES, "[Console]::OutputEncoding = [Text.Encoding]::UTF8"))

	utf8 := `[{"Name":"RSAT-System-Insights","DisplayName":"System Insights-Modul für Windows PowerShell","Description":"Das Modul „System Insights“ für Windows PowerShell.","Installed":false,"InstallState":0,"FeatureType":"Feature","Path":"Remoteserver-Verwaltungstools\\System Insights-Modul für Windows PowerShell","DependsOn":[],"Parent":"RSAT-Feature-Tools","SubFeatures":[]}]`
	items, err := ParseWindowsFeatures(strings.NewReader(utf8))
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "Das Modul „System Insights“ für Windows PowerShell.", items[0].Description)

	bestFit := strings.NewReplacer("„", `"`, "“", `"`).Replace(utf8)
	_, err = ParseWindowsFeatures(strings.NewReader(bestFit))
	assert.Error(t, err, "the code page's plain quotes break the JSON")
}
