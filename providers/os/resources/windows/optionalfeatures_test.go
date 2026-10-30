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

// the detailed form (-FeatureName *) carries display name and description
func TestWindowsOptionalFeatures(t *testing.T) {
	r, err := os.Open("./testdata/optionalfeatures.json")
	require.NoError(t, err)

	items, err := ParseWindowsOptionalFeatures(r)
	assert.Nil(t, err)
	assert.Equal(t, 134, len(items))
	assert.Equal(t, "MicrosoftWindowsPowerShellV2", items[9].Name)
	assert.Equal(t, "Windows PowerShell 2.0 Engine", items[9].DisplayName)
	assert.True(t, items[9].Enabled)
	assert.Equal(t, int64(2), items[9].State)
	assert.Equal(t, "Adds or Removes Windows PowerShell 2.0 Engine", items[9].Description)
}

// The plain listing has no display name or description — that is the whole point
// of it — but it still carries the state every check keys on.
func TestWindowsOptionalFeatures_Listing(t *testing.T) {
	input := `[
    {
        "FeatureName": "SMB1Protocol",
        "State": 2
    },
    {
        "FeatureName": "TelnetClient",
        "State": 0
    }
]`

	items, err := ParseWindowsOptionalFeatures(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, items, 2)

	assert.Equal(t, "SMB1Protocol", items[0].Name)
	assert.Equal(t, int64(2), items[0].State)
	assert.True(t, items[0].Enabled)
	assert.Empty(t, items[0].DisplayName)
	assert.Empty(t, items[0].Description)

	assert.Equal(t, "TelnetClient", items[1].Name)
	assert.False(t, items[1].Enabled)
}

// a single-feature lookup makes ConvertTo-Json emit a bare object, not an array
func TestWindowsOptionalFeatures_SingleObject(t *testing.T) {
	input := `{
    "FeatureName": "TelnetClient",
    "DisplayName": "Telnet Client",
    "Description": "Telnet Client uses the Telnet protocol",
    "State": 2
}`

	items, err := ParseWindowsOptionalFeatures(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "TelnetClient", items[0].Name)
	assert.Equal(t, "Telnet Client", items[0].DisplayName)
	assert.Equal(t, "Telnet Client uses the Telnet protocol", items[0].Description)
	assert.Equal(t, int64(2), items[0].State)
	assert.True(t, items[0].Enabled)
}

func TestWindowsOptionalFeatures_Empty(t *testing.T) {
	items, err := ParseWindowsOptionalFeatures(strings.NewReader("   \n  "))
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestOptionalFeatureQuery(t *testing.T) {
	assert.Equal(t,
		"Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' | Select-Object -Property FeatureName,DisplayName,Description,State | ConvertTo-Json",
		OptionalFeatureQuery("TelnetClient"))

	// single quotes must be doubled so the name stays a literal string
	assert.Equal(t,
		"Get-WindowsOptionalFeature -Online -FeatureName 'O''Brien' | Select-Object -Property FeatureName,DisplayName,Description,State | ConvertTo-Json",
		OptionalFeatureQuery("O'Brien"))
}

// The enumeration must not ask for a feature name: -FeatureName makes DISM look
// up detailed information for every feature it matches, which is what makes the
// call cost tens of seconds on a Windows client.
func TestOptionalFeatureQueries(t *testing.T) {
	assert.NotContains(t, QUERY_OPTIONAL_FEATURES, "-FeatureName")
	assert.NotContains(t, QUERY_OPTIONAL_FEATURES, "Description")
	assert.Contains(t, QUERY_OPTIONAL_FEATURES, "FeatureName,State")

	assert.Contains(t, QUERY_OPTIONAL_FEATURE_DETAILS, "-FeatureName *")
	assert.Contains(t, QUERY_OPTIONAL_FEATURE_DETAILS, "FeatureName,DisplayName,Description,State")
}
