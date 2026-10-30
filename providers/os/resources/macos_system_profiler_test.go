// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// Shaped on `system_profiler -json SPPowerDataType` from a macOS 27 MacBook.
const systemProfilerPowerJSON = `{
  "SPPowerDataType" : [
    {
      "_name" : "spbattery_information",
      "sppower_battery_charge_info" : {
        "sppower_battery_fully_charged" : "FALSE",
        "sppower_battery_state_of_charge" : 28
      },
      "sppower_battery_health_info" : {
        "sppower_battery_cycle_count" : 315,
        "sppower_battery_health" : "Good"
      }
    },
    {
      "_name" : "sppower_information",
      "AC Power" : { "Sleep On Power Button" : "Yes" }
    }
  ]
}`

const systemProfilerListOutput = `Available Datatypes:
SPParallelATADataType
SPPowerDataType
SPStorageDataType
`

func TestInitMacosSystemProfiler(t *testing.T) {
	for _, name := range []string{"SPPowerDataType", "SPStorageDataType", "SPUSBHostDataType", "SPNetworkDataType"} {
		_, _, err := initMacosSystemProfiler(nil, map[string]*llx.RawData{"dataType": llx.StringData(name)})
		assert.NoError(t, err, name)
	}

	for _, name := range []string{
		"",
		"SPPowerDataType; rm -rf /",
		"SPPowerDataType -detailLevel full",
		"$(id)DataType",
		"spPowerDataType",
		"SPPower",
		"SPDataType",
	} {
		_, _, err := initMacosSystemProfiler(nil, map[string]*llx.RawData{"dataType": llx.StringData(name)})
		assert.Error(t, err, name)
	}

	_, _, err := initMacosSystemProfiler(nil, map[string]*llx.RawData{})
	assert.Error(t, err)
}

func TestParseSystemProfilerItems(t *testing.T) {
	items, err := parseSystemProfilerItems([]byte(systemProfilerPowerJSON), "SPPowerDataType")
	require.NoError(t, err)
	require.Len(t, items, 2)
	battery := items[0].(map[string]any)
	assert.Equal(t, "spbattery_information", battery["_name"])
	health := battery["sppower_battery_health_info"].(map[string]any)
	assert.Equal(t, float64(315), health["sppower_battery_cycle_count"])
	assert.Equal(t, "Good", health["sppower_battery_health"])

	// The records sit under the data type's own key, nowhere else.
	_, err = parseSystemProfilerItems([]byte(systemProfilerPowerJSON), "SPStorageDataType")
	assert.Error(t, err)

	_, err = parseSystemProfilerItems([]byte("Power:\n\n  Battery Information:\n"), "SPPowerDataType")
	assert.Error(t, err)

	_, err = parseSystemProfilerItems([]byte(`{"SPPowerDataType": {"_name": "x"}}`), "SPPowerDataType")
	assert.Error(t, err)

	// An empty report is an empty list, not null.
	for _, in := range []string{"{\n  \"SPStorageDataType\" : [\n\n  ]\n}", `{"SPStorageDataType": null}`} {
		items, err = parseSystemProfilerItems([]byte(in), "SPStorageDataType")
		require.NoError(t, err)
		assert.NotNil(t, items)
		assert.Empty(t, items)
	}
}

func TestSystemProfilerListsDataType(t *testing.T) {
	assert.True(t, systemProfilerListsDataType(systemProfilerListOutput, "SPPowerDataType"))
	assert.True(t, systemProfilerListsDataType(systemProfilerListOutput, "SPStorageDataType"))
	assert.False(t, systemProfilerListsDataType(systemProfilerListOutput, "SPSharingDataType"))
	assert.False(t, systemProfilerListsDataType(systemProfilerListOutput, "SPPower"))
	assert.False(t, systemProfilerListsDataType(systemProfilerListOutput, "Available Datatypes"))
	assert.False(t, systemProfilerListsDataType("", "SPPowerDataType"))
}

func newSystemProfilerTestResource(t *testing.T, dataType string, commands map[string]*mock.Command) *mqlMacosSystemProfiler {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &mqlMacosSystemProfiler{
		MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}},
		DataType:   plugin.TValue[string]{Data: dataType, State: plugin.StateIsSet},
	}
}

func TestMacosSystemProfilerItems(t *testing.T) {
	t.Run("records", func(t *testing.T) {
		sp := newSystemProfilerTestResource(t, "SPPowerDataType", map[string]*mock.Command{
			"system_profiler -json SPPowerDataType": {Stdout: systemProfilerPowerJSON},
		})
		items, err := sp.items()
		require.NoError(t, err)
		assert.Len(t, items, 2)
	})

	t.Run("known type with nothing to report", func(t *testing.T) {
		sp := newSystemProfilerTestResource(t, "SPStorageDataType", map[string]*mock.Command{
			"system_profiler -json SPStorageDataType": {Stdout: `{"SPStorageDataType" : []}`},
			"system_profiler -listDataTypes":          {Stdout: systemProfilerListOutput},
		})
		items, err := sp.items()
		require.NoError(t, err)
		assert.Empty(t, items)
	})

	// macOS 26 removed SPSharingDataType, but system_profiler still answers
	// it with exit 0 and an empty list.
	t.Run("unknown type", func(t *testing.T) {
		sp := newSystemProfilerTestResource(t, "SPSharingDataType", map[string]*mock.Command{
			"system_profiler -json SPSharingDataType": {Stdout: `{"SPSharingDataType" : []}`},
			"system_profiler -listDataTypes":          {Stdout: systemProfilerListOutput},
		})
		_, err := sp.items()
		assert.ErrorContains(t, err, "no data type SPSharingDataType")
	})

	t.Run("command fails", func(t *testing.T) {
		sp := newSystemProfilerTestResource(t, "SPPowerDataType", map[string]*mock.Command{
			"system_profiler -json SPPowerDataType": {Stderr: "system_profiler: command not found", ExitStatus: 127},
		})
		_, err := sp.items()
		assert.ErrorContains(t, err, "exit code 127")
	})
}
