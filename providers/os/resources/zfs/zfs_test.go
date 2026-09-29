// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package zfs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const singlePoolJSON = `{
	"pools": {
		"rpool": {
			"properties": {
				"guid": {"value": "1234567890"},
				"health": {"value": "ONLINE"},
				"size": {"value": "107374182400"},
				"allocated": {"value": "53687091200"},
				"free": {"value": "53687091200"},
				"fragmentation": {"value": "12"},
				"capacity": {"value": "50"},
				"dedupratio": {"value": "1.00"},
				"readonly": {"value": "off"},
				"autoexpand": {"value": "off"},
				"autoreplace": {"value": "off"},
				"autotrim": {"value": "on"}
			}
		}
	}
}`

func TestParsePools_SinglePool(t *testing.T) {
	pools, err := ParsePools(singlePoolJSON)
	require.NoError(t, err)
	require.Len(t, pools, 1)

	p := pools[0]
	assert.Equal(t, "rpool", p.Name)
	assert.Equal(t, "1234567890", p.GUID)
	assert.Equal(t, int64(107374182400), p.Size)
	assert.Equal(t, int64(53687091200), p.Allocated)
	assert.Equal(t, int64(53687091200), p.Free)
	require.NotNil(t, p.Fragmentation)
	assert.Equal(t, int64(12), *p.Fragmentation)
	assert.Equal(t, int64(50), p.PercentUsed)
	assert.InDelta(t, 1.0, p.Dedupratio, 0.001)
	assert.Equal(t, "ONLINE", p.Health)
	assert.False(t, p.Readonly)
	assert.False(t, p.Autoexpand)
	assert.False(t, p.Autoreplace)
	assert.True(t, p.Autotrim)
}

func TestParsePools_MultiplePools(t *testing.T) {
	jsonOutput := `{
		"pools": {
			"rpool": {
				"properties": {
					"guid": {"value": "1111"},
					"health": {"value": "ONLINE"},
					"size": {"value": "107374182400"},
					"allocated": {"value": "53687091200"},
					"free": {"value": "53687091200"},
					"fragmentation": {"value": "12"},
					"capacity": {"value": "50"},
					"dedupratio": {"value": "1.00"},
					"readonly": {"value": "off"},
					"autoexpand": {"value": "off"},
					"autoreplace": {"value": "off"},
					"autotrim": {"value": "on"}
				}
			},
			"data": {
				"properties": {
					"guid": {"value": "2222"},
					"health": {"value": "DEGRADED"},
					"size": {"value": "214748364800"},
					"allocated": {"value": "107374182400"},
					"free": {"value": "107374182400"},
					"fragmentation": {"value": "5"},
					"capacity": {"value": "50"},
					"dedupratio": {"value": "1.25x"},
					"readonly": {"value": "off"},
					"autoexpand": {"value": "on"},
					"autoreplace": {"value": "off"},
					"autotrim": {"value": "off"}
				}
			}
		}
	}`

	pools, err := ParsePools(jsonOutput)
	require.NoError(t, err)
	require.Len(t, pools, 2)

	poolMap := make(map[string]Pool)
	for _, p := range pools {
		poolMap[p.Name] = p
	}

	rpool := poolMap["rpool"]
	assert.Equal(t, "ONLINE", rpool.Health)
	assert.Equal(t, int64(107374182400), rpool.Size)

	data := poolMap["data"]
	assert.Equal(t, "DEGRADED", data.Health)
	assert.InDelta(t, 1.25, data.Dedupratio, 0.001)
	assert.True(t, data.Autoexpand)
}

func TestParsePools_EmptyOutput(t *testing.T) {
	pools, err := ParsePools("")
	require.NoError(t, err)
	assert.Nil(t, pools)

	pools, err = ParsePools(`{"pools": {}}`)
	require.NoError(t, err)
	assert.Nil(t, pools)
}

func TestParsePools_InvalidJSON(t *testing.T) {
	_, err := ParsePools("not json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing zpool get JSON")
}

const mixedDatasetsJSON = `{
	"datasets": {
		"rpool": {
			"properties": {
				"type": {"value": "FILESYSTEM"},
				"used": {"value": "53687091200"},
				"available": {"value": "53687091200"},
				"referenced": {"value": "8589934592"},
				"mountpoint": {"value": "/rpool"},
				"compression": {"value": "lz4"},
				"compressratio": {"value": "1.50"},
				"mounted": {"value": "yes"},
				"recordsize": {"value": "131072"},
				"quota": {"value": "0"},
				"reservation": {"value": "0"},
				"origin": {"value": "-"},
				"creation": {"value": "1609459200"},
				"encryption": {"value": "off"}
			}
		},
		"rpool/data": {
			"properties": {
				"type": {"value": "FILESYSTEM"},
				"used": {"value": "42949672960"},
				"available": {"value": "53687091200"},
				"referenced": {"value": "42949672960"},
				"mountpoint": {"value": "/rpool/data"},
				"compression": {"value": "lz4"},
				"compressratio": {"value": "1.75x"},
				"mounted": {"value": "yes"},
				"recordsize": {"value": "131072"},
				"quota": {"value": "0"},
				"reservation": {"value": "0"},
				"origin": {"value": "-"},
				"creation": {"value": "1609459200"},
				"encryption": {"value": "off"}
			}
		},
		"rpool/data@snap1": {
			"properties": {
				"type": {"value": "SNAPSHOT"},
				"used": {"value": "1073741824"},
				"available": {"value": "-"},
				"referenced": {"value": "42949672960"},
				"mountpoint": {"value": "-"},
				"compression": {"value": "-"},
				"compressratio": {"value": "1.75"},
				"mounted": {"value": "-"},
				"recordsize": {"value": "-"},
				"quota": {"value": "0"},
				"reservation": {"value": "-"},
				"origin": {"value": "-"},
				"creation": {"value": "1704067200"},
				"encryption": {"value": "-"}
			}
		}
	}
}`

func TestParseDatasets_MixedTypes(t *testing.T) {
	datasets, err := ParseDatasets(mixedDatasetsJSON)
	require.NoError(t, err)
	require.Len(t, datasets, 3)

	dsMap := make(map[string]Dataset)
	for _, ds := range datasets {
		dsMap[ds.Name] = ds
	}

	// Filesystem
	ds := dsMap["rpool"]
	assert.Equal(t, "rpool", ds.Name)
	assert.Equal(t, "filesystem", ds.Type)
	assert.Equal(t, int64(53687091200), ds.Used)
	assert.Equal(t, int64(53687091200), ds.Available)
	assert.Equal(t, int64(8589934592), ds.Referenced)
	assert.Equal(t, "/rpool", ds.Mountpoint)
	assert.Equal(t, "lz4", ds.Compression)
	assert.InDelta(t, 1.50, ds.Compressratio, 0.001)
	assert.True(t, ds.Mounted)
	assert.Equal(t, int64(131072), ds.Recordsize)
	assert.Equal(t, int64(0), ds.Quota)
	assert.Equal(t, int64(0), ds.Reservation)
	assert.Equal(t, "", ds.Origin)
	require.NotNil(t, ds.Creation)
	assert.Equal(t, time.Unix(1609459200, 0), *ds.Creation)
	assert.Equal(t, "off", ds.Encryption)

	// Nested filesystem with x suffix on ratio
	ds = dsMap["rpool/data"]
	assert.Equal(t, "rpool/data", ds.Name)
	assert.InDelta(t, 1.75, ds.Compressratio, 0.001)

	// Snapshot (many dash fields)
	ds = dsMap["rpool/data@snap1"]
	assert.Equal(t, "rpool/data@snap1", ds.Name)
	assert.Equal(t, "snapshot", ds.Type)
	assert.Equal(t, int64(1073741824), ds.Used)
	assert.Equal(t, int64(0), ds.Available)
	assert.Equal(t, "", ds.Mountpoint)
	assert.Equal(t, "", ds.Compression)
	assert.False(t, ds.Mounted)
	assert.Equal(t, int64(0), ds.Recordsize)
	require.NotNil(t, ds.Creation)
	assert.Equal(t, time.Unix(1704067200, 0), *ds.Creation)
	assert.Equal(t, "", ds.Encryption)
}

func TestParseDatasets_EmptyOutput(t *testing.T) {
	datasets, err := ParseDatasets("")
	require.NoError(t, err)
	assert.Nil(t, datasets)

	datasets, err = ParseDatasets(`{"datasets": {}}`)
	require.NoError(t, err)
	assert.Nil(t, datasets)
}

func TestParseDatasets_InvalidJSON(t *testing.T) {
	_, err := ParseDatasets("not json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing zfs get JSON")
}

func TestParseProperties_Pool(t *testing.T) {
	jsonOutput := `{
		"pools": {
			"rpool": {
				"properties": {
					"size": {"value": "107374182400"},
					"capacity": {"value": "50"},
					"health": {"value": "ONLINE"},
					"readonly": {"value": "off"},
					"autoexpand": {"value": "off"},
					"autotrim": {"value": "on"}
				}
			}
		}
	}`

	props, err := ParseProperties(jsonOutput)
	require.NoError(t, err)
	assert.Equal(t, "107374182400", props["size"])
	assert.Equal(t, "50", props["capacity"])
	assert.Equal(t, "ONLINE", props["health"])
	assert.Equal(t, "off", props["readonly"])
	assert.Equal(t, "off", props["autoexpand"])
	assert.Equal(t, "on", props["autotrim"])
}

func TestParseProperties_Dataset(t *testing.T) {
	jsonOutput := `{
		"datasets": {
			"rpool": {
				"properties": {
					"used": {"value": "53687091200"},
					"compression": {"value": "lz4"},
					"mountpoint": {"value": "/rpool"}
				}
			}
		}
	}`

	props, err := ParseProperties(jsonOutput)
	require.NoError(t, err)
	assert.Equal(t, "53687091200", props["used"])
	assert.Equal(t, "lz4", props["compression"])
	assert.Equal(t, "/rpool", props["mountpoint"])
}

func TestParseProperties_EmptyOutput(t *testing.T) {
	props, err := ParseProperties("")
	require.NoError(t, err)
	assert.Empty(t, props)
}

func TestParseVdevs_Raidz2(t *testing.T) {
	statusJSON := `{
		"pools": {
			"storage": {
				"vdevs": {
					"storage": {
						"name": "storage",
						"vdev_type": "root",
						"state": "ONLINE",
						"vdevs": {
							"raidz2-0": {
								"name": "raidz2-0",
								"vdev_type": "raidz2",
								"state": "ONLINE",
								"read_errors": "0",
								"write_errors": "0",
								"checksum_errors": "0",
								"slow_ios": "0",
								"vdevs": {
									"sda": {
										"name": "sda",
										"vdev_type": "disk",
										"state": "ONLINE",
										"path": "/dev/sda",
										"read_errors": "0",
										"write_errors": "0",
										"checksum_errors": "2",
										"slow_ios": "1"
									},
									"sdb": {
										"name": "sdb",
										"vdev_type": "disk",
										"state": "ONLINE",
										"path": "/dev/sdb",
										"read_errors": "0",
										"write_errors": "0",
										"checksum_errors": "0",
										"slow_ios": "0"
									},
									"sdc": {
										"name": "sdc",
										"vdev_type": "disk",
										"state": "ONLINE",
										"path": "/dev/sdc",
										"read_errors": "0",
										"write_errors": "0",
										"checksum_errors": "0",
										"slow_ios": "0"
									},
									"sdd": {
										"name": "sdd",
										"vdev_type": "disk",
										"state": "ONLINE",
										"path": "/dev/sdd",
										"read_errors": "0",
										"write_errors": "0",
										"checksum_errors": "0",
										"slow_ios": "0"
									}
								}
							}
						}
					}
				}
			}
		}
	}`

	vdevs, err := ParseVdevs(statusJSON)
	require.NoError(t, err)
	require.Len(t, vdevs, 1)

	raidz := vdevs[0]
	assert.Equal(t, "raidz2-0", raidz.Name)
	assert.Equal(t, "raidz2", raidz.Type)
	assert.Equal(t, "ONLINE", raidz.State)
	assert.Equal(t, "", raidz.Path)
	assert.Equal(t, int64(0), raidz.ReadErrors)
	require.Len(t, raidz.Devices, 4)

	// Find sda by name since map order isn't guaranteed.
	var sda *Vdev
	for i := range raidz.Devices {
		if raidz.Devices[i].Name == "sda" {
			sda = &raidz.Devices[i]
			break
		}
	}
	require.NotNil(t, sda)
	assert.Equal(t, "disk", sda.Type)
	assert.Equal(t, "/dev/sda", sda.Path)
	assert.Equal(t, int64(2), sda.ChecksumErrors)
	assert.Equal(t, int64(1), sda.SlowIOs)
	assert.Nil(t, sda.Devices)
}

func TestParseVdevs_EmptyOutput(t *testing.T) {
	vdevs, err := ParseVdevs("")
	require.NoError(t, err)
	assert.Nil(t, vdevs)

	vdevs, err = ParseVdevs(`{"pools": {}}`)
	require.NoError(t, err)
	assert.Nil(t, vdevs)
}

func TestParseRatio(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"1.00", 1.0},
		{"1.50x", 1.5},
		{"2.75x", 2.75},
		{"-", 0},
		{"", 0},
	}
	for _, tt := range tests {
		v, err := parseRatio(tt.input)
		require.NoError(t, err, "input: %q", tt.input)
		assert.InDelta(t, tt.expected, v, 0.001, "input: %q", tt.input)
	}
}

func TestParseBool(t *testing.T) {
	assert.True(t, parseBool("on"))
	assert.True(t, parseBool("yes"))
	assert.False(t, parseBool("off"))
	assert.False(t, parseBool("no"))
	assert.False(t, parseBool("-"))
	assert.False(t, parseBool(""))
}

func TestParseInt(t *testing.T) {
	v, err := parseInt("12345")
	require.NoError(t, err)
	assert.Equal(t, int64(12345), v)

	v, err = parseInt("-")
	require.NoError(t, err)
	assert.Equal(t, int64(0), v)

	v, err = parseInt("")
	require.NoError(t, err)
	assert.Equal(t, int64(0), v)

	_, err = parseInt("notanumber")
	assert.Error(t, err)
}
