// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// disksServer2022 is MSFT_Disk as a live Windows Server 2022 EC2 host reported
// it, with three EBS volumes: the boot disk (MBR), a GPT data disk, and an
// uninitialized (RAW) disk. The order is the order Windows returned, which is
// not by disk number. Serial numbers and ids are shortened.
const disksServer2022 = `[
  {"Number":2,"FriendlyName":"NVMe Amazon Elastic B","SerialNumber":"vol05e7_00000001.","UniqueId":"vol05e70001Amazon Elastic Block Store              1D0F","Size":10737418240,"BusType":17,"PartitionStyle":0,"IsBoot":false,"IsSystem":false,"IsOffline":false,"IsReadOnly":false,"OperationalStatus":[53264],"HealthStatus":0},
  {"Number":0,"FriendlyName":"NVMe Amazon Elastic B","SerialNumber":"vol0284_00000001.","UniqueId":"vol02840001Amazon Elastic Block Store              1D0F","Size":64424509440,"BusType":17,"PartitionStyle":1,"IsBoot":true,"IsSystem":true,"IsOffline":false,"IsReadOnly":false,"OperationalStatus":[53264],"HealthStatus":0},
  {"Number":1,"FriendlyName":"NVMe Amazon Elastic B","SerialNumber":"vol0aac_00000001.","UniqueId":"vol0aac0001Amazon Elastic Block Store              1D0F","Size":10737418240,"BusType":17,"PartitionStyle":2,"IsBoot":false,"IsSystem":false,"IsOffline":false,"IsReadOnly":false,"OperationalStatus":[53264],"HealthStatus":0}
]`

func strp(s string) *string { return &s }

func TestParseDisksLiveServer2022(t *testing.T) {
	disks, err := ParseDisks(strings.NewReader(disksServer2022))
	require.NoError(t, err)
	require.Len(t, disks, 3)

	// Sorted by disk number, not in the order Windows listed them.
	for i, d := range disks {
		require.NotNil(t, d.Number)
		assert.Equal(t, int64(i), *d.Number)
	}

	boot := disks[0]
	assert.Equal(t, "NVMe Amazon Elastic B", *boot.FriendlyName)
	assert.Equal(t, "vol0284_00000001.", *boot.TrimmedSerialNumber())
	assert.Equal(t, "vol02840001Amazon Elastic Block Store              1D0F", *boot.UniqueId)
	assert.Equal(t, int64(64424509440), *boot.Size)
	assert.Equal(t, "NVMe", *boot.BusTypeName())
	assert.Equal(t, "MBR", *boot.PartitionStyleName())
	assert.True(t, *boot.IsBoot)
	assert.True(t, *boot.IsSystem)
	assert.False(t, *boot.IsOffline)
	assert.False(t, *boot.IsReadOnly)
	assert.Equal(t, []string{"Online"}, boot.OperationalStatusNames())
	assert.Equal(t, "Healthy", *boot.HealthStatusName())

	assert.Equal(t, "GPT", *disks[1].PartitionStyleName())
	assert.False(t, *disks[1].IsBoot)
	assert.Equal(t, "RAW", *disks[2].PartitionStyleName())
}

// A single disk piped straight into ConvertTo-Json arrives as a bare object,
// which is what a one-disk Server 2016 host prints for Get-Disk.
func TestParseDisksSingleObject(t *testing.T) {
	disks, err := ParseDisks(strings.NewReader(`{"Number":0,"Size":64424509440,"IsBoot":true,"PartitionStyle":1}`))
	require.NoError(t, err)
	require.Len(t, disks, 1)
	assert.Equal(t, int64(64424509440), *disks[0].Size)
	assert.True(t, *disks[0].IsBoot)
}

func TestParseDisksEmptyArrayIsNoDisks(t *testing.T) {
	disks, err := ParseDisks(strings.NewReader("[]\r\n"))
	require.NoError(t, err)
	assert.NotNil(t, disks)
	assert.Empty(t, disks)
}

// Empty output is a script that never ran, not a host without disks.
func TestParseDisksNoOutputIsAnError(t *testing.T) {
	_, err := ParseDisks(strings.NewReader(" \r\n"))
	assert.ErrorIs(t, err, ErrNoDiskOutput)
}

func TestParseDisksMalformed(t *testing.T) {
	_, err := ParseDisks(strings.NewReader(`[{"Number":"zero"}]`))
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoDiskOutput)
}

func TestParseDisksAbsentPropertiesStayNull(t *testing.T) {
	disks, err := ParseDisks(strings.NewReader(`[{"Number":3,"IsBoot":null,"BusType":null}]`))
	require.NoError(t, err)
	require.Len(t, disks, 1)
	d := disks[0]
	assert.Nil(t, d.IsBoot)
	assert.Nil(t, d.IsSystem)
	assert.Nil(t, d.Size)
	assert.Nil(t, d.BusTypeName())
	assert.Nil(t, d.PartitionStyleName())
	assert.Nil(t, d.HealthStatusName())
	assert.Nil(t, d.TrimmedSerialNumber())
	assert.Nil(t, d.OperationalStatusNames())
}

// Disks without a number sort after numbered ones instead of panicking or
// jumping to the front.
func TestParseDisksUnnumberedSortLast(t *testing.T) {
	disks, err := ParseDisks(strings.NewReader(`[{"FriendlyName":"a"},{"Number":1},{"Number":0}]`))
	require.NoError(t, err)
	require.Len(t, disks, 3)
	assert.Equal(t, int64(0), *disks[0].Number)
	assert.Equal(t, int64(1), *disks[1].Number)
	assert.Nil(t, disks[2].Number)
}

// OperationalStatus is a list, and PowerShell may wrap it or flatten a single
// value. Every shape has to decode to the same names.
func TestParseDisksOperationalStatusShapes(t *testing.T) {
	cases := map[string]struct {
		json string
		want []string
	}{
		"array":   {`[{"OperationalStatus":[2,53267]}]`, []string{"OK", "Offline"}},
		"wrapped": {`[{"OperationalStatus":{"value":[5,53268],"Count":2}}]`, []string{"Predictive Failure", "Failed"}},
		"scalar":  {`[{"OperationalStatus":3}]`, []string{"Degraded"}},
		"empty":   {`[{"OperationalStatus":[]}]`, []string{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			disks, err := ParseDisks(strings.NewReader(tc.json))
			require.NoError(t, err)
			require.Len(t, disks, 1)
			assert.Equal(t, tc.want, disks[0].OperationalStatusNames())
		})
	}
}

func TestDiskEnumNames(t *testing.T) {
	code := func(v int64) *int64 { return &v }

	busTypes := map[int64]string{
		0: "Unknown", 1: "SCSI", 3: "ATA", 7: "USB", 8: "RAID", 9: "iSCSI",
		10: "SAS", 11: "SATA", 14: "Virtual", 15: "File Backed Virtual",
		16: "Storage Spaces", 17: "NVMe",
		// Not in the documented table: newer Windows releases add bus types.
		18: "18", 99: "99",
	}
	for c, want := range busTypes {
		assert.Equal(t, want, *Disk{BusType: code(c)}.BusTypeName(), "bus type %d", c)
	}

	styles := map[int64]string{0: "RAW", 1: "MBR", 2: "GPT", 7: "7"}
	for c, want := range styles {
		assert.Equal(t, want, *Disk{PartitionStyle: code(c)}.PartitionStyleName(), "partition style %d", c)
	}

	health := map[int64]string{0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "5"}
	for c, want := range health {
		assert.Equal(t, want, *Disk{HealthStatus: code(c)}.HealthStatusName(), "health status %d", c)
	}

	ops := Disk{OperationalStatus: PSInt64Array{0, 2, 7, 13, 0xD010, 0xD011, 0xD012, 0xD013, 0xD014, 40000}}
	assert.Equal(t, []string{
		"Unknown", "OK", "Non-Recoverable Error", "Lost Communication",
		"Online", "Not Ready", "No Media", "Offline", "Failed", "40000",
	}, ops.OperationalStatusNames())
}

func TestDiskTrimmedSerialNumber(t *testing.T) {
	// ATA serial numbers are fixed-width, space-padded fields.
	assert.Equal(t, "WD-WCC4N1234567", *Disk{SerialNumber: strp("     WD-WCC4N1234567 ")}.TrimmedSerialNumber())
	assert.Equal(t, "", *Disk{SerialNumber: strp("   ")}.TrimmedSerialNumber())
}
