// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A scanning host with exactly one disk gets a bare object from ConvertTo-Json.
func TestParseDiskDrivesSingleDisk(t *testing.T) {
	drives, err := parseDiskDrives([]byte(`{"Name":"\\\\.\\PHYSICALDRIVE0","SCSILogicalUnit":0,"Index":0,"SerialNumber":"vol0123"}`))
	require.NoError(t, err)
	require.Len(t, drives, 1)
	assert.Equal(t, "vol0123", drives[0].SerialNumber)
}

func TestParseDiskDrivesSeveralDisks(t *testing.T) {
	drives, err := parseDiskDrives([]byte(`[{"Index":0,"SerialNumber":"a"},{"Index":1,"SerialNumber":"b"}]`))
	require.NoError(t, err)
	require.Len(t, drives, 2)
	assert.Equal(t, 1, drives[1].Index)
}

func TestParseDiskDrivesNoOutput(t *testing.T) {
	_, err := parseDiskDrives([]byte("  "))
	assert.Error(t, err, "no output is a failed query, not a host without disks")
}

func TestParsePartitionsSinglePartition(t *testing.T) {
	parts, err := parsePartitions([]byte(`{"DriveLetter":"C","Size":1024,"Type":"Basic"}`))
	require.NoError(t, err)
	require.Len(t, parts, 1)
	assert.Equal(t, "C", parts[0].DriveLetter)
}
