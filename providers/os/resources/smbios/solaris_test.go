// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Captured from `smbios` on Oracle Solaris 11.4.86, a QEMU guest on OCI. It
// has no baseboard structure and no serial numbers.
func TestParseSolarisSmbios(t *testing.T) {
	f, err := os.Open("./testdata/solaris114_oci_smbios.txt")
	require.NoError(t, err)
	defer f.Close()

	info, err := ParseSolarisSmbios(f)
	require.NoError(t, err)

	assert.Equal(t, BiosInfo{
		Vendor:      "Oracle",
		Version:     "20260522",
		ReleaseDate: "May-22-2026",
	}, info.BIOS)

	assert.Equal(t, SysInfo{
		Vendor:  "QEMU",
		Model:   "Standard PC (Q35 + ICH9, 2009)",
		Version: "pc-q35-7.2",
		UUID:    "470cde01-97dd-f348-a57e-fc5b24699374",
	}, info.SysInfo)

	assert.Equal(t, BaseBoardInfo{}, info.BaseBoardInfo)

	assert.Equal(t, "QEMU", info.ChassisInfo.Vendor)
	assert.Equal(t, "pc-q35-7.2", info.ChassisInfo.Version)
	assert.Equal(t, "OracleCloud.com", info.ChassisInfo.AssetTag)
	assert.Equal(t, "1", info.ChassisInfo.Type)
}

// Only the first structure of a type counts, and keys of other structure
// types (the processor's "Manufacturer") must not leak into the ones read.
func TestParseSolarisSmbiosFirstStructureWins(t *testing.T) {
	in := `ID    SIZE TYPE
1     20   SMB_TYPE_BASEBOARD (base board)

  Manufacturer: Oracle Corporation
  Product: ASY,MB,X86
  Serial Number: 7093HV0-1234AB0001
  Asset Tag:

ID    SIZE TYPE
2     40   SMB_TYPE_PROCESSOR (processor)

  Manufacturer: Intel(R) Corporation

ID    SIZE TYPE
3     20   SMB_TYPE_BASEBOARD (base board)

  Manufacturer: Second Board Inc.
`
	info, err := ParseSolarisSmbios(strings.NewReader(in))
	require.NoError(t, err)
	assert.Equal(t, BaseBoardInfo{
		Vendor:       "Oracle Corporation",
		Model:        "ASY,MB,X86",
		SerialNumber: "7093HV0-1234AB0001",
	}, info.BaseBoardInfo)
	assert.Equal(t, "", info.SysInfo.Vendor)
}
