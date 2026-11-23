// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
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

// The SPARC fixtures are the sample outputs in Oracle's "Displaying System
// Configuration Information" chapter of the Oracle Solaris 11.2/11.3 system
// administration guides (docs.oracle.com/cd/E36784_01/html/E36819/gmabc.html
// and docs.oracle.com/cd/E53394_01/html/E54798/gkkwk.html):
//   - solaris_sparc_t4-2_prtconf_b.txt: `prtconf -b` on a SPARC T4-2
//   - solaris_sparc_t3-4_prtconf_vb.txt: `prtconf -vb` on a SPARC T3-4
//   - solaris_sparc_t200_prtdiag.txt: `prtdiag -v` on a Sun Fire T200, with
//     the guide's "." elision lines removed
//   - solaris_x86_prtdiag.txt: the head of `prtdiag -l` on a Sun Fire X4100
//     M2, where the guide elides the manufacturer as "..."
func readSolarisFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("./testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

func TestParseSolarisPrtconfRoot(t *testing.T) {
	assert.Equal(t, SolarisPrtconfRoot{
		Name:       "ORCL,SPARC-T4-2",
		BannerName: "SPARC T4-2",
		Compatible: "sun4v",
	}, ParseSolarisPrtconfRoot(readSolarisFixture(t, "solaris_sparc_t4-2_prtconf_b.txt")))

	// -vb adds the idprom and the OpenBoot PROM, whose "openprom model" must
	// not be taken for the platform model
	assert.Equal(t, SolarisPrtconfRoot{
		Name:            "ORCL,SPARC-T3-4",
		BannerName:      "SPARC T3-4",
		Compatible:      "sun4v",
		FirmwareVersion: "OBP 4.33.0.b 2011/05/16 16:26",
	}, ParseSolarisPrtconfRoot(readSolarisFixture(t, "solaris_sparc_t3-4_prtconf_vb.txt")))
}

func TestParseSolarisPrtdiagConfig(t *testing.T) {
	assert.Equal(t, SolarisPrtdiagConfig{
		Manufacturer: "Oracle Corporation",
		Architecture: "sun4v",
		Product:      "Sun Fire T200",
	}, ParseSolarisPrtdiagConfig(readSolarisFixture(t, "solaris_sparc_t200_prtdiag.txt")))

	// without an architecture the manufacturer cannot be told from the product
	assert.Equal(t, SolarisPrtdiagConfig{},
		ParseSolarisPrtdiagConfig(readSolarisFixture(t, "solaris_x86_prtdiag.txt")))
}

func TestParseSneepSerial(t *testing.T) {
	// sneep prints "unknown" for a tag that holds no value
	assert.Equal(t, "", ParseSneepSerial("unknown\n"))
	assert.Equal(t, "", ParseSneepSerial(""))
	assert.Equal(t, "AK00123456", ParseSneepSerial("AK00123456\n"))
}

func newSolarisManager(t *testing.T, files map[string]string, commands map[string]*mock.Command) *SolarisSmbiosManager {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for path, content := range files {
		mockFiles[path] = &mock.MockFileData{Path: path, Content: content}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: "solaris", Arch: "sun4v"}},
		mock.WithData(&mock.TomlData{Files: mockFiles, Commands: commands}))
	require.NoError(t, err)
	return &SolarisSmbiosManager{provider: conn}
}

// SPARC has no smbios command. The identity comes from the device tree and
// prtdiag; this pairs the T3-4 device tree with the T200 prtdiag, so each
// field shows which source it was read from.
func TestSolarisSmbiosManagerSparc(t *testing.T) {
	m := newSolarisManager(t, nil, map[string]*mock.Command{
		"/usr/sbin/smbios":      {Stderr: "sh: /usr/sbin/smbios: not found", ExitStatus: 127},
		"/usr/sbin/prtconf -vb": {Stdout: readSolarisFixture(t, "solaris_sparc_t3-4_prtconf_vb.txt")},
		"/usr/sbin/prtdiag":     {Stdout: readSolarisFixture(t, "solaris_sparc_t200_prtdiag.txt")},
	})
	info, err := m.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:  "Oracle Corporation",
			Version: "OBP 4.33.0.b 2011/05/16 16:26",
		},
		SysInfo: SysInfo{
			Vendor: "Oracle Corporation",
			Model:  "SPARC T3-4",
			SKU:    "ORCL,SPARC-T3-4",
			Family: "sun4v",
		},
	}, info)
}

// Without prtdiag the vendor comes from the platform name, and sneep supplies
// the serial when it is installed. sneep prints only the stored serial; the
// value here is illustrative.
func TestSolarisSmbiosManagerSparcSneep(t *testing.T) {
	m := newSolarisManager(t,
		map[string]string{"/usr/sbin/sneep": ""},
		map[string]*mock.Command{
			"/usr/sbin/smbios":      {Stderr: "sh: /usr/sbin/smbios: not found", ExitStatus: 127},
			"/usr/sbin/prtconf -vb": {Stdout: readSolarisFixture(t, "solaris_sparc_t4-2_prtconf_b.txt")},
			"/usr/sbin/prtdiag":     {ExitStatus: 1},
			"/usr/sbin/sneep":       {Stdout: "AK00123456\n"},
		})
	info, err := m.Info()
	require.NoError(t, err)
	assert.Equal(t, SysInfo{
		Vendor:       "Oracle Corporation",
		Model:        "SPARC T4-2",
		SerialNumber: "AK00123456",
		SKU:          "ORCL,SPARC-T4-2",
		Family:       "sun4v",
	}, info.SysInfo)
	assert.Equal(t, "AK00123456", info.ChassisInfo.SerialNumber)
}

// No smbios and no device tree identity: the smbios error is reported, and
// no serial or model is made up.
func TestSolarisSmbiosManagerNothing(t *testing.T) {
	m := newSolarisManager(t, nil, map[string]*mock.Command{
		"/usr/sbin/smbios":      {Stderr: "smbios: failed to load SMBIOS", ExitStatus: 1},
		"/usr/sbin/prtconf -vb": {Stdout: "name:  i86pc\nbanner-name:  i86pc\ncompatible: 'i86pc'\n"},
	})
	_, err := m.Info()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load SMBIOS")
}

// x86 keeps reading smbios, and never runs the fallback.
func TestSolarisSmbiosManagerX86(t *testing.T) {
	m := newSolarisManager(t, nil, map[string]*mock.Command{
		"/usr/sbin/smbios":      {Stdout: readSolarisFixture(t, "solaris114_oci_smbios.txt")},
		"/usr/sbin/prtconf -vb": {Stdout: readSolarisFixture(t, "solaris_sparc_t3-4_prtconf_vb.txt")},
	})
	info, err := m.Info()
	require.NoError(t, err)
	assert.Equal(t, "QEMU", info.SysInfo.Vendor)
	assert.Equal(t, "Standard PC (Q35 + ICH9, 2009)", info.SysInfo.Model)
}
