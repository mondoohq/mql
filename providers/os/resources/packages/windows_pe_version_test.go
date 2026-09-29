// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// buildPE assembles a minimal PE32+ image with one .rsrc section holding an
// RT_VERSION resource with the given file version, laid out the way the
// resource compiler writes it: type, name and language directories, a data
// entry, then VS_VERSIONINFO with its VS_FIXEDFILEINFO. withVersion=false
// leaves the resource tree without an RT_VERSION type.
func buildPE(t *testing.T, major, minor, build, private uint16, withVersion bool) []byte {
	t.Helper()
	const rsrcRVA = 0x1000
	le := binary.LittleEndian

	write := func(w io.Writer, v any) {
		require.NoError(t, binary.Write(w, le, v))
	}
	rsrc := &bytes.Buffer{}
	dir := func(id, offset uint32) {
		write(rsrc, [4]uint32{0, 0, 0, 1 << 16}) // one id entry
		write(rsrc, [2]uint32{id, offset})
	}
	typeID := uint32(peResourceTypeVersion)
	if !withVersion {
		typeID = 3 // RT_ICON
	}
	dir(typeID, 0x80000000|24)
	dir(1, 0x80000000|48)
	dir(0x409, 72)
	vi := &bytes.Buffer{}
	write(vi, [3]uint16{0, 52, 0})
	vi.Write(vsVersionInfoKey)
	vi.Write([]byte{0, 0}) // pad to 32 bits
	write(vi, [13]uint32{
		peFixedFileInfoSignature, 0x10000,
		uint32(major)<<16 | uint32(minor), uint32(build)<<16 | uint32(private),
		uint32(major)<<16 | uint32(minor), uint32(build)<<16 | uint32(private),
		0x3f, 0, 0x40004, 1, 0, 0, 0,
	})
	viBytes := vi.Bytes()
	le.PutUint16(viBytes[0:], uint16(len(viBytes)))
	write(rsrc, [4]uint32{rsrcRVA + 88, uint32(len(viBytes)), 0, 0})
	require.Equal(t, 88, rsrc.Len())
	rsrc.Write(viBytes)
	for rsrc.Len()%0x200 != 0 {
		rsrc.WriteByte(0)
	}

	out := &bytes.Buffer{}
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	le.PutUint32(dos[0x3c:], 0x40)
	out.Write(dos)
	out.WriteString("PE\x00\x00")
	write(out, pe.FileHeader{
		Machine:              pe.IMAGE_FILE_MACHINE_AMD64,
		NumberOfSections:     1,
		SizeOfOptionalHeader: uint16(binary.Size(pe.OptionalHeader64{})),
		Characteristics:      pe.IMAGE_FILE_EXECUTABLE_IMAGE,
	})
	oh := pe.OptionalHeader64{
		Magic:               0x20b,
		SectionAlignment:    0x1000,
		FileAlignment:       0x200,
		SizeOfImage:         0x2000,
		SizeOfHeaders:       0x200,
		NumberOfRvaAndSizes: 16,
	}
	oh.DataDirectory[peResourceDirectoryEntry] = pe.DataDirectory{VirtualAddress: rsrcRVA, Size: uint32(rsrc.Len())}
	write(out, oh)
	sh := pe.SectionHeader32{
		VirtualSize:      uint32(rsrc.Len()),
		VirtualAddress:   rsrcRVA,
		SizeOfRawData:    uint32(rsrc.Len()),
		PointerToRawData: 0x200,
		Characteristics:  0x40000040,
	}
	copy(sh.Name[:], ".rsrc")
	write(out, sh)
	for out.Len() < 0x200 {
		out.WriteByte(0)
	}
	out.Write(rsrc.Bytes())
	return out.Bytes()
}

func TestPEFileVersion(t *testing.T) {
	v, ok := peFileVersion(bytes.NewReader(buildPE(t, 26, 3, 0, 0, true)))
	require.True(t, ok)
	assert.Equal(t, []uint64{26, 3, 0, 0}, v)

	v, ok = peFileVersion(bytes.NewReader(buildPE(t, 10, 0, 26100, 1882, true)))
	require.True(t, ok)
	assert.Equal(t, []uint64{10, 0, 26100, 1882}, v)

	_, ok = peFileVersion(bytes.NewReader(buildPE(t, 26, 3, 0, 0, false)))
	assert.False(t, ok, "no RT_VERSION resource")

	_, ok = peFileVersion(bytes.NewReader(buildPE(t, 0, 0, 0, 0, true)))
	assert.False(t, ok, "an all-zero version is no version")

	img := buildPE(t, 26, 3, 0, 0, true)
	_, ok = peFileVersion(bytes.NewReader(img[:0x200+60]))
	assert.False(t, ok, "truncated image")

	corrupt := append([]byte{}, img...)
	copy(corrupt[0x200+88+6:], "XX") // damage the VS_VERSION_INFO key
	_, ok = peFileVersion(bytes.NewReader(corrupt))
	assert.False(t, ok, "resource that is not VS_VERSIONINFO")

	_, ok = peFileVersion(strings.NewReader("#!/bin/sh\necho not a PE\n"))
	assert.False(t, ok)
}

func TestFsFileVersionReader(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "Program Files/7-Zip/7zFM.exe", buildPE(t, 26, 3, 0, 0, true), 0o644))
	require.NoError(t, afero.WriteFile(fs, "Program Files/7-Zip/readme.txt", []byte("7-Zip"), 0o644))

	read := fsFileVersionReader(fs, mountedSystemDrivePath)
	got := read([]string{
		`C:\Program Files\7-Zip\7zFM.exe`,
		`C:\Program Files\7-Zip\readme.txt`,
		`C:\Program Files\7-Zip\missing.exe`,
		`D:\Program Files\7-Zip\7zFM.exe`,
	})
	assert.Equal(t, map[string][]uint64{`C:\Program Files\7-Zip\7zFM.exe`: {26, 3, 0, 0}}, got)

	// The whole offline flow: the captured 7-Zip entries plus the file on
	// the mounted volume.
	raw, err := parseWindowsAppPackages(winX64Platform(), strings.NewReader("["+sevenZipExe23+","+sevenZipMsi26+"]"))
	require.NoError(t, err)
	pkgs := dropSupersededUninstallEntries(raw, nil, read)
	require.Len(t, pkgs, 1, namesAndVersions(pkgs))
	assert.Equal(t, "26.03.00.0", pkgs[0].Version)
}

func TestFileVersionsScript(t *testing.T) {
	script, ok := fileVersionsScript([]string{
		`C:\Program Files\7-Zip\7zFM.exe`,
		`C:\Program Files\it's\a.exe`,
		"C:\\Program Files\\x\u2019\\a.exe",
		"C:\\Program Files\\x\n\\a.exe",
	})
	require.True(t, ok)
	assert.Contains(t, script, `$paths = @('C:\Program Files\7-Zip\7zFM.exe')`)
	assert.NotContains(t, script, "it's")

	_, ok = fileVersionsScript([]string{`C:\it's.exe`})
	assert.False(t, ok, "nothing safe to ask for")
}

func TestParseFileVersionsOutput(t *testing.T) {
	got, err := parseFileVersionsOutput(strings.NewReader(
		`[{"Path":"C:\\Program Files\\7-Zip\\7zFM.exe","FileVersion":"26.3.0.0"},{"Path":"C:\\missing.exe","FileVersion":null},{"Path":"C:\\noversion.exe","FileVersion":"0.0.0.0"}]`))
	require.NoError(t, err)
	assert.Equal(t, map[string][]uint64{`C:\Program Files\7-Zip\7zFM.exe`: {26, 3, 0, 0}}, got)

	// ConvertTo-Json prints a single object, not an array, for one row.
	got, err = parseFileVersionsOutput(strings.NewReader(`{"Path":"C:\\Program Files\\7-Zip\\7zFM.exe","FileVersion":"26.3.0.0"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string][]uint64{`C:\Program Files\7-Zip\7zFM.exe`: {26, 3, 0, 0}}, got)

	got, err = parseFileVersionsOutput(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// The remote (PowerShell) path end to end: the inventory script returns the
// captured 7-Zip entries, and the one follow-up script asks for 7zFM.exe
// only.
func TestGetInstalledAppsRemoteFileVersionRule(t *testing.T) {
	versionsCmd, ok := fileVersionsScript([]string{`C:\Program Files\7-Zip\7zFM.exe`})
	require.True(t, ok)

	for _, tc := range []struct {
		name     string
		versions *snapCommandResult
		want     []string
	}{
		{
			name:     "7zFM.exe at 26.03",
			versions: &snapCommandResult{stdout: `{"Path":"C:\\Program Files\\7-Zip\\7zFM.exe","FileVersion":"26.3.0.0"}`},
			want:     []string{"7-Zip 26.03 (x64 edition) 26.03.00.0"},
		},
		{
			name:     "file versions can't be read",
			versions: &snapCommandResult{stderr: "access denied", exitStatus: 1},
			want:     []string{"7-Zip 23.01 (x64) 23.01", "7-Zip 26.03 (x64 edition) 26.03.00.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands := map[string]snapCommandResult{
				powershell.Encode(installedAppsScript): {stdout: "[" + sevenZipExe23 + "," + sevenZipMsi26 + "]"},
				powershell.Encode(versionsCmd):         *tc.versions,
			}
			w := &WinPkgManager{
				conn:     &snapTestConnection{capabilities: shared.Capability_RunCommand, commands: commands},
				platform: &inventory.Platform{Name: "windows", Version: "10.0.26100", Arch: "x86_64", Family: []string{"windows"}},
			}
			pkgs, err := w.getInstalledApps()
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, namesAndVersions(pkgs))
		})
	}
}
