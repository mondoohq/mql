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
	"unicode/utf16"

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
	v := [4]uint16{major, minor, build, private}
	return buildPEVersions(t, v, v, withVersion)
}

// buildPEVersions is buildPE with a fixed product version that differs from the
// file version.
func buildPEVersions(t *testing.T, file, product [4]uint16, withVersion bool) []byte {
	t.Helper()
	return buildPEStrings(t, file, product, nil, withVersion)
}

// verNode assembles a VS_VERSIONINFO child node: wLength, wValueLength, wType,
// UTF-16 key, padding, value, padding, children.
func verNode(key string, valueLen, typ uint16, value, children []byte) []byte {
	pad := func(b []byte) []byte {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	b := make([]byte, 6)
	binary.LittleEndian.PutUint16(b[2:], valueLen)
	binary.LittleEndian.PutUint16(b[4:], typ)
	b = append(b, utf16le(key)...)
	b = pad(b)
	b = append(b, value...)
	b = pad(b)
	b = append(b, children...)
	binary.LittleEndian.PutUint16(b[0:], uint16(len(b)))
	return pad(b)
}

// utf16le encodes s with a terminator.
func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return append(b, 0, 0)
}

// stringFileInfo builds a StringFileInfo node with one string table holding
// the key/value pairs.
func stringFileInfo(kv ...string) []byte {
	var strs []byte
	for i := 0; i+1 < len(kv); i += 2 {
		v := utf16le(kv[i+1])
		strs = append(strs, verNode(kv[i], uint16(len(v)/2), 1, v, nil)...)
	}
	return verNode("StringFileInfo", 0, 1, nil, verNode("040904b0", 0, 1, nil, strs))
}

// buildPEStrings is buildPEVersions with a StringFileInfo holding the given
// key/value pairs; none leaves it out.
func buildPEStrings(t *testing.T, file, product [4]uint16, strs []string, withVersion bool) []byte {
	t.Helper()
	return buildPEMachine(t, pe.IMAGE_FILE_MACHINE_AMD64, file, product, strs, withVersion)
}

// buildPEMachine is buildPEStrings for an image of the given machine type.
func buildPEMachine(t *testing.T, machine uint16, file, product [4]uint16, strs []string, withVersion bool) []byte {
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
		uint32(file[0])<<16 | uint32(file[1]), uint32(file[2])<<16 | uint32(file[3]),
		uint32(product[0])<<16 | uint32(product[1]), uint32(product[2])<<16 | uint32(product[3]),
		0x3f, 0, 0x40004, 1, 0, 0, 0,
	})
	if len(strs) > 0 {
		vi.Write(stringFileInfo(strs...))
	}
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
		Machine:              machine,
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

// The PE images in these tests are synthesized (no Microsoft binaries are
// shipped) from version resources measured on real VMs: the fixed file and
// product versions and the FileVersion and ProductVersion strings.
func TestPEProductVersion(t *testing.T) {
	file := [4]uint16{4, 8, 4811, 0}
	clrProduct := [4]uint16{4, 0, 30319, 0}
	cases := []struct {
		name string
		img  []byte
		want string
		ok   bool
	}{
		// Measured: values read from Server 2022 (20348), Server 2016 (14393)
		// and Win11 24H2 (26100) on 2026-10-23. The fixed product version of
		// clr.dll is 4.0.30319.0 everywhere, the ProductVersion string is the
		// real build, and the FileVersion string carries a "built by" suffix.
		{"Server 2022 clr.dll", buildPEStrings(t, file, clrProduct, []string{"FileVersion", "4.8.4811.0 built by: NET48REL1LAST_B", "ProductVersion", "4.8.4811.0"}, true), "4.8.4811.0", true},
		{"Server 2016 clr.dll", buildPEStrings(t, [4]uint16{4, 7, 4150, 0}, clrProduct, []string{"FileVersion", "4.7.4150.0 built by: NET472REL1LAST_B", "ProductVersion", "4.7.4150.0"}, true), "4.7.4150.0", true},
		{"Win11 24H2 clr.dll", buildPEStrings(t, [4]uint16{4, 8, 9363, 0}, clrProduct, []string{"FileVersion", "4.8.9363.0 built by: NET481REL1LAST_25H2_B", "ProductVersion", "4.8.9363.0"}, true), "4.8.9363.0", true},
		// Server 2022 mscorlib.dll: FileVersion has a "(WinRelRS6...)" suffix,
		// ProductVersion is clean, fixed file equals fixed product.
		{"Server 2022 mscorlib.dll", buildPEStrings(t, [4]uint16{2, 0, 50727, 9188}, [4]uint16{2, 0, 50727, 9188}, []string{"FileVersion", "2.0.50727.9188 (WinRelRS6.050727-9100)", "ProductVersion", "2.0.50727.9188"}, true), "2.0.50727.9188", true},

		// Synthetic: behaviour no VM showed (every measured ProductVersion was
		// clean, with no trailing text).
		{"ProductVersion string only, differs from fixed product", buildPEStrings(t, file, clrProduct, []string{"ProductVersion", "4.8.4811.0"}, true), "4.8.4811.0", true},
		{"trailing text is kept for the caller to cut", buildPEStrings(t, file, file, []string{"ProductVersion", "2.0.50727.9149 (synthetic suffix)"}, true), "2.0.50727.9149 (synthetic suffix)", true},
		{"no StringFileInfo falls back to the fixed file version", buildPEStrings(t, file, clrProduct, nil, true), "4.8.4811.0", true},
		{"StringFileInfo without ProductVersion", buildPEStrings(t, file, clrProduct, []string{"FileVersion", "4.8.4811.0"}, true), "4.8.4811.0", true},
		{"no RT_VERSION resource", buildPE(t, 4, 8, 1, 0, false), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := peProductVersion(bytes.NewReader(tc.img))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, v)
		})
	}

	// Synthetic: corrupted StringFileInfo nodes; no VM showed these.
	t.Run("malformed StringFileInfo falls back without panic", func(t *testing.T) {
		img := buildPEStrings(t, file, file, []string{"ProductVersion", "9.9.9.9"}, true)
		// VS_VERSIONINFO starts at 0x200+88; StringFileInfo at +92.
		sfi := 0x200 + 88 + 92
		for name, mutate := range map[string]func(b []byte){
			"huge wLength":       func(b []byte) { binary.LittleEndian.PutUint16(b[sfi:], 0xffff) },
			"tiny wLength":       func(b []byte) { binary.LittleEndian.PutUint16(b[sfi:], 2) },
			"zero wLength":       func(b []byte) { binary.LittleEndian.PutUint16(b[sfi:], 0) },
			"huge wValueLength":  func(b []byte) { binary.LittleEndian.PutUint16(b[sfi+2:], 0xffff) },
			"unterminated key":   func(b []byte) { copy(b[sfi+6:], bytes.Repeat([]byte{'A', 0}, 40)) },
			"damaged table node": func(b []byte) { binary.LittleEndian.PutUint16(b[sfi+36:], 0xfff0) },
		} {
			t.Run(name, func(t *testing.T) {
				bad := append([]byte{}, img...)
				mutate(bad)
				v, ok := peProductVersion(bytes.NewReader(bad))
				require.True(t, ok)
				assert.Equal(t, "4.8.4811.0", v, "fixed file version fallback")
			})
		}
	})
}

func TestPEVersionInfo(t *testing.T) {
	v := [4]uint16{7, 3, 33, 0}
	php := []string{"FileVersion", "7.3.33", "ProductVersion", "7.3.33", "ProductName", "PHP", "CompanyName", "The PHP Group"}
	want := peInfo{File: []uint64{7, 3, 33, 0}, ProductVersion: "7.3.33", ProductName: "PHP", CompanyName: "The PHP Group"}
	withMachine := func(m string) peInfo {
		w := want
		w.Machine = m
		return w
	}
	ssl := []string{"FileVersion", "1.1.1a", "ProductVersion", "1.1.1a", "ProductName", "The OpenSSL Toolkit", "CompanyName", "The OpenSSL Project, https://www.openssl.org/"}
	cases := []struct {
		name string
		img  []byte
		want peInfo
		ok   bool
	}{
		// Measured: Azure Windows Server 2022, php.net 7.3.33 TS zip, XAMPP
		// 7.3.2, 2026-10-26. The PE images are synthesized from the measured
		// version resources, not copied binaries.
		{"php.exe x64", buildPEStrings(t, v, v, php, true), withMachine("x64"), true},
		{"openssl.exe: ProductVersion string differs from the fixed version",
			buildPEStrings(t, [4]uint16{1, 1, 1, 1}, [4]uint16{1, 1, 1, 1}, ssl, true),
			peInfo{File: []uint64{1, 1, 1, 1}, ProductVersion: "1.1.1a", ProductName: "The OpenSSL Toolkit", CompanyName: "The OpenSSL Project, https://www.openssl.org/", Machine: "x64"}, true},
		{"mysqld.exe: resource without names",
			buildPEStrings(t, [4]uint16{10, 1, 38, 0}, [4]uint16{10, 1, 38, 0}, []string{"FileVersion", "10.1.38.0", "ProductVersion", "10.1.38.0"}, true),
			peInfo{File: []uint64{10, 1, 38, 0}, ProductVersion: "10.1.38.0", Machine: "x64"}, true},

		// Synthetic: machine types no host showed; every measured binary was x64.
		{"x86 image", buildPEMachine(t, pe.IMAGE_FILE_MACHINE_I386, v, v, php, true), withMachine("x86"), true},
		{"arm64 image", buildPEMachine(t, pe.IMAGE_FILE_MACHINE_ARM64, v, v, php, true), withMachine("arm64"), true},
		{"unmapped machine has no arch", buildPEMachine(t, pe.IMAGE_FILE_MACHINE_RISCV64, v, v, php, true), withMachine(""), true},
		{"no RT_VERSION", buildPE(t, 7, 3, 33, 0, false), peInfo{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := peVersionInfo(bytes.NewReader(tc.img))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
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
