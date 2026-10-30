// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// File versions of Windows executables, read for the file-version rule in
// windows_superseded.go. Only ever called with the handful of executables
// that rule selected, never for every package.

const (
	peResourceDirectoryEntry = 2  // IMAGE_DIRECTORY_ENTRY_RESOURCE
	peResourceTypeVersion    = 16 // RT_VERSION
	peFixedFileInfoSignature = 0xFEEF04BD
	peMaxResourceEntries     = 4096
	peMaxExecutableSize      = 1 << 30
	peMaxVersionInfoSize     = 1 << 16
)

// vsVersionInfoKey is "VS_VERSION_INFO" with its terminator, in UTF-16LE.
var vsVersionInfoKey = []byte("V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00")

// peFileVersion returns the file version from a PE image's version resource
// (VS_FIXEDFILEINFO dwFileVersionMS/LS), the value Windows shows as "File
// version". It walks the resource directory to the first RT_VERSION entry
// and reads only the bytes it needs. Returns false for anything that is not
// a PE image, has no version resource, or whose version is all zero.
func peFileVersion(r io.ReaderAt) ([]uint64, bool) {
	file, _, ok := peFixedVersions(r)
	return file, ok
}

// peProductVersion returns the ProductVersion string of a PE image's version
// resource (StringFileInfo), the value PowerShell's VersionInfo.ProductVersion
// returns, such as "4.8.4811.0". The fixed dwProductVersion is not the same:
// clr.dll carries 4.0.30319.0 there. When the resource has no usable
// ProductVersion string, the fixed file version formatted a.b.c.d is returned.
// Returns false in the same cases as peFileVersion.
func peProductVersion(r io.ReaderAt) (string, bool) {
	file, product, ok := peFixedVersions(r)
	if !ok {
		return "", false
	}
	if product != "" {
		return product, true
	}
	return formatWindowsVersion(file), true
}

// peFixedVersions returns the fixed file version of a PE image and its
// StringFileInfo ProductVersion string, which is empty when the resource has
// none or it is malformed.
func peFixedVersions(r io.ReaderAt) (file []uint64, product string, ok bool) {
	info, ok := peVersionInfo(r)
	if !ok {
		return nil, "", false
	}
	return info.File, info.ProductVersion, true
}

// peInfo is what a PE image's version resource and header say about it.
type peInfo struct {
	// File is the fixed file version.
	File []uint64
	// ProductVersion, ProductName and CompanyName are StringFileInfo strings,
	// empty when the resource has none or it is malformed.
	ProductVersion string
	ProductName    string
	CompanyName    string
	// Machine is the architecture of the image in the vocabulary of the
	// package architectures ("x64", "x86", "arm64"), empty for any other
	// machine type.
	Machine string
}

// peMachineArch maps the PE header machine onto a package architecture.
func peMachineArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return ""
}

// peVersionInfo reads the fixed file version, the StringFileInfo strings the
// package code needs and the machine of a PE image. It fails in the same
// cases as peFileVersion.
func peVersionInfo(r io.ReaderAt) (peInfo, bool) {
	f, err := pe.NewFile(r)
	if err != nil {
		return peInfo{}, false
	}
	defer f.Close()
	info, ok := peReadVersion(f)
	if !ok {
		return peInfo{}, false
	}
	info.Machine = peMachineArch(f.Machine)
	return info, true
}

func peReadVersion(f *pe.File) (peInfo, bool) {
	file, product, block, ok := peVersionBlock(f)
	if !ok {
		return peInfo{}, false
	}
	info := peInfo{File: file, ProductVersion: product}
	if block != nil {
		info.ProductName = versionInfoString(block, "ProductName")
		info.CompanyName = versionInfoString(block, "CompanyName")
	}
	return info, true
}

// peVersionBlock returns the fixed file version, the ProductVersion string
// and the raw VS_VERSIONINFO block (nil when it is too short to hold strings).
func peVersionBlock(f *pe.File) (file []uint64, product string, strBlock []byte, ok bool) {

	var rsrcRVA uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes <= peResourceDirectoryEntry {
			return nil, "", nil, false
		}
		rsrcRVA = oh.DataDirectory[peResourceDirectoryEntry].VirtualAddress
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes <= peResourceDirectoryEntry {
			return nil, "", nil, false
		}
		rsrcRVA = oh.DataDirectory[peResourceDirectoryEntry].VirtualAddress
	default:
		return nil, "", nil, false
	}
	if rsrcRVA == 0 {
		return nil, "", nil, false
	}

	// readRVA reads n bytes at a relative virtual address, from whichever
	// section holds it.
	readRVA := func(rva uint32, n int) ([]byte, bool) {
		for _, s := range f.Sections {
			if rva < s.VirtualAddress || rva-s.VirtualAddress >= s.Size {
				continue
			}
			off := int64(rva - s.VirtualAddress)
			if off+int64(n) > int64(s.Size) {
				return nil, false
			}
			buf := make([]byte, n)
			if _, err := s.ReadAt(buf, off); err != nil {
				return nil, false
			}
			return buf, true
		}
		return nil, false
	}

	// entries returns the (id-or-name, offset) pairs of the resource
	// directory at rsrc-relative offset off.
	type entry struct{ name, offset uint32 }
	entries := func(off uint32) ([]entry, bool) {
		hdr, ok := readRVA(rsrcRVA+off, 16)
		if !ok {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint16(hdr[12:])) + int(binary.LittleEndian.Uint16(hdr[14:]))
		if n == 0 || n > peMaxResourceEntries {
			return nil, false
		}
		raw, ok := readRVA(rsrcRVA+off+16, 8*n)
		if !ok {
			return nil, false
		}
		out := make([]entry, n)
		for i := range out {
			out[i] = entry{binary.LittleEndian.Uint32(raw[8*i:]), binary.LittleEndian.Uint32(raw[8*i+4:])}
		}
		return out, true
	}
	const subdir = 0x80000000

	root, ok := entries(0)
	if !ok {
		return nil, "", nil, false
	}
	var next uint32
	found := false
	for _, e := range root {
		if e.name == peResourceTypeVersion && e.offset&subdir != 0 {
			next, found = e.offset&^subdir, true
			break
		}
	}
	if !found {
		return nil, "", nil, false
	}
	// Name level, then language level: the first of each.
	names, ok := entries(next)
	if !ok || names[0].offset&subdir == 0 {
		return nil, "", nil, false
	}
	langs, ok := entries(names[0].offset &^ subdir)
	if !ok || langs[0].offset&subdir != 0 {
		return nil, "", nil, false
	}
	dataEntry, ok := readRVA(rsrcRVA+langs[0].offset, 16)
	if !ok {
		return nil, "", nil, false
	}
	dataRVA := binary.LittleEndian.Uint32(dataEntry[0:])
	dataSize := binary.LittleEndian.Uint32(dataEntry[4:])

	// VS_VERSIONINFO: wLength, wValueLength, wType, szKey "VS_VERSION_INFO",
	// padding to 32 bits, then VS_FIXEDFILEINFO (52 bytes) at offset 40.
	const fixedOff, fixedLen = 40, 52
	if dataSize < fixedOff+fixedLen {
		return nil, "", nil, false
	}
	vi, ok := readRVA(dataRVA, fixedOff+fixedLen)
	if !ok {
		return nil, "", nil, false
	}
	if binary.LittleEndian.Uint16(vi[2:]) < fixedLen || !bytes.Equal(vi[6:6+len(vsVersionInfoKey)], vsVersionInfoKey) {
		return nil, "", nil, false
	}
	fixed := vi[fixedOff:]
	if binary.LittleEndian.Uint32(fixed[0:]) != peFixedFileInfoSignature {
		return nil, "", nil, false
	}
	split := func(ms, ls uint32) []uint64 {
		return []uint64{uint64(ms >> 16), uint64(ms & 0xffff), uint64(ls >> 16), uint64(ls & 0xffff)}
	}
	file = split(binary.LittleEndian.Uint32(fixed[8:]), binary.LittleEndian.Uint32(fixed[12:]))
	if file[0] == 0 && file[1] == 0 && file[2] == 0 && file[3] == 0 {
		return nil, "", nil, false
	}
	// The strings follow the fixed info. Reading them is best effort: any
	// failure leaves the product string empty.
	if n := min(dataSize, peMaxVersionInfoSize); n > fixedOff+fixedLen {
		if block, ok := readRVA(dataRVA, int(n)); ok {
			product = versionInfoString(block, "ProductVersion")
			strBlock = block
		}
	}
	return file, product, strBlock, true
}

// versionInfoString finds a string value in the StringFileInfo of a
// VS_VERSIONINFO block, looking at the first string table only. Every node is
// wLength, wValueLength, wType, a UTF-16 key, padding to 32 bits, the value,
// padding, then child nodes. All offsets are checked against the block, and
// every node is at least six bytes, so a malformed block ends the walk instead
// of panicking or looping. Returns "" when the string is not there.
func versionInfoString(block []byte, name string) string {
	type node struct {
		key           string
		valOff, valSz int
		textValue     bool
		childOff, end int
	}
	align4 := func(n int) int { return (n + 3) &^ 3 }
	// parse reads the node at off, which must end by limit.
	parse := func(off, limit int) (node, bool) {
		var n node
		if off < 0 || off+6 > limit {
			return n, false
		}
		length := int(binary.LittleEndian.Uint16(block[off:]))
		valLen := int(binary.LittleEndian.Uint16(block[off+2:]))
		n.textValue = binary.LittleEndian.Uint16(block[off+4:]) == 1
		if length < 6 || off+length > limit {
			return n, false
		}
		n.end = off + length
		var key []uint16
		p := off + 6
		for {
			if p+2 > n.end {
				return n, false
			}
			c := binary.LittleEndian.Uint16(block[p:])
			p += 2
			if c == 0 {
				break
			}
			key = append(key, c)
		}
		n.key = string(utf16.Decode(key))
		n.valOff = align4(p)
		n.valSz = valLen
		if n.textValue {
			n.valSz = valLen * 2
		}
		if n.valOff > n.end || n.valSz > n.end-n.valOff {
			return n, false
		}
		n.childOff = align4(n.valOff + n.valSz)
		return n, true
	}

	root, ok := parse(0, len(block))
	if !ok {
		return ""
	}
	// First child with the key StringFileInfo.
	var sfi node
	found := false
	for off := root.childOff; ; {
		c, ok := parse(off, root.end)
		if !ok {
			return ""
		}
		if c.key == "StringFileInfo" {
			sfi, found = c, true
			break
		}
		off = align4(c.end)
	}
	if !found {
		return ""
	}
	table, ok := parse(sfi.childOff, sfi.end)
	if !ok {
		return ""
	}
	for off := table.childOff; ; {
		str, ok := parse(off, table.end)
		if !ok {
			return ""
		}
		if str.key == name && str.textValue {
			raw := block[str.valOff : str.valOff+str.valSz]
			units := make([]uint16, 0, len(raw)/2)
			for i := 0; i+1 < len(raw); i += 2 {
				u := binary.LittleEndian.Uint16(raw[i:])
				if u == 0 {
					break
				}
				units = append(units, u)
			}
			return strings.TrimSpace(string(utf16.Decode(units)))
		}
		off = align4(str.end)
	}
}

// fsFileVersionReader reads file versions through a filesystem. toFsPath
// maps a Windows path from the registry to the path on fs, or reports that
// it can't be reached.
func fsFileVersionReader(fs afero.Fs, toFsPath func(string) (string, bool)) fileVersionReader {
	return func(paths []string) map[string][]uint64 {
		out := map[string][]uint64{}
		for _, p := range paths {
			fp, ok := toFsPath(p)
			if !ok {
				continue
			}
			if v, ok := fsFileVersion(fs, fp); ok {
				out[p] = v
			} else {
				log.Debug().Str("path", p).Msg("could not read file version")
			}
		}
		return out
	}
}

func fsFileVersion(fs afero.Fs, path string) ([]uint64, bool) {
	return fsPEVersion(fs, path, peFileVersion)
}

// fsProductVersion is fsFileVersion for the ProductVersion string.
func fsProductVersion(fs afero.Fs, path string) (string, bool) {
	return fsPEVersion(fs, path, peProductVersion)
}

func fsPEVersion[T any](fs afero.Fs, path string, read func(io.ReaderAt) (T, bool)) (T, bool) {
	var zero T
	fi, err := fs.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > peMaxExecutableSize {
		return zero, false
	}
	f, err := fs.Open(path)
	if err != nil {
		return zero, false
	}
	defer f.Close()
	return read(f)
}

// nativeWindowsPath is toFsPath for a filesystem rooted at the host's own
// root: the registry path is used as is.
func nativeWindowsPath(p string) (string, bool) {
	return p, true
}

var systemDrivePath = regexp.MustCompile(`(?i)^c:[\\/]`)

// mountedSystemDrivePath is toFsPath for a filesystem rooted at a mounted
// system volume (offline image or device): C:\a\b becomes a/b. Paths on any
// other drive are not on the mounted volume.
func mountedSystemDrivePath(p string) (string, bool) {
	if !systemDrivePath.MatchString(p) {
		return "", false
	}
	return strings.ReplaceAll(p[3:], `\`, "/"), true
}

// fileVersionsScript returns a PowerShell script that prints the file
// version of each path as JSON. Paths are embedded as single-quoted literals;
// any path that could break out of one (a quote character PowerShell
// accepts, a control character) is left out.
func fileVersionsScript(paths []string) (string, bool) {
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.ContainsAny(p, "'\u2018\u2019\u201a\u201b") || strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		quoted = append(quoted, "'"+p+"'")
	}
	if len(quoted) == 0 {
		return "", false
	}
	return `$paths = @(` + strings.Join(quoted, ",") + `)
@($paths | ForEach-Object {
    $v = $null
    try {
        if (Test-Path -LiteralPath $_ -PathType Leaf) {
            $i = (Get-Item -LiteralPath $_ -ErrorAction Stop).VersionInfo
            $v = '{0}.{1}.{2}.{3}' -f $i.FileMajorPart, $i.FileMinorPart, $i.FileBuildPart, $i.FilePrivatePart
        }
    } catch {}
    [pscustomobject]@{ Path = $_; FileVersion = $v }
}) | ConvertTo-Json -Compress
`, true
}

// parseFileVersionsOutput reads fileVersionsScript's output.
func parseFileVersionsOutput(r io.Reader) (map[string][]uint64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out := map[string][]uint64{}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return out, nil
	}
	type row struct {
		Path        string  `json:"Path"`
		FileVersion *string `json:"FileVersion"`
	}
	var rows []row
	if strings.HasPrefix(s, "{") {
		var one row
		if err := json.Unmarshal([]byte(s), &one); err != nil {
			return nil, err
		}
		rows = []row{one}
	} else if err := json.Unmarshal([]byte(s), &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.FileVersion == nil {
			continue
		}
		v, ok := windowsNumericVersion(*r.FileVersion)
		if !ok || compareWindowsNumericVersions(v, nil) == 0 {
			continue
		}
		out[r.Path] = v
	}
	return out, nil
}

// remoteFileVersions reads file versions on the target over the active
// connection with one PowerShell run. A failure is logged and yields no
// versions, which leaves every entry in place.
func (w *WinPkgManager) remoteFileVersions(paths []string) map[string][]uint64 {
	script, ok := fileVersionsScript(paths)
	if !ok {
		return nil
	}
	cmd, err := w.conn.RunCommand(powershell.Encode(script))
	if err != nil {
		log.Debug().Err(err).Msg("could not read file versions")
		return nil
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Int("exit", cmd.ExitStatus).Msg("could not read file versions")
		return nil
	}
	out, err := parseFileVersionsOutput(cmd.Stdout)
	if err != nil {
		log.Debug().Err(err).Int("files", len(paths)).Msg("could not parse file versions")
		return nil
	}
	return out
}
