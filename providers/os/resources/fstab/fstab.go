// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package fstab parses /etc/fstab.
//
// The parser lives in its own package so that a caller needing only it does not
// have to import providers/os/resources. That is a single package holding every
// OS resource implementation, and through them every language SBOM parser and
// everything those in turn depend on.
//
// The device-mount code needs exactly two symbols from here. Importing the
// whole of resources to reach them put the SBOM parsers' dependencies — toml,
// yaml, nvdtools, and most recently hcl/v2 and go-cty — into the module graph
// of every provider that mounts a disk, and so into their go.sum files.
package fstab

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Entry is one row of an fstab file.
type Entry struct {
	Device     string
	Mountpoint string
	Fstype     string
	Options    []string
	Dump       *int
	Fsck       *int
}

// Parse reads an fstab file into its entries. A line util-linux cannot parse,
// one without a device, a mount point and a type, or whose dump or fsck field
// is not a number, is skipped as libmount skips it ("parse error ... --
// ignored"), so it does not hide the lines around it.
func Parse(file io.Reader) ([]Entry, error) {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var entries []Entry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines, including indented comments and
		// whitespace-only lines (both are valid in /etc/fstab).
		if line == "" || line[0] == '#' {
			continue
		}

		record := strings.Fields(line)
		if len(record) < 3 {
			continue
		}

		var options []string
		if len(record) >= 4 {
			options = strings.Split(record[3], ",")
		}

		var dump *int
		if len(record) >= 5 {
			_dump, err := strconv.Atoi(record[4])
			if err != nil {
				continue
			}
			dump = &_dump
		}

		var fsck *int
		if len(record) >= 6 {
			_fsck, err := strconv.Atoi(record[5])
			if err != nil {
				continue
			}
			fsck = &_fsck
		}

		entries = append(entries, Entry{
			Device:     UnescapeOctal(record[0]),
			Mountpoint: UnescapeOctal(record[1]),
			Fstype:     record[2],
			Options:    options,
			Dump:       dump,
			Fsck:       fsck,
		})
	}

	return entries, scanner.Err()
}

// UnescapeOctal decodes the three-digit octal escapes (\040 for a space)
// that fstab, the kernel's mount tables and the NFS exports file use for
// characters that would otherwise split a field. Anything else is kept as
// written.
func UnescapeOctal(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] <= '3' && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool {
	return c >= '0' && c <= '7'
}
