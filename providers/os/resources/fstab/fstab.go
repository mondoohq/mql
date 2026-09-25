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
	"errors"
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

// Parse reads an fstab file into its entries.
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
		if len(record) < 4 {
			return nil, errors.New("invalid fstab entry")
		}

		var dump *int
		if len(record) >= 5 {
			_dump, err := strconv.Atoi(record[4])
			if err != nil {
				return nil, err
			}
			dump = &_dump
		}

		var fsck *int
		if len(record) >= 6 {
			_fsck, err := strconv.Atoi(record[5])
			if err != nil {
				return nil, err
			}
			fsck = &_fsck
		}

		entries = append(entries, Entry{
			Device:     record[0],
			Mountpoint: record[1],
			Fstype:     record[2],
			Options:    strings.Split(record[3], ","),
			Dump:       dump,
			Fsck:       fsck,
		})
	}

	return entries, nil
}
