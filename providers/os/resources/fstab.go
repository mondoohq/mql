// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

func initFstab(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok || path == "" {
			path = "/etc/fstab"
		}

		f, err := CreateResource(runtime, "fstab", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["path"] = llx.StringData(path)
		return args, f, nil
	}

	args["path"] = llx.StringData("/etc/fstab")
	return args, nil, nil
}

func (f *mqlFstab) entries() ([]any, error) {
	conn, ok := f.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	fs := conn.FileSystem()
	if fs == nil {
		return nil, errors.New("filesystem not available")
	}

	fstabFile, err := fs.Open(f.GetPath().Data)
	if err != nil {
		return nil, err
	}
	defer fstabFile.Close()

	entries, err := ParseFstab(fstabFile)
	if err != nil {
		return nil, err
	}

	resources := []any{}
	for _, entry := range entries {
		resource, err := CreateResource(f.MqlRuntime, "fstab.entry", map[string]*llx.RawData{
			"device":     llx.StringData(entry.Device),
			"mountpoint": llx.StringData(entry.Mountpoint),
			"fstype":     llx.StringData(entry.Fstype),
			"options":    llx.StringData(strings.Join(entry.Options, ",")),
			"dump":       llx.IntDataPtr(entry.Dump),
			"fsck":       llx.IntDataPtr(entry.Fsck),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

type FstabEntry struct {
	Device     string
	Mountpoint string
	Fstype     string
	Options    []string
	Dump       *int
	Fsck       *int
}

func ParseFstab(file io.Reader) ([]FstabEntry, error) {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var entries []FstabEntry
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

		entry := FstabEntry{
			Device:     record[0],
			Mountpoint: record[1],
			Fstype:     record[2],
			Options:    strings.Split(record[3], ","),
			Dump:       dump,
			Fsck:       fsck,
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func (e *mqlFstabEntry) id() (string, error) {
	// The device alone is not unique: "tmpfs /tmp" and "tmpfs /dev/shm" are both
	// ordinary fstab rows, as are two swap devices that both mount at "none".
	// Sharing an __id makes the runtime serve the first entry for every
	// collision, so the later rows vanish from the list entirely. A mount point
	// appears at most once, so device plus mount point is unique.
	return e.Device.Data + " " + e.Mountpoint.Data, nil
}
