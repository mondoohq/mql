// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/fstab"
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

// id keys the resource on the file it reads. Without it every fstab shares
// the empty cache key, so `fstab("/a")` and `fstab("/b")` resolve to whichever
// one was built first.
func (f *mqlFstab) id() (string, error) {
	return "fstab:" + f.Path.Data, nil
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

	entries, err := fstab.Parse(fstabFile)
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

func (e *mqlFstabEntry) id() (string, error) {
	// The device alone is not unique: "tmpfs /tmp" and "tmpfs /dev/shm" are both
	// ordinary fstab rows, as are two swap devices that both mount at "none".
	// Sharing an __id makes the runtime serve the first entry for every
	// collision, so the later rows vanish from the list entirely. A mount point
	// appears at most once, so device plus mount point is unique.
	return e.Device.Data + " " + e.Mountpoint.Data, nil
}
