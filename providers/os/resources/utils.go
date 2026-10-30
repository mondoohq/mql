// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// For a given path, return either the path itself it if it's a file
// or return the list of files in the path sorted.
// This is super useful for loading e.g. /etc/some/config.d
func getSortedPathFiles(runtime *plugin.Runtime, path string) ([]any, error) {
	// check if the folder exists
	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	f := raw.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}

	if !exists.Data {
		return nil, errors.New("The path doesn't exist: " + path)
	}

	perm := f.GetPermissions()
	if perm.Error != nil {
		return nil, perm.Error
	}

	if !perm.Data.IsDirectory.Data {
		return []any{f}, nil
	}

	files, err := CreateResource(runtime, "files.find", map[string]*llx.RawData{
		"from": llx.StringData(path),
		"type": llx.StringData("file"),
	})
	if err != nil {
		return nil, err
	}

	res := files.(*mqlFilesFind).GetList()
	if res.Data != nil {
		sort.Slice(res.Data, func(i, j int) bool {
			a := res.Data[i]
			b := res.Data[j]
			return a.(*mqlFile).Path.Data < b.(*mqlFile).Path.Data
		})
	}

	return res.Data, res.Error
}
