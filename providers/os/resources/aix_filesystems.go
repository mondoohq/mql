// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
	"go.mondoo.com/mql/types"
)

const aixFilesystemsFile = "/etc/filesystems"

func (f *mqlAixFilesystems) id() (string, error) {
	return "aix.filesystems", nil
}

func (f *mqlAixFilesystems) list() ([]any, error) {
	if err := requireAix(f.MqlRuntime, "aix.filesystems"); err != nil {
		return nil, err
	}
	st, err := readAixStanzas(f.MqlRuntime, aixFilesystemsFile)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(st.List))
	for _, s := range st.List {
		str := func(key string) *llx.RawData {
			return aix.StringData(s.Get(key))
		}
		options := []any{}
		if v, ok := s.Get("options"); ok {
			for _, o := range aix.SplitList(v) {
				options = append(options, o)
			}
		}
		r, err := CreateResource(f.MqlRuntime, "aix.filesystem", map[string]*llx.RawData{
			"mountPoint":  llx.StringData(s.Name),
			"dev":         str("dev"),
			"vfs":         str("vfs"),
			"mountAtBoot": str("mount"),
			"nodename":    str("nodename"),
			"options":     llx.ArrayData(options, types.String),
			"log":         str("log"),
			"check":       str("check"),
			"type":        str("type"),
			"account":     aix.BoolData(s.Get("account")),
			"attributes":  llx.MapData(aix.StringMap(s.Attrs), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func initAixFilesystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	raw := args["mountPoint"]
	if raw == nil {
		return nil, nil, fmt.Errorf("aix.filesystem requires a mountPoint")
	}
	mp, ok := raw.Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("aix.filesystem mountPoint must be a string")
	}
	obj, err := CreateResource(runtime, "aix.filesystems", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlAixFilesystems).GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, x := range list.Data {
		if fs := x.(*mqlAixFilesystem); fs.MountPoint.Data == mp {
			return nil, fs, nil
		}
	}
	return nil, nil, fmt.Errorf("aix.filesystem with mountPoint %q not found", mp)
}

func (f *mqlAixFilesystem) id() (string, error) {
	return "aix.filesystem/" + f.MountPoint.Data, nil
}
