// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/installations"
	"go.mondoo.com/mql/types"
)

type mqlInstallationInternal struct {
	versionFilePath string
}

func (i *mqlInstallations) list() ([]any, error) {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_File) {
		return []any{}, nil
	}

	found, err := installations.Detect(conn.FileSystem(), installations.Detectors)
	if err != nil {
		return nil, classifyFsError(err)
	}

	res := make([]any, 0, len(found))
	for _, inst := range found {
		r, err := newMqlInstallation(i.MqlRuntime, inst)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newMqlInstallation(runtime *plugin.Runtime, inst installations.Installation) (*mqlInstallation, error) {
	cpes := []any{}
	for _, uri := range inst.CPEs {
		c, err := runtime.CreateSharedResource("cpe", map[string]*llx.RawData{
			"uri": llx.StringData(uri),
		})
		if err != nil {
			return nil, err
		}
		cpes = append(cpes, c)
	}

	r, err := CreateResource(runtime, "installation", map[string]*llx.RawData{
		"__id":          llx.StringData(inst.Name + "\x00" + inst.Path),
		"name":          llx.StringData(inst.Name),
		"vendor":        llx.StringData(inst.Vendor),
		"path":          llx.StringData(inst.Path),
		"version":       llx.StringData(inst.Version),
		"versionSource": llx.StringData(inst.VersionSource),
		"locatedBy":     llx.StringData(inst.LocatedBy),
		"purl":          llx.StringData(inst.Purl),
		"cpes":          llx.ArrayData(cpes, types.Resource("cpe")),
	})
	if err != nil {
		return nil, err
	}
	res := r.(*mqlInstallation)
	res.versionFilePath = inst.VersionFile
	return res, nil
}

func (i *mqlInstallation) versionFile() (*mqlFile, error) {
	if i.versionFilePath == "" {
		i.VersionFile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := CreateResource(i.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(i.versionFilePath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}
