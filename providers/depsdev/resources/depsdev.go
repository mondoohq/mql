// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/depsdev/connection"
)

func (r *mqlDepsdev) id() (string, error) {
	return "depsdev", nil
}

func (r *mqlDepsdev) packages() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	if len(conn.Deps) == 0 {
		return []any{}, nil
	}

	var packages []any
	for _, dep := range conn.Deps {
		pkg, err := CreateResource(r.MqlRuntime, "depsdev.package", map[string]*llx.RawData{
			"name":           llx.StringData(dep.Path),
			"currentVersion": llx.StringData(dep.Version),
		})
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}
