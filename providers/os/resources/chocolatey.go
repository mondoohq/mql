// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/types"
)

func (r *mqlChocolateyPackages) list() ([]any, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)
	mgr := &packages.ChocolateyPkgManager{Conn: conn}

	pkgs, err := mgr.ListExtended()
	if err != nil {
		// ListExtended returns empty slice (not error) when Chocolatey is not installed.
		// Errors here indicate real problems (read/parse failures) — propagate them.
		return nil, err
	}

	mqlPkgs := make([]any, len(pkgs))
	for i, pkg := range pkgs {
		pkgID := "chocolatey.package/" + pkg.Name + "@" + pkg.Version

		deps := make([]any, len(pkg.Dependencies))
		for j, d := range pkg.Dependencies {
			deps[j] = d
		}

		tags := make([]any, len(pkg.Tags))
		for j, t := range pkg.Tags {
			tags[j] = t
		}

		mqlPkg, err := CreateResource(r.MqlRuntime, "chocolatey.package", map[string]*llx.RawData{
			"__id":         llx.StringData(pkgID),
			"name":         llx.StringData(pkg.Name),
			"version":      llx.StringData(pkg.Version),
			"purl":         llx.StringData(pkg.Purl),
			"summary":      llx.StringData(pkg.Summary),
			"description":  llx.StringData(pkg.Description),
			"author":       llx.StringData(pkg.Author),
			"license":      llx.StringData(pkg.License),
			"licenseUrl":   llx.StringData(pkg.LicenseUrl),
			"path":         llx.StringData(pkg.Path),
			"pinned":       llx.BoolData(pkg.Pinned),
			"dependencies": llx.ArrayData(deps, types.String),
			"tags":         llx.ArrayData(tags, types.String),
			"projectUrl":   llx.StringData(pkg.ProjectUrl),
		})
		if err != nil {
			return nil, err
		}
		mqlPkgs[i] = mqlPkg
	}

	return mqlPkgs, nil
}
