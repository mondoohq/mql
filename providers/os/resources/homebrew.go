// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

func (r *mqlHomebrewPackages) id() (string, error) {
	return "homebrew.packages", nil
}

func (r *mqlHomebrewPackages) list() ([]any, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)
	mgr := &packages.HomebrewPkgManager{Conn: conn}

	pkgs, err := mgr.ListExtended()
	if err != nil {
		log.Debug().Err(err).Msg("mql[homebrew]> could not list packages, returning empty")
		return []any{}, nil
	}

	mqlPkgs := make([]any, len(pkgs))
	for i, pkg := range pkgs {
		pkgID := "homebrew.package/" + pkg.Type + "/" + pkg.Name + "@" + pkg.Version
		mqlPkg, err := CreateResource(r.MqlRuntime, "homebrew.package", map[string]*llx.RawData{
			"__id":                  llx.StringData(pkgID),
			"name":                  llx.StringData(pkg.Name),
			"version":               llx.StringData(pkg.Version),
			"latestVersion":         llx.StringData(pkg.LatestVersion),
			"purl":                  llx.StringData(pkg.Purl),
			"description":           llx.StringData(pkg.Description),
			"homepage":              llx.StringData(pkg.Homepage),
			"path":                  llx.StringData(pkg.Path),
			"type":                  llx.StringData(pkg.Type),
			"appName":               llx.StringData(pkg.AppName),
			"autoUpdates":           llx.BoolData(pkg.AutoUpdates),
			"installedOnRequest":    llx.BoolData(pkg.InstalledOnRequest),
			"installedAsDependency": llx.BoolData(pkg.InstalledAsDependency),
			"outdated":              brewOutdated(pkg),
			"pinned":                llx.BoolData(pkg.Pinned),
			"tap":                   llx.StringData(pkg.Tap),
			"prefix":                llx.StringData(pkg.Prefix),
		})
		if err != nil {
			return nil, err
		}
		mqlPkgs[i] = mqlPkg
	}

	return mqlPkgs, nil
}

func (r *mqlHomebrewPackage) id() (string, error) {
	// __id is always set via CreateResource; this is a required fallback for the generated code.
	return "homebrew.package/" + r.Type.Data + "/" + r.Name.Data + "@" + r.Version.Data, nil
}

// brewOutdated is null when the listing could not tell whether a newer
// version exists, rather than a false that reads as up to date.
func brewOutdated(pkg packages.HomebrewPackage) *llx.RawData {
	if pkg.OutdatedUnknown {
		return llx.NilData
	}
	return llx.BoolData(pkg.Outdated)
}
