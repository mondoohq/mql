// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	CosPkgFormat = "cos"
)

type cosPackages struct {
	InstalledPackages []cosPackage `json:"installedPackages"`
}

type cosPackage struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Category      string `json:"category"`
	EbuildVersion string `json:"ebuild_version"`
}

type CosPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (cpm *CosPkgManager) Name() string {
	return "COS Package Manager"
}

func (cpm *CosPkgManager) Format() string {
	return CosPkgFormat
}

func (cpm *CosPkgManager) List() ([]Package, error) {
	// added as a feature in cos 85
	// https://docs.cloud.google.com/container-optimized-os/docs/release-notes/m85#cos-85-13310-1260-1
	fr, err := cpm.conn.FileSystem().Open("/etc/cos-package-info.json")
	if err != nil {
		return nil, fmt.Errorf("could not read cos package list")
	}
	defer fr.Close()

	return ParseCosPackages(cpm.platform, fr)
}

func (cpm *CosPkgManager) Available() (map[string]PackageUpdate, error) {
	return nil, errors.New("cannot determine available packages for cos")
}

func ParseCosPackages(pf *inventory.Platform, input io.Reader) ([]Package, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// handle case where no packages are installed
	if len(data) == 0 {
		return []Package{}, nil
	}

	cPkgs := cosPackages{}
	err = json.Unmarshal(data, &cPkgs)
	if err != nil {
		return nil, err
	}

	pkgs := make([]Package, len(cPkgs.InstalledPackages))
	for i, src := range cPkgs.InstalledPackages {
		// older /etc/cos-package-info.json entries only populate `version`
		// with the COS image version; newer ones add `ebuild_version`. Prefer
		// the ebuild version when present and fall back so we still emit a
		// usable PURL.
		version := src.EbuildVersion
		if version == "" {
			version = src.Version
		}
		pkgs[i].Name = src.Name
		pkgs[i].Version = version
		pkgs[i].Format = CosPkgFormat
		pkgs[i].PUrl = newCosPurl(pf, src.Name, version, src.Version)
	}

	return pkgs, nil
}

// newCosPurl builds a PURL for a COS package. Shape follows osv-scalibr and
// the open purl-spec PR #270: `pkg:cos/<name>@<version>?distro=cos-<id>`. We
// deviate from scalibr by using the ebuild version (the actual upstream
// package version, useful for CVE matching) instead of the COS image version;
// the image version is preserved as a `build` qualifier so it isn't lost.
func newCosPurl(pf *inventory.Platform, name, ebuildVersion, imageVersion string) string {
	qualifiers := map[string]string{}
	if imageVersion != "" && imageVersion != ebuildVersion {
		qualifiers[purl.QualifierBuild] = imageVersion
	}
	return purl.NewPackageURL(pf, purl.TypeCos, name, ebuildVersion,
		// pkg:cos has no namespace (matches osv-scalibr); override the
		// platform-derived default that NewPackageURL would otherwise set.
		purl.WithNamespace(""),
		purl.WithQualifiers(qualifiers),
	).String()
}

func (cpm *CosPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// not yet implemented
	return nil, nil
}
