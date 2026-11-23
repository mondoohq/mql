// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package csproj

import (
	"encoding/xml"
	"io"
	"strings"
)

// CentralVersionResolver supplies the versions NuGet Central Package
// Management assigns a project.
//
// Under Central Package Management a project's <PackageReference> carries no
// Version; the version is stated once, as <PackageVersion Include="…"
// Version="…"/>, in the Directory.Packages.props that MSBuild imports for the
// project (the nearest one in the project's directory or above it). Reading
// the project file alone leaves those packages without a version, and so
// without a purl that matches anything.
//
// projectFile is the filename Parse was called with. The result maps a
// package id to its version; ids are compared case-insensitively, as NuGet
// does. Returning nil means the project's versions are not centrally managed,
// or the props file could not be read.
type CentralVersionResolver interface {
	CentralPackageVersions(projectFile string) map[string]string
}

// maxPropsBytes bounds how much ParsePackageVersions reads from its reader.
// It guards this parser only: a caller that reads the file into memory
// before handing over a reader should bound that read itself.
const maxPropsBytes = 8 << 20

type packageVersionsDoc struct {
	PropertyGroups []struct {
		ManagePackageVersionsCentrally string `xml:"ManagePackageVersionsCentrally"`
	} `xml:"PropertyGroup"`
	ItemGroups []struct {
		PackageVersions []struct {
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		} `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

// ParsePackageVersions reads a Directory.Packages.props: the <PackageVersion>
// items it declares (package id -> version) and whether it turns Central
// Package Management on (<ManagePackageVersionsCentrally>true</…>).
//
// A version spelled as an MSBuild property ("$(SerilogVersion)") is not
// evaluated and is left out: this reads a file, it does not run MSBuild, and
// an absent version is better than a wrong one. At most maxPropsBytes (8 MiB)
// are read from r.
func ParsePackageVersions(r io.Reader) (versions map[string]string, enabled bool, err error) {
	var doc packageVersionsDoc
	dec := xml.NewDecoder(io.LimitReader(r, maxPropsBytes))
	dec.Strict = false
	if err := dec.Decode(&doc); err != nil {
		return nil, false, err
	}
	for _, pg := range doc.PropertyGroups {
		if strings.EqualFold(strings.TrimSpace(pg.ManagePackageVersionsCentrally), "true") {
			enabled = true
		}
	}
	versions = map[string]string{}
	for _, ig := range doc.ItemGroups {
		for _, pv := range ig.PackageVersions {
			id := strings.TrimSpace(pv.Include)
			v := strings.TrimSpace(pv.VersionAttr)
			if v == "" {
				v = strings.TrimSpace(pv.VersionElem)
			}
			if id == "" || v == "" || strings.Contains(v, "$(") {
				continue
			}
			versions[id] = v
		}
	}
	return versions, enabled, nil
}
