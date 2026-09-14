// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// CycloneDX models neither the source package a binary was built from nor an
// operating system's architecture, title or family, so they travel as
// namespaced properties. The same mechanism already carries the parts of a
// license conclusion the schema has no home for.
//
// The source package is the one that has to survive. Debian and RPM advisories
// are published against it, so an advisory for glibc reaches the installed
// libc6 and libc-bin through this field and no other. A BOM written without it
// scans clean: the packages are all present and correct, nothing matches them,
// and the result is indistinguishable from an asset that genuinely has no
// findings.
const (
	propPlatformArch   = "mondoo:platform:arch"
	propPlatformTitle  = "mondoo:platform:title"
	propPlatformFamily = "mondoo:platform:family"
	propPackageOrigin  = "mondoo:package:origin"
	propPackageArch    = "mondoo:package:arch"
)

// platformProperties renders the platform fields CycloneDX cannot hold, or nil
// when there is nothing to carry.
func platformProperties(platform *Platform) *[]cyclonedx.Property {
	if platform == nil {
		return nil
	}
	props := appendProp(nil, propPlatformArch, platform.GetArch())
	props = appendProp(props, propPlatformTitle, platform.GetTitle())
	props = appendProp(props, propPlatformFamily, strings.Join(platform.GetFamily(), ","))
	if len(props) == 0 {
		return nil
	}
	return &props
}

// packageProperties renders the package fields CycloneDX cannot hold, or nil
// when there is nothing to carry.
func packageProperties(pkg *Package) *[]cyclonedx.Property {
	if pkg == nil {
		return nil
	}
	props := appendProp(nil, propPackageOrigin, pkg.Origin)
	props = appendProp(props, propPackageArch, pkg.Architecture)
	if len(props) == 0 {
		return nil
	}
	return &props
}

func appendProp(props []cyclonedx.Property, name, value string) []cyclonedx.Property {
	if value == "" {
		return props
	}
	return append(props, cyclonedx.Property{Name: name, Value: value})
}

// applyPlatformProperties restores what platformProperties carried. Values that
// are absent leave what the caller already derived untouched, so a document
// from another tool keeps the family looked up from its name.
func applyPlatformProperties(platform *Platform, props *[]cyclonedx.Property) {
	if platform == nil || props == nil {
		return
	}
	for _, prop := range *props {
		switch prop.Name {
		case propPlatformArch:
			platform.Arch = prop.Value
		case propPlatformTitle:
			platform.Title = prop.Value
		case propPlatformFamily:
			if prop.Value != "" {
				platform.Family = strings.Split(prop.Value, ",")
			}
		}
	}
}

// applyPackageProperties restores what packageProperties carried.
func applyPackageProperties(pkg *Package, props *[]cyclonedx.Property) {
	if pkg == nil || props == nil {
		return
	}
	for _, prop := range *props {
		switch prop.Name {
		case propPackageOrigin:
			pkg.Origin = prop.Value
		case propPackageArch:
			pkg.Architecture = prop.Value
		}
	}
}
