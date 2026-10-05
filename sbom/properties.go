// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"strconv"
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

	// Where a package came from (ADR 049). os-provided is written only when
	// the scan answered it: an absent property means unknown, not false.
	propPackageOSProvided    = "mondoo:package:os-provided"
	propPackageSourceChannel = "mondoo:package:source:channel"
	propPackageSourceName    = "mondoo:package:source:name"
	propPackageSourceURL     = "mondoo:package:source:url"
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
	if pkg.OsProvided != nil {
		props = appendProp(props, propPackageOSProvided, strconv.FormatBool(pkg.GetOsProvided()))
	}
	if src := pkg.GetSource(); src != nil {
		props = appendProp(props, propPackageSourceChannel, src.GetChannel())
		props = appendProp(props, propPackageSourceName, src.GetName())
		props = appendProp(props, propPackageSourceURL, src.GetUrl())
	}
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
		case propPackageOSProvided:
			if v, err := strconv.ParseBool(prop.Value); err == nil {
				pkg.OsProvided = &v
			}
		case propPackageSourceChannel:
			packageSource(pkg).Channel = prop.Value
		case propPackageSourceName:
			packageSource(pkg).Name = prop.Value
		case propPackageSourceURL:
			packageSource(pkg).Url = prop.Value
		}
	}
}

// packageSource returns the package's source, creating it on first use.
func packageSource(pkg *Package) *PackageSource {
	if pkg.Source == nil {
		pkg.Source = &PackageSource{}
	}
	return pkg.Source
}
