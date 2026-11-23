// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package csproj

import "encoding/xml"

// project represents a parsed .csproj / .fsproj / .vbproj file.
type project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []itemGroup `xml:"ItemGroup"`

	// evidence is a list of file paths where the project file was found.
	evidence []string `xml:"-"`
	// central maps a lower-cased package id to its centrally managed version.
	central map[string]string `xml:"-"`
}

// itemGroup contains PackageReference elements.
type itemGroup struct {
	PackageReferences []packageReference `xml:"PackageReference"`
}

// packageReference represents a single <PackageReference> element.
// Version and PrivateAssets can appear as either XML attributes or child elements:
//
//	<PackageReference Include="Foo" Version="1.0" />                  (attribute form)
//	<PackageReference Include="Foo"><Version>1.0</Version></PackageReference>  (element form)
type packageReference struct {
	Include           string `xml:"Include,attr"`
	VersionAttr       string `xml:"Version,attr"`
	VersionElem       string `xml:"Version"`
	PrivateAssetsAttr string `xml:"PrivateAssets,attr"`
	PrivateAssetsElem string `xml:"PrivateAssets"`
	// VersionOverride replaces the centrally managed version for one project
	// under Central Package Management.
	VersionOverrideAttr string `xml:"VersionOverride,attr"`
	VersionOverrideElem string `xml:"VersionOverride"`
}

// version returns the package version, preferring the attribute form.
func (p *packageReference) version() string {
	if p.VersionAttr != "" {
		return p.VersionAttr
	}
	return p.VersionElem
}

// versionOverride returns the VersionOverride value, preferring the attribute form.
func (p *packageReference) versionOverride() string {
	if p.VersionOverrideAttr != "" {
		return p.VersionOverrideAttr
	}
	return p.VersionOverrideElem
}

// privateAssets returns the PrivateAssets value, preferring the attribute form.
func (p *packageReference) privateAssets() string {
	if p.PrivateAssetsAttr != "" {
		return p.PrivateAssetsAttr
	}
	return p.PrivateAssetsElem
}

// isDev returns true if this is a development-only package (PrivateAssets="all").
func (p *packageReference) isDev() bool {
	return p.privateAssets() == "all"
}
