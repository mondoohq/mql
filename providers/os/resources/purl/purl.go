// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package purl

import (
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/detector"
)

const (
	QualifierArch   = "arch"
	QualifierDistro = "distro"
	QualifierEpoch  = "epoch"
	QualifierBuild  = "build"
)

// PackageURL is a helper struct that renters a package url based of an inventory
// platform, purl type, and modifiers.
type PackageURL struct {
	// Required: minimal attributes to render a PURL.
	Type    Type
	Name    string
	Version string

	// Optional: can be set via modifiers.
	Namespace string
	Arch      string
	Epoch     string

	// Used as metadata to fetch things like the architecture or linux distribution.
	platform *inventory.Platform

	// Optional: qualifiers
	Qualifiers map[string]string
}

// NewQualifiers creates a new Qualifiers slice from a map of key/value pairs.
// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst for more information
func NewQualifiers(qualifier map[string]string) packageurl.Qualifiers {
	// Create a slice for the keys to sort them
	keys := make([]string, 0, len(qualifier))
	for k := range qualifier {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Create the list of Qualifiers
	list := make(packageurl.Qualifiers, 0, len(keys))
	for _, k := range keys {
		val := qualifier[k]
		if val != "" {
			list = append(list, packageurl.Qualifier{
				Key:   k,
				Value: val,
			})
		}
	}

	return list
}

// NewPackageURL creates a new package url for a given platform, name, version, and type.
//
// For more information, see:
// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
func NewPackageURL(pf *inventory.Platform, t Type, name, version string, modifiers ...Modifier) *PackageURL {
	purl := &PackageURL{
		Type:     t,
		Name:     name,
		Version:  version,
		platform: pf,
	}

	// if a platform was provided
	if pf != nil {
		// use the platform architecture for the package
		purl.Arch = pf.Arch

		purlNamespace := pf.Name
		// Some special cases for the namespace
		switch purlNamespace {
		case "photon":
			purlNamespace = "photon os"
		case "rockylinux":
			purlNamespace = "rocky-linux"
		case "opensuse-leap":
			purlNamespace = "opensuse"
		case "opensuse-tumbleweed":
			purlNamespace = "opensuse"
		case "opensuse-microos":
			purlNamespace = "opensuse"
		case "sles":
			purlNamespace = "suse"
		}
		if purlNamespace != "" {
			purl.Namespace = purlNamespace
		}

	}

	// apply modifiers
	for _, modifier := range modifiers {
		modifier(purl)
	}

	return purl
}

func (purl PackageURL) String() string {
	qualifiers := purl.Qualifiers
	if qualifiers == nil {
		qualifiers = map[string]string{}
	}

	if purl.Arch != "" {
		qualifiers[QualifierArch] = purl.Arch
	}

	if purl.Epoch != "" && purl.Epoch != "0" {
		qualifiers[QualifierEpoch] = purl.Epoch
	}

	if distroQualifiers, ok := purl.distroQualifiers(); ok {
		qualifiers[QualifierDistro] = distroQualifiers
	}

	return packageurl.NewPackageURL(
		string(purl.Type),
		purl.Namespace,
		purl.Name,
		purl.Version,
		NewQualifiers(qualifiers),
		"",
	).ToString()
}

// generate distro qualifier
func (purl PackageURL) distroQualifiers() (string, bool) {
	if purl.platform == nil || len(purl.platform.Labels) == 0 {
		return "", false
	}

	distroId := ""
	if val, ok := purl.platform.Labels[detector.LabelDistroID]; ok {
		distroId = val
	}
	if distroId == "" {
		return "", false
	}

	distroQualifiers := []string{}
	distroQualifiers = append(distroQualifiers, distroId)
	if purl.platform.Version != "" {
		distroQualifiers = append(distroQualifiers, purl.platform.Version)
	} else if purl.platform.Build != "" {
		distroQualifiers = append(distroQualifiers, purl.platform.Build)
	}
	return strings.Join(distroQualifiers, "-"), true
}

type Modifier func(*PackageURL)

func WithArch(arch string) Modifier {
	return func(purl *PackageURL) {
		purl.Arch = arch
	}
}

func WithEpoch(epoch string) Modifier {
	return func(purl *PackageURL) {
		purl.Epoch = epoch
	}
}

func WithNamespace(namespace string) Modifier {
	return func(purl *PackageURL) {
		purl.Namespace = namespace
	}
}

func WithQualifiers(qualifiers map[string]string) Modifier {
	return func(purl *PackageURL) {
		purl.Qualifiers = qualifiers
	}
}
