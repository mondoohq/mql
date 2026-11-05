// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

const (
	// yoctoPlatformName is the platform an OpenEmbedded/Yocto SBOM resolves to.
	yoctoPlatformName = "yocto"

	// yoctoPurlType is the purl type for a Yocto recipe output.
	yoctoPurlType = "yocto"

	// yoctoOeCoreLayer is the OpenEmbedded layer used as the pkg:yocto
	// namespace. v1 covers OE-Core/poky, whose layer is "core" -- the layer the
	// Yocto advisories are keyed on and the one native SBOMs emit.
	yoctoOeCoreLayer = "core"

	// yoctoCreatorOrg is the organization bitbake's create-spdx records as the
	// creator of every OpenEmbedded/Yocto SBOM, in both SPDX 2.x and SPDX 3.
	yoctoCreatorOrg = "OpenEmbedded"

	// yoctoCreatorToolPrefix is the tool bitbake's SPDX 3 export records
	// ("oe-spdx-creator <version>").
	yoctoCreatorToolPrefix = "oe-spdx-creator"
)

// isYoctoSbom reports whether a document was produced by an OpenEmbedded/Yocto
// build.
//
// A Yocto build SBOM carries CPEs and no purls: the package name is the recipe
// output name (curl, libcurl4) and the recipe base lives only in the CPE
// product field. With no purl, such a package cannot match the pkg:yocto Yocto
// advisories, so when the document is a Yocto one the importer synthesizes a
// pkg:yocto purl from the package name (the vulnerability backend reconciles
// the debian soname rename and the recipe->packages mapping on its side).
//
// bitbake's create-spdx records the creating organization as "OpenEmbedded" in
// both SPDX 2.x and SPDX 3, and the SPDX 3 export additionally records the tool
// "oe-spdx-creator". Either is a reliable signal.
func isYoctoSbom(g *Generator) bool {
	if g == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(g.GetVendor()), yoctoCreatorOrg) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(g.GetName())), yoctoCreatorToolPrefix)
}

// yoctoPackageURL builds the pkg:yocto/core/<name>@<version> purl for a Yocto
// recipe output. The name is the installed package name verbatim.
func yoctoPackageURL(name, version string) string {
	return packageurl.NewPackageURL(yoctoPurlType, yoctoOeCoreLayer, name, version, nil, "").String()
}

// synthesizeYoctoPurl assigns a pkg:yocto purl to a purl-less package that is an
// installed artifact, so a CPE-only Yocto SBOM matches the Yocto advisories. It
// is a no-op for a package that already has a purl (a forward-looking SBOM that
// emits pkg:yocto natively keeps it) or that is a source/build artifact rather
// than something installed on the device (installed reports true then).
func synthesizeYoctoPurl(pkg *Package, installed bool) {
	if pkg == nil || pkg.Purl != "" || !installed || pkg.Name == "" || pkg.Version == "" {
		return
	}
	pkg.Purl = yoctoPackageURL(pkg.Name, pkg.Version)
	pkg.Type = yoctoPurlType
}

// setYoctoPlatform marks the asset as a Yocto image. A Yocto SBOM has no purls
// to derive a platform from, so it would otherwise import as the generic "spdx"
// platform; naming it keeps the asset's identity and lets the vulnerability
// backend resolve the Yocto release.
func setYoctoPlatform(bom *Sbom) {
	if bom.Asset == nil {
		bom.Asset = &Asset{}
	}
	bom.Asset.Platform = &Platform{
		Name:   yoctoPlatformName,
		Title:  "Yocto",
		Family: familyMap[yoctoPlatformName],
	}
}
