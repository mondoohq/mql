// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// yoctoOeCoreLayer is the OpenEmbedded layer used as the pkg:yocto namespace.
// v1 covers OE-Core/poky, whose layer is "core"; it matches the layer the
// Yocto advisories are keyed on and the one native 6.0 SBOMs emit.
const yoctoOeCoreLayer = "core"

// SetYoctoPurl assigns a pkg:yocto/core/<name>@<version> purl to a package
// installed on a Yocto image, overriding whatever purl the backend package
// manager produced.
//
// A Yocto image can use any package backend -- opkg, rpm or deb. Those managers
// emit their own purl type (pkg:opkg, pkg:rpm, pkg:deb), none of which match the
// Yocto vulnerability advisories. On a Yocto platform the package IS a Yocto
// recipe output regardless of the backend that installed it, so it is identified
// by its pkg:yocto purl. This runs centrally over every listed package (see the
// packages resource list()), which is what unifies all backends.
//
// It is a no-op for any non-Yocto platform, so opkg on OpenWrt -- the other user
// of opkg -- keeps its previous behaviour. The package name is the installed
// name, which the vulnerability backend matches against the recipe's
// output-package identities (reconciling the debian soname rename on its side).
func SetYoctoPurl(pf *inventory.Platform, pkg *Package) {
	if pf == nil || pf.Name != "yocto" || pkg.Name == "" || pkg.Version == "" {
		return
	}
	pkg.PUrl = purl.NewPackageURL(pf, purl.TypeYocto, pkg.Name, pkg.Version,
		purl.WithNamespace(yoctoOeCoreLayer)).String()
}
