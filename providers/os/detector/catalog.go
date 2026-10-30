// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"slices"
	"sort"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// osPlatformKinds is the closed set of kinds an operating-system platform can
// be detected as. Which one applies is decided by the connection at runtime
// (see detector/platform_resolver.go and provider/detector.go), not by the
// platform name, so every OS entry carries the full set as its possible kinds.
var osPlatformKinds = []string{
	inventory.AssetKindBaremetal, // "baremetal"
	inventory.AssetKindCloudVM,   // "virtualmachine"
	"container",                  // running container
	"container-image",            // container image layers
}

// CatalogPlatforms returns the static platform catalog for the OS provider,
// derived from the live detector tree (osTree) so it stays in sync with the
// platforms detection can actually produce. Each entry carries the platform
// name and its family chain (leaf-first, matching the runtime-emitted
// platform.Family order) plus the possible OS kinds.
//
// Runtime is intentionally left unconstrained: an OS platform's runtime is set
// by the scanning context (ssh/local, a container engine, or a cloud provider
// such as "aws-ec2-instance"), which spans providers and is open-ended, so it
// cannot be enumerated as a closed set here.
func CatalogPlatforms() []*plugin.PlatformInfo {
	names := make([]string, 0, len(osTree))
	for name := range osTree {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic output for a stable provider config

	platforms := make([]*plugin.PlatformInfo, 0, len(names))
	for _, name := range names {
		// osTree stores parents root-first (["os","unix","linux","debian"]);
		// the runtime emits them leaf-first (["debian","linux","unix","os"]).
		family := slices.Clone(osTree[name])
		slices.Reverse(family)

		platforms = append(platforms, &plugin.PlatformInfo{
			Name:   name,
			Family: family,
			Kind:   osPlatformKinds,
		})
	}
	return platforms
}
