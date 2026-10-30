// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// assetRoot returns the resource that roots this asset's tree, chosen from the
// platform the connection detected (ADR 031). It is what `_` resolves to, and
// what bounds the query: on a Linux host `_.registrykey` then fails to compile
// rather than answering with an unset field.
//
// This cannot be the provider's static `Root` declaration, which has to cover
// every platform this provider serves and is therefore the `os.any` union. Only
// connecting reveals which family it actually is.
//
// Most specific first, and `os.base` when the platform says nothing we can place
// - an unknown platform still has the universal surface, and claiming a family
// we did not detect would bound the query by a guess.
func assetRoot(platform *inventory.Platform) string {
	if platform == nil {
		return "os.base"
	}

	switch {
	case platform.IsFamily("windows"):
		return "os.windows"
	case platform.IsFamily("darwin"):
		return "os.macos"
	case platform.IsFamily("linux"):
		return "os.linux"
	case platform.IsFamily("unix"):
		return "os.unix"
	default:
		return "os.base"
	}
}
