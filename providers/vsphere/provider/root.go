// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

// assetRoot returns the resource that roots this asset's tree (ADR 031). This
// provider serves two kinds: the vSphere API and an individual ESXi host, which
// it already distinguishes by platform (connection.EsxiPlatform), so this reads
// that rather than deciding again.
//
// The API is the fallback, matching what the provider declares statically.
func assetRoot(platform *inventory.Platform) string {
	if platform != nil && platform.Name == connection.EsxiPlatform {
		return "vsphere.host"
	}
	return "vsphere"
}
