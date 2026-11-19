// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/codesphere/connection"
)

// assetRoot returns the resource that roots this asset's tree, chosen from the
// platform the connection reports (ADR 031).
func assetRoot(platform *inventory.Platform) string {
	if platform == nil {
		return "codesphere"
	}
	switch platform.Name {
	case connection.PlatformOrganization:
		return "codesphere.organization"
	case connection.PlatformResourceGroup:
		return "codesphere.resourceGroup"
	case connection.PlatformWorkspace:
		return "codesphere.workspace"
	default:
		return "codesphere"
	}
}
