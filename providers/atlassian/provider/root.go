// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// assetRoot returns the resource that roots this asset's tree, chosen from the
// platform the connection reports (ADR 031). It is what `_` resolves to, and
// what bounds the query.
//
// This cannot be the provider's static Root declaration, which has to name one
// resource for a provider that serves several kinds. Only the asset in hand
// says which of them this is. The keys are the platform names this provider
// already assigns, so the two cannot drift into disagreeing about what a thing
// is.
func assetRoot(platform *inventory.Platform) string {
	if platform == nil {
		return "atlassian.admin.organization"
	}

	switch platform.Name {
	case "atlassian-scim":
		return "atlassian.scim"
	case "atlassian-jira":
		return "atlassian.jira"
	case "atlassian-confluence":
		return "atlassian.confluence"
	case "atlassian-admin":
		return "atlassian.admin.organization"
	default:
		return "atlassian.admin.organization"
	}
}
