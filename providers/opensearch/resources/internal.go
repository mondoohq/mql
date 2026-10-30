// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// mqlOpensearchRoleInternal caches the source role so its index permissions
// resolve without a second fetch. The code generator embeds this into
// mqlOpensearchRole.
type mqlOpensearchRoleInternal struct {
	cacheRole *osRole
}
